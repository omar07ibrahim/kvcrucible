//! Coordinated trace validation, normalization, and sealed scenario capabilities.

use std::{collections::BTreeMap, sync::Arc};

use thiserror::Error as ThisError;

use crate::{
    ir::{Record, ValidatedRecord},
    limits::Limits,
    state::{
        self, BaselineAuthority, EnvelopeNormalizer, PreparedEnvelope, SealedSession,
        StreamBlueprint, StreamState, StreamSummary,
    },
    trace::{
        self, DeliveryKey, PlannedAction, SchedulePlan, SourceIndex, TraceSummary, TraceValidator,
        ValidatedTraceParts, ValidatedTracePlan,
    },
};

/// Stable assembly failures that never echo trace-controlled identities.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// A caller continued after the first assembly failure.
    #[error("trace assembler is already failed")]
    AssemblerFailed,
    /// A stream declaration omitted its external baseline-authority decision.
    #[error("stream records require a baseline-authority decision")]
    BaselineAuthorityRequired,
    /// A baseline-authority decision accompanied a non-stream record.
    #[error("baseline authority is only valid for stream records")]
    UnexpectedBaselineAuthority,
    /// Structural trace validation rejected a record or EOF.
    #[error("trace validation failed: {error}")]
    Trace {
        /// Redacted structural failure.
        #[source]
        error: trace::Error,
    },
    /// Source normalization or stream registration failed.
    #[error("trace normalization failed: {error}")]
    State {
        /// Redacted state-layer failure.
        #[source]
        error: state::Error,
    },
    /// Coordinated components disagreed after successful EOF processing.
    #[error("sealed trace components violate an internal assembly invariant")]
    AssemblyInvariant,
    /// A bounded sealed-manifest allocation could not be reserved.
    #[error("sealed trace manifest storage could not be reserved")]
    AssemblyCapacity,
    /// A stream ordinal was outside the sealed manifest.
    #[error("stream index {actual} is outside sealed stream count {count}")]
    StreamIndexOutOfRange {
        /// Number of streams in the sealed trace.
        count: usize,
        /// Requested zero-based stream ordinal.
        actual: usize,
    },
    /// A fault-schedule ordinal was outside the sealed manifest.
    #[error("schedule index {actual} is outside sealed schedule count {count}")]
    ScheduleIndexOutOfRange {
        /// Number of schedules in the sealed trace.
        count: usize,
        /// Requested zero-based schedule ordinal.
        actual: usize,
    },
    /// A bounded materialization allocation could not be reserved.
    #[error("fault schedule storage could not be reserved")]
    MaterializationCapacity,
    /// A crate-private numeric plan violated its validated invariants.
    #[error("fault schedule violates an internal materialization invariant")]
    MaterializationInvariant,
}

impl Error {
    /// Return a machine-stable error code without trace-derived text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AssemblerFailed => "assembler_failed",
            Self::BaselineAuthorityRequired => "baseline_authority_required",
            Self::UnexpectedBaselineAuthority => "unexpected_baseline_authority",
            Self::Trace { .. } => "trace_validation",
            Self::State { .. } => "trace_normalization",
            Self::AssemblyInvariant => "assembly_invariant",
            Self::AssemblyCapacity => "assembly_capacity",
            Self::StreamIndexOutOfRange { .. } => "stream_index_out_of_range",
            Self::ScheduleIndexOutOfRange { .. } => "schedule_index_out_of_range",
            Self::MaterializationCapacity => "materialization_capacity",
            Self::MaterializationInvariant => "materialization_invariant",
        }
    }
}

/// Fail-closed owner of one structural validator and one source normalizer.
///
/// Every accepted stream or envelope is passed to both layers from the same
/// owned [`ValidatedRecord`]. This prevents a numeric fault plan validated over
/// one payload from being paired with a different normalized payload that
/// happens to reuse the same trace-local identity.
pub struct TraceAssembler {
    validator: TraceValidator,
    normalizer: EnvelopeNormalizer,
    streams: Vec<StreamBlueprint>,
    sources: Vec<Arc<PreparedEnvelope>>,
    failed: bool,
}

impl TraceAssembler {
    /// Create an empty coordinated assembler under explicit finite limits.
    ///
    /// # Errors
    ///
    /// Returns a redacted trace- or state-layer configuration error when the
    /// requested limits exceed a compile-time safety ceiling.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let validator = TraceValidator::new(limits).map_err(trace_error)?;
        let normalizer = EnvelopeNormalizer::new(limits).map_err(state_error)?;
        Ok(Self {
            validator,
            normalizer,
            streams: Vec::new(),
            sources: Vec::new(),
            failed: false,
        })
    }

    /// Accept the next owned trace record and its optional trust decision.
    ///
    /// `authority` must be present exactly for [`Record::Stream`] and absent
    /// for every other record kind. The assembler becomes permanently failed
    /// after any error, including caller misuse detected before either inner
    /// layer is mutated.
    ///
    /// # Errors
    ///
    /// Returns a stable authority, structural-validation, normalization, or
    /// prior-failure error.
    pub fn push(
        &mut self,
        record: ValidatedRecord,
        authority: Option<BaselineAuthority>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::AssemblerFailed);
        }
        let result = self.push_inner(record, authority);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Reach EOF and return the only executable trace capability.
    ///
    /// Structural EOF validation completes before the normalization session is
    /// sealed, so an incomplete or previously failed trace cannot expose fault
    /// plans, prepared sources, or scenario-state blueprints.
    ///
    /// # Errors
    ///
    /// Returns a stable error after prior failure, missing structural state,
    /// normalization seal failure, or an internal binding inconsistency.
    pub fn finish(self) -> Result<SealedTrace, Error> {
        if self.failed {
            return Err(Error::AssemblerFailed);
        }
        let plan = self.validator.finish_planned().map_err(trace_error)?;
        let sealed = self.normalizer.seal().map_err(state_error)?;
        SealedTrace::bind_owned(
            plan,
            sealed,
            self.streams.into_boxed_slice(),
            self.sources.into_boxed_slice(),
        )
    }

    fn push_inner(
        &mut self,
        record: ValidatedRecord,
        authority: Option<BaselineAuthority>,
    ) -> Result<(), Error> {
        let route = RecordRoute::from(record.as_record());
        let stream_authority = match (route, authority) {
            (RecordRoute::Stream, Some(authority)) => Some(authority),
            (RecordRoute::Stream, None) => return Err(Error::BaselineAuthorityRequired),
            (_, Some(_)) => return Err(Error::UnexpectedBaselineAuthority),
            (_, None) => None,
        };

        self.validator.push(&record).map_err(trace_error)?;
        match route {
            RecordRoute::Stream => {
                let authority = stream_authority
                    .expect("stream authority was established before structural validation");
                let blueprint = self
                    .normalizer
                    .register_stream(&record, authority)
                    .map_err(state_error)?;
                self.streams.push(blueprint);
            }
            RecordRoute::Envelope => {
                let source = self.normalizer.prepare(record).map_err(state_error)?;
                self.sources.push(source);
            }
            RecordRoute::Other => {}
        }
        Ok(())
    }
}

/// EOF-sealed source corpus and opaque fault-plan manifest.
///
/// The type exposes content-free counts, deliberate identity lookups, and
/// deterministic materialization, but neither raw numeric actions nor
/// constructors. Materialization accepts only this capability instead of
/// arbitrary records or sources.
pub struct SealedTrace {
    summary: TraceSummary,
    limits: Limits,
    sealed: SealedSession,
    streams: Box<[StreamBlueprint]>,
    sources: Box<[Arc<PreparedEnvelope>]>,
    source_streams: Box<[usize]>,
    schedules: Box<[SchedulePlan]>,
}

impl SealedTrace {
    /// Content-free trace accounting established at EOF.
    #[must_use]
    pub const fn summary(&self) -> TraceSummary {
        self.summary
    }

    /// Finite limits shared by validation, normalization, and execution.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Number of registered publisher streams in physical declaration order.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Number of prepared physical source envelopes.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Number of validated fault schedules in physical record order.
    #[must_use]
    pub fn schedule_count(&self) -> usize {
        self.schedules.len()
    }

    /// Deliberately inspect one trace-local stream identity by ordinal.
    #[must_use]
    pub fn stream_id(&self, index: usize) -> Option<&str> {
        self.streams.get(index).map(StreamBlueprint::stream_id)
    }

    /// Deliberately inspect one trace-local source identity by ordinal.
    #[must_use]
    pub fn source_id(&self, index: usize) -> Option<&str> {
        self.sources.get(index).map(|source| source.envelope_id())
    }

    /// Deliberately inspect one trace-local fault-schedule identity by ordinal.
    #[must_use]
    pub fn schedule_id(&self, index: usize) -> Option<&str> {
        self.schedules
            .get(index)
            .map(|schedule| schedule.id.as_ref())
    }

    /// Number of physical source envelopes visible to one schedule.
    #[must_use]
    pub fn schedule_source_prefix(&self, index: usize) -> Option<usize> {
        self.schedules
            .get(index)
            .map(|schedule| schedule.prefix_len)
    }

    /// Materialize one validated fault schedule in deterministic delivery order.
    ///
    /// The operation retains tombstones for dropped occurrences, shares each
    /// immutable prepared source through [`Arc`], and never recomputes semantic
    /// fingerprints. Repeating the call produces the same stable occurrence
    /// order without mutating this sealed trace.
    ///
    /// For prefix length `P`, action count `A`, and synthesized-copy count `C`,
    /// materialization uses `O((P + A + C) log(P + C + 1))` time and `O(P + C)`
    /// retained working memory.
    ///
    /// # Errors
    ///
    /// Returns a stable bounds, capacity, or internal invariant error.
    pub fn materialize(&self, index: usize) -> Result<MaterializedSchedule, Error> {
        let plan = self
            .schedules
            .get(index)
            .ok_or(Error::ScheduleIndexOutOfRange {
                count: self.schedules.len(),
                actual: index,
            })?;
        materialize_schedule(plan, &self.sources, &self.source_streams, &self.limits)
    }

    /// Start a fresh empty state for one stream in the sealed manifest.
    ///
    /// # Errors
    ///
    /// Returns a stable bounds error or an internal state-capability failure.
    pub fn start_stream(&self, index: usize) -> Result<StreamState, Error> {
        let blueprint = self
            .streams
            .get(index)
            .ok_or(Error::StreamIndexOutOfRange {
                count: self.streams.len(),
                actual: index,
            })?;
        blueprint.start(&self.sealed).map_err(state_error)
    }

    /// Finalize a state against this exact sealed source session.
    ///
    /// # Errors
    ///
    /// Returns a redacted state-layer error for a foreign or failed state.
    pub fn finish_stream(&self, state: StreamState) -> Result<StreamSummary, Error> {
        state.finish(&self.sealed).map_err(state_error)
    }

    fn bind_owned(
        plan: ValidatedTracePlan,
        sealed: SealedSession,
        streams: Box<[StreamBlueprint]>,
        sources: Box<[Arc<PreparedEnvelope>]>,
    ) -> Result<Self, Error> {
        let ValidatedTraceParts {
            summary,
            limits,
            stream_ids,
            envelope_ids,
            schedules,
        } = plan.into_parts();

        let streams_match = stream_ids.len() == streams.len()
            && stream_ids.iter().zip(&streams).all(|(expected, actual)| {
                expected.as_ref() == actual.stream_id() && sealed.owns_blueprint(actual)
            });
        let sources_match = envelope_ids.len() == sources.len()
            && envelope_ids.iter().zip(&sources).all(|(expected, actual)| {
                expected.as_ref() == actual.envelope_id() && sealed.owns_source(actual)
            });
        if limits != sealed.limits() || !streams_match || !sources_match {
            return Err(Error::AssemblyInvariant);
        }

        let stream_ordinals: BTreeMap<_, _> = streams
            .iter()
            .enumerate()
            .map(|(index, blueprint)| (blueprint.stream_id(), index))
            .collect();
        let mut source_streams = Vec::new();
        source_streams
            .try_reserve_exact(sources.len())
            .map_err(|_| Error::AssemblyCapacity)?;
        for source in &sources {
            let stream = stream_ordinals
                .get(source.stream_id())
                .copied()
                .ok_or(Error::AssemblyInvariant)?;
            source_streams.push(stream);
        }

        Ok(Self {
            summary,
            limits,
            sealed,
            streams,
            sources,
            source_streams: source_streams.into_boxed_slice(),
            schedules,
        })
    }
}

/// One stable delivery occurrence in a materialized fault schedule.
///
/// Positive occurrences share the exact immutable prepared source allocation
/// with occurrence zero. The wrapper deliberately does not implement `Debug`
/// or serialization.
#[derive(Clone)]
pub struct ScheduledDelivery {
    source: Arc<PreparedEnvelope>,
    stream_index: usize,
    occurrence: u16,
}

impl ScheduledDelivery {
    /// Trace-local identity of the physical source envelope.
    #[must_use]
    pub fn envelope_id(&self) -> &str {
        self.source.envelope_id()
    }

    /// Zero for the physical delivery, positive for a synthesized duplicate.
    #[must_use]
    pub const fn occurrence(&self) -> u16 {
        self.occurrence
    }

    /// Zero-based publisher-stream ordinal in the sealed manifest.
    #[must_use]
    pub const fn stream_index(&self) -> usize {
        self.stream_index
    }

    /// Borrow the immutable prepared source capability.
    #[must_use]
    pub const fn source(&self) -> &Arc<PreparedEnvelope> {
        &self.source
    }
}

/// Immutable deterministic result of one validated fault schedule.
pub struct MaterializedSchedule {
    schedule_id: Arc<str>,
    source_prefix: usize,
    allocated_occurrences: usize,
    deliveries: Box<[ScheduledDelivery]>,
}

impl MaterializedSchedule {
    /// Trace-local schedule identity.
    #[must_use]
    pub fn schedule_id(&self) -> &str {
        self.schedule_id.as_ref()
    }

    /// Number of physical sources visible at the schedule record.
    #[must_use]
    pub const fn source_prefix(&self) -> usize {
        self.source_prefix
    }

    /// Original plus synthesized occurrences, including later tombstones.
    #[must_use]
    pub const fn allocated_occurrences(&self) -> usize {
        self.allocated_occurrences
    }

    /// Number of live deliveries after all transformations.
    #[must_use]
    pub fn delivery_count(&self) -> usize {
        self.deliveries.len()
    }

    /// Live deliveries in final deterministic order.
    #[must_use]
    pub const fn deliveries(&self) -> &[ScheduledDelivery] {
        &self.deliveries
    }
}

fn materialize_schedule(
    plan: &SchedulePlan,
    sources: &[Arc<PreparedEnvelope>],
    source_streams: &[usize],
    limits: &Limits,
) -> Result<MaterializedSchedule, Error> {
    if plan.prefix_len > sources.len() || sources.len() != source_streams.len() {
        return Err(Error::MaterializationInvariant);
    }
    let mut allocated = plan.prefix_len;
    for action in &plan.actions {
        if let PlannedAction::Duplicate { copies, .. } = action {
            allocated = allocated
                .checked_add(usize::from(*copies))
                .ok_or(Error::MaterializationInvariant)?;
        }
    }
    let allocated_u64 = u64::try_from(allocated).map_err(|_| Error::MaterializationInvariant)?;
    if allocated_u64 > limits.max_occurrences_per_schedule {
        return Err(Error::MaterializationInvariant);
    }

    let mut arena = DeliveryArena::new(plan.prefix_len, allocated)?;
    for action in &plan.actions {
        match *action {
            PlannedAction::Drop { target } => arena.drop_delivery(target)?,
            PlannedAction::Duplicate {
                target,
                first_occurrence,
                copies,
            } => arena.duplicate(target, first_occurrence, copies)?,
            PlannedAction::MoveBefore { target, anchor } => {
                arena.move_before(target, anchor)?;
            }
        }
    }
    let deliveries = arena.materialize(sources, source_streams, plan.prefix_len)?;
    Ok(MaterializedSchedule {
        schedule_id: Arc::clone(&plan.id),
        source_prefix: plan.prefix_len,
        allocated_occurrences: allocated,
        deliveries,
    })
}

struct DeliveryArena {
    nodes: Vec<DeliveryNode>,
    positions: BTreeMap<DeliveryKey, usize>,
    head: Option<usize>,
    tail: Option<usize>,
}

impl DeliveryArena {
    fn new(prefix_len: usize, capacity: usize) -> Result<Self, Error> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity)
            .map_err(|_| Error::MaterializationCapacity)?;
        let mut arena = Self {
            nodes,
            positions: BTreeMap::new(),
            head: None,
            tail: None,
        };
        for source in 0..prefix_len {
            arena.append_original(DeliveryKey {
                source: SourceIndex(source),
                occurrence: 0,
            })?;
        }
        Ok(arena)
    }

    fn append_original(&mut self, key: DeliveryKey) -> Result<(), Error> {
        if self.positions.contains_key(&key) {
            return Err(Error::MaterializationInvariant);
        }
        let index = self.nodes.len();
        self.nodes.push(DeliveryNode {
            key,
            prev: self.tail,
            next: None,
            live: true,
        });
        if let Some(tail) = self.tail {
            self.nodes[tail].next = Some(index);
        } else {
            self.head = Some(index);
        }
        self.tail = Some(index);
        self.positions.insert(key, index);
        Ok(())
    }

    fn drop_delivery(&mut self, key: DeliveryKey) -> Result<(), Error> {
        let index = self.resolve_live(key)?;
        self.unlink(index);
        self.nodes[index].live = false;
        Ok(())
    }

    fn duplicate(
        &mut self,
        target: DeliveryKey,
        first_occurrence: u16,
        copies: u16,
    ) -> Result<(), Error> {
        let mut cursor = self.resolve_live(target)?;
        for offset in 0..copies {
            let occurrence = first_occurrence
                .checked_add(offset)
                .ok_or(Error::MaterializationInvariant)?;
            let key = DeliveryKey {
                source: target.source,
                occurrence,
            };
            if self.positions.contains_key(&key) {
                return Err(Error::MaterializationInvariant);
            }
            cursor = self.insert_after(cursor, key)?;
        }
        Ok(())
    }

    fn move_before(&mut self, target: DeliveryKey, anchor: DeliveryKey) -> Result<(), Error> {
        let target = self.resolve_live(target)?;
        let anchor = self.resolve_live(anchor)?;
        if target == anchor {
            return Err(Error::MaterializationInvariant);
        }
        if self.nodes[target].next == Some(anchor) {
            return Ok(());
        }

        self.unlink(target);
        let previous = self.nodes[anchor].prev;
        self.nodes[target].prev = previous;
        self.nodes[target].next = Some(anchor);
        self.nodes[anchor].prev = Some(target);
        if let Some(previous) = previous {
            self.nodes[previous].next = Some(target);
        } else {
            self.head = Some(target);
        }
        Ok(())
    }

    fn insert_after(&mut self, anchor: usize, key: DeliveryKey) -> Result<usize, Error> {
        if !self.nodes.get(anchor).is_some_and(|node| node.live) {
            return Err(Error::MaterializationInvariant);
        }
        let next = self.nodes[anchor].next;
        let index = self.nodes.len();
        self.nodes.push(DeliveryNode {
            key,
            prev: Some(anchor),
            next,
            live: true,
        });
        self.nodes[anchor].next = Some(index);
        if let Some(next) = next {
            self.nodes[next].prev = Some(index);
        } else {
            self.tail = Some(index);
        }
        self.positions.insert(key, index);
        Ok(index)
    }

    fn unlink(&mut self, index: usize) {
        let previous = self.nodes[index].prev;
        let next = self.nodes[index].next;
        if let Some(previous) = previous {
            self.nodes[previous].next = next;
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            self.nodes[next].prev = previous;
        } else {
            self.tail = previous;
        }
        self.nodes[index].prev = None;
        self.nodes[index].next = None;
    }

    fn resolve_live(&self, key: DeliveryKey) -> Result<usize, Error> {
        let index = self
            .positions
            .get(&key)
            .copied()
            .ok_or(Error::MaterializationInvariant)?;
        if !self.nodes.get(index).is_some_and(|node| node.live) {
            return Err(Error::MaterializationInvariant);
        }
        Ok(index)
    }

    fn materialize(
        &self,
        sources: &[Arc<PreparedEnvelope>],
        source_streams: &[usize],
        prefix_len: usize,
    ) -> Result<Box<[ScheduledDelivery]>, Error> {
        let live = self.nodes.iter().filter(|node| node.live).count();
        let mut deliveries = Vec::new();
        deliveries
            .try_reserve_exact(live)
            .map_err(|_| Error::MaterializationCapacity)?;
        let mut cursor = self.head;
        let mut visited = 0_usize;
        while let Some(index) = cursor {
            if visited >= self.nodes.len() {
                return Err(Error::MaterializationInvariant);
            }
            let node = self
                .nodes
                .get(index)
                .ok_or(Error::MaterializationInvariant)?;
            if !node.live || node.key.source.0 >= prefix_len {
                return Err(Error::MaterializationInvariant);
            }
            let source = sources
                .get(node.key.source.0)
                .ok_or(Error::MaterializationInvariant)?;
            let stream_index = source_streams
                .get(node.key.source.0)
                .copied()
                .ok_or(Error::MaterializationInvariant)?;
            deliveries.push(ScheduledDelivery {
                source: Arc::clone(source),
                stream_index,
                occurrence: node.key.occurrence,
            });
            cursor = node.next;
            visited = visited
                .checked_add(1)
                .ok_or(Error::MaterializationInvariant)?;
        }
        if visited != live {
            return Err(Error::MaterializationInvariant);
        }
        Ok(deliveries.into_boxed_slice())
    }
}

struct DeliveryNode {
    key: DeliveryKey,
    prev: Option<usize>,
    next: Option<usize>,
    live: bool,
}

#[derive(Clone, Copy)]
enum RecordRoute {
    Stream,
    Envelope,
    Other,
}

impl From<&Record> for RecordRoute {
    fn from(record: &Record) -> Self {
        match record {
            Record::Stream(_) => Self::Stream,
            Record::Envelope(_) => Self::Envelope,
            Record::TraceHeader(_) | Record::FaultSchedule(_) => Self::Other,
        }
    }
}

fn trace_error(error: trace::Error) -> Error {
    Error::Trace { error }
}

fn state_error(error: state::Error) -> Error {
    Error::State { error }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use proptest::prelude::*;

    use super::{DeliveryArena, Error, ScheduledDelivery, TraceAssembler};
    use crate::{
        TRACE_FORMAT_VERSION,
        ir::{
            Baseline, DecimalU64, DeliveryRef, EventEnvelope, FaultAction, FaultSchedule, Origin,
            Record, RedactionMode, StreamDeclaration, TraceHeader, ValidatedRecord,
        },
        limits::Limits,
        state::{BaselineAuthority, Certainty, Error as StateError},
        trace::{DeliveryKey, Error as TraceError, SourceIndex},
    };

    fn validated(record: Record, limits: &Limits) -> ValidatedRecord {
        ValidatedRecord::new(record, limits).expect("scenario fixture must be record-valid")
    }

    fn header(limits: &Limits) -> ValidatedRecord {
        validated(
            Record::TraceHeader(TraceHeader {
                format: TRACE_FORMAT_VERSION.to_owned(),
                trace_id: "trace".to_owned(),
                redaction: RedactionMode::Omitted,
                created_by: "test".to_owned(),
                extensions: BTreeMap::new(),
            }),
            limits,
        )
    }

    fn stream(limits: &Limits, baseline: Baseline) -> ValidatedRecord {
        stream_named(limits, "stream", baseline)
    }

    fn stream_named(limits: &Limits, stream_id: &str, baseline: Baseline) -> ValidatedRecord {
        validated(
            Record::Stream(StreamDeclaration {
                stream_id: stream_id.to_owned(),
                engine: format!("engine-{stream_id}"),
                engine_version: format!("version-{stream_id}"),
                engine_instance: format!("instance-{stream_id}"),
                publisher: format!("publisher-{stream_id}"),
                data_parallel_rank: 0,
                epoch: format!("epoch-{stream_id}"),
                initial_cursor: DecimalU64::new(0),
                baseline,
                worker_metadata: Vec::new(),
                extensions: BTreeMap::new(),
            }),
            limits,
        )
    }

    fn envelope(limits: &Limits) -> ValidatedRecord {
        envelope_named(limits, "source", "stream")
    }

    fn envelope_named(limits: &Limits, envelope_id: &str, stream_id: &str) -> ValidatedRecord {
        validated(
            Record::Envelope(EventEnvelope {
                envelope_id: envelope_id.to_owned(),
                stream_id: stream_id.to_owned(),
                cursor: DecimalU64::new(0),
                origin: Origin::Live,
                mutations: Vec::new(),
                extensions: BTreeMap::new(),
            }),
            limits,
        )
    }

    fn schedule(limits: &Limits) -> ValidatedRecord {
        schedule_named(
            limits,
            "fault",
            vec![FaultAction::Drop {
                target: delivery("source", 0),
            }],
        )
    }

    fn empty_schedule(limits: &Limits, schedule_id: &str) -> ValidatedRecord {
        schedule_named(limits, schedule_id, Vec::new())
    }

    fn schedule_named(
        limits: &Limits,
        schedule_id: &str,
        actions: Vec<FaultAction>,
    ) -> ValidatedRecord {
        validated(
            Record::FaultSchedule(FaultSchedule {
                schedule_id: schedule_id.to_owned(),
                actions,
                extensions: BTreeMap::new(),
            }),
            limits,
        )
    }

    fn delivery(envelope_id: &str, occurrence: u16) -> DeliveryRef {
        DeliveryRef {
            envelope_id: envelope_id.to_owned(),
            occurrence,
        }
    }

    #[test]
    fn owned_ingestion_seals_one_exact_manifest() {
        let limits = Limits::default();
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(
                stream(&limits, Baseline::EmptyAtEngineStart),
                Some(BaselineAuthority::TrustDeclaredEmpty),
            )
            .unwrap();
        assembler.push(envelope(&limits), None).unwrap();
        assembler.push(schedule(&limits), None).unwrap();

        let sealed = assembler.finish().unwrap();
        assert_eq!(sealed.summary().records(), 4);
        assert_eq!(sealed.stream_count(), 1);
        assert_eq!(sealed.source_count(), 1);
        assert_eq!(sealed.schedule_count(), 1);
        assert_eq!(sealed.stream_id(0), Some("stream"));
        assert_eq!(sealed.source_id(0), Some("source"));
        assert_eq!(sealed.schedule_id(0), Some("fault"));
        assert_eq!(sealed.schedule_source_prefix(0), Some(1));

        let state = sealed.start_stream(0).unwrap();
        let summary = sealed.finish_stream(state).unwrap();
        assert_eq!(summary.certainty(), Certainty::Exact);
        assert_eq!(summary.frontier(), None);
    }

    #[test]
    fn public_manifest_preserves_interleaved_physical_order_and_prefixes() {
        let limits = Limits::default();
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(
                stream_named(&limits, "stream-z", Baseline::EmptyAtEngineStart),
                Some(BaselineAuthority::TrustDeclaredEmpty),
            )
            .unwrap();
        assembler
            .push(envelope_named(&limits, "source-z", "stream-z"), None)
            .unwrap();
        assembler
            .push(empty_schedule(&limits, "first"), None)
            .unwrap();
        assembler
            .push(
                stream_named(&limits, "stream-a", Baseline::UnknownAtAttach),
                Some(BaselineAuthority::TreatAsUnknown),
            )
            .unwrap();
        assembler
            .push(envelope_named(&limits, "source-a", "stream-a"), None)
            .unwrap();
        assembler
            .push(empty_schedule(&limits, "second"), None)
            .unwrap();

        let sealed = assembler.finish().unwrap();
        assert_eq!(sealed.stream_id(0), Some("stream-z"));
        assert_eq!(sealed.stream_id(1), Some("stream-a"));
        assert_eq!(sealed.source_id(0), Some("source-z"));
        assert_eq!(sealed.source_id(1), Some("source-a"));
        assert_eq!(sealed.schedule_id(0), Some("first"));
        assert_eq!(sealed.schedule_source_prefix(0), Some(1));
        assert_eq!(sealed.schedule_id(1), Some("second"));
        assert_eq!(sealed.schedule_source_prefix(1), Some(2));

        let first = sealed.materialize(0).unwrap();
        assert_eq!(first.allocated_occurrences(), 1);
        assert_eq!(first.delivery_count(), 1);
        assert_eq!(first.deliveries()[0].envelope_id(), "source-z");
        let second = sealed.materialize(1).unwrap();
        assert_eq!(second.allocated_occurrences(), 2);
        assert!(
            second
                .deliveries()
                .iter()
                .map(ScheduledDelivery::envelope_id)
                .eq(["source-z", "source-a"])
        );
        assert!(
            second
                .deliveries()
                .iter()
                .map(ScheduledDelivery::stream_index)
                .eq([0, 1])
        );

        let mut states = (0..sealed.stream_count())
            .map(|index| sealed.start_stream(index).unwrap())
            .collect::<Vec<_>>();
        for delivery in second.deliveries() {
            states[delivery.stream_index()]
                .admit(Arc::clone(delivery.source()))
                .unwrap();
        }
        let summaries = states
            .into_iter()
            .map(|state| sealed.finish_stream(state).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(summaries[0].certainty(), Certainty::Exact);
        assert_eq!(summaries[1].certainty(), Certainty::Unknown);
        assert_eq!(summaries[0].frontier(), Some(0));
        assert_eq!(summaries[1].frontier(), Some(0));
    }

    #[test]
    fn empty_zero_prefix_schedule_materializes_without_special_cases() {
        let limits = Limits {
            max_occurrences_per_schedule: 0,
            max_schedule_work_per_trace: 0,
            ..Limits::default()
        };
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(empty_schedule(&limits, "empty"), None)
            .unwrap();

        let sealed = assembler.finish().unwrap();
        let materialized = sealed.materialize(0).unwrap();
        assert_eq!(materialized.source_prefix(), 0);
        assert_eq!(materialized.allocated_occurrences(), 0);
        assert!(materialized.deliveries().is_empty());
    }

    #[test]
    fn public_materializer_accepts_the_last_occurrence_in_the_u16_namespace() {
        let limits = Limits {
            max_duplicate_copies: u16::MAX,
            ..Limits::default()
        };
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(
                stream(&limits, Baseline::EmptyAtEngineStart),
                Some(BaselineAuthority::TrustDeclaredEmpty),
            )
            .unwrap();
        assembler.push(envelope(&limits), None).unwrap();
        assembler
            .push(
                schedule_named(
                    &limits,
                    "boundary",
                    vec![FaultAction::Duplicate {
                        target: delivery("source", 0),
                        copies: u16::MAX,
                    }],
                ),
                None,
            )
            .unwrap();

        let sealed = assembler.finish().unwrap();
        let materialized = sealed.materialize(0).unwrap();
        assert_eq!(materialized.allocated_occurrences(), 65_536);
        assert_eq!(materialized.delivery_count(), 65_536);
        let first = materialized.deliveries().first().unwrap();
        let last = materialized.deliveries().last().unwrap();
        assert_eq!(first.occurrence(), 0);
        assert_eq!(last.occurrence(), u16::MAX);
        assert!(Arc::ptr_eq(first.source(), last.source()));
    }

    #[test]
    fn materializer_composes_actions_and_shares_duplicate_sources() {
        let limits = Limits::default();
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(
                stream(&limits, Baseline::EmptyAtEngineStart),
                Some(BaselineAuthority::TrustDeclaredEmpty),
            )
            .unwrap();
        for source in ["a", "b", "c"] {
            assembler
                .push(envelope_named(&limits, source, "stream"), None)
                .unwrap();
        }
        assembler
            .push(
                schedule_named(
                    &limits,
                    "composed",
                    vec![
                        FaultAction::Duplicate {
                            target: delivery("b", 0),
                            copies: 2,
                        },
                        FaultAction::MoveBefore {
                            target: delivery("b", 2),
                            anchor: delivery("a", 0),
                        },
                        FaultAction::Drop {
                            target: delivery("b", 1),
                        },
                        FaultAction::Duplicate {
                            target: delivery("b", 0),
                            copies: 1,
                        },
                    ],
                ),
                None,
            )
            .unwrap();

        let sealed = assembler.finish().unwrap();
        let materialized = sealed.materialize(0).unwrap();
        assert_eq!(materialized.schedule_id(), "composed");
        assert_eq!(materialized.source_prefix(), 3);
        assert_eq!(materialized.allocated_occurrences(), 6);
        assert_eq!(materialized.delivery_count(), 5);
        let identities: Vec<_> = materialized
            .deliveries()
            .iter()
            .map(|item| (item.envelope_id(), item.occurrence()))
            .collect();
        assert_eq!(
            identities,
            [("b", 2), ("a", 0), ("b", 0), ("b", 3), ("c", 0)]
        );

        let b_deliveries: Vec<_> = materialized
            .deliveries()
            .iter()
            .filter(|item| item.envelope_id() == "b")
            .collect();
        assert!(
            b_deliveries
                .windows(2)
                .all(|pair| Arc::ptr_eq(pair[0].source(), pair[1].source()))
        );
        assert!(
            b_deliveries
                .iter()
                .all(|item| item.source().origin() == Origin::Live)
        );

        let repeated = sealed.materialize(0).unwrap();
        assert!(
            materialized
                .deliveries()
                .iter()
                .zip(repeated.deliveries())
                .all(|(left, right)| {
                    left.occurrence() == right.occurrence()
                        && left.envelope_id() == right.envelope_id()
                        && Arc::ptr_eq(left.source(), right.source())
                })
        );
    }

    #[test]
    fn newest_duplicate_block_is_inserted_immediately_after_its_target() {
        let limits = Limits::default();
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(
                stream(&limits, Baseline::EmptyAtEngineStart),
                Some(BaselineAuthority::TrustDeclaredEmpty),
            )
            .unwrap();
        assembler.push(envelope(&limits), None).unwrap();
        assembler
            .push(
                schedule_named(
                    &limits,
                    "blocks",
                    vec![
                        FaultAction::Duplicate {
                            target: delivery("source", 0),
                            copies: 2,
                        },
                        FaultAction::Duplicate {
                            target: delivery("source", 1),
                            copies: 2,
                        },
                        FaultAction::Duplicate {
                            target: delivery("source", 0),
                            copies: 1,
                        },
                    ],
                ),
                None,
            )
            .unwrap();

        let sealed = assembler.finish().unwrap();
        let materialized = sealed.materialize(0).unwrap();
        assert!(
            materialized
                .deliveries()
                .iter()
                .map(ScheduledDelivery::occurrence)
                .eq([0, 5, 1, 3, 4, 2])
        );
    }

    #[test]
    fn head_tail_adjacent_moves_and_an_all_dropped_result_are_total() {
        let limits = Limits::default();
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        assembler
            .push(
                stream(&limits, Baseline::EmptyAtEngineStart),
                Some(BaselineAuthority::TrustDeclaredEmpty),
            )
            .unwrap();
        for source in ["a", "b", "c", "d"] {
            assembler
                .push(envelope_named(&limits, source, "stream"), None)
                .unwrap();
        }
        let move_actions = vec![
            FaultAction::MoveBefore {
                target: delivery("a", 0),
                anchor: delivery("d", 0),
            },
            FaultAction::MoveBefore {
                target: delivery("d", 0),
                anchor: delivery("b", 0),
            },
            FaultAction::MoveBefore {
                target: delivery("b", 0),
                anchor: delivery("c", 0),
            },
            FaultAction::MoveBefore {
                target: delivery("a", 0),
                anchor: delivery("d", 0),
            },
        ];
        assembler
            .push(
                schedule_named(&limits, "moves-only", move_actions.clone()),
                None,
            )
            .unwrap();
        let mut all_dropped = move_actions;
        all_dropped.extend([
            FaultAction::Drop {
                target: delivery("a", 0),
            },
            FaultAction::Drop {
                target: delivery("d", 0),
            },
            FaultAction::Drop {
                target: delivery("b", 0),
            },
            FaultAction::Drop {
                target: delivery("c", 0),
            },
        ]);
        assembler
            .push(schedule_named(&limits, "all-dropped", all_dropped), None)
            .unwrap();

        let sealed = assembler.finish().unwrap();
        let reordered = sealed.materialize(0).unwrap();
        assert!(
            reordered
                .deliveries()
                .iter()
                .map(ScheduledDelivery::envelope_id)
                .eq(["a", "d", "b", "c"])
        );
        let all_dropped = sealed.materialize(1).unwrap();
        assert_eq!(all_dropped.allocated_occurrences(), 4);
        assert_eq!(all_dropped.delivery_count(), 0);
        assert!(all_dropped.deliveries().is_empty());
    }

    #[test]
    fn authority_shape_is_checked_before_inner_mutation_and_is_sticky() {
        let limits = Limits::default();
        let mut unexpected = TraceAssembler::new(limits).unwrap();
        assert_eq!(
            unexpected
                .push(header(&limits), Some(BaselineAuthority::TreatAsUnknown))
                .unwrap_err(),
            Error::UnexpectedBaselineAuthority
        );
        assert_eq!(
            unexpected.push(header(&limits), None).unwrap_err(),
            Error::AssemblerFailed
        );
        assert_eq!(unexpected.finish().err(), Some(Error::AssemblerFailed));

        let mut missing = TraceAssembler::new(limits).unwrap();
        missing.push(header(&limits), None).unwrap();
        assert_eq!(
            missing
                .push(stream(&limits, Baseline::UnknownAtAttach), None)
                .unwrap_err(),
            Error::BaselineAuthorityRequired
        );
        assert_eq!(missing.finish().err(), Some(Error::AssemblerFailed));
    }

    #[test]
    fn inner_failures_never_expose_a_partially_accepted_capability() {
        let limits = Limits::default();
        let mut structural = TraceAssembler::new(limits).unwrap();
        structural.push(header(&limits), None).unwrap();
        assert_eq!(
            structural.push(header(&limits), None).unwrap_err(),
            Error::Trace {
                error: TraceError::DuplicateHeader { record: 1 }
            }
        );
        assert_eq!(structural.finish().err(), Some(Error::AssemblerFailed));

        let mut normalization = TraceAssembler::new(limits).unwrap();
        normalization.push(header(&limits), None).unwrap();
        assert_eq!(
            normalization
                .push(
                    stream(&limits, Baseline::UnknownAtAttach),
                    Some(BaselineAuthority::TrustDeclaredEmpty),
                )
                .unwrap_err(),
            Error::State {
                error: StateError::BaselineAuthorityMismatch
            }
        );
        assert_eq!(normalization.finish().err(), Some(Error::AssemblerFailed));
    }

    #[test]
    fn stream_indices_are_bounded_without_echoing_identities() {
        let limits = Limits::default();
        let mut assembler = TraceAssembler::new(limits).unwrap();
        assembler.push(header(&limits), None).unwrap();
        let sealed = assembler.finish().unwrap();

        assert_eq!(
            sealed.start_stream(7).err(),
            Some(Error::StreamIndexOutOfRange {
                count: 0,
                actual: 7
            })
        );
        assert_eq!(
            sealed.start_stream(7).err().unwrap().code(),
            "stream_index_out_of_range"
        );
        assert_eq!(
            sealed.materialize(9).err(),
            Some(Error::ScheduleIndexOutOfRange {
                count: 0,
                actual: 9
            })
        );
        assert_eq!(
            sealed.materialize(9).err().unwrap().code(),
            "schedule_index_out_of_range"
        );
    }

    #[test]
    fn every_scenario_error_has_a_stable_code() {
        let errors = [
            (Error::AssemblerFailed, "assembler_failed"),
            (
                Error::BaselineAuthorityRequired,
                "baseline_authority_required",
            ),
            (
                Error::UnexpectedBaselineAuthority,
                "unexpected_baseline_authority",
            ),
            (
                Error::Trace {
                    error: TraceError::MissingHeader,
                },
                "trace_validation",
            ),
            (
                Error::State {
                    error: StateError::NormalizerFailed,
                },
                "trace_normalization",
            ),
            (Error::AssemblyInvariant, "assembly_invariant"),
            (Error::AssemblyCapacity, "assembly_capacity"),
            (
                Error::StreamIndexOutOfRange {
                    count: 0,
                    actual: 0,
                },
                "stream_index_out_of_range",
            ),
            (
                Error::ScheduleIndexOutOfRange {
                    count: 0,
                    actual: 0,
                },
                "schedule_index_out_of_range",
            ),
            (Error::MaterializationCapacity, "materialization_capacity"),
            (Error::MaterializationInvariant, "materialization_invariant"),
        ];

        for (error, expected) in errors {
            assert_eq!(error.code(), expected);
        }
    }

    proptest! {
        #[test]
        fn indexed_arena_matches_a_slow_vector_model(
            operations in prop::collection::vec(
                (0_u8..3, any::<usize>(), any::<usize>(), 1_u16..4),
                0..80,
            )
        ) {
            let capacity = 4 + operations.len() * 3;
            let mut arena = DeliveryArena::new(4, capacity).unwrap();
            let mut slow: Vec<_> = (0..4)
                .map(|source| DeliveryKey {
                    source: SourceIndex(source),
                    occurrence: 0,
                })
                .collect();
            let mut next_occurrence = [1_u16; 4];

            for (operation, target_seed, anchor_seed, copies) in operations {
                if slow.is_empty() {
                    break;
                }
                let target_position = target_seed % slow.len();
                let target = slow[target_position];
                match operation {
                    0 => {
                        arena.drop_delivery(target).unwrap();
                        slow.remove(target_position);
                    }
                    1 => {
                        let source = target.source.0;
                        let first = next_occurrence[source];
                        next_occurrence[source] += copies;
                        arena.duplicate(target, first, copies).unwrap();
                        let block = (0..copies).map(|offset| DeliveryKey {
                            source: target.source,
                            occurrence: first + offset,
                        });
                        let insertion = target_position + 1;
                        slow.splice(insertion..insertion, block);
                    }
                    _ if slow.len() > 1 => {
                        let mut anchor_position = anchor_seed % slow.len();
                        if anchor_position == target_position {
                            anchor_position = (anchor_position + 1) % slow.len();
                        }
                        let anchor = slow[anchor_position];
                        arena.move_before(target, anchor).unwrap();
                        let removed = slow.remove(target_position);
                        let new_anchor = slow.iter().position(|key| *key == anchor).unwrap();
                        slow.insert(new_anchor, removed);
                    }
                    _ => {}
                }
            }

            let mut actual = Vec::new();
            let mut cursor = arena.head;
            while let Some(index) = cursor {
                prop_assert!(actual.len() < arena.nodes.len());
                let node = &arena.nodes[index];
                prop_assert!(node.live);
                actual.push(node.key);
                cursor = node.next;
            }
            prop_assert!(actual == slow);
        }
    }
}
