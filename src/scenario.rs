//! Coordinated trace validation, normalization, and sealed scenario capabilities.

use std::sync::Arc;

use thiserror::Error as ThisError;

use crate::{
    ir::{Record, ValidatedRecord},
    limits::Limits,
    state::{
        self, BaselineAuthority, EnvelopeNormalizer, PreparedEnvelope, SealedSession,
        StreamBlueprint, StreamState, StreamSummary,
    },
    trace::{
        self, SchedulePlan, TraceSummary, TraceValidator, ValidatedTraceParts, ValidatedTracePlan,
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
    /// A stream ordinal was outside the sealed manifest.
    #[error("stream index {actual} is outside sealed stream count {count}")]
    StreamIndexOutOfRange {
        /// Number of streams in the sealed trace.
        count: usize,
        /// Requested zero-based stream ordinal.
        actual: usize,
    },
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
            Self::StreamIndexOutOfRange { .. } => "stream_index_out_of_range",
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
/// The type exposes content-free counts and deliberate identity lookups, but
/// neither raw numeric actions nor constructors. Future materializers consume
/// this capability instead of accepting arbitrary records or sources.
pub struct SealedTrace {
    summary: TraceSummary,
    limits: Limits,
    sealed: SealedSession,
    streams: Box<[StreamBlueprint]>,
    sources: Box<[Arc<PreparedEnvelope>]>,
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

        Ok(Self {
            summary,
            limits,
            sealed,
            streams,
            sources,
            schedules,
        })
    }
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
    use std::collections::BTreeMap;

    use super::{Error, TraceAssembler};
    use crate::{
        TRACE_FORMAT_VERSION,
        ir::{
            Baseline, DecimalU64, DeliveryRef, EventEnvelope, FaultAction, FaultSchedule, Origin,
            Record, RedactionMode, StreamDeclaration, TraceHeader, ValidatedRecord,
        },
        limits::Limits,
        state::{BaselineAuthority, Certainty, Error as StateError},
        trace::Error as TraceError,
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
        validated(
            Record::FaultSchedule(FaultSchedule {
                schedule_id: "fault".to_owned(),
                actions: vec![FaultAction::Drop {
                    target: DeliveryRef {
                        envelope_id: "source".to_owned(),
                        occurrence: 0,
                    },
                }],
                extensions: BTreeMap::new(),
            }),
            limits,
        )
    }

    fn empty_schedule(limits: &Limits, schedule_id: &str) -> ValidatedRecord {
        validated(
            Record::FaultSchedule(FaultSchedule {
                schedule_id: schedule_id.to_owned(),
                actions: Vec::new(),
                extensions: BTreeMap::new(),
            }),
            limits,
        )
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
    }
}
