//! Streaming structural validation across already decoded trace records.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use thiserror::Error as ThisError;

use crate::{
    ir::{
        DeliveryRef, FaultAction, FaultSchedule, Mutation, Record, RedactionMode,
        StreamDeclaration, TokenEvidence, ValidatedRecord, ValidationError,
    },
    limits::{Limits, MAX_JSON_DEPTH},
};

/// A bounded resource retained or consumed by trace-wide validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Resource {
    /// Accepted records.
    Records,
    /// Declared publisher streams.
    Streams,
    /// Accepted event envelopes.
    Envelopes,
    /// Independent fault schedules.
    FaultSchedules,
    /// Fault actions summed across schedules.
    FaultActions,
    /// UTF-8 bytes cloned into trace-wide indexes.
    IdentityBytes,
    /// Original and synthesized occurrences in one schedule namespace.
    ScheduleOccurrences,
    /// Envelope-prefix plus synthesized-occurrence work across schedules.
    ScheduleWork,
}

impl fmt::Display for Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Records => "records",
            Self::Streams => "streams",
            Self::Envelopes => "envelopes",
            Self::FaultSchedules => "fault_schedules",
            Self::FaultActions => "fault_actions",
            Self::IdentityBytes => "identity_bytes",
            Self::ScheduleOccurrences => "schedule_occurrences",
            Self::ScheduleWork => "schedule_work",
        };
        formatter.write_str(name)
    }
}

/// Position of a delivery reference inside a fault action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryRole {
    /// Primary action target.
    Target,
    /// Reordering anchor.
    Anchor,
}

/// Privacy-relevant token evidence variant without its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEvidenceKind {
    /// HMAC-SHA256 evidence.
    KeyedDigest,
    /// Linkable SHA-256 evidence.
    UnkeyedDigest,
    /// Raw ordered token IDs.
    TokenIds,
}

/// Stable trace-structural failures that never echo user-controlled identities.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// Configured recursion exceeds the library's stack-safety ceiling.
    #[error("configured JSON depth {configured} exceeds hard maximum {maximum}")]
    UnsupportedDepthLimit {
        /// Requested maximum JSON depth.
        configured: usize,
        /// Compile-time stack-safety ceiling.
        maximum: usize,
    },
    /// A caller tried to continue after the first validation failure.
    #[error("trace validator is already failed")]
    ValidatorFailed,
    /// EOF arrived before a header was accepted.
    #[error("trace is missing its required header")]
    MissingHeader,
    /// Record zero was not a trace header.
    #[error("record {record} must be the trace header")]
    HeaderNotFirst {
        /// Zero-based record index.
        record: u64,
    },
    /// A second header appeared.
    #[error("record {record} repeats the trace header")]
    DuplicateHeader {
        /// Zero-based record index.
        record: u64,
    },
    /// A record validated under looser ceilings failed the active ceilings.
    #[error("record {record} failed record-local validation: {error}")]
    RecordValidation {
        /// Zero-based record index.
        record: u64,
        /// Redacted record-local failure.
        error: ValidationError,
    },
    /// A trace-wide ceiling was exceeded.
    #[error(
        "record {record} exceeds trace {resource} limit {maximum} with observed value {observed}"
    )]
    ResourceLimit {
        /// Zero-based record index.
        record: u64,
        /// Resource whose budget was exhausted.
        resource: Resource,
        /// Configured inclusive maximum.
        maximum: u64,
        /// First observed value known to exceed the maximum.
        observed: u64,
    },
    /// A checked trace-wide counter could not be represented.
    #[error("trace counter overflow at record {record}")]
    CounterOverflow {
        /// Zero-based record index.
        record: u64,
    },
    /// A stream ID was declared twice.
    #[error("record {record} repeats a stream ID")]
    DuplicateStreamId {
        /// Zero-based record index.
        record: u64,
    },
    /// Two stream IDs named the same canonical publisher identity.
    #[error("record {record} repeats a canonical stream identity")]
    DuplicateStreamIdentity {
        /// Zero-based record index.
        record: u64,
    },
    /// An envelope referenced a stream not declared earlier.
    #[error("record {record} references an undeclared stream")]
    UndeclaredStream {
        /// Zero-based record index.
        record: u64,
    },
    /// An envelope cursor was below the stream's declared first valid cursor.
    #[error("record {record} has a cursor below its stream initial cursor")]
    CursorBeforeInitial {
        /// Zero-based record index.
        record: u64,
    },
    /// An envelope ID was reused.
    #[error("record {record} repeats an envelope ID")]
    DuplicateEnvelopeId {
        /// Zero-based record index.
        record: u64,
    },
    /// Token evidence disagreed with the header's privacy declaration.
    #[error(
        "record {record} mutation {mutation} has {observed:?} evidence under {expected:?} redaction"
    )]
    TokenEvidenceRedactionMismatch {
        /// Zero-based record index.
        record: u64,
        /// Zero-based mutation index.
        mutation: usize,
        /// Header privacy mode.
        expected: RedactionMode,
        /// Evidence variant without sensitive contents.
        observed: TokenEvidenceKind,
    },
    /// A schedule ID was reused.
    #[error("record {record} repeats a fault schedule ID")]
    DuplicateScheduleId {
        /// Zero-based record index.
        record: u64,
    },
    /// A fault reference named no envelope in the schedule's earlier prefix.
    #[error("record {record} action {action} {role:?} does not name an earlier envelope")]
    FaultEnvelopeNotPrior {
        /// Zero-based record index.
        record: u64,
        /// Zero-based action index.
        action: usize,
        /// Target or anchor position.
        role: DeliveryRole,
    },
    /// A positive occurrence had not been synthesized earlier in this schedule.
    #[error("record {record} action {action} {role:?} occurrence was not created")]
    FaultOccurrenceNotCreated {
        /// Zero-based record index.
        record: u64,
        /// Zero-based action index.
        action: usize,
        /// Target or anchor position.
        role: DeliveryRole,
    },
    /// A fault action referenced an occurrence dropped earlier in this schedule.
    #[error("record {record} action {action} {role:?} occurrence was already dropped")]
    FaultOccurrenceRemoved {
        /// Zero-based record index.
        record: u64,
        /// Zero-based action index.
        action: usize,
        /// Target or anchor position.
        role: DeliveryRole,
    },
    /// Duplicate synthesis would exceed the stable `u16` occurrence namespace.
    #[error("record {record} action {action} exhausts the occurrence namespace")]
    FaultOccurrenceOverflow {
        /// Zero-based record index.
        record: u64,
        /// Zero-based action index.
        action: usize,
    },
}

impl Error {
    /// Return a machine-stable error code without trace-derived text.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedDepthLimit { .. } => "unsupported_depth_limit",
            Self::ValidatorFailed => "validator_failed",
            Self::MissingHeader => "missing_header",
            Self::HeaderNotFirst { .. } => "header_not_first",
            Self::DuplicateHeader { .. } => "duplicate_header",
            Self::RecordValidation { .. } => "record_validation",
            Self::ResourceLimit { .. } => "trace_resource_limit",
            Self::CounterOverflow { .. } => "counter_overflow",
            Self::DuplicateStreamId { .. } => "duplicate_stream_id",
            Self::DuplicateStreamIdentity { .. } => "duplicate_stream_identity",
            Self::UndeclaredStream { .. } => "undeclared_stream",
            Self::CursorBeforeInitial { .. } => "cursor_before_initial",
            Self::DuplicateEnvelopeId { .. } => "duplicate_envelope_id",
            Self::TokenEvidenceRedactionMismatch { .. } => "token_evidence_redaction_mismatch",
            Self::DuplicateScheduleId { .. } => "duplicate_schedule_id",
            Self::FaultEnvelopeNotPrior { .. } => "fault_envelope_not_prior",
            Self::FaultOccurrenceNotCreated { .. } => "fault_occurrence_not_created",
            Self::FaultOccurrenceRemoved { .. } => "fault_occurrence_removed",
            Self::FaultOccurrenceOverflow { .. } => "fault_occurrence_overflow",
        }
    }
}

/// Content-free accounting facts from a structurally valid trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceSummary {
    records: u64,
    streams: u64,
    envelopes: u64,
    fault_schedules: u64,
    fault_actions: u64,
    identity_bytes: u64,
    schedule_work: u64,
    redaction: RedactionMode,
}

impl TraceSummary {
    /// Number of accepted records.
    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }

    /// Number of declared streams.
    #[must_use]
    pub const fn streams(self) -> u64 {
        self.streams
    }

    /// Number of event envelopes.
    #[must_use]
    pub const fn envelopes(self) -> u64 {
        self.envelopes
    }

    /// Number of independent fault schedules.
    #[must_use]
    pub const fn fault_schedules(self) -> u64 {
        self.fault_schedules
    }

    /// Fault actions summed across schedules.
    #[must_use]
    pub const fn fault_actions(self) -> u64 {
        self.fault_actions
    }

    /// UTF-8 bytes retained in trace-wide identity indexes.
    #[must_use]
    pub const fn identity_bytes(self) -> u64 {
        self.identity_bytes
    }

    /// Envelope-prefix plus synthesized-occurrence work across schedules.
    #[must_use]
    pub const fn schedule_work(self) -> u64 {
        self.schedule_work
    }

    /// Header token redaction mode.
    #[must_use]
    pub const fn redaction(self) -> RedactionMode {
        self.redaction
    }
}

/// Opaque EOF proof containing validated, numerically resolved fault plans.
///
/// The capability is available only after the complete trace succeeds. Its
/// executable schedule representation remains crate-private so callers cannot
/// construct actions from records that bypassed trace-wide validation.
pub struct ValidatedTracePlan {
    summary: TraceSummary,
    limits: Limits,
    stream_ids: Box<[Arc<str>]>,
    envelope_ids: Box<[Arc<str>]>,
    schedules: Box<[SchedulePlan]>,
}

impl ValidatedTracePlan {
    /// Return content-free accounting facts for the complete trace.
    #[must_use]
    pub const fn summary(&self) -> TraceSummary {
        self.summary
    }

    /// Consume the EOF proof for a crate-internal sealed-scenario binding.
    #[must_use]
    pub(crate) fn into_parts(self) -> ValidatedTraceParts {
        ValidatedTraceParts {
            summary: self.summary,
            limits: self.limits,
            stream_ids: self.stream_ids,
            envelope_ids: self.envelope_ids,
            schedules: self.schedules,
        }
    }
}

/// Crate-private pieces needed to bind a validated plan to normalized sources.
pub(crate) struct ValidatedTraceParts {
    pub(crate) summary: TraceSummary,
    pub(crate) limits: Limits,
    pub(crate) stream_ids: Box<[Arc<str>]>,
    pub(crate) envelope_ids: Box<[Arc<str>]>,
    pub(crate) schedules: Box<[SchedulePlan]>,
}

/// Zero-based physical source-envelope position, excluding other record kinds.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SourceIndex(pub(crate) usize);

/// Stable numeric identity of an original or synthesized delivery.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DeliveryKey {
    pub(crate) source: SourceIndex,
    pub(crate) occurrence: u16,
}

/// One validated action with every trace identity resolved to a numeric key.
#[allow(
    dead_code,
    reason = "the next linked-list materializer consumes the validated action fields"
)]
pub(crate) enum PlannedAction {
    Drop {
        target: DeliveryKey,
    },
    Duplicate {
        target: DeliveryKey,
        first_occurrence: u16,
        copies: u16,
    },
    MoveBefore {
        target: DeliveryKey,
        anchor: DeliveryKey,
    },
}

/// One independent schedule over the physical envelope prefix at its record.
#[allow(
    dead_code,
    reason = "the next linked-list materializer consumes the validated action list"
)]
pub(crate) struct SchedulePlan {
    pub(crate) id: Arc<str>,
    pub(crate) prefix_len: usize,
    pub(crate) actions: Box<[PlannedAction]>,
}

/// Incremental validator for ordering, identity, privacy, and fault references.
pub struct TraceValidator {
    limits: Limits,
    records: u64,
    header: Option<HeaderFacts>,
    streams: BTreeMap<Arc<str>, StreamFacts>,
    stream_order: Vec<Arc<str>>,
    stream_identities: BTreeSet<StreamIdentity>,
    envelopes: BTreeMap<Arc<str>, SourceIndex>,
    envelope_order: Vec<Arc<str>>,
    schedules: BTreeSet<Arc<str>>,
    schedule_plans: Vec<SchedulePlan>,
    fault_actions: u64,
    identity_bytes: u64,
    schedule_work: u64,
    failed: bool,
}

impl TraceValidator {
    /// Create an empty validator under explicit finite limits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedDepthLimit`] before retaining state when the
    /// configured recursion limit exceeds the library's stack-safety ceiling.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.max_depth > MAX_JSON_DEPTH {
            return Err(Error::UnsupportedDepthLimit {
                configured: limits.max_depth,
                maximum: MAX_JSON_DEPTH,
            });
        }
        Ok(Self {
            limits,
            records: 0,
            header: None,
            streams: BTreeMap::new(),
            stream_order: Vec::new(),
            stream_identities: BTreeSet::new(),
            envelopes: BTreeMap::new(),
            envelope_order: Vec::new(),
            schedules: BTreeSet::new(),
            schedule_plans: Vec::new(),
            fault_actions: 0,
            identity_bytes: 0,
            schedule_work: 0,
            failed: false,
        })
    }

    /// Accept one record at the next zero-based trace position.
    ///
    /// The validator becomes permanently failed after the first error, so a
    /// caller cannot accidentally continue from partially checked input.
    ///
    /// # Errors
    ///
    /// Returns a stable [`Error`] for ordering, uniqueness, privacy, reference,
    /// active-limit, or record-local validation failures.
    pub fn push(&mut self, record: &ValidatedRecord) -> Result<(), Error> {
        if self.failed {
            return Err(Error::ValidatorFailed);
        }
        let result = self.push_inner(record);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Finish validation and return content-free accounting facts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingHeader`] for an empty trace or
    /// [`Error::ValidatorFailed`] after an earlier failure.
    pub fn finish(self) -> Result<TraceSummary, Error> {
        self.finish_planned().map(|plan| plan.summary())
    }

    /// Finish validation and return an opaque numerically resolved trace plan.
    ///
    /// No plan is returned until EOF succeeds, so schedules retained before a
    /// late or sticky validation failure cannot become executable capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingHeader`] for an empty trace or
    /// [`Error::ValidatorFailed`] after an earlier failure.
    pub fn finish_planned(self) -> Result<ValidatedTracePlan, Error> {
        if self.failed {
            return Err(Error::ValidatorFailed);
        }
        let header = self.header.ok_or(Error::MissingHeader)?;
        let summary = TraceSummary {
            records: self.records,
            streams: count_len(self.streams.len(), self.records)?,
            envelopes: count_len(self.envelopes.len(), self.records)?,
            fault_schedules: count_len(self.schedules.len(), self.records)?,
            fault_actions: self.fault_actions,
            identity_bytes: self.identity_bytes,
            schedule_work: self.schedule_work,
            redaction: header.redaction,
        };
        debug_assert_eq!(self.streams.len(), self.stream_order.len());
        debug_assert_eq!(self.envelopes.len(), self.envelope_order.len());
        debug_assert_eq!(self.schedules.len(), self.schedule_plans.len());
        Ok(ValidatedTracePlan {
            summary,
            limits: self.limits,
            stream_ids: self.stream_order.into_boxed_slice(),
            envelope_ids: self.envelope_order.into_boxed_slice(),
            schedules: self.schedule_plans.into_boxed_slice(),
        })
    }

    fn push_inner(&mut self, record: &ValidatedRecord) -> Result<(), Error> {
        let index = self.records;
        checked_limit(
            index,
            Resource::Records,
            self.records,
            1,
            self.limits.max_records_per_trace,
        )?;
        record
            .as_record()
            .validate(&self.limits)
            .map_err(|error| Error::RecordValidation {
                record: index,
                error,
            })?;

        match record.as_record() {
            Record::TraceHeader(header) if index == 0 => {
                self.header = Some(HeaderFacts {
                    redaction: header.redaction,
                });
            }
            Record::TraceHeader(_) => return Err(Error::DuplicateHeader { record: index }),
            _ if index == 0 => return Err(Error::HeaderNotFirst { record: index }),
            Record::Stream(stream) => self.push_stream(index, stream)?,
            Record::Envelope(envelope) => {
                self.push_envelope(index, envelope)?;
            }
            Record::FaultSchedule(schedule) => self.push_schedule(index, schedule)?,
        }

        self.records = self
            .records
            .checked_add(1)
            .ok_or(Error::CounterOverflow { record: index })?;
        Ok(())
    }

    fn push_stream(&mut self, record: u64, stream: &StreamDeclaration) -> Result<(), Error> {
        if self.streams.contains_key(stream.stream_id.as_str()) {
            return Err(Error::DuplicateStreamId { record });
        }
        let identity = StreamIdentity::from(stream);
        if self.stream_identities.contains(&identity) {
            return Err(Error::DuplicateStreamIdentity { record });
        }
        checked_limit(
            record,
            Resource::Streams,
            count_len(self.streams.len(), record)?,
            1,
            self.limits.max_streams_per_trace,
        )?;
        let identity_bytes = checked_identity_bytes(
            record,
            self.identity_bytes,
            [
                stream.stream_id.as_str(),
                stream.engine.as_str(),
                stream.engine_version.as_str(),
                stream.engine_instance.as_str(),
                stream.publisher.as_str(),
                stream.epoch.as_str(),
            ],
            self.limits.max_identity_bytes_per_trace,
        )?;

        let stream_id: Arc<str> = Arc::from(stream.stream_id.as_str());
        self.streams.insert(
            Arc::clone(&stream_id),
            StreamFacts {
                initial_cursor: stream.initial_cursor.get(),
            },
        );
        self.stream_order.push(stream_id);
        self.stream_identities.insert(identity);
        self.identity_bytes = identity_bytes;
        Ok(())
    }

    fn push_envelope(
        &mut self,
        record: u64,
        envelope: &crate::ir::EventEnvelope,
    ) -> Result<(), Error> {
        if self.envelopes.contains_key(envelope.envelope_id.as_str()) {
            return Err(Error::DuplicateEnvelopeId { record });
        }
        checked_limit(
            record,
            Resource::Envelopes,
            count_len(self.envelopes.len(), record)?,
            1,
            self.limits.max_envelopes_per_trace,
        )?;
        let stream = self
            .streams
            .get(envelope.stream_id.as_str())
            .ok_or(Error::UndeclaredStream { record })?;
        if envelope.cursor.get() < stream.initial_cursor {
            return Err(Error::CursorBeforeInitial { record });
        }
        let redaction = self
            .header
            .as_ref()
            .ok_or(Error::HeaderNotFirst { record })?
            .redaction;
        validate_redaction(record, redaction, &envelope.mutations)?;
        let identity_bytes = checked_identity_bytes(
            record,
            self.identity_bytes,
            [envelope.envelope_id.as_str()],
            self.limits.max_identity_bytes_per_trace,
        )?;

        let envelope_id: Arc<str> = Arc::from(envelope.envelope_id.as_str());
        let source = SourceIndex(self.envelope_order.len());
        self.envelopes.insert(Arc::clone(&envelope_id), source);
        self.envelope_order.push(envelope_id);
        self.identity_bytes = identity_bytes;
        Ok(())
    }

    fn push_schedule(&mut self, record: u64, schedule: &FaultSchedule) -> Result<(), Error> {
        if self.schedules.contains(schedule.schedule_id.as_str()) {
            return Err(Error::DuplicateScheduleId { record });
        }
        checked_limit(
            record,
            Resource::FaultSchedules,
            count_len(self.schedules.len(), record)?,
            1,
            self.limits.max_fault_schedules_per_trace,
        )?;
        let action_count = count_len(schedule.actions.len(), record)?;
        let fault_actions = checked_limit(
            record,
            Resource::FaultActions,
            self.fault_actions,
            action_count,
            self.limits.max_fault_actions_per_trace,
        )?;
        let identity_bytes = checked_identity_bytes(
            record,
            self.identity_bytes,
            [schedule.schedule_id.as_str()],
            self.limits.max_identity_bytes_per_trace,
        )?;
        let (local_work, actions) = self.plan_schedule(record, schedule)?;
        let schedule_work = checked_limit(
            record,
            Resource::ScheduleWork,
            self.schedule_work,
            local_work,
            self.limits.max_schedule_work_per_trace,
        )?;

        let schedule_id: Arc<str> = Arc::from(schedule.schedule_id.as_str());
        let inserted = self.schedules.insert(Arc::clone(&schedule_id));
        debug_assert!(inserted, "a planned schedule ID must be newly registered");
        self.schedule_plans.push(SchedulePlan {
            id: schedule_id,
            prefix_len: self.envelope_order.len(),
            actions,
        });
        self.fault_actions = fault_actions;
        self.identity_bytes = identity_bytes;
        self.schedule_work = schedule_work;
        Ok(())
    }

    fn plan_schedule(
        &self,
        record: u64,
        schedule: &FaultSchedule,
    ) -> Result<(u64, Box<[PlannedAction]>), Error> {
        let prefix = count_len(self.envelopes.len(), record)?;
        let mut occurrences = checked_limit(
            record,
            Resource::ScheduleOccurrences,
            0,
            prefix,
            self.limits.max_occurrences_per_schedule,
        )?;
        let mut work = prefix;
        let mut next_occurrence = BTreeMap::<SourceIndex, u32>::new();
        let mut removed = BTreeSet::<DeliveryKey>::new();
        let mut actions = Vec::with_capacity(schedule.actions.len());

        for (action_index, action) in schedule.actions.iter().enumerate() {
            match action {
                FaultAction::Drop { target } => {
                    let target = self.resolve_delivery(
                        record,
                        action_index,
                        target,
                        DeliveryRole::Target,
                        &next_occurrence,
                        &removed,
                    )?;
                    removed.insert(target);
                    actions.push(PlannedAction::Drop { target });
                }
                FaultAction::Duplicate { target, copies } => {
                    let target = self.resolve_delivery(
                        record,
                        action_index,
                        target,
                        DeliveryRole::Target,
                        &next_occurrence,
                        &removed,
                    )?;
                    let next = next_occurrence.get(&target.source).copied().unwrap_or(1);
                    let new_next = next.checked_add(u32::from(*copies)).ok_or(
                        Error::FaultOccurrenceOverflow {
                            record,
                            action: action_index,
                        },
                    )?;
                    if new_next > u32::from(u16::MAX) + 1 {
                        return Err(Error::FaultOccurrenceOverflow {
                            record,
                            action: action_index,
                        });
                    }
                    let first_occurrence =
                        u16::try_from(next).map_err(|_| Error::FaultOccurrenceOverflow {
                            record,
                            action: action_index,
                        })?;
                    occurrences = checked_limit(
                        record,
                        Resource::ScheduleOccurrences,
                        occurrences,
                        u64::from(*copies),
                        self.limits.max_occurrences_per_schedule,
                    )?;
                    work = work
                        .checked_add(u64::from(*copies))
                        .ok_or(Error::CounterOverflow { record })?;
                    checked_limit(
                        record,
                        Resource::ScheduleWork,
                        self.schedule_work,
                        work,
                        self.limits.max_schedule_work_per_trace,
                    )?;
                    next_occurrence.insert(target.source, new_next);
                    actions.push(PlannedAction::Duplicate {
                        target,
                        first_occurrence,
                        copies: *copies,
                    });
                }
                FaultAction::MoveBefore { target, anchor } => {
                    let target = self.resolve_delivery(
                        record,
                        action_index,
                        target,
                        DeliveryRole::Target,
                        &next_occurrence,
                        &removed,
                    )?;
                    let anchor = self.resolve_delivery(
                        record,
                        action_index,
                        anchor,
                        DeliveryRole::Anchor,
                        &next_occurrence,
                        &removed,
                    )?;
                    actions.push(PlannedAction::MoveBefore { target, anchor });
                }
            }
        }
        Ok((work, actions.into_boxed_slice()))
    }

    fn resolve_delivery(
        &self,
        record: u64,
        action: usize,
        delivery: &DeliveryRef,
        role: DeliveryRole,
        next_occurrence: &BTreeMap<SourceIndex, u32>,
        removed: &BTreeSet<DeliveryKey>,
    ) -> Result<DeliveryKey, Error> {
        let source = self
            .envelopes
            .get(delivery.envelope_id.as_str())
            .copied()
            .ok_or(Error::FaultEnvelopeNotPrior {
                record,
                action,
                role,
            })?;
        let occurrence = delivery.occurrence;
        let next = next_occurrence.get(&source).copied().unwrap_or(1);
        if u32::from(occurrence) >= next {
            return Err(Error::FaultOccurrenceNotCreated {
                record,
                action,
                role,
            });
        }
        let key = DeliveryKey { source, occurrence };
        if removed.contains(&key) {
            return Err(Error::FaultOccurrenceRemoved {
                record,
                action,
                role,
            });
        }
        Ok(key)
    }
}

/// Validate an in-memory sequence without constructing an unbounded index first.
///
/// # Errors
///
/// Returns the first stable trace-structural failure.
pub fn validate_trace<'record, I>(records: I, limits: Limits) -> Result<TraceSummary, Error>
where
    I: IntoIterator<Item = &'record ValidatedRecord>,
{
    let mut validator = TraceValidator::new(limits)?;
    for record in records {
        validator.push(record)?;
    }
    validator.finish()
}

#[derive(Clone, Copy)]
struct HeaderFacts {
    redaction: RedactionMode,
}

#[derive(Clone, Copy)]
struct StreamFacts {
    initial_cursor: u64,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct StreamIdentity {
    engine: Box<str>,
    engine_version: Box<str>,
    engine_instance: Box<str>,
    publisher: Box<str>,
    data_parallel_rank: u32,
    epoch: Box<str>,
}

impl From<&StreamDeclaration> for StreamIdentity {
    fn from(stream: &StreamDeclaration) -> Self {
        Self {
            engine: stream.engine.clone().into_boxed_str(),
            engine_version: stream.engine_version.clone().into_boxed_str(),
            engine_instance: stream.engine_instance.clone().into_boxed_str(),
            publisher: stream.publisher.clone().into_boxed_str(),
            data_parallel_rank: stream.data_parallel_rank,
            epoch: stream.epoch.clone().into_boxed_str(),
        }
    }
}

fn validate_redaction(
    record: u64,
    redaction: RedactionMode,
    mutations: &[Mutation],
) -> Result<(), Error> {
    for (mutation, value) in mutations.iter().enumerate() {
        let Mutation::StoreRun {
            token_evidence: Some(evidence),
            ..
        } = value
        else {
            continue;
        };
        let observed = token_evidence_kind(evidence);
        if !evidence_matches(redaction, observed) {
            return Err(Error::TokenEvidenceRedactionMismatch {
                record,
                mutation,
                expected: redaction,
                observed,
            });
        }
    }
    Ok(())
}

const fn token_evidence_kind(evidence: &TokenEvidence) -> TokenEvidenceKind {
    match evidence {
        TokenEvidence::KeyedDigest { .. } => TokenEvidenceKind::KeyedDigest,
        TokenEvidence::UnkeyedDigest { .. } => TokenEvidenceKind::UnkeyedDigest,
        TokenEvidence::TokenIds { .. } => TokenEvidenceKind::TokenIds,
    }
}

const fn evidence_matches(redaction: RedactionMode, evidence: TokenEvidenceKind) -> bool {
    matches!(
        (redaction, evidence),
        (RedactionMode::KeyedDigests, TokenEvidenceKind::KeyedDigest)
            | (
                RedactionMode::UnkeyedLinkable,
                TokenEvidenceKind::UnkeyedDigest
            )
            | (RedactionMode::ContainsTokenIds, TokenEvidenceKind::TokenIds)
    )
}

fn checked_identity_bytes<const N: usize>(
    record: u64,
    current: u64,
    values: [&str; N],
    maximum: u64,
) -> Result<u64, Error> {
    let mut added = 0_u64;
    for value in values {
        added = added
            .checked_add(u64::try_from(value.len()).map_err(|_| Error::CounterOverflow { record })?)
            .ok_or(Error::CounterOverflow { record })?;
    }
    checked_limit(record, Resource::IdentityBytes, current, added, maximum)
}

fn checked_limit(
    record: u64,
    resource: Resource,
    current: u64,
    added: u64,
    maximum: u64,
) -> Result<u64, Error> {
    let observed = current
        .checked_add(added)
        .ok_or(Error::CounterOverflow { record })?;
    if observed > maximum {
        return Err(Error::ResourceLimit {
            record,
            resource,
            maximum,
            observed,
        });
    }
    Ok(observed)
}

fn count_len(length: usize, record: u64) -> Result<u64, Error> {
    u64::try_from(length).map_err(|_| Error::CounterOverflow { record })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        DeliveryKey, DeliveryRole, Error, PlannedAction, Resource, SourceIndex, TokenEvidenceKind,
        TraceValidator, checked_limit, validate_trace,
    };
    use crate::{
        TRACE_FORMAT_VERSION,
        ir::{
            Baseline, CacheGroup, DecimalU64, DeliveryRef, EventEnvelope, FaultAction,
            FaultSchedule, KeyedDigestAlgorithm, Mutation, OpaqueHash, Origin, Record,
            RedactionMode, Sha256Digest, StorageMedium, StreamDeclaration, TokenEvidence,
            TraceHeader, UnkeyedDigestAlgorithm, ValidatedRecord, ValidationError,
        },
        limits::{Limits, MAX_JSON_DEPTH},
    };

    fn validated(record: Record) -> ValidatedRecord {
        validated_with(record, &Limits::default())
    }

    fn validated_with(record: Record, limits: &Limits) -> ValidatedRecord {
        ValidatedRecord::new(record, limits).expect("test fixture must be record-valid")
    }

    fn header(redaction: RedactionMode) -> ValidatedRecord {
        validated(Record::TraceHeader(TraceHeader {
            format: TRACE_FORMAT_VERSION.to_owned(),
            trace_id: "trace".to_owned(),
            redaction,
            created_by: "test".to_owned(),
            extensions: BTreeMap::new(),
        }))
    }

    fn stream_declaration(
        stream_id: &str,
        identity: &str,
        rank: u32,
        initial_cursor: u64,
    ) -> StreamDeclaration {
        StreamDeclaration {
            stream_id: stream_id.to_owned(),
            engine: format!("engine-{identity}"),
            engine_version: format!("version-{identity}"),
            engine_instance: format!("instance-{identity}"),
            publisher: format!("publisher-{identity}"),
            data_parallel_rank: rank,
            epoch: format!("epoch-{identity}"),
            initial_cursor: DecimalU64::new(initial_cursor),
            baseline: Baseline::UnknownAtAttach,
            worker_metadata: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    fn stream(stream_id: &str, identity: &str, rank: u32, initial_cursor: u64) -> ValidatedRecord {
        validated(Record::Stream(stream_declaration(
            stream_id,
            identity,
            rank,
            initial_cursor,
        )))
    }

    fn envelope(
        envelope_id: &str,
        stream_id: &str,
        cursor: u64,
        mutations: Vec<Mutation>,
    ) -> ValidatedRecord {
        validated(Record::Envelope(EventEnvelope {
            envelope_id: envelope_id.to_owned(),
            stream_id: stream_id.to_owned(),
            cursor: DecimalU64::new(cursor),
            origin: Origin::Live,
            mutations,
            extensions: BTreeMap::new(),
        }))
    }

    fn delivery(envelope_id: &str, occurrence: u16) -> DeliveryRef {
        DeliveryRef {
            envelope_id: envelope_id.to_owned(),
            occurrence,
        }
    }

    fn schedule(schedule_id: &str, actions: Vec<FaultAction>) -> ValidatedRecord {
        schedule_with(schedule_id, actions, &Limits::default())
    }

    fn schedule_with(
        schedule_id: &str,
        actions: Vec<FaultAction>,
        limits: &Limits,
    ) -> ValidatedRecord {
        validated_with(
            Record::FaultSchedule(FaultSchedule {
                schedule_id: schedule_id.to_owned(),
                actions,
                extensions: BTreeMap::new(),
            }),
            limits,
        )
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "test helper mirrors the public owned-limits constructor"
    )]
    fn with_header(limits: Limits, redaction: RedactionMode) -> TraceValidator {
        let mut validator = TraceValidator::new(limits).expect("test limits must be supported");
        validator
            .push(&header(redaction))
            .expect("header must be accepted");
        validator
    }

    fn assert_resource(
        error: &Error,
        record: u64,
        resource: Resource,
        maximum: u64,
        observed: u64,
    ) {
        assert_eq!(
            error,
            &Error::ResourceLimit {
                record,
                resource,
                maximum,
                observed,
            }
        );
    }

    #[test]
    fn constructor_rejects_unsafe_depth_before_recursive_validation() {
        let limits = Limits {
            max_depth: MAX_JSON_DEPTH + 1,
            ..Limits::default()
        };

        assert_eq!(
            TraceValidator::new(limits).err(),
            Some(Error::UnsupportedDepthLimit {
                configured: MAX_JSON_DEPTH + 1,
                maximum: MAX_JSON_DEPTH,
            })
        );
        assert_eq!(
            validate_trace(std::iter::empty(), limits),
            Err(Error::UnsupportedDepthLimit {
                configured: MAX_JSON_DEPTH + 1,
                maximum: MAX_JSON_DEPTH,
            })
        );
    }

    #[test]
    fn header_is_required_first_exactly_once_and_failures_are_sticky() {
        let empty = TraceValidator::new(Limits::default()).unwrap();
        assert_eq!(empty.finish(), Err(Error::MissingHeader));

        let mut validator = TraceValidator::new(Limits::default()).unwrap();
        assert_eq!(
            validator.push(&stream("s", "a", 0, 0)),
            Err(Error::HeaderNotFirst { record: 0 })
        );
        assert_eq!(
            validator.push(&header(RedactionMode::Omitted)),
            Err(Error::ValidatorFailed)
        );
        assert_eq!(validator.finish(), Err(Error::ValidatorFailed));

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        assert_eq!(
            validator.push(&header(RedactionMode::Omitted)),
            Err(Error::DuplicateHeader { record: 1 })
        );
    }

    #[test]
    fn header_only_trace_returns_content_free_summary() {
        let records = [header(RedactionMode::UnkeyedLinkable)];
        let summary = validate_trace(&records, Limits::default()).unwrap();

        assert_eq!(summary.records(), 1);
        assert_eq!(summary.streams(), 0);
        assert_eq!(summary.envelopes(), 0);
        assert_eq!(summary.fault_schedules(), 0);
        assert_eq!(summary.fault_actions(), 0);
        assert_eq!(summary.identity_bytes(), 0);
        assert_eq!(summary.schedule_work(), 0);
        assert_eq!(summary.redaction(), RedactionMode::UnkeyedLinkable);
    }

    #[test]
    fn eof_plan_summary_matches_the_compatible_finish_path() {
        let records = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule(
                "drop",
                vec![FaultAction::Drop {
                    target: delivery("e", 0),
                }],
            ),
        ];
        let expected = validate_trace(&records, Limits::default()).unwrap();
        let mut validator = TraceValidator::new(Limits::default()).unwrap();
        for record in &records {
            validator.push(record).unwrap();
        }

        let planned = validator.finish_planned().unwrap();
        assert_eq!(planned.summary(), expected);
        assert_eq!(planned.into_parts().summary, expected);
    }

    #[test]
    fn active_limits_revalidate_records_and_record_count_has_precedence() {
        let loose_header = header(RedactionMode::Omitted);
        let strict = Limits {
            max_identity_bytes: 2,
            ..Limits::default()
        };
        let mut validator = TraceValidator::new(strict).unwrap();
        assert_eq!(
            validator.push(&loose_header),
            Err(Error::RecordValidation {
                record: 0,
                error: ValidationError::FieldTooLong {
                    field: "trace_id",
                    limit: 2,
                    actual: 5,
                },
            })
        );

        let no_records = Limits {
            max_records_per_trace: 0,
            max_identity_bytes: 0,
            ..Limits::default()
        };
        let mut validator = TraceValidator::new(no_records).unwrap();
        assert_resource(
            &validator.push(&loose_header).unwrap_err(),
            0,
            Resource::Records,
            0,
            1,
        );
    }

    #[test]
    fn canonical_stream_identity_ignores_only_non_identity_fields() {
        let base = stream_declaration("s0", "same", 7, 10);
        let mut non_identity = base.clone();
        non_identity.stream_id = "s1".to_owned();
        non_identity.initial_cursor = DecimalU64::new(999);
        non_identity.baseline = Baseline::EmptyAtEngineStart;
        non_identity.worker_metadata = vec!["different-worker".to_owned()];

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&validated(Record::Stream(base))).unwrap();
        assert_eq!(
            validator.push(&validated(Record::Stream(non_identity))),
            Err(Error::DuplicateStreamIdentity { record: 2 })
        );
    }

    #[test]
    fn every_canonical_stream_identity_component_is_significant() {
        let base = stream_declaration("s0", "same", 7, 10);
        let variants = [
            {
                let mut value = base.clone();
                value.stream_id = "s1".to_owned();
                value.engine.push('x');
                value
            },
            {
                let mut value = base.clone();
                value.stream_id = "s1".to_owned();
                value.engine_version.push('x');
                value
            },
            {
                let mut value = base.clone();
                value.stream_id = "s1".to_owned();
                value.engine_instance.push('x');
                value
            },
            {
                let mut value = base.clone();
                value.stream_id = "s1".to_owned();
                value.publisher.push('x');
                value
            },
            {
                let mut value = base.clone();
                value.stream_id = "s1".to_owned();
                value.data_parallel_rank += 1;
                value
            },
            {
                let mut value = base.clone();
                value.stream_id = "s1".to_owned();
                value.epoch.push('x');
                value
            },
        ];

        for variant in variants {
            let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
            validator
                .push(&validated(Record::Stream(base.clone())))
                .unwrap();
            validator.push(&validated(Record::Stream(variant))).unwrap();
        }
    }

    #[test]
    fn stream_ids_are_unique_before_identity_and_count_checks() {
        let mut validator = with_header(
            Limits {
                max_streams_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();

        assert_eq!(
            validator.push(&stream("s", "different", 1, 0)),
            Err(Error::DuplicateStreamId { record: 2 })
        );
    }

    #[test]
    fn envelope_requires_prior_stream_and_cursor_at_or_above_initial() {
        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        assert_eq!(
            validator.push(&envelope("e", "missing", 10, Vec::new())),
            Err(Error::UndeclaredStream { record: 1 })
        );

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 10)).unwrap();
        assert_eq!(
            validator.push(&envelope("below", "s", 9, Vec::new())),
            Err(Error::CursorBeforeInitial { record: 2 })
        );

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 10)).unwrap();
        validator
            .push(&envelope("exact", "s", 10, Vec::new()))
            .unwrap();
        validator
            .push(&envelope("later", "s", 12, Vec::new()))
            .unwrap();
        validator
            .push(&envelope("out-of-order", "s", 10, Vec::new()))
            .unwrap();
    }

    #[test]
    fn structural_validation_preserves_same_cursor_conflicts_for_semantic_folding() {
        let records = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("first", "s", 0, Vec::new()),
            envelope(
                "conflict",
                "s",
                0,
                vec![store_with_evidence(EvidenceCase::None)],
            ),
        ];

        let summary = validate_trace(&records, Limits::default()).unwrap();
        assert_eq!(summary.envelopes(), 2);
    }

    #[test]
    fn envelope_ids_are_globally_unique_even_when_payload_changes() {
        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();

        assert_eq!(
            validator.push(&envelope("e", "s", 1, Vec::new())),
            Err(Error::DuplicateEnvelopeId { record: 3 })
        );
    }

    #[derive(Clone, Copy)]
    enum EvidenceCase {
        None,
        Keyed,
        Unkeyed,
        TokenIds,
    }

    impl EvidenceCase {
        const fn kind(self) -> Option<TokenEvidenceKind> {
            match self {
                Self::None => None,
                Self::Keyed => Some(TokenEvidenceKind::KeyedDigest),
                Self::Unkeyed => Some(TokenEvidenceKind::UnkeyedDigest),
                Self::TokenIds => Some(TokenEvidenceKind::TokenIds),
            }
        }
    }

    fn store_with_evidence(case: EvidenceCase) -> Mutation {
        let token_evidence = match case {
            EvidenceCase::None => None,
            EvidenceCase::Keyed => Some(TokenEvidence::KeyedDigest {
                algorithm: KeyedDigestAlgorithm::HmacSha256,
                key_id: "private-key-label".to_owned(),
                value: Sha256Digest::new([1; 32]),
            }),
            EvidenceCase::Unkeyed => Some(TokenEvidence::UnkeyedDigest {
                algorithm: UnkeyedDigestAlgorithm::Sha256,
                value: Sha256Digest::new([2; 32]),
            }),
            EvidenceCase::TokenIds => Some(TokenEvidence::TokenIds {
                values: vec![11, 12],
            }),
        };
        Mutation::StoreRun {
            hashes: vec![OpaqueHash::U64 {
                value: DecimalU64::new(1),
            }],
            lineage: None,
            token_count: None,
            token_evidence,
            block_size: None,
            group: CacheGroup::Unspecified,
            medium: StorageMedium::Unspecified,
            block_metadata: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn redaction_mode_and_token_evidence_form_a_closed_matrix() {
        let modes = [
            RedactionMode::Omitted,
            RedactionMode::KeyedDigests,
            RedactionMode::UnkeyedLinkable,
            RedactionMode::ContainsTokenIds,
        ];
        let evidence_cases = [
            EvidenceCase::None,
            EvidenceCase::Keyed,
            EvidenceCase::Unkeyed,
            EvidenceCase::TokenIds,
        ];

        for mode in modes {
            for evidence_case in evidence_cases {
                let mut validator = with_header(Limits::default(), mode);
                validator.push(&stream("s", "a", 0, 0)).unwrap();
                let mutations = vec![
                    Mutation::Clear {
                        metadata: BTreeMap::new(),
                    },
                    store_with_evidence(evidence_case),
                ];
                let result = validator.push(&envelope("e", "s", 0, mutations));
                let expected_kind = evidence_case.kind();
                let matches = expected_kind.is_none()
                    || matches!(
                        (mode, expected_kind),
                        (
                            RedactionMode::KeyedDigests,
                            Some(TokenEvidenceKind::KeyedDigest)
                        ) | (
                            RedactionMode::UnkeyedLinkable,
                            Some(TokenEvidenceKind::UnkeyedDigest)
                        ) | (
                            RedactionMode::ContainsTokenIds,
                            Some(TokenEvidenceKind::TokenIds)
                        )
                    );

                if matches {
                    result.unwrap();
                } else {
                    assert_eq!(
                        result,
                        Err(Error::TokenEvidenceRedactionMismatch {
                            record: 2,
                            mutation: 1,
                            expected: mode,
                            observed: expected_kind.unwrap(),
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn interleaved_records_use_each_schedules_prior_envelope_prefix() {
        let records = [
            header(RedactionMode::Omitted),
            stream("sa", "a", 0, 0),
            envelope("ea", "sa", 0, Vec::new()),
            schedule("first", Vec::new()),
            stream("sb", "b", 1, 0),
            envelope("eb", "sb", 0, Vec::new()),
            schedule(
                "second",
                vec![FaultAction::MoveBefore {
                    target: delivery("eb", 0),
                    anchor: delivery("ea", 0),
                }],
            ),
        ];

        let summary = validate_trace(&records, Limits::default()).unwrap();
        assert_eq!(summary.records(), 7);
        assert_eq!(summary.streams(), 2);
        assert_eq!(summary.envelopes(), 2);
        assert_eq!(summary.fault_schedules(), 2);
        assert_eq!(summary.fault_actions(), 1);
        assert_eq!(summary.schedule_work(), 3);
    }

    #[test]
    fn eof_plan_preserves_physical_orders_prefixes_and_numeric_sources() {
        let records = [
            header(RedactionMode::Omitted),
            stream("sa", "a", 0, 0),
            envelope("ea", "sa", 0, Vec::new()),
            schedule("first", Vec::new()),
            stream("sb", "b", 1, 0),
            envelope("eb", "sb", 0, Vec::new()),
            schedule(
                "second",
                vec![FaultAction::MoveBefore {
                    target: delivery("eb", 0),
                    anchor: delivery("ea", 0),
                }],
            ),
            envelope("ec", "sa", 1, Vec::new()),
            schedule(
                "third",
                vec![FaultAction::Drop {
                    target: delivery("ec", 0),
                }],
            ),
        ];
        let mut validator = TraceValidator::new(Limits::default()).unwrap();
        for record in &records {
            validator.push(record).unwrap();
        }

        let parts = validator.finish_planned().unwrap().into_parts();
        assert_eq!(parts.limits, Limits::default());
        assert!(parts.stream_ids.iter().map(AsRef::as_ref).eq(["sa", "sb"]));
        assert!(
            parts
                .envelope_ids
                .iter()
                .map(AsRef::as_ref)
                .eq(["ea", "eb", "ec"])
        );
        assert_eq!(parts.schedules.len(), 3);
        assert_eq!(parts.schedules[0].id.as_ref(), "first");
        assert_eq!(parts.schedules[0].prefix_len, 1);
        assert!(parts.schedules[0].actions.is_empty());

        assert_eq!(parts.schedules[1].id.as_ref(), "second");
        assert_eq!(parts.schedules[1].prefix_len, 2);
        let [PlannedAction::MoveBefore { target, anchor }] = parts.schedules[1].actions.as_ref()
        else {
            panic!("second schedule must contain one numeric move");
        };
        assert!(
            *target
                == DeliveryKey {
                    source: SourceIndex(1),
                    occurrence: 0,
                }
        );
        assert!(
            *anchor
                == DeliveryKey {
                    source: SourceIndex(0),
                    occurrence: 0,
                }
        );

        assert_eq!(parts.schedules[2].id.as_ref(), "third");
        assert_eq!(parts.schedules[2].prefix_len, 3);
        let [PlannedAction::Drop { target }] = parts.schedules[2].actions.as_ref() else {
            panic!("third schedule must contain one numeric drop");
        };
        assert!(
            *target
                == DeliveryKey {
                    source: SourceIndex(2),
                    occurrence: 0,
                }
        );
    }

    #[test]
    fn eof_plan_freezes_duplicate_ranges_and_resets_each_schedule_namespace() {
        let records = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule(
                "first",
                vec![
                    FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: 2,
                    },
                    FaultAction::Duplicate {
                        target: delivery("e", 1),
                        copies: 2,
                    },
                ],
            ),
            schedule(
                "second",
                vec![FaultAction::Duplicate {
                    target: delivery("e", 0),
                    copies: 1,
                }],
            ),
        ];
        let mut validator = TraceValidator::new(Limits::default()).unwrap();
        for record in &records {
            validator.push(record).unwrap();
        }

        let parts = validator.finish_planned().unwrap().into_parts();
        assert_eq!(parts.schedules.len(), 2);
        let [
            PlannedAction::Duplicate {
                target: first_target,
                first_occurrence: first,
                copies: first_copies,
            },
            PlannedAction::Duplicate {
                target: second_target,
                first_occurrence: second,
                copies: second_copies,
            },
        ] = parts.schedules[0].actions.as_ref()
        else {
            panic!("first schedule must contain two numeric duplicates");
        };
        assert!(
            *first_target
                == DeliveryKey {
                    source: SourceIndex(0),
                    occurrence: 0,
                }
        );
        assert_eq!((*first, *first_copies), (1, 2));
        assert!(
            *second_target
                == DeliveryKey {
                    source: SourceIndex(0),
                    occurrence: 1,
                }
        );
        assert_eq!((*second, *second_copies), (3, 2));

        let [
            PlannedAction::Duplicate {
                target,
                first_occurrence,
                copies,
            },
        ] = parts.schedules[1].actions.as_ref()
        else {
            panic!("second schedule must contain one numeric duplicate");
        };
        assert!(
            *target
                == DeliveryKey {
                    source: SourceIndex(0),
                    occurrence: 0,
                }
        );
        assert_eq!((*first_occurrence, *copies), (1, 1));
    }

    #[test]
    fn eof_plan_retains_the_last_representable_occurrence_allocation() {
        let limits = Limits {
            max_duplicate_copies: u16::MAX,
            ..Limits::default()
        };
        let records = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule_with(
                "boundary",
                vec![
                    FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: u16::MAX - 1,
                    },
                    FaultAction::Duplicate {
                        target: delivery("e", u16::MAX - 1),
                        copies: 1,
                    },
                ],
                &limits,
            ),
        ];
        let mut validator = TraceValidator::new(limits).unwrap();
        for record in &records {
            validator.push(record).unwrap();
        }

        let parts = validator.finish_planned().unwrap().into_parts();
        let PlannedAction::Duplicate {
            first_occurrence,
            copies,
            ..
        } = &parts.schedules[0].actions[1]
        else {
            panic!("boundary action must remain a numeric duplicate");
        };
        assert_eq!((*first_occurrence, *copies), (u16::MAX, 1));
    }

    #[test]
    fn eof_plan_is_unavailable_after_missing_header_or_late_sticky_failure() {
        assert!(matches!(
            TraceValidator::new(Limits::default())
                .unwrap()
                .finish_planned(),
            Err(Error::MissingHeader)
        ));

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        validator
            .push(&schedule(
                "already-planned",
                vec![FaultAction::Drop {
                    target: delivery("e", 0),
                }],
            ))
            .unwrap();
        assert_eq!(
            validator.push(&envelope("e", "s", 1, Vec::new())),
            Err(Error::DuplicateEnvelopeId { record: 4 })
        );
        assert_eq!(
            validator.push(&schedule("after-failure", Vec::new())),
            Err(Error::ValidatorFailed)
        );
        assert!(matches!(
            validator.finish_planned(),
            Err(Error::ValidatorFailed)
        ));
    }

    #[test]
    fn schedules_allocate_contiguous_occurrences_and_track_removal() {
        let actions = vec![
            FaultAction::Duplicate {
                target: delivery("e", 0),
                copies: 2,
            },
            FaultAction::MoveBefore {
                target: delivery("e", 2),
                anchor: delivery("e", 0),
            },
            FaultAction::Drop {
                target: delivery("e", 1),
            },
            FaultAction::Duplicate {
                target: delivery("e", 0),
                copies: 1,
            },
            FaultAction::MoveBefore {
                target: delivery("e", 3),
                anchor: delivery("e", 2),
            },
        ];
        let records = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule("valid", actions),
        ];

        let summary = validate_trace(&records, Limits::default()).unwrap();
        assert_eq!(summary.fault_actions(), 5);
        assert_eq!(summary.schedule_work(), 4);

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        assert_eq!(
            validator.push(&schedule(
                "removed",
                vec![
                    FaultAction::Drop {
                        target: delivery("e", 0),
                    },
                    FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: 1,
                    },
                ],
            )),
            Err(Error::FaultOccurrenceRemoved {
                record: 3,
                action: 1,
                role: DeliveryRole::Target,
            })
        );
    }

    #[test]
    fn fault_errors_distinguish_future_envelopes_occurrences_and_anchors() {
        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        assert_eq!(
            validator.push(&schedule(
                "future",
                vec![FaultAction::Drop {
                    target: delivery("future-envelope", 0),
                }],
            )),
            Err(Error::FaultEnvelopeNotPrior {
                record: 1,
                action: 0,
                role: DeliveryRole::Target,
            })
        );

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        assert_eq!(
            validator.push(&schedule(
                "uncreated",
                vec![FaultAction::MoveBefore {
                    target: delivery("e", 1),
                    anchor: delivery("e", 0),
                }],
            )),
            Err(Error::FaultOccurrenceNotCreated {
                record: 3,
                action: 0,
                role: DeliveryRole::Target,
            })
        );

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        assert_eq!(
            validator.push(&schedule(
                "missing-anchor",
                vec![FaultAction::MoveBefore {
                    target: delivery("e", 0),
                    anchor: delivery("missing", 0),
                }],
            )),
            Err(Error::FaultEnvelopeNotPrior {
                record: 3,
                action: 0,
                role: DeliveryRole::Anchor,
            })
        );
    }

    #[test]
    fn schedules_have_independent_occurrence_and_removal_namespaces() {
        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        validator
            .push(&schedule(
                "first",
                vec![FaultAction::Duplicate {
                    target: delivery("e", 0),
                    copies: 1,
                }],
            ))
            .unwrap();

        assert_eq!(
            validator.push(&schedule(
                "second",
                vec![FaultAction::MoveBefore {
                    target: delivery("e", 1),
                    anchor: delivery("e", 0),
                }],
            )),
            Err(Error::FaultOccurrenceNotCreated {
                record: 4,
                action: 0,
                role: DeliveryRole::Target,
            })
        );

        let records = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule(
                "drop-first",
                vec![FaultAction::Drop {
                    target: delivery("e", 0),
                }],
            ),
            schedule(
                "drop-again-independently",
                vec![FaultAction::Drop {
                    target: delivery("e", 0),
                }],
            ),
        ];
        validate_trace(&records, Limits::default()).unwrap();
    }

    #[test]
    fn synthesized_occurrences_survive_original_drop_and_removed_anchors_fail() {
        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();

        assert_eq!(
            validator.push(&schedule(
                "liveness",
                vec![
                    FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: 2,
                    },
                    FaultAction::Drop {
                        target: delivery("e", 0),
                    },
                    FaultAction::MoveBefore {
                        target: delivery("e", 1),
                        anchor: delivery("e", 2),
                    },
                    FaultAction::Drop {
                        target: delivery("e", 2),
                    },
                    FaultAction::MoveBefore {
                        target: delivery("e", 1),
                        anchor: delivery("e", 2),
                    },
                ],
            )),
            Err(Error::FaultOccurrenceRemoved {
                record: 3,
                action: 4,
                role: DeliveryRole::Anchor,
            })
        );
    }

    #[test]
    fn occurrence_namespace_accepts_65535_and_rejects_the_next_copy() {
        let limits = Limits {
            max_duplicate_copies: u16::MAX,
            ..Limits::default()
        };
        let accepted = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule_with(
                "boundary",
                vec![
                    FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: u16::MAX,
                    },
                    FaultAction::MoveBefore {
                        target: delivery("e", u16::MAX),
                        anchor: delivery("e", 0),
                    },
                ],
                &limits,
            ),
        ];
        validate_trace(&accepted, limits).unwrap();

        let overflowing = [
            header(RedactionMode::Omitted),
            stream("s", "a", 0, 0),
            envelope("e", "s", 0, Vec::new()),
            schedule_with(
                "overflow",
                vec![
                    FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: u16::MAX,
                    },
                    FaultAction::Duplicate {
                        target: delivery("e", u16::MAX),
                        copies: 1,
                    },
                ],
                &limits,
            ),
        ];
        assert_eq!(
            validate_trace(&overflowing, limits),
            Err(Error::FaultOccurrenceOverflow {
                record: 3,
                action: 1,
            })
        );
    }

    #[test]
    fn record_stream_and_envelope_limits_have_exact_boundaries() {
        let mut validator = with_header(
            Limits {
                max_records_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        assert_resource(
            &validator.push(&stream("s", "a", 0, 0)).unwrap_err(),
            1,
            Resource::Records,
            1,
            2,
        );

        let mut validator = with_header(
            Limits {
                max_streams_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s0", "a", 0, 0)).unwrap();
        assert_resource(
            &validator.push(&stream("s1", "b", 0, 0)).unwrap_err(),
            2,
            Resource::Streams,
            1,
            2,
        );

        let mut validator = with_header(
            Limits {
                max_envelopes_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e0", "s", 0, Vec::new())).unwrap();
        assert_resource(
            &validator
                .push(&envelope("e1", "s", 1, Vec::new()))
                .unwrap_err(),
            3,
            Resource::Envelopes,
            1,
            2,
        );
    }

    #[test]
    fn schedule_and_action_limits_have_exact_boundaries() {
        let mut validator = with_header(
            Limits {
                max_fault_schedules_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&schedule("f0", Vec::new())).unwrap();
        assert_resource(
            &validator.push(&schedule("f1", Vec::new())).unwrap_err(),
            2,
            Resource::FaultSchedules,
            1,
            2,
        );

        let mut validator = with_header(
            Limits {
                max_fault_actions_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        validator
            .push(&schedule(
                "f0",
                vec![FaultAction::Drop {
                    target: delivery("e", 0),
                }],
            ))
            .unwrap();
        assert_resource(
            &validator
                .push(&schedule(
                    "f1",
                    vec![FaultAction::Drop {
                        target: delivery("e", 0),
                    }],
                ))
                .unwrap_err(),
            4,
            Resource::FaultActions,
            1,
            2,
        );
    }

    #[test]
    fn duplicate_schedule_id_precedes_the_full_schedule_count_limit() {
        let mut validator = with_header(
            Limits {
                max_fault_schedules_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&schedule("same", Vec::new())).unwrap();

        assert_eq!(
            validator.push(&schedule("same", Vec::new())),
            Err(Error::DuplicateScheduleId { record: 2 })
        );
    }

    #[test]
    fn schedule_prefix_and_duplicates_cross_limits_at_the_first_excess() {
        let mut validator = with_header(
            Limits {
                max_occurrences_per_schedule: 0,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        assert_resource(
            &validator.push(&schedule("prefix", Vec::new())).unwrap_err(),
            3,
            Resource::ScheduleOccurrences,
            0,
            1,
        );

        let mut validator = with_header(
            Limits {
                max_schedule_work_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        assert_resource(
            &validator
                .push(&schedule(
                    "duplicate",
                    vec![FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: 1,
                    }],
                ))
                .unwrap_err(),
            3,
            Resource::ScheduleWork,
            1,
            2,
        );
    }

    #[test]
    fn retained_identity_occurrence_and_work_limits_have_exact_boundaries() {
        let minimal_stream = StreamDeclaration {
            stream_id: "s".to_owned(),
            engine: "e".to_owned(),
            engine_version: "v".to_owned(),
            engine_instance: "i".to_owned(),
            publisher: "p".to_owned(),
            data_parallel_rank: 0,
            epoch: "x".to_owned(),
            initial_cursor: DecimalU64::new(0),
            baseline: Baseline::UnknownAtAttach,
            worker_metadata: vec!["not-retained".to_owned()],
            extensions: BTreeMap::new(),
        };
        let mut validator = with_header(
            Limits {
                max_identity_bytes_per_trace: 8,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator
            .push(&validated(Record::Stream(minimal_stream)))
            .unwrap();
        validator.push(&envelope("é", "s", 0, Vec::new())).unwrap();
        assert_resource(
            &validator.push(&schedule("q", Vec::new())).unwrap_err(),
            3,
            Resource::IdentityBytes,
            8,
            9,
        );

        let mut validator = with_header(
            Limits {
                max_occurrences_per_schedule: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        assert_resource(
            &validator
                .push(&schedule(
                    "f",
                    vec![FaultAction::Duplicate {
                        target: delivery("e", 0),
                        copies: 1,
                    }],
                ))
                .unwrap_err(),
            3,
            Resource::ScheduleOccurrences,
            1,
            2,
        );

        let mut validator = with_header(
            Limits {
                max_schedule_work_per_trace: 1,
                ..Limits::default()
            },
            RedactionMode::Omitted,
        );
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        validator.push(&envelope("e", "s", 0, Vec::new())).unwrap();
        validator.push(&schedule("f0", Vec::new())).unwrap();
        assert_resource(
            &validator.push(&schedule("f1", Vec::new())).unwrap_err(),
            4,
            Resource::ScheduleWork,
            1,
            2,
        );
    }

    #[test]
    fn identity_accounting_counts_only_retained_utf8_bytes() {
        let stream = StreamDeclaration {
            stream_id: "s".to_owned(),
            engine: "e".to_owned(),
            engine_version: "v".to_owned(),
            engine_instance: "i".to_owned(),
            publisher: "p".to_owned(),
            data_parallel_rank: 0,
            epoch: "x".to_owned(),
            initial_cursor: DecimalU64::new(0),
            baseline: Baseline::UnknownAtAttach,
            worker_metadata: vec!["ignored-worker-metadata".to_owned()],
            extensions: BTreeMap::new(),
        };
        let records = [
            header(RedactionMode::Omitted),
            validated(Record::Stream(stream)),
            envelope("é", "s", 0, Vec::new()),
            schedule("q", Vec::new()),
        ];

        let summary = validate_trace(&records, Limits::default()).unwrap();
        assert_eq!(summary.identity_bytes(), 9);
    }

    #[test]
    fn checked_counters_report_overflow_without_saturating() {
        assert_eq!(
            checked_limit(7, Resource::Records, u64::MAX, 1, u64::MAX),
            Err(Error::CounterOverflow { record: 7 })
        );

        let mut validator = TraceValidator::new(Limits {
            max_records_per_trace: u64::MAX,
            ..Limits::default()
        })
        .unwrap();
        validator.records = u64::MAX;
        assert_eq!(
            validator.push(&header(RedactionMode::Omitted)),
            Err(Error::CounterOverflow { record: u64::MAX })
        );
    }

    #[test]
    fn every_trace_error_has_a_stable_code() {
        let errors = [
            (
                Error::UnsupportedDepthLimit {
                    configured: 65,
                    maximum: 64,
                },
                "unsupported_depth_limit",
            ),
            (Error::ValidatorFailed, "validator_failed"),
            (Error::MissingHeader, "missing_header"),
            (Error::HeaderNotFirst { record: 0 }, "header_not_first"),
            (Error::DuplicateHeader { record: 1 }, "duplicate_header"),
            (
                Error::RecordValidation {
                    record: 1,
                    error: ValidationError::EmptyField { field: "stream_id" },
                },
                "record_validation",
            ),
            (
                Error::ResourceLimit {
                    record: 1,
                    resource: Resource::Streams,
                    maximum: 0,
                    observed: 1,
                },
                "trace_resource_limit",
            ),
            (Error::CounterOverflow { record: 1 }, "counter_overflow"),
            (
                Error::DuplicateStreamId { record: 1 },
                "duplicate_stream_id",
            ),
            (
                Error::DuplicateStreamIdentity { record: 1 },
                "duplicate_stream_identity",
            ),
            (Error::UndeclaredStream { record: 1 }, "undeclared_stream"),
            (
                Error::CursorBeforeInitial { record: 1 },
                "cursor_before_initial",
            ),
            (
                Error::DuplicateEnvelopeId { record: 1 },
                "duplicate_envelope_id",
            ),
            (
                Error::TokenEvidenceRedactionMismatch {
                    record: 1,
                    mutation: 0,
                    expected: RedactionMode::Omitted,
                    observed: TokenEvidenceKind::KeyedDigest,
                },
                "token_evidence_redaction_mismatch",
            ),
            (
                Error::DuplicateScheduleId { record: 1 },
                "duplicate_schedule_id",
            ),
            (
                Error::FaultEnvelopeNotPrior {
                    record: 1,
                    action: 0,
                    role: DeliveryRole::Target,
                },
                "fault_envelope_not_prior",
            ),
            (
                Error::FaultOccurrenceNotCreated {
                    record: 1,
                    action: 0,
                    role: DeliveryRole::Target,
                },
                "fault_occurrence_not_created",
            ),
            (
                Error::FaultOccurrenceRemoved {
                    record: 1,
                    action: 0,
                    role: DeliveryRole::Target,
                },
                "fault_occurrence_removed",
            ),
            (
                Error::FaultOccurrenceOverflow {
                    record: 1,
                    action: 0,
                },
                "fault_occurrence_overflow",
            ),
        ];
        for (error, code) in errors {
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn errors_never_carry_trace_identities_or_token_evidence() {
        const SECRET: &str = "ZXQ_SECRET_IDENTITY_91D";
        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        let error = validator
            .push(&envelope(SECRET, SECRET, 0, Vec::new()))
            .unwrap_err();
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));

        let mut validator = with_header(Limits::default(), RedactionMode::Omitted);
        validator.push(&stream("s", "a", 0, 0)).unwrap();
        let error = validator
            .push(&envelope(
                "e",
                "s",
                0,
                vec![store_with_evidence(EvidenceCase::Keyed)],
            ))
            .unwrap_err();
        assert!(!error.to_string().contains("private-key-label"));
        assert!(!format!("{error:?}").contains("private-key-label"));
    }
}
