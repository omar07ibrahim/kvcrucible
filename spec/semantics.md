# Replay and certainty semantics

Status: bounded internal semantic fingerprinting, the delivered-envelope state
fold, sealed numeric fault plans, and deterministic drop/duplicate/reorder
materialization are implemented. Schedule-prefix pristine/faulted execution and
eligibility-aware per-stream convergence are also implemented. Replay request,
outcome, response-attribution, and expiry orchestration, reduction, and reports
remain v0.1 contracts for later slices.

## Current execution boundary

The fold consumes envelopes in caller-supplied admission order or in the order
of a materialized fault schedule. `compare_schedule` starts fresh pristine and
faulted states over the exact stream and source prefixes visible at the schedule
record. The envelope `origin` remains observed provenance: a synthesized
transport duplicate shares its source allocation and does not become a replay
response. Origin does not change cache-mutation semantics.

The public coordinated path is one `TraceAssembler` under one `Limits` value:

1. acquire an untrusted physical JSONL trace through `JsonlReader`, which bounds
   per-line bytes, cumulative trace bytes, and physical record count;
2. give each owned validated record to the assembler, with an external baseline
   authority exactly for stream declarations;
3. let its incremental validator resolve schedule references to numeric source
   occurrences while its normalizer prepares that same owned record exactly
   once;
4. at EOF, require both structural completion and normalization seal before a
   `SealedTrace` capability is returned;
5. materialize a schedule by ordinal over its physical source prefix, sharing
   prepared sources through `Arc`;
6. compare fresh occurrence-zero physical-order and materialized-order folds for
   every stream visible at that schedule; or
7. start and finalize individual stream states against the matching sealed trace
   when a caller needs direct disposition-level inspection.

Streams and envelopes declared after a schedule record are outside that
schedule's immutable snapshot and cannot affect either comparison side.

State accumulated before a later structural failure is not an admissible
result. The validator enforces header order, declaration order, redaction,
global identity uniqueness, and fault references; the normalizer is not a
replacement for it. The low-level validator and normalizer remain available,
but only the coordinated assembler can create an executable sealed corpus.

`decode_line` is a one-record primitive. A caller using it directly must supply
an outer framing layer that independently enforces cumulative trace bytes and
physical record count; it does not replace `JsonlReader` for untrusted files.

The one-session-per-physical-trace rule binds cumulative fingerprint work,
stream and envelope counts, unique envelope IDs, immutable stream contracts,
and retained identity bytes to the trace. Prepared envelopes and seals from a
different session are rejected. Any assembler error prevents EOF sealing. A
hard `admit` failure makes that constructed stream state sticky-failed. A
baseline-authority mismatch is non-poisoning in the low-level normalizer but
fail-closed at the coordinated assembler boundary.

## Consumer state

Each declared publisher stream owns an independent state:

```text
certainty: exact | recovering | unknown
frontier: last applied dense cursor, if any
cache_view: bounded set of canonical cache keys
pending: bounded out-of-order or conflicted cursor slots
recent_fingerprints: bounded applied-cursor fingerprint window
unknown_reasons: baseline | equivocation | unavailable_gap
final-only reason: unclosed_gap
diagnostics: bounded historical counters
```

No cursor comparison crosses stream or epoch scope. Cache-view equality also
includes the complete canonical stream scope, so snapshots from distinct
publishers cannot compare equal merely because they contain the same hashes.

## Initialization and cursor domain

The raw baseline declaration is evidence, not authority. `TrustDeclaredEmpty`
may be supplied only when a pinned adapter, capture boundary, or synthetic
fixture independently establishes an `empty_at_engine_start` declaration. It
starts an `exact`, empty view. `TreatAsUnknown` starts `unknown` regardless of
the raw declaration. An `unknown_at_attach` declaration can never be promoted
to trusted empty.

The fold requires a dense unit-step cursor domain inside one stream and epoch.
`initial_cursor` is the first valid cursor and may be nonzero. After cursor `n`,
the only contiguous successor is `n + 1`; `u64::MAX` is terminal. An adapter for
a sparse or otherwise incompatible source must reject that source or define a
new versioned IR mapping. It must not silently renumber observations.

An unknown-baseline state applies its first accepted envelope as a partial
frontier and may fold a contiguous suffix. That view is not authoritative until
a valid forward clear establishes a membership anchor.

## Semantic fingerprinting

KVCrucible recomputes an internal, non-exported SHA-256 digest over the RFC 8785
canonical bytes of the complete normalized `mutations` array. It never trusts
an input digest. Envelope ID, stream ID, cursor, origin, and top-level extensions
are excluded; validated fields inside mutations are included. The digest has no
public textual representation, serialization, formatting, or report form.

Canonical bytes are streamed into the hash under both a per-envelope ceiling
and the normalizer session's cumulative fingerprint-work ceiling. A prepared
envelope is compact: it retains the ID and origin evidence, delivery facts,
mutations, internal digest, and charged byte count, but not top-level extensions.

The applied fingerprint window contains at most
`max_recent_fingerprints_per_stream` cursors. It covers applied cursors only;
pending candidates have a separate bounded ledger. A zero-sized window is
valid. When the window overflows, the lowest retained cursor is evicted.
Draining a pending candidate transfers its fingerprint into the applied window.

## Contiguous delivery

For a trusted-empty baseline, the first expected cursor is `initial_cursor`. An
unknown baseline instead accepts any first cursor at or above that bound as a
partial frontier. Thereafter, an envelope at the checked successor of the
frontier is applied in mutation order. Application may also drain the contiguous
clean pending suffix. The entire cache projection is planned against an overlay
and committed atomically: a hard cache-resource or accounting failure changes
neither the view, frontier, pending ledger, recent fingerprints, nor diagnostics.

The deterministic result of admitting one delivery is a modeled disposition:
`Applied`, `BarrierApplied`, `Buffered`, `Duplicate`, `Equivocation`,
`StaleUnverifiable`, `StaleBarrier`, `PendingLimit`, `GapLimit`, or
`UnverifiableGap`. Duplicate, equivocation, stale delivery, and modeled gap-limit
outcomes are not hard API errors. Hard errors are reserved for validation,
session or stream misuse, stack-safety, checked accounting, and cache-resource
failures; they fail the affected normalizer or stream closed.

## Duplicate and equivocation

For an applied cursor still in the recent window, the same semantic fingerprint
is an idempotent duplicate. A different fingerprint is equivocation: the
redelivery is not applied, the current view becomes non-authoritative, and
certainty becomes `unknown`. The recent slot retains the first two distinct
internal digests. Repeating either known variant is a duplicate; every new
variant is another equivocation without growing the slot.

The same rules apply to a retained pending cursor, except that no conflicting
payload is chosen. On the first conflict, the candidate payload and its pending
canonical-byte charge are released and the slot retains only the first two
internal digests. The slot stays count-bounded. Known variants are
duplicates; later new variants are equivocations.

An envelope at or below the frontier with no retained fingerprint is never
re-applied. It is `StaleUnverifiable`, or `StaleBarrier` if it contains a clear.
The configured recent-window size therefore defines the exact duplicate and
equivocation coverage claim.

Active uncertainty and historical diagnostics are separate. A later clear may
make an old conflict irrelevant to current membership and restore authority,
but it never erases the historical equivocation counter.

## Gaps and modeled exhaustion

An envelope above the next expected cursor is buffered when all three modeled
bounds permit it:

- pending cursor-slot count;
- canonical bytes held by clean pending candidates; and
- numeric distance from the next expected cursor.

A clean open gap makes an otherwise authoritative state `recovering`. Filling
every missing dense cursor applies each candidate once and returns the state to
`exact`. At source EOF, `finish` converts a retained unclosed gap to `unknown`
and records the active `unclosed_gap` reason.

If count, byte, or span capacity rejects evidence, the delivery receives
`PendingLimit` or `GapLimit` rather than a hard error. The state records a
conservative unavailable horizon beginning at the lowest discarded cursor. A
non-clear delivery at or above that floor cannot be verified and extends the
horizon's observed ceiling; it receives `UnverifiableGap`. A clear inside the
inclusive floor-to-ceiling range cannot supersede the discarded evidence. A
clear below the floor may anchor an earlier partial prefix, but the higher
unavailable horizon keeps the overall certainty `unknown`. Full recovery from
this reason requires a clear strictly above its current ceiling.

This horizon deliberately represents an unverifiable suffix, not a closed
interval. It prevents a later delivery from appearing contiguous merely because
the evidence that preceded it was discarded to remain bounded.

## Clear barriers

A clear in ordinary contiguous delivery while the stream is exact is an
ordinary `Applied` envelope. All mutations execute in order, including any
prefix before the clear, and their diagnostics count. The clear's final cache
effect still removes earlier membership.

A forward clear becomes a recovery barrier when the stream is `recovering` or
`unknown`, or when an exact stream receives a clear beyond its next expected
cursor. A barrier must be above the current frontier. Barrier application:

1. ignores mutations before the envelope's first clear;
2. applies that clear and its mutation suffix;
3. discards pending and recent evidence at or below the barrier cursor;
4. establishes an authoritative view and frontier at that cursor; and
5. drains any clean contiguous pending suffix above it.

The transition is publisher-scoped. It cannot repair another stream. Active
equivocation or unavailable evidence above the barrier remains relevant, and a
higher conflicted pending slot remains unresolved. Consequently a barrier does
not promise `exact`: it restores `exact` only when no higher active poison or
gap remains. Historical counters remain visible in all cases.

## Cache mutation fold

- `store_run` inserts each canonical key idempotently;
- `remove` deletes each present key;
- a missing remove increments a bounded exact-view or partial-view diagnostic;
- `clear` removes every key in the publishing stream's scope;
- missing lineage does not invalidate a store;
- repeated stores do not imply repeated physical allocation; and
- removals do not imply physical memory release.

The view is bounded by cache-key count and variable identity bytes. Metadata
outside canonical cache identity cannot split or merge keys.

## Restart boundaries

Cursor reset is legal only across a new externally declared epoch. A lower
cursor in the same epoch follows retained duplicate/equivocation or stale rules;
it is never treated as an automatically detected restart. Fault schedules may
eventually alter delivery around a declared boundary, but may not invent an
epoch or producer incarnation.

## Convergence and future replay contract

Slice 4 executes deterministic fault schedules while preserving physical
occurrence-zero order; the materializer never silently sorts envelopes by
cursor. `compare_schedule` then executes that physical order as the pristine
side and the materialized order as the faulted side. For each visible publisher
stream it returns `Converged`, `Diverged`, or `Ineligible`.

A comparison is eligible only when both finalized states are `Exact`, both
cache views are authoritative, neither side has an active unknown reason, both
pending-envelope count and pending canonical bytes are zero, and the logical
frontiers match. Equal same-scope canonical cache views then mean `Converged`;
different views mean `Diverged`. Any failed prerequisite means `Ineligible`,
not divergence. Historical diagnostics do not change the verdict. A hard fold
failure remains a typed execution error, and a zero-stream comparison contains
no per-stream verdict rather than an aggregate convergence claim.

Replay orchestration remains a distinct future layer. In `v1alpha1`,
`origin: replay` records observed provenance only; the IR has no replay-request
identity, attempt outcome, response attribution, or expiry record. The model
therefore never infers a replay transaction from a cursor gap or origin flag.

## Future witness contract

Slice 5 will accept a reduced witness only when re-execution under identical
limits preserves:

- the check identifier;
- the pass, fail, or ineligible verdict;
- the primary diagnostic category;
- the relevant stream identity and epoch; and
- the redaction policy.

Reduction may remove unrelated streams, envelopes, mutations, hashes, metadata,
and fault actions. Stable envelope IDs and occurrence numbers keep surviving
targets fixed. A reducer may remove a dangling action with its target but may
not retarget it by ordinal, synthesize events, renumber cursors, change mutation
payloads, or replace an unknown baseline with an empty one.

The v0.1 target is 1-minimality under a recorded deterministic reduction order,
not a globally shortest trace.

## Reporting language

Future reports distinguish observed trace facts, modeled delivery faults,
derived state transitions, and facts left unknown by the trace. The terms
“proof” and “exhaustive” are valid only with the exact bounded model, limits,
and explored schedule space recorded beside the result.
