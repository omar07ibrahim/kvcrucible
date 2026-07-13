# Replay and certainty semantics

Status: design contract; state machine not yet implemented.

## Consumer state

Each declared publisher stream owns an independent consumer state:

```text
certainty: exact | recovering | unknown
frontier: last contiguous cursor, if any
cache_view: set of canonical cache keys
pending: bounded out-of-order envelopes
recent_fingerprints: bounded cursor-to-fingerprint window
diagnostics: bounded counters and evidence
```

No operation compares cursors or cache equality across distinct streams.

## Initialization

An `empty_at_engine_start` baseline begins `exact` with an empty cache view and
expects the declared `initial_cursor`. An `unknown_at_attach` baseline begins
`unknown`; later events may build a partial view but cannot retroactively prove
the missing prefix of history.

An explicit authoritative snapshot can change that rule in a future format.
Snapshot semantics are not part of v1alpha1.

A publisher-scoped `clear` is already part of v1alpha1 and acts as an
authoritative membership barrier. Its recovery behavior is defined below; it is
not a general snapshot.

An unknown-at-attach consumer treats its first accepted envelope as a partial
frontier and can fold later contiguous envelopes into a non-authoritative view.
Gaps and reordering remain bounded exactly as they are for an exact consumer,
but filling them does not repair the unknown history that predates attachment.

## Contiguous delivery

For an exact stream with frontier `n`, cursor `n + 1` is applied in mutation
order and advances the frontier. The declared `initial_cursor` is the first
contiguous envelope for an empty baseline. Cursor addition is checked for
unsigned overflow.

The fold is deterministic: identical state and normalized envelope values
produce identical state and diagnostics.

## Duplicate and equivocation

KVCrucible recomputes a semantic fingerprint from the normalized mutation
payload; it never trusts a digest declared by trace input. For cursors retained
in `recent_fingerprints`, redelivery with the same fingerprint is an idempotent
duplicate. It changes neither the cache view nor the frontier.

The same retained cursor with a different fingerprint is equivocation. It is a
hard protocol error because the consumer cannot establish which history is
authoritative. The witness retains both internal fingerprints while respecting
report redaction.

On equivocation, the conflicting redelivery is never applied. If one payload was
already applied, that first-path view is retained only as a non-authoritative
partial view; if both payloads were pending, neither is chosen for authoritative
application. In either case certainty becomes `unknown`, buffered envelopes stay
bounded and non-authoritative, and convergence is ineligible until a later
forward clear barrier makes the conflict irrelevant to current membership. The
historical diagnostic remains in the report after such recovery.

Fingerprint history has a configured cursor-count ceiling. A redelivery older
than the retained window is ignored as `stale_unverifiable`: it is neither
re-applied nor classified as a duplicate/equivocation. Reports must state the
window and cannot claim equivocation coverage outside it. This rule keeps the
state bound explicit instead of hiding an unbounded digest ledger.

More generally, an envelope at or below the current frontier with no retained
fingerprint is never applied. This also covers a previously unseen late cursor
after unknown-at-attach established a higher partial frontier. It is reported as
`stale_unverifiable`; if it contains a clear, the more specific diagnostic is
`stale_barrier`.

## Gaps and reordering

If an exact stream at frontier `n` receives cursor greater than `n + 1`, the
consumer enters `recovering`. The out-of-order envelope may be held only inside
a configured bound. Cache mutations beyond the gap are not authoritative until
the interval is closed.

Either delayed live delivery or replay may supply a missing cursor. Once every
cursor in the interval has a consistent recomputed fingerprint and the
contiguous frontier reaches the buffered envelopes, the consumer returns to
`exact` and applies each mutation exactly once. `origin` remains evidence about
delivery, not a different cache-mutation semantics.

If replay has expired, exceeds its attempt bound, contradicts an observed
fingerprint, or cannot close the full interval, the consumer becomes `unknown`.
It may continue tracking a bounded partial view and cursor evidence, but it must
not emit an exact-cache verdict from that view.

While `recovering` or `unknown`, an accepted, non-equivocated `clear` makes all
mutations ordered before that operation irrelevant to current membership. A
barrier is eligible only when its cursor is greater than the current partial
frontier, or when no frontier exists and it is the first accepted envelope. A
clear at or below the partial frontier is ignored as `stale_barrier`; v0.1 does
not retain and replay an arbitrarily old applied suffix.

For an eligible barrier, the fold discards the prior partial view and every
buffered envelope at or below the barrier cursor, applies the `clear` and any
later mutations in the same envelope, sets that cursor as the frontier, and
returns to `exact`. If the envelope contains mutations before `clear`, they are
ignored for the post-barrier view. Buffered envelopes above the new frontier are
then handled by the ordinary contiguous/gap rules. This transition is valid
only for a clear scoped to the same publisher stream; it does not repair another
stream.

## Restart boundaries

Cursor reset is legal only across a new externally declared epoch. A lower
cursor in the same epoch is handled by retained duplicate/equivocation or
`stale_unverifiable` rules, not as an automatically detected restart.

This rule is intentional: vLLM event payloads do not provide enough information
to distinguish every restart from delayed delivery. Fault schedules may alter
delivery around an epoch boundary already present in the trace; they never
synthesize an epoch or producer incarnation.

## Cache mutation fold

- `store_run` inserts every canonical key idempotently.
- `remove` deletes every present canonical key. Missing keys increment a bounded
  diagnostic counter but are not a correctness failure.
- `clear` deletes every key in the publishing stream's scope and may establish
  an authoritative barrier as described above.
- a missing parent does not invalidate a store;
- repeated stores do not imply repeated physical allocation;
- removals do not imply physical memory release.

Metadata that does not participate in canonical cache identity cannot split or
merge keys.

## Convergence oracle

For one canonical input trace, KVCrucible computes:

1. a pristine fold with original contiguous delivery; and
2. a faulted fold with the declared schedule and replay responses.

A convergence check is eligible only when the faulted consumer returns to
`exact` at the same logical frontier as the pristine consumer. It passes when
their canonical cache views are equal and no hard protocol error remains
relevant after the most recent accepted barrier. Historical errors remain
visible even when their membership impact has been superseded.

An `unknown` consumer is not “non-convergent.” It is ineligible for an exact
comparison, and the report must say why. This prevents missing telemetry from
being mislabeled as an engine cache bug.

Convergence is publisher-local. Different publishers and workers are expected
to cache different prefixes.

## Witness preservation

A reduced witness is valid only if replaying it under the same limits preserves:

- the check identifier;
- the pass, fail, or ineligible verdict;
- the primary diagnostic category;
- the relevant stream identity and epoch;
- the redaction policy.

Reduction may remove unrelated streams, envelopes, mutations, hashes, metadata,
and fault actions. Stable envelope IDs and occurrence numbers keep surviving
fault targets fixed. A reducer may remove a dangling action with its target but
may not retarget it by ordinal, synthesize events, renumber cursors, change
mutation payloads, or replace an unknown baseline with an empty one.

The v0.1 reducer seeks **1-minimality under a recorded deterministic reduction
order**: no single remaining candidate unit in that order can be removed while
preserving the witness predicate. It does not claim a globally shortest trace.

## Reporting language

Reports distinguish:

- **observed** facts decoded from a trace;
- **modeled** delivery faults and recovery responses;
- **derived** state transitions and comparisons;
- **unknown** facts that the trace cannot establish.

The terms “proof” and “exhaustive” may be used only with the exact bounded model,
limits, and schedule space recorded in the report.
