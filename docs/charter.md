# Project charter

## Research question

When an LLM-serving component reconstructs prefix-cache metadata from a
publisher-local, bounded-replay event stream, under which observable conditions
may it call its view exact, and which fault schedule is sufficient to disprove
that claim?

KVCrucible answers that narrow question with an executable state model. The
current API returns delivery dispositions and a finalized stream summary; the
v0.1 report will carry a verdict about consumer reconstruction, never a verdict
about the serving engine that produced the events.

The delivered-envelope state model is implemented. Fault scheduling,
replay-attempt and expiry policies, convergence, reduction, reporting, and the
pinned engine adapter remain later v0.1 slices.

## Scope of v0.1

KVCrucible will:

1. Decode a versioned canonical trace under explicit resource limits.
2. Keep transport state separate from cache-metadata state.
3. Track cursors independently for each publisher stream and epoch.
4. Fold store, remove, and publisher-scoped clear mutations deterministically.
5. Inject loss, duplication, and reordering around already declared epoch
   boundaries. A fault never invents a producer restart.
6. Model bounded replay and transitions among exact, recovering, and unknown.
7. Compare a recovered view with an unfaulted reference execution.
8. Produce a deterministic 1-minimal failing schedule without changing its
   observed verdict.
9. Emit human-readable and stable JSON reports.
10. Decode one pinned vLLM event version without importing vLLM.

The executable model is bounded. Any exhaustive claim must state the explored
trace, event, and schedule bounds.

## Non-goals

The first release does not:

- prove vLLM, Dynamo, or another serving engine correct;
- observe or validate GPU KV tensors;
- reconstruct physical block allocation, ownership, or reference counts;
- equate a prefix-cache removal with a GPU memory free;
- verify scheduler optimality, fairness, latency, or throughput;
- require different workers to hold identical cache contents;
- prove a cache hash collision-resistant;
- auto-detect producer epochs across an opaque process restart;
- repair or mutate a live production system;
- accept network traffic or execute dynamically loaded adapters.

An experimental allocator model or tiny-Transformer cache-key oracle may be
useful later, but neither can be presented as evidence about hidden production
state.

## Trust boundary

Trusted:

- the KVCrucible binary identified by its build metadata;
- the selected invariant definitions and declared input limits;
- the pristine reference fold for the same canonical trace;
- the external `BaselineAuthority` decision supplied by a pinned adapter,
  verified capture boundary, or synthetic fixture; and
- explicit capture metadata that marks epoch boundaries.

Untrusted:

- JSONL and future MessagePack input;
- cache hashes, token metadata, adapter metadata, and diagnostic text;
- producer timing and delivery order;
- raw claims that a trace begins at engine startup or has an empty baseline;
- engine-specific fields not validated by a pinned adapter.

The consumer cannot recover information that was neither observed nor present
in an available replay. The correct result in that case is `unknown`, not a
fabricated empty baseline.

## Required evidence

A v0.1 release needs all of the following:

- deterministic canonical encodings and golden vectors;
- negative tests at every documented input bound;
- state-machine tests for exact, recovering, and unknown transitions;
- property-generated traces with reproducible seeds;
- a fault corpus covering drop, duplicate, reorder, declared restart boundaries,
  and replay expiry;
- convergence checks against the same unfaulted canonical execution;
- mutation tests or seeded bugs for the invariant layer;
- deterministic 1-minimal witness reduction with replay verification and a
  recorded reduction order;
- upstream-derived vLLM fixtures pinned to one version and documented provenance;
- a static release binary and a clean offline end-to-end demo.

No latency or throughput result is a correctness result. If performance numbers
are published, their machine, build, dataset, warm-up, and repetition metadata
must be retained with the raw observations.

## Vocabulary

**Publisher stream**

A single engine instance, publisher endpoint/incarnation, data-parallel rank,
and externally declared epoch. Cursor ordering exists only inside this identity.
An engine worker is optional adapter metadata because one publisher may
aggregate events from several tensor-parallel workers.

**Pristine fold**

The deterministic cache-metadata view produced from the canonical trace before
fault injection.

**Faulted fold**

The view produced after applying an explicit delivery schedule and recovery
responses.

**Convergence**

Equality between the recovered faulted view and the pristine view for the same
publisher stream at the same logical frontier. It never means that two distinct
publishers or workers must have equal caches.

**Witness**

A self-contained trace, schedule, configuration, and diagnostic set that
reproduces a failed check. The v0.1 reducer targets 1-minimality under its
recorded deterministic reduction order, not the globally smallest trace.
