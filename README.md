# KVCrucible

KVCrucible is an offline conformance lab for recovering LLM KV-cache metadata
from unreliable event streams.

Modern inference routers consume cache events to estimate which worker already
holds a prompt prefix. That view can become subtly wrong when a consumer joins
late, misses a bounded replay window, receives a duplicate, observes a restart,
or mistakes a publisher-local sequence for a global one. KVCrucible already
turns delivered traces into explicit, bounded uncertainty; the planned
orchestrator will turn faulted executions into replayable counterexamples.

This is not a serving engine, a throughput simulator, or a claim that vLLM or
Dynamo is formally verified.

> **Status:** the typed IR, bounded streaming canonical JSONL codec, incremental
> structural validator, internal non-exported semantic fingerprinting, and
> bounded tri-state cache-view fold are implemented. Fault/replay orchestration,
> the convergence oracle, witness reduction, reports, and a production-engine
> adapter are next.

## The problem

A cache-event consumer has at least three materially different states:

- **exact** — its view follows an externally trusted baseline or clear anchor
  with no active gap, equivocation, or unavailable evidence;
- **recovering** — it retains a bounded clean gap and awaits missing delivery;
- **unknown** — missing or conflicting history prevents an authoritative
  complete view.

Collapsing those states into “healthy” or “failed” creates false confidence. A
late subscriber may continue building a useful partial view, but it cannot
truthfully call that view complete. A duplicate store may be harmless, while
the same cursor carrying a different payload is not.

The delivered-envelope fold already makes those distinctions executable. It
does not yet execute fault schedules or issue replay requests: those arrive with
the orchestration layer in Slice 4.

## v0.1 contract

The first release will provide:

- a bounded, engine-neutral JSONL trace format;
- publisher-local cursor and externally declared epoch semantics;
- deterministic drop, duplicate, reorder, and declared-boundary schedules;
- replay recovery with explicit `exact`, `recovering`, and `unknown` states;
- a convergence oracle against an unfaulted reference execution;
- deterministic shrinking to a 1-minimal replayable witness under a recorded
  reduction order;
- one version-pinned vLLM wire adapter backed by golden fixtures;
- a static CPU-only CLI and machine-readable reports.

It will not infer GPU allocation, reference counts, scheduler state, or tensor
correctness from prefix-cache events. Those facts are not present in the event
stream.

The detailed boundary lives in [the project charter](docs/charter.md), and the
wire-independent data model lives in [the IR specification](spec/ir-v1.md).

## Intended workflow

```text
version-pinned capture
        │
        ▼
bounded adapter ──► canonical envelopes ──► pristine reference fold
                              │                         │
                              ├─► fault schedule        │
                              │         │               │
                              │         ▼               │
                              └─► recovery fold ────────┤
                                        │              │
                                        ▼              ▼
                              certainty + diagnostics + convergence
                                        │
                                        ▼
                                 1-minimal witness
```

Transport envelopes and cache mutations are separate layers. This prevents a
transport gap from being misreported as a cache mutation bug.

## Inspect the current contract

The repository pins Rust. Native development commands work on the current host:

```bash
cargo run -- contract
cargo run -- contract --format json
```

The JSON form separates current capabilities from the remaining v0.1 plan. It
is intentionally suitable for CI assertions and future report metadata.

## Run the implemented fold

Slice 3 is a library API, with a small executable example that exercises the
complete current trust boundary:

```bash
cargo run --example delivered_fold
```

It decodes five bounded JSONL records, validates the complete trace, registers
one stream blueprint, and prepares each source envelope. Only after sealing the
normalization session does it start a fresh scenario state, apply an
out-of-order delivery sequence, and finalize an exact three-key view:

```text
Applied
Buffered
Applied
certainty=Exact frontier=Some(2) keys=3
```

The release gate builds a static Linux x86-64 binary explicitly:

```bash
cargo build --release --target x86_64-unknown-linux-musl --locked
```

Other development hosts use their native target; the published Linux artifact
never depends on that native build.

## Roadmap

Slices 1–3 are implemented. The current core strictly decodes and encodes the
IR, validates a trace incrementally, fingerprints each normalized mutation list
under a session-wide work budget, and folds already delivered envelopes into a
bounded per-stream cache view. State tests cover deterministic transitions,
equivocation, modeled gap exhaustion, clear-barrier recovery, and atomic
rollback on hard failure.

| Slice | Status | Deliverable | Evidence gate |
|---|---|---|---|
| 1 | implemented | Charter, IR, threat model, static CLI | format, lint, test, release build |
| 2 | implemented | Bounded IR ingestion and trace validation | golden vectors and adversarial limits |
| 3 | implemented | Tri-state delivered-envelope fold | state-machine and property tests |
| 4 | next | Fault/replay schedules and oracle | faulted/pristine convergence corpus |
| 5 | planned | Witness reducer and report CLI | deterministic 1-minimal regressions |
| 6 | planned | Pinned vLLM adapter | upstream-derived fixtures and differential tests |
| 7 | planned | v0.1 reproducibility release | end-to-end demo and compatibility matrix |

Dynamo tree-dump recovery and cache-aware routing counterfactuals are v0.2
work. They will not be advertised as supported before their adapters and
fixtures exist.

## Design constraints

- Inputs are untrusted and resource-bounded before semantic processing.
- Cache hashes remain opaque and preserve their wire type; an integer and byte
  string are never silently conflated.
- Sequence and epoch are scoped to one publisher stream, never globally.
- Raw token IDs are omitted or keyed-digested by default. An unkeyed digest is
  labeled as linkable pseudonymization, not confidentiality.
- The core has no network listener, dynamic plugin loading, or engine import.
- Future verdicts will identify whether they came from observed data, a modeled
  fault, or a recovery assumption.

See [the semantics](spec/semantics.md) and [threat model](docs/threat-model.md)
for the rules behind those constraints.

## Why this exists now

The design follows documented behavior rather than treating cache events as a
generic message queue:

- [vLLM's KV-event subscriber example](https://docs.vllm.ai/en/stable/examples/features/kv_events/)
  exposes stored, removed, and cleared prefix-cache events.
- [vLLM's KV-event configuration](https://docs.vllm.ai/en/v0.23.0/api/vllm/config/kv_events/)
  documents a bounded replay buffer and publisher queue behavior.
- [NVIDIA Dynamo's router design](https://docs.dynamo.nvidia.com/dynamo/dev/design-docs/component-design/router-design)
  maintains a distributed prefix view for cache-aware routing.
- [Dynamo's replay comparison](https://docs.nvidia.com/dynamo/v1.0.2/components/router/kv-event-replay-dynamo-vs-v-llm)
  makes the recovery differences between Dynamo and vLLM explicit.

These sources motivate the model; they do not imply endorsement or
compatibility. Supported versions will appear only in the
[compatibility matrix](docs/compatibility.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
