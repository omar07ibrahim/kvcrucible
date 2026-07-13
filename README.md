# KVCrucible

KVCrucible is an offline conformance lab for recovering LLM KV-cache metadata
from unreliable event streams.

Modern inference routers consume cache events to estimate which worker already
holds a prompt prefix. That view can become subtly wrong when a consumer joins
late, misses a bounded replay window, receives a duplicate, observes a restart,
or mistakes a publisher-local sequence for a global one. KVCrucible turns those
conditions into deterministic traces, explicit uncertainty, and replayable
counterexamples.

This is not a serving engine, a throughput simulator, or a claim that vLLM or
Dynamo is formally verified.

> **Status:** contract-first prototype. The typed IR and bounded per-record
> canonical JSONL codec are implemented; trace-wide validation, the state model,
> and the production-engine adapter are still pending.

## The problem

A cache-event consumer has at least three materially different states:

- **exact** — its view follows a declared baseline with no unresolved gap;
- **recovering** — it has detected a gap and is waiting for bounded replay;
- **unknown** — the missing history cannot be reconstructed safely.

Collapsing those states into “healthy” or “failed” creates false confidence. A
late subscriber may continue building a useful partial view, but it cannot
truthfully call that view complete. A duplicate store may be harmless, while
the same cursor carrying a different payload is not.

KVCrucible is designed to make those distinctions executable.

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

The JSON form is intentionally suitable for CI assertions and future report
metadata.

The release gate builds a static Linux x86-64 binary explicitly:

```bash
cargo build --release --target x86_64-unknown-linux-musl --locked
```

Other development hosts use their native target; the published Linux artifact
never depends on that native build.

## Roadmap

Slice 2 currently covers strict single-record decoding and encoding: duplicate
decoded keys, non-integer numbers, unsafe integers, malformed UTF-8, structural
budgets, and noncanonical input are tested before typed-IR construction. The
bounded multi-record reader and trace-wide ordering checks are the next gate.

| Slice | Deliverable | Evidence gate |
|---|---|---|
| 1 | Charter, IR, threat model, static CLI | format, lint, test, release build |
| 2 | Typed IR and bounded JSONL codec | golden vectors and adversarial limits |
| 3 | Tri-state cache-view fold | state-machine and property tests |
| 4 | Fault/replay schedules and oracle | faulted/pristine convergence corpus |
| 5 | Witness reducer and report CLI | deterministic 1-minimal regressions |
| 6 | Pinned vLLM adapter | upstream-derived fixtures and differential tests |
| 7 | v0.1 reproducibility release | end-to-end demo and compatibility matrix |

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
- Every verdict identifies whether it came from observed data, a modeled fault,
  or a recovery assumption.

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
