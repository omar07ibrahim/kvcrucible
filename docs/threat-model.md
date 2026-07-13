# Threat model

KVCrucible is an offline trace processor. It is designed to analyze captures
that may be malformed, adversarial, privacy-sensitive, or simply produced by a
different engine version than the user expected.

## Protected assets

- Availability of the analysis host.
- Integrity and determinism of verdicts and witnesses.
- Confidentiality of token IDs and engine metadata in derived reports.
- Separation of independent engine, publisher, rank, and epoch scopes.
- Honesty of the consumer certainty state.

## Adversary capabilities

An input author may control line size, nesting, event counts, hash fan-out,
string lengths, metadata cardinality, cursor order, duplicate volume, replay
responses, and engine-specific extension fields. They may try to:

- exhaust memory or CPU before limits are checked;
- create quadratic state or diagnostic growth;
- alias byte and integer cache hashes;
- reuse a cursor with different content;
- trigger replay loops or an unbounded reorder buffer;
- smuggle raw token content into a supposedly redacted report;
- make an incomplete capture appear exact;
- exploit an adapter's assumptions about another engine version.

## Controls required by v0.1

- A maximum encoded line size is enforced before JSON-tree allocation; the
  bounded stream reader must also cap acquisition of the physical line.
- JSON depth, strings, envelopes, mutations, hashes, metadata, buffered gaps,
  replay attempts, and emitted diagnostics have explicit ceilings.
- Unknown fields follow a versioned policy; they are never executed.
- Cache hashes preserve an explicit wire representation.
- Raw token IDs are omitted by default; an opt-in capture must be labeled.
- A trace cannot assert an empty baseline without capture provenance.
- Cursor equivocation is an error inside a configured fingerprint-retention
  window; older redelivery is ignored and labeled `stale_unverifiable`.
- Reducer output is re-executed before it is accepted as a witness.
- Engine adapters are data decoders, not dynamic imports of serving runtimes.
- The CLI opens no socket and invokes no command from trace content.
- Diagnostic accumulation is bounded and reports truncation explicitly.
- The Rust crate forbids `unsafe` code.

Initial default ceilings are centralized in `Limits` and boundary-tested by the
codec. They will also be printed in report metadata so that changing a bound
cannot silently change a verdict.

## Privacy posture

Prefix token IDs, adapter identifiers, tenant salts, multimodal digests, model
revisions, and host names can all reveal deployment details. The canonical IR
therefore prefers omission, counts, or keyed digests over raw values. An
unkeyed digest provides stable linkability and pseudonymization only; short or
predictable token sequences remain vulnerable to dictionary testing. Reports
must distinguish omitted, keyed, unkeyed-linkable, and raw modes without
including the digest key. Test fixtures must be synthetic or have explicit
redistribution provenance.

## Out of scope

- Kernel, container, or hypervisor escapes.
- Malicious native serving-engine code running on the same host.
- Cryptographic proof that an upstream cache hash cannot collide.
- Authenticating captures or securing their transport.
- Live mitigation of a compromised router or worker.
- Correctness of tensors, allocators, schedulers, or GPU kernels not represented
  in the event stream.

KVCrucible can show that a bounded model and an observed trace violate a stated
invariant. It cannot turn missing telemetry into proof about hidden state.
