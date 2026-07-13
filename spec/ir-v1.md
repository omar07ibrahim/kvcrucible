# KVCrucible trace IR `v1alpha1`

Status: design contract; decoder not yet implemented.

The trace IR records two independent facts:

1. how a payload moved through a publisher-local event stream; and
2. which cache-metadata mutations that payload describes.

Keeping those layers separate is required for useful diagnoses. A dropped
envelope is a transport/recovery fact, not evidence that the engine performed an
invalid cache mutation.

## Encoding

The interchange form is UTF-8 JSON Lines. Each physical line contains exactly
one JSON object. A decoder must reject an oversized line before constructing a
JSON value.

Canonical output follows the [JSON Canonicalization Scheme in RFC
8785](https://www.rfc-editor.org/rfc/rfc8785), with
additional IR restrictions: floating-point values are forbidden, ordinary JSON
integers are limited to the interoperable range `-(2^53-1)..=(2^53-1)`, wider
unsigned values use decimal strings, digests use lowercase hexadecimal, opaque
bytes use RFC 4648 base64 without line breaks, and records end with `\n`.
Duplicate object keys, invalid Unicode, `NaN`, and infinities are rejected.

Input need not already be canonical. Re-encoding a valid record must produce a
single deterministic byte sequence.

Examples below are pretty-printed for readability. They are not canonical byte
vectors.

## Trace header

The first record declares the format and capture policy:

```json
{
  "kind": "trace_header",
  "format": "kvcrucible.trace/v1alpha1",
  "trace_id": "example-gap",
  "redaction": "keyed_digests",
  "created_by": "synthetic-fixture",
  "extensions": {}
}
```

`trace_id` is a label, not a security identity. `redaction` is one of `omitted`,
`keyed_digests`, `unkeyed_linkable`, or `contains_token_ids`. A report must carry
this value forward. `unkeyed_linkable` is pseudonymization, not a confidentiality
claim.

## Stream declaration

Every publisher stream is declared before its first envelope:

```json
{
  "kind": "stream",
  "stream_id": "publisher-a-rank-0-epoch-7",
  "engine": "vllm",
  "engine_version": "0.23.0",
  "engine_instance": "synthetic-instance-a",
  "publisher": "publisher-a",
  "data_parallel_rank": 0,
  "epoch": "capture-session-7",
  "initial_cursor": "0",
  "baseline": {"kind": "empty_at_engine_start"},
  "worker_metadata": ["tp-worker-a", "tp-worker-b"],
  "extensions": {}
}
```

The canonical stream identity is the complete tuple `(engine, engine_version,
engine_instance, publisher, data_parallel_rank, epoch)`. `stream_id` is only a
trace-local reference to that tuple. `worker_metadata` is optional evidence and
does not participate in identity because one vLLM publisher may aggregate
events from several tensor-parallel workers.

Supported baseline declarations are:

- `empty_at_engine_start` — trusted capture provenance says the publisher cache
  began empty before `initial_cursor`;
- `unknown_at_attach` — the capture joined a running publisher and cannot claim a
  complete initial view.

`initial_cursor` is the first valid cursor for this publisher and is encoded as
an unsigned decimal string with no leading zero unless its value is exactly
zero. Adapters preserve the upstream cursor domain; they do not silently
normalize a one-based source to zero. An adapter may never infer
`empty_at_engine_start` solely from the first observed cursor value.

The epoch is supplied by the capture boundary. It is not inferred from an
opaque engine payload. A process restart that can reset its cursor requires a
new epoch.

## Event envelope

```json
{
  "kind": "envelope",
  "envelope_id": "env-publisher-a-12",
  "stream_id": "publisher-a-rank-0-epoch-7",
  "cursor": "12",
  "origin": "live",
  "mutations": [],
  "extensions": {}
}
```

Fields:

- `envelope_id`: stable, trace-local identity used by fault schedules and
  preserved during witness reduction;
- `cursor`: unsigned publisher-local sequence number encoded as a decimal
  string;
- `origin`: `live` or `replay` in v1alpha1;
- `mutations`: ordered cache-metadata mutations from this envelope.

Every `envelope_id` is unique within a trace. Reusing one is a structural error,
even if the cursor and mutation payload match.

The trace does not supply a trusted payload digest. After bounded decoding,
KVCrucible computes an internal `sha256:` fingerprint over the RFC 8785 bytes of
the complete normalized `mutations` array. A duplicate/equivocation check uses
that recomputed value. Capture timing and top-level `extensions` are excluded;
validated mutation metadata is included. A claimed digest from an engine wire
format is retained only as non-authoritative adapter evidence.

The cursor is not globally comparable. Two streams may legally emit the same
cursor, advance at different rates, or contain different cache sets.

## Opaque cache hashes

Hash representation is part of identity:

```json
{"encoding": "u64", "value": "18446744073709551615"}
{"encoding": "bytes", "value": "AAECAwQ="}
```

An unsigned integer is encoded as a decimal string with no leading zero unless
its value is zero, so JSON runtimes cannot lose precision. Byte strings use
base64 and must decode to at least one byte; the default decoded-size ceiling is
256 bytes. Decoders must not coerce one representation into the other, even if
their displayed values appear equivalent.

Within the modeled cache view, a key is:

```text
(stream identity, tagged cache group, tagged storage medium, opaque hash)
```

Adapter, multimodal, model, tokenizer, tenant-salt, and other identity inputs
may already be incorporated into an upstream content hash. The IR preserves
such fields as optional metadata when available; it does not silently hash them
into the key a second time.

## Mutations

### `store_run`

A store run preserves upstream grouping rather than pretending every hash is an
independent physical allocation:

```json
{
  "op": "store_run",
  "hashes": [
    {"encoding": "u64", "value": "1042"},
    {"encoding": "u64", "value": "1043"}
  ],
  "lineage": {
    "kind": "chain",
    "parent_of_first": {"encoding": "u64", "value": "1041"}
  },
  "token_count": 32,
  "token_evidence": {
    "kind": "keyed_digest",
    "algorithm": "hmac-sha256",
    "key_id": "fixture-key",
    "value": "9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a9f2a"
  },
  "block_size": 16,
  "group": {"kind": "index", "value": 0},
  "medium": {"kind": "named", "value": "GPU"},
  "block_metadata": [{}, {}],
  "metadata": {}
}
```

`lineage`, `token_count`, `token_evidence`, `block_size`, and `block_metadata`
may be absent when the source does not expose them. A `chain` lineage means
`parent_of_first` is the parent of `hashes[0]`, and each later hash has the
previous hash as its parent. An adapter that cannot establish that relationship
uses `{"kind":"opaque"}` instead. Missing lineage in a local live view is not
itself an error: the parent may have been evicted, predate capture, or live
outside the observed metadata scope.

When present, `block_metadata` has exactly one bounded object per hash. It can
preserve redacted, adapter-specific evidence such as the per-block identity
inputs exposed by vLLM. It does not independently participate in cache identity.

Group and medium are tagged values. Group is either `index` with an unsigned
32-bit value or `unspecified`. Medium is either `named` with the case-preserved
source value or `unspecified`. Missing group or medium is never coerced to group
zero or GPU, because that would alias distinct upstream keys.

When present, `token_evidence` is exactly one of:

- `keyed_digest` with algorithm `hmac-sha256`, a non-secret `key_id`, and 64
  lowercase hexadecimal characters;
- `unkeyed_digest` with algorithm `sha256` and 64 lowercase hexadecimal
  characters, explicitly labeled as linkable rather than confidential;
- `token_ids` with a bounded ordered `values` array for a trace whose header says
  `contains_token_ids`.

Trace-level validation checks that evidence agrees with the header redaction
mode. Optional fields are omitted when unavailable; explicit JSON `null` is not
accepted as a synonym for absence.

A repeated store of an existing key is idempotent at this abstraction level. It
does not prove that a physical block was newly allocated.

### `remove`

```json
{
  "op": "remove",
  "hashes": [{"encoding": "u64", "value": "1042"}],
  "group": {"kind": "index", "value": 0},
  "medium": {"kind": "named", "value": "GPU"},
  "metadata": {}
}
```

Removing a key that is absent from the consumer view is not a hard invariant
failure. It may indicate duplicate delivery, an incomplete baseline, or
upstream idempotency. The fold records a bounded diagnostic metric.

A remove represents prefix-cache metadata. It must not be described as a GPU
free or reference-count transition.

### `clear`

```json
{"op": "clear", "metadata": {}}
```

`clear` removes every modeled cache key owned by the envelope's publisher
stream. It never clears another publisher, rank, instance, or epoch. The
operation has no group or medium selector in v1alpha1.

## Fault schedule

Faults are stored separately from the captured envelopes:

```json
{
  "kind": "fault_schedule",
  "schedule_id": "drop-12-replay",
  "actions": [
    {
      "action": "drop",
      "target": {"envelope_id": "env-publisher-a-12", "occurrence": 0}
    },
    {
      "action": "duplicate",
      "target": {"envelope_id": "env-publisher-a-14", "occurrence": 0},
      "copies": 1
    },
    {
      "action": "move_before",
      "target": {"envelope_id": "env-publisher-a-14", "occurrence": 1},
      "anchor": {"envelope_id": "env-publisher-a-13", "occurrence": 0}
    }
  ],
  "extensions": {}
}
```

Every original envelope begins with occurrence zero. Duplicate actions create
stable later occurrences. Reordering names both a stable target and stable
anchor rather than a global delivery ordinal. `move_before` removes the target
occurrence from the current materialized order and inserts it immediately before
the anchor; target and anchor must differ and already exist. Actions are applied
in recorded order, must be deterministic and seed-free after materialization,
and may refer only to records or occurrences created earlier in the same trace.
Removing an envelope during reduction never renumbers another fault target; any
now-dangling action must be removed with it.

## Extension policy

Each top-level record carries an `extensions` object reserved for namespaced,
non-executable metadata. Core semantics ignore unknown extension keys after
enforcing generic depth, size, and cardinality limits. Unknown fields outside
`extensions` are rejected in v1alpha1 so misspellings cannot silently change a
verdict.

## Versioning

`v1alpha1` may change incompatibly before v0.1. Once a stable trace version is
released:

- additive optional metadata may use a minor format revision;
- changes to identity, ordering, mutation, or certainty semantics require a new
  major trace version;
- an adapter must name both its source engine version and emitted IR version;
- compatibility is proven by fixtures, not assumed from version ranges.
