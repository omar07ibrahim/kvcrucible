# Compatibility matrix

No engine is supported in the current contract-first prototype.

| Source | Targeted version | Ingestion | Recovery model | Evidence |
|---|---:|---|---|---|
| Canonical JSONL | `v1alpha1` | specified, not implemented | replay scenarios | specification draft |
| vLLM | `0.23.0` target | planned for v0.1 | bounded event replay | fixtures pending |
| NVIDIA Dynamo | `1.0.2` research target | not supported | tree dump / event slice / too-new | v0.2 only |

“Targeted” is not “compatible.” A row becomes supported only after the decoder,
golden fixtures, provenance notes, negative tests, and end-to-end replay are all
present in a tagged release.

Engine versions are pinned because hash encodings, optional metadata, event
batching, and recovery behavior can change independently. KVCrucible will reject
an unrecognized adapter version unless the caller explicitly selects a raw
canonical-input path.
