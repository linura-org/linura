# ADR 0038: Derive qualification acceptance semantically and upload only sealed evidence

**Status:** Accepted

## Context

ADR 0037 separated execution identity from qualification-evidence acceptance and
bound accepted bytes to execution envelopes. Its first implementation still let
the evidence layer manufacture `independent=true` after checking a producer
JSON pass receipt and then left a mutable directory for a later workflow upload.
That preserved byte identity better than the previous state, but it did not
independently establish that retained bytes proved the reviewed qualification,
and the uploaded bytes were not necessarily the exact bytes last verified.

## Decision

Refine ADR 0037 with two mandatory boundaries.

First, every evidence-bearing lane selects a reviewed semantic verifier adapter.
The adapter consumes the already-verified execution envelope plus retained
structured results, raw transcripts, repository contracts, environment
identity, and lane-specific witnesses. It independently derives the accepted
result, environment-verification conclusion, verified claims, and reviewed
test/contract conclusions. The generic binder may check producer metadata for
consistency, but it may not mint an independent pass from that metadata.

Second, accepted upload authority moves inside the repository-owned admission
action. After semantic attestation, binding, and semantic re-verification, the
action deterministically serializes the complete bound bundle as
`qualification-evidence.tar` with canonical member metadata, structurally
verifies that sealed tar against the evidence binding, and immediately uploads
that exact tar. Evidence-bearing workflows may upload mutable producer
directories only on failure and only under an explicitly unqualified diagnostic
artifact name.

Downstream consumers unseal and structurally verify the tar before use. Trusted
release proof remains a separate release authority and does not reclassify the
qualification binder as release authorization.

## Consequences

A producer JSON object containing `result=passed`, arbitrary digest text, or a
self-selected `independent` field cannot satisfy evidence admission. Missing
lane-specific proof material fails closed. A post-admission write to the mutable
producer directory cannot alter the already sealed accepted object. Static
workflow validation rejects a missing artifact name, a disconnected
execution-envelope producer, or a caller-controlled success upload after the
admission action.

This ADR refines, but does not erase, ADR 0037.
