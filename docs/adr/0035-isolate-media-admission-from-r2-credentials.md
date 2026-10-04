# ADR 0035 — Isolate media admission from R2 credentials and validate retained approval provenance

- **Status:** Accepted
- **Date:** 2026-10-04
- **Refines:** ADR 0034 private qualification-evidence publication
- **Does not supersede:** the Level A qualification, category, retention, privacy or human-approval contracts
- **Threat model:** [Private R2 evidence publication](../qualification/evidence-publication-threat-model.md)

## Context

ADR 0034 separates selection, admission, authorization and storage conceptually. The initial publisher repeated untrusted FFV1/Matroska probing after R2 secrets were injected. A malicious or decoder-triggering recording could exploit the media parser and extract bucket credentials. Further, a retry could accept an existing index whose stable evidence fields matched but whose original selector, reviewer, reason, timestamp or publication-run information was malformed.

## Decision

- Perform untrusted media probing and full Level A admission only in a dedicated credential-free GitHub-hosted job. This job produces an O_NOFOLLOW SHA-256-verified snapshot and a canonical receipt bound to the exact source, run/attempt, publisher identity, selection, category, policy and complete admitted file inventory.
- Transfer only the admitted snapshot and receipt through a short-lived same-workflow Actions artifact. Independently pass the receipt SHA-256 using a trusted admission-job output. Do not execute scripts from the downloaded evidence.
- Use a distinct protected GitHub-hosted archive job after successful admission and environment review. Recheck the receipt digest, run and approval provenance and every file's digest/size, then create a separate private snapshot before upload. **Do not invoke ffprobe, FFmpeg or media decoders in the job that receives R2 secrets.**
- Preserve private conditional writes, independent remote readback and index-last commit. On retry, validate the retained original selector, reviewer, reason, timezone-aware timestamp and positive publication run ID, attempt 1, publisher-code SHA and exact workflow reference. Reject malformed original audit records even when evidence fields match.

## Threat assumptions and residual risks

The admission job handles hostile media and a narrowly scoped GitHub read token. A decoder compromise could alter the admission snapshot, receipt or trusted job output but cannot directly access the R2 credentials of the different runner. GitHub's protected source, runner separation, artifact/job-output integrity and environment approval remain trusted infrastructure. SHA-256 transport bindings are not independent producer signatures, privacy approval, qualification success or release authority. A compromised protected archive runner or Read & Write token may still corrupt or delete R2 objects.

## Consequences

The publisher gains a separate short-lived internal artifact and an additional GitHub-hosted job, with a second bounded digest-verified snapshot in the protected job. Unmatched receipts, changed evidence bytes and invalid historical approval provenance fail closed. The private R2 configuration, environment controls, lifecycle policy and first approved live upload remain separate operational validation requirements.
