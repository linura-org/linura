# ADR 0034 — Approve private qualification-evidence publication as a separate authority boundary

- **Status:** Accepted
- **Date:** 2026-10-04
- **Refines:** ADR 0014 release contracts/evidence; ADR 0022 development proof; ADR 0027 protected publication handoff; ADR 0033 workstation scope
- **Does not supersede:** the canonical qualification gates, release-support approval or Linura's runtime authority model
- **Threat model:** [Private R2 evidence publication](../qualification/evidence-publication-threat-model.md)

## Context

Exact-source A/B/C qualification captures reproducible evidence, but retaining it, selecting it for longer-term storage and granting access to it are separate decisions. GitHub Actions artifacts have short retention, whereas selected passing Level A baselines and regressions need an independently controlled private archive. Raw interactive and physical workstation evidence may contain user information and must not inherit Level A publication authority. GitHub environment approval and R2 credentials cross a new trust boundary; neither video nor a stored index may become a qualification oracle.

An earlier implementation admitted only a synthetic recording shape, lacked attempt-specific artifact naming and could treat a previous environment approval as valid on a publication-job rerun. These boundaries must be explicit and fail closed. This ADR records the implemented controlled Level A policy; external bucket and approval settings still require operational validation.

## Decision

- Keep qualification, evidence selection, reviewer authorization, remote publication and reader access as distinct steps. Admit only a successful exact-`main` Level A manually dispatched run with GitHub-authenticated source SHA, run ID, attempt, trusted workflow identity and complete independent case results.
- Bind the actual FFV1/Matroska recording, metadata, digest sidecars, canonical runtime contract and complete retained case results. Treat downloaded artifacts as untrusted; reject unsafe paths, unbound general diagnostics and incomplete/tampered bundles. A recording supports observation but cannot prove pass/fail.
- Allow only manually selected, privacy-reviewed passing `baselines/` (180 days) or `regressions/` (90 days) through the protected `qualification-archive` GitHub environment. Require the recorded environment review; reject job reruns because approval history is run-wide. A retry is a new manual dispatch with a new environment approval.
- Limit credential exposure to the authorized upload step on a GitHub-hosted runner; restrict to the private, named R2 bucket and exact Cloudflare account endpoint. The publisher performs bounded, conditional uploads and independent remote readback. An index under `index/` is written last, and an approved retry can verify an existing record without rewriting the first selector/reviewer/admission audit.
- Reserve `physical/`, `interactive/` and `releases/` as **disabled**. Future Level B/C derivatives require authenticated owner approval, full privacy review/redaction and a separate intake and retention design. Release evidence additionally requires independent release qualification and approved audit retention.
- Do not grant execution authority, product support promotion or public access through archive existence. The private index is an inventory/completion record, not a signature, a WORM protection guarantee or evidence that referenced objects still exist.
- Require the [publication threat model](../qualification/evidence-publication-threat-model.md) to be reviewed alongside changes to trusted workflows, authentication, credentials, retention, privacy and index semantics. The operator guide describes the external GitHub environment, R2 permissions, lifecycle and first real upload that must be verified before operational activation.

## Trust assumptions and non-goals

This design trusts GitHub's protected source/workflow provenance, Actions/approval API, configured environment policy, the isolated GitHub-hosted runner and the account-scoped S3 service. A compromised trusted publisher or R2 Object Read & Write credential could read, corrupt or delete archived evidence; application-level conditional writes are not storage-enforced immutability. Object SHA-256 detects divergence from separately trusted provenance but cannot authenticate a maliciously regenerated manifest and index under a compromised trusted source. A real recording may contain secrets even if it passes structural media checks, so manual privacy approval is not optional.

This PR does not implement a public observatory, presigned-URL authorizer, signed index, write-only broker, physical workstation evidence publisher, automatic failure archive, release-proof promotion or Cloudflare administrative configuration. Such additions require their own reviewed authority and privacy decisions.

## Consequences

Selected Level A evidence becomes retrievable beyond GitHub's artifact retention without weakening qualification, introducing R2 credentials into PR jobs or publishing physical-user content by default. Manual selection and protected approval create deliberate operational work. Missing approvals, stale source, failed qualification, incomplete files, recording mismatch, R2 uncertainty and index conflict remain explicit failures rather than silently accepted publication. Live R2 readiness and periodic credential/lifecycle/access verification remain separate operational gates; a green PR cannot certify Cloudflare configuration.
