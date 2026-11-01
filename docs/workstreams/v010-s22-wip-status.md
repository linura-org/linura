# S22 WIP implementation status — not release qualification

This is a living workstream note for \`wip/v010-s22-utilities\` only. It does
not activate capabilities, reserve GitHub PR numbers or replace the accepted
release and qualification ledgers. All effects remain unregistered.

## Implemented source foundations

- **S22-1:** authenticated root-kernel-peer system bus and UID-bound logind
  session/seat observation, verified Hyprland presence and user-bus portal
  current unique owner/version probe. Source and secure/lock epoch lineage
  validators reject drift and stale state. Neither provides protected-pixel
  exclusion, which remains permanently denied in the candidate preflight.
- **S22-2:** screen and region buffer dimensions/stride/size fail-closed guards
  and tests. No screenshot URI, frame handling, private storage or export yet.
- **S22-3:** recording origin/portal/stream metadata, resource caps and
  stop/reconcile directives. Supervisor witness has no production constructor,
  and independent Stop verification always fails closed. No native recorder.
- **S22-4:** narrow clipboard MIME/size/seat/offer metadata continuity and
  protected-read preflight that denies even when metadata matches. No native
  clipboard transport, payload read or write.
- **S22-5:** revision- and owner-scoped policy foundation with history
  disabled by default. Enabling and ingesting are rejected without reviewed
  key custody and protected-source exclusion. No persistent history.
- **S22-6:** architecture, security and A/B/C qualification contracts exist.
  No user-visible GUI or CLI effect is implemented.

## Evidence explicitly **not** established

A real portal/Hyprland frame-source protection oracle, atomic descriptor-based
file publication, owned native PipeWire recorder stop/recovery, independent
clipboard offer consent and source exclusion, protected encrypted history,
first-party accessibility and actual user experience, and exact-source native
Level A / interactive Level B / maintained physical Level C/Q11 acceptance.
No synthetic fixture or CI pass can substitute for those proofs.

A WIP-only GitHub Actions workflow tests formatting, native crate unit tests,
Clippy and source/design governance. Its result is scoped development evidence,
not canonical/security/release or native hardware acceptance. Only report it
as passed when the exact-head run succeeds.

Do not open, close, rewrite or merge PRs until explicitly instructed to
extract reviewed complete implementation from this WIP branch.
