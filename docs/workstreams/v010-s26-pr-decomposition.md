# S26 Phase 2 — Proposed six-PR implementation decomposition

**Status:** Contract and test only; no implementation PRs, new runtime registration, or qualified machine effects. This remains on the WIP reference branch and must not be merged wholesale.

The machine-readable source is [S26 PR decomposition](../../contracts/v010-s26-pr-decomposition.toml). The source of scope remains [Phase 1](v010-s26-library-phase1.md), proposed [ADR 0054](../adr/0054-s26-local-library-workstation-authority.md), the existing v0.7 LocalLibrary APIs, and the v0.10 slice roadmap.

| Proposed PR | Scope | Prerequisites |
| --- | --- | --- |
| S26-1 | Typed bounded exact-revision catalog and causal ownership reads | Current accepted main, S16 |
| S26-2 | Setup/Profile immutable drafts, graph validation, CAS/idempotency | S26-1 |
| S26-3 | Deterministic safe portable import/export and local-only adoption | S26-1, S26-2 |
| S26-4 | Safely selected backup and destructive quiescent restore/recovery | S26-1 |
| S26-5 | Fresh canonical machine adoption planning, per-domain effect composition | S26-1, S26-2, S26-3 |
| S26-6 | Complete Shell Library experience, SDK/CLI, no-model, qualification | S26-1 through S26-5 |

PR IDs are planning identifiers, not GitHub PR numbers. Six is an initial independently reviewable count, not an unchangeable quota. Each change must be extracted onto a clean branch from accepted main; do not merge the WIP branch wholesale. Review scoped AGENTS, existing SDK/CLI/Control callers, contract stability, branch CI and native evidence before extracting each PR. Each PR must include its own code, negative tests, and applicable qualification instead of deferring essential work.

Critical separations: local import does not apply OS effects; an imported author is not an authenticated principal; a portable digest is not approval; the existing AdoptionReport is not an executable Control plan. External export, backup and destructive restore require safe destinations and independently verified recovery, with restore owner quiescence. No generic apply-Setup executor or automatic shared-resource deletion. S26-5 must reuse current canonical Control planning and separately qualified provider effects.

Start implementation with S26-1 against the same SQLite LocalLibrary. Prove real history/closure/owner query identity, stale DB epochs, invalid and colliding revisions, bounded graph behavior, crash/reopen, and read-only no-side-effect. Keep all still-disabled candidates inactive until separately authorized, implemented, and qualified.

Verify the proposed decomposition locally with: python3 -m unittest discover -s tests/tooling -p test_v010_s26_pr_decomposition.py. Passing this static test is not SQLite, interactive VM, or physical Q11 proof. Do not advance the main roadmap ledger or enable release readiness without merged implementation and exact-source A/B/C evidence.
