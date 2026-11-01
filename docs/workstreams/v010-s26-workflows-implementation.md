# S26 WIP Library workstation workflows

All functionality in this branch is nonprivileged and unqualified. No runtime
operation, generic executor, machine effect, schema v1 change, or portable
format v1 change is introduced.

Implemented in the Library workflows module:
- Exact immutable root and complete closure digest through released portable codec
- Deterministic typed Setup/Profile revision comparison with static field labels
- Identity and expected-base-checked draft preparation, not an authenticated save
- In-memory portable export previews; no selected filesystem effect
- Decoded untrusted portable import/preflight review without SQLite mutation
- Read-only bounded regular-file backup validation and streaming digest
- Explicit fail-closed machine adoption readiness, never machine verified

The existing authenticated control, CAS, local import, safe external-file
publication and destructive restore authority remain separate concerns.
The SDK reexports these read-only models. None of these projections is a
fresh canonical Control reconciliation plan. A stored draft/import, digest,
SQLite commit or successful dry-run cannot claim OS convergence.

Still required: exact-source Rust formatting/Clippy/tests, adversarial
SQLite and filesystem races, selected-file managed paths, authenticated
client wiring, first-party accessible QML and CLI integration, VM visual
evidence and separate real physical Q11 when native effects are claimed.
