# S26 Phase 1 — Local Library source audit and workstation implementation requirements

- **Status:** Proposed contract-first architecture, not an implemented v0.10 UI, new authority operation or qualification result.
- **Slice:** v0.10 S26 — Library, Setups and MachineProfiles workstation workflows, `arch-hyprland-v1`; predecessor S16; downstream S27.
- **Audited baseline:** `e867f5348f1a0b6833d0b622187e1213cac0039e` plus [existing S26 WIP engineering reference](v010-s26-library.md).
- **Companions:** [ADR 0054](../adr/0054-s26-local-library-workstation-authority.md), [inactive design](../../contracts/v010-s26-design.toml), [native qualification](../qualification/v0.10.0-s26.md), [security qualification](../qualification/v0.10.0-s26-security.md).
- **Authority:** Released v0.7/v0.8/v0.9 contracts and accepted ADRs override proposed WIP. No Main/ledger mutation or release promotion.

## 1. Source and released capability audit

| ID | Source | Confirmed behavior and S26 gap |
| --- | --- | --- |
| A26-01 | `crates/linura-library/src/lib.rs` | Actual `LocalLibrary`, `StoredSetup`, `StoredProfile`, revision refs, `AdoptionReport` and exported portable functions; not a UI permission |
| A26-02 | `crates/linura-library/src/store.rs` | Real SQLite CRUD/list/history for intents, Setups and Profiles, local transition idempotency, shared removal impact, export and backup; no integrated S26 native QML workstation workflow |
| A26-03 | `crates/linura-library/src/schema.rs` | Released `LIBRARY_SCHEMA_VERSION: u32 = 1`, strict tables/foreign keys and bounded schema metadata verification; must not change casually |
| A26-04 | `crates/linura-library/src/portable.rs` | Released deterministic `PORTABLE_FORMAT_VERSION: u16 = 1`, setup/profile complete bundle encode/decode, `MAX_PORTABLE_BYTES` and record bounds, digest; no origin signature/authority |
| A26-05 | `crates/linura-library/src/adoption.rs` | Existing `preflight_*_adoption`, `import_*_bytes`, `adopt_*_bundle` with dry-run and transaction/idempotent local storage; **not** a native OS executor |
| A26-06 | `crates/linura-library/src/lib.rs` | `AdoptionContext` secret *references*, machine class, unsupported capabilities and `AdoptionReport` collisions/missing refs/`requires_plan`/`is_blocked`; report is not Control plan |
| A26-07 | `crates/linura-library/tests/v07_qualification.rs` | Released native Rust tests for lifecycle CAS, immutable revision, cycles, portable roundtrip/negative cases, backup restore/corruption/crash and causal owner |
| A26-08 | `docs/qualification/v0.7.0.md` | Explicit released v0.7 native acceptance and proof; S26 extends not replaces it |
| A26-09 | `docs/reusable-setups.md` | Stable concept hierarchy Intent→Setup→MachineProfile vs Snapshot and requirement of fresh target plan instead of replay |
| A26-10 | `crates/linura-sdk/src/lib.rs` | First-party SDK exports existing Library/Setup/Profile types, including app-level integration opportunities |
| A26-11 | `contracts/operation-semantics.toml` / ADR 0032 | Trusted Control's operation-class/plan/risk and domain-effect registration; no reviewed generic “apply Setup” executor |
| A26-12 | `contracts/v010-workstation-slices.toml` and `docs/qualification/v0.10.0.md` | S26 planned, S16 predecessor, S27 consumer; required local Library UI and Q9–Q14 evidence, not currently qualified by v0.7 alone |
| A26-13 | `tools/verify_v010_slice_pr_evidence.py` | S26 owns UI areas `plugins/library/`, `setups/`, `machine-profiles/` and reuses `crates/linura-library/`; ownership is not evidence |
| A26-14 | `crates/linura-control/src/proposal_acceptance_secure.rs` / ADR 0028 | Model/agent proposal acceptance is a separate authenticated Control boundary, not restored by importing bundles |

This is inspected source, not a claim of a production vulnerability, executed test suite or finished new feature.

## 2. Full product and capability inventory

| Feature | Audited foundation | Required S26 result |
| --- | --- | --- |
| S26-01 Library catalog and filters | Existing backend list/history | Bounded current exact ID+revision+digest, status/owner, UI freshness/errors |
| S26-02 nested Setup detail/history | Immutable stored versions | Full exact included Setup/Intent closure, no silent latest substitution |
| S26-03 MachineProfile detail/history | Stored profile revisions | Machine class/requirements, exact Setup and standalone Intent refs |
| S26-04 Setup create/edit/save | `save_setup` exists | Authenticated draft, explicit CAS/new immutable version, revision conflict and readback |
| S26-05 Profile create/edit/save | `save_profile` exists | Strict machine class/graph edit, append-only version and readback |
| S26-06 structural compare/diff | Revision histories exist | Deterministic semantic diff, provenance and closure changes, no title-as-identity |
| S26-07 causal ownership/removal impact | `removal_impact` exists | Shared and indeterminate never classified as safe cleanup |
| S26-08 portable export | Released deterministic codec | Safe user destination, full closure, content digest and no secret values |
| S26-09 portable import and review | Import/adopt transaction exists | Stage/validate, resolve collisions, missing secret refs, class/format compatibility |
| S26-10 local adoption and dry-run | Existing `AdoptionContext` | Separate local write from machine apply, idempotent import and no approval import |
| S26-11 fresh machine impact preview | Existing canonical Control planner | Target machine/boot/PlatformProfile/observations/capability/current policy, per-effect plan |
| S26-12 machine configuration application | Domain control exists by support | No generic executor, independently qualified per-provider effects and state |
| S26-13 intent lifecycle and safe cleanup | Durable lifecycle/owner evidence | Separate local transition and verified OS cleanup, shared-owner denial |
| S26-14 backup/migration/restore | Released backup validation | Safe selected destination, schema/integrity, quiescent active restore/recovery |
| S26-15 UI/CLI/SDK and no-model | SDK/backend foundation | One typed Control authority across Shell, Library/Setup/Profile panels and CLI |
| S26-16 exact-source A/B/C qualification | v0.7 native tests only | Full Q10 experience, crash/restore, true Q11 device effects and permissions |

Optional hosted sync, fleet, Git catalogs, third-party marketplace, arbitrary extension scripts and inferred portable trust are not silently part of S26.

## 3. Identity and lifecycle architecture

**LibraryDatabaseEpoch:** actual selected local DB identity, schema, boot/service/owner where relevant, integrity and current projection. A cached UI model, plain path or restored database with same filename is not equivalent to its previous epoch; old CAS/permissions must revalidate after restore.

**SetupRevisionClosure:** stable `SetupId`, immutable `u32` revision, canonical digest, exact included Setup revision refs and `IntentId` `u64` refs, visited graph, depth/size, valid supporting definitions and ownership. A later Setup edit cannot re-point historical refs. Dependency cycles, missing definitions or same logical intent at incompatible revisions fail closed.

**MachineProfileRevisionClosure:** `ProfileId`, immutable `u32` revision, exact Setup and direct Intent refs, machine class, constraints, hardware hints and full closure digest. Hints don't override PlatformProfile support or target native identity. On target transfer validate all required capabilities, currently available referenced secrets and machine compatibility.

**PreviewContext:** signed only by current Control context/revision where actual authority is required, current observed target provider states and ownership, canonical plan and trusted registered effect/risk. Existing `AdoptionReport` supplies *local import compatibility*, not this native plan. Store an explicit \`requires_plan\` and blockers without turning preflight text into approvals.

**Saved/Applied/Verified:** local import transaction, selected desired intent activation, native effect dispatch and independently observed machine convergence are separate timelines. Optimistic UI reports or SQLite records cannot assert a system change; each attempted real OS resource gets its own lifecycle and recovery evidence.

## 4. Inactive operation taxonomy and trust

Eight **disabled candidates** are proposed: four \`LinuraOwnedState\` wrappers around existing Setup/Profile save/import; two \`ManagedExternalEffect\` portable export to selected external user files; and two \`ManagedExternalEffect\` backup creation and destructive restore. Export/backup class is conservative and subject to future native review; these descriptors do not force a privileged executor and they do not deactivate the released backend methods.

Browse, revision compare, history, import dry-run and local ownership preview are \`AuthoritativeQuery\` or pure UI projection; navigation is \`ExperienceEphemeral\`. Actual machine adoption requires **no generic S26 external operation**. It composes existing trusted per-domain operations and policy, matching the signed current target source and canonical \`ReconciliationPlan\`. Never use a portable digest as executable grant, copied request ID to replay OS action, or imported actor provenance as current authenticated principal.

For local operations preserve operation ID semantics, immutable save CAS and atomic SQLite state; return independent fresh revision readback. For external export/backup enforce selected safe destination descriptor and independently verified result. Backup restore is destructive, must validate source/newer schema, quiesce database owners and preserve recoverability; no “rollback means undo OS effects” assumption. For machine effects the true registered domain lifecycle is mandatory, including timeout/restart/indeterminate with no blind replay.

## 5. Security/adversarial matrix

| ID | Failure or attack | Required outcome |
| --- | --- | --- |
| L26-01 | Impersonated actor/Principal through imported bundle | Provenance only, no authenticated authority |
| L26-02 | Same Setup name, different exact revision/digest | No wrong-target mutation |
| L26-03 | Same intent referenced at contradictory revisions in nested Setups | Reject, not silently select latest |
| L26-04 | Setup inclusion cycle, deep recursion or oversized records | Bounded reject, no partial import |
| L26-05 | Unknown newer portable or SQLite schema | Unsupported without destructive migration |
| L26-06 | Valid digest with untrusted author and untrusted claimed signature | Integrity not trust/authority |
| L26-07 | Secret values embedded in bundle or missing local refs | Reject secret leakage; report absent refs |
| L26-08 | Stale CAS between GUI and CLI editor commits | Conflict, preserve immutable old revision |
| L26-09 | Reused operation ID with different payload | Idempotency conflict, no substituted write |
| L26-10 | Crash during SQLite transaction/import of nested closure | All-or-nothing with valid reopen |
| L26-11 | SQLite corrupt/WAL full/unsupported schema metadata | Fail closed, prior valid store recoverable |
| L26-12 | Restore older valid backup while daemon writing | Quiesce/deny live swap, no old approval elevation |
| L26-13 | Bundle import dry-run mutates active state | Negative native test fails |
| L26-14 | Local import “adoption” launches systemd/package/native effect | Deny; local-only |
| L26-15 | Machine-class mismatch and unsupported provider | Block fresh target plan |
| L26-16 | Profile references secret ref not locally available | Explicit missing ref, no credential fabrication |
| L26-17 | Displayed target observation stale despite same revision | Reacquire current authoritative provider state |
| L26-18 | Imported previous policy or approval reference | Not current approval; no effect |
| L26-19 | Model/client chooses weaker operation class or risk | Trusted registry and current plan deny |
| L26-20 | Shared resource with two owning intents; one retires | Retained shared, no cleanup |
| L26-21 | Causal owner projection incomplete/contradictory | Indeterminate, no deletion |
| L26-22 | Profile execution partly applied with reply lost | Per-domain indeterminate, observe-only |
| L26-23 | Export path symlink/hardlink/wrong owner/partial write | Safe descriptor/atomic publication |
| L26-24 | Restore source swapped after review or corrupted | Validated digest/schema/owner, no target loss |
| L26-25 | Library card title contains script/markup/URL injection | Escaped bounded UI data only |
| L26-26 | No-model workstation path blocked by cloud/catalog | Offline current local Library works |
| L26-27 | File/digest/secret/audit payload leaks through logs or visual evidence | Sanitized and secret-free |
| L26-28 | Library import/VM test used as real physical machine effect evidence | Q11 not promoted |
| L26-29 | GUI optimistic saved/applied/verified conflation | Distinct independently verified states |
| L26-30 | Restored DB replays previous request/acceptance on restart | No new effect or authority |

## 6. Requirement-to-proof traceability

| Requirement | Mandatory evidence |
| --- | --- |
| R26-BASE-01 | Preserve released v0.7/v0.8/v0.9 Library APIs, schema/portable and tests; L26-04/05/09–12 |
| R26-OBS-01 | Exact database + revision + complete nested graph + provenance; L26-02–04/17 |
| R26-STATE-01 | Authenticated local CAS, atomic import, idempotency/readback; L26-08–14 |
| R26-PORT-01 | Secret-free versioned digest/portable export and safe destinations; L26-05–07/23/24 |
| R26-ADOPT-01 | Local preflight distinct from current machine planning/verification; L26-13–19/29 |
| R26-OWN-01 | Complete shared causal owner impact and safe cleanup; L26-20/21 |
| R26-REC-01 | Backup integrity, quiescent restore, transaction and effect no replay; L26-10–12/22/30 |
| R26-SEC-01 | Imported data/actor cannot delegate or restore permission; L26-01/06/18/19/25/27 |
| R26-UX-01 | Library/Setups/MachineProfiles panel, CLI/SDK, offline no-model and accessible Q10; L26-25–27/29 |
| R26-QUAL-01 | Separate exact-source SQLite/VM/physical Q11 and provider effect qualification; L26-28/30 |

## 7. Phase 2 implementation sequence and boundaries

1. Reproduce v0.7 Library tests and existing CLI/SDK/Control/First Boot consumers; inspect scoped AGENTS, v0.8 acceptance, v0.9 migrations and schema compatibility. Establish source/toolchain before modifying runtime.
2. Add bounded read-only typed façade over the **same** `LocalLibrary` instance (with exact history, refs/digests/causal ownership) and current authenticated principal; do not build a new catalog.
3. Draft/edit/save immutable Setup/Profile revisions and graph-aware version comparison using existing CAS and adoption APIs; adversarial collision/cycle/transaction/restart tests.
4. Stage portable import and export: native current format and secret-ref rules, explicit collision/preflight/target review; safe user artifact publication and independent digest verification.
5. Design controlled backup/restore activation with existing schema and migration constraints, actual owner quiescence, original DB safeguard and negative interruption tests.
6. Project **fresh** actual machine impact via canonical Control plan, supported capability/PlatformProfile and ownership; never give the UI its own executor or policy. Qualify individual native domains separately.
7. Build first-party Library/Setups/MachineProfiles/CLI/SDK accessible no-model experiences, clearly separating locally stored, intended, approved, native attempted, verified and indeterminate.
8. Run exact-source v0.7+v0.8+v0.9 regressions, SQLite crash and A/B VM UI tests, S17/S21 interactions, true Q11 physical machine effects, Q10 visual/a11y, policy/security and CI gates.
9. Reconcile provisional ADR/registry against then-current accepted main; extract **as many independently reviewable PRs as justified** by actual store/plan/export/backup/UI/qualification seams, not an arbitrary count. No unqualified activation or ledger promotion.

## 8. Validation and nonclaims

Use `python3 -m unittest discover -s tests/tooling -p test_v010_s26_design.py`, `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py`, `python3 tools/check_roadmap.py`, `cargo xtask check` and released v0.7/v0.8/v0.9 suites in a prepared pinned repo. Native/physical qualification must be run separately under actual accepted source. This design work does **not** assert those checks passed, complete S26 or enable workstation adoption.
