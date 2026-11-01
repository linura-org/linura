# S25 Phase 1 — source audit, typed personalization architecture and implementation requirements

- **Status:** Contract-first architecture only, without new runtime functionality, registered effect, native CI or release qualification.
- **Slice:** v0.10 S25 — themes, wallpaper, fonts, icons and personalization; target `arch-hyprland-v1`; dependency S16.
- **Audited baseline:** `e867f5348f1a0b6833d0b622187e1213cac0039e` and [existing S25 WIP reference](v010-s25-personalization.md).
- **Companions:** [proposed ADR 0053](../adr/0053-s25-personalization-authority-and-safe-rendering.md), [inactive design](../../contracts/v010-s25-design.toml), [native qualification](../qualification/v0.10.0-s25.md), [security qualification](../qualification/v0.10.0-s25-security.md).
- Accepted ADRs, original S10/S16 implementation and operation registry are authoritative, not this proposed capability list.

## 1. Actual source and consumer audit

| ID | Existing source | Confirmed behavior / S25 gap |
| --- | --- | --- |
| A25-01 | `design/tokens.json` | v1 semantic token vocabulary (background/surface/foreground/accent/muted/danger/warning/success/focus), spacing, radii, control/icon dimensions, typography, motion; no persisted user scheme |
| A25-02 | `apps/linura-shell/ui/LinuraTheme.qml` | Real token metrics and semantic colors from Qt `SystemPalette`, fixed danger/warning/success; per-instance theme rather than versioned saved preference projection |
| A25-03 | `apps/linura-shell/ui/CMakeLists.txt` | Compiles/installs `org.linura.UI 1.0` module and shared components; no S25 runtime owner/preferences backend |
| A25-04 | `apps/linura-shell/ui/README.md` / `docs/design-system.md` | Presentation-only reusable controls; shell components do not receive policy/executor handles |
| A25-05 | `apps/linura-shell/plugins/control-center/ControlCenterPanel.qml` | Imports shared `LinuraTheme`; uses spacing/accent/status/size; no inspected typed personalization Apply/Cancel persistence |
| A25-06 | `apps/linura-shell/plugins/quick-settings/`, panel, command palette and OSD | Existing compiled UI SDK and local theme per surface; require shared revisions and exact applied-state reporting |
| A25-07 | `apps/linura-shell/security-owner/LockPresentation.qml` | Uses visual primitives, while native security owner owns auth/protected input. Theme changes must not take secure authority |
| A25-08 | `apps/linura-shell/security-owner/fonts.conf` | Explicit restricted fontconfig with fixed safe DejaVu Sans fallback and no user include; preserve independently of personalization |
| A25-09 | `docs/visual-testing.md` / `tools/check_v010_workstation_qualification.py` | Existing digest-bound Q10 reviewed non-null baseline/capture/diff/interaction gates; screenshot alone insufficient |
| A25-10 | `contracts/operation-semantics.toml` / ADR 0032 | Trusted operation class/risk Control; no inspected S25 wallpaper/compositor effect registered |
| A25-11 | `contracts/v010-workstation-slices.toml` / ADR 0033 | S25 remains planned, depends on S16, required for v0.10; S27 depends on S25 among peers |
| A25-12 | `tools/verify_v010_slice_pr_evidence.py` | S25 owned implementation paths include personalization plugin, shell theme and design files; not acceptance by docs alone |

**Audit boundary:** No native test, hardware renderer, saved local preferences or wallpaper compositor effects were executed. Missing features are not asserted to be vulnerabilities in existing running code.

## 2. Feature inventory

| Feature | Current state | Required supported behavior |
| --- | --- | --- |
| S25-01 canonical tokens and component SDK | Implemented S10/S16 | Preserve `design/tokens.json` and compiled UI 1.0 consumers |
| S25-02 user theme mode/palette/accent | No persisted S25 owner | Typed safe semantic roles, contrast, allowed modes and effective revision |
| S25-03 per-user preference schema | Not established | Strict versioned, owner-authenticated persisted keys and canonical revision CAS |
| S25-04 live preview, Apply, Cancel | Not established | Ephemeral window/session generation, no implicit commit or external effect |
| S25-05 transactional restore/reset | Not established | Previous good revision, atomic migration/recovery/overwrite prevention |
| S25-06 density, focus and interaction | Fixed metrics foundation | Bounded control/spacing scales preserving hit targets/focus/accessibility |
| S25-07 reduced motion | Static duration tokens | User preference overrides motion in all supported components |
| S25-08 font families and sizes | Fixed typography metrics | Installed allowed fonts, multilingual/RTL glyph fallback and bounded scaling |
| S25-09 icon family | Shared icon size tokens | Installed allowlisted icon packs, safe fallback and sanitized image format |
| S25-10 wallpaper chooser and asset store | Not established | Safe regular file and hash provenance, bounded decoder/crop/fit/output choices |
| S25-11 compositor wallpaper apply/clear | Not established | Separately reviewed Control effect and independent actual renderer state |
| S25-12 desktop color-scheme bridge | `SystemPalette` currently read | Explicit native provider if qualified, never assume local revision propagates |
| S25-13 shell/control-center/quick-settings/OSD | UI SDK exists | Common preference revision, per-surface effective state, no optimistic claims |
| S25-14 First Boot/installer integration | First Boot design separate | Same versioned safe tokens where supported; no S17/First Boot privilege confusion |
| S25-15 Q10/Q11 visual, a11y, physical | Baseline infrastructure exists | Executed screenshots/diffs, interaction report, real GPU/HiDPI/lock/hotplug |

Out of scope absent separately reviewed architecture: remote theme download, dynamic QML/JS/CSS/shader themes, arbitrary compositor config, external package installation, third-party theme plugin authority, cross-user sync or replacing the fixed S17 lock-screen font security environment.

## 3. Data and authority design

**PreferenceRevision:** exact authenticated principal/UID, canonical schema version and key set, prior revision/hash, accepted values, durable next revision and owner-only persistent storage. A conflicting/stale edit fails, never silently overwrites. No rollback without a new explicit owner revision commit. Unknown/newer format must report incompatible and preserve bytes for reviewed migration.

**PreviewEpoch:** user/seat/window, source revision, proposed tokens, current generation and expiry; one approved live preview per affected scope; cancellation, lock, seat switch and crash invalidate. Preview does not write preference files, update provider state, bypass session protections or become an accepted plan.

**EffectiveThemeRevision:** per-renderer source revision, compiled `org.linura.UI` module version, token mapping, current system palette/fallback and actual state. Distinguish stored, pending, applied, degraded/unsupported and rejected. A QML component binding a token is not proof the compositor or independent surface rendered the target color.

**AssetDigest:** safe-open regular user-owned image/font/icon identity, source root/descriptor, content digest, MIME/decoder/size/dimensions, installed allowed font/icon references and stable fallback; no remote-fetch/script metadata. For wallpaper per-output state include actual S21 topology, transform, scale, selected output and current compositor generation.

**Native effect:** wallpaper/desktop appearance is an external user-session provider write and must have separate trusted operation/class, authenticated principal, exact resource, canonical plan/policy, precondition/dispatch, independently observed postcondition, audit/recovery. No `hyprctl` shell fallback and no user configuration strings as method names. A settings CAS commit cannot be used as executor permission.

## 4. Operation map

The inert design declares **ten disabled candidates**. Seven `LinuraOwnedState` preference operations cover appearance, typography, density, motion, icon family, wallpaper selection and explicit profile reset; three conservative `ManagedExternalEffect` candidates cover per-output wallpaper apply/clear and native desktop color-scheme set. These managed proposals may be considered for a narrower path only after independently reviewed unprivileged, at-most-`UserState`, bounded nondurable/verified semantics. Existing per-window preview is `ExperienceEphemeral` and needs no new operation. Authoritative renderer/saved-state queries are separate observation/read functions.

A wallpaper apply that changes only one of multiple targets can leave a valid saved preference but **incomplete native application**. Renderer and Control receipts must show such partial/failure state, not force old saved settings or replay an old effect after restart.

## 5. Security and adversarial matrix

| Case | Fault/attack | Expected result |
| --- | --- | --- |
| T25-01 | Theme supplies raw QML/JavaScript/CSS/shader or policy field | Strict schema rejects executable text/authority |
| T25-02 | Newer/unknown schema or duplicate invalid token | Incompatible, preserve old state |
| T25-03 | Stale revision edited concurrently in Control Center/CLI | CAS conflict, never last-writer silent overwrite |
| T25-04 | Full disk/crash during settings commit | Previous valid revision or explicit recovery |
| T25-05 | Foreign UID/session writes user theme | Authenticated owner denied |
| T25-06 | Preview window gone, session locked, or UI restarts | Cancel/expire, no effect or leaked preview |
| T25-07 | Accent makes failed or denied status resemble success | Protected semantic contrast/role rejection |
| T25-08 | Reduced-motion setting ignored by animation | Interaction/a11y gate failure |
| T25-09 | Unsupported font/scale hides label, RTL glyphs or focus | Bounded fallback and accessible layout |
| T25-10 | Icon theme includes script/foreignObject/external URI | Reject and fallback |
| T25-11 | Wallpaper symlink/hardlink/path race | Safe fd/digest denies substitution |
| T25-12 | Huge image/decompression bomb/animated resource | Decode budget fail closed |
| T25-13 | Remote wallpaper URL or malicious SVG external reference | No network fetch/script |
| T25-14 | Provider changes output connector/geometry during apply | S21 epoch invalid, no retarget |
| T25-15 | Native wallpaper method returns before frame displayed | Not verified without actual native state |
| T25-16 | Compositor dies or receipt lost after wallpaper write | Indeterminate, re-observe; no replay |
| T25-17 | User theme alters S17 lock input or packaged fonts.conf | Security-owner isolation preserved |
| T25-18 | First Boot owner has no logged-in user yet | Separate safe built-in defaults, no foreign preferences |
| T25-19 | Reboot/Qt system palette changes but preference revision same | Effective state distinct, explicit re-evaluation |
| T25-20 | Contradictory Shell/Quick Settings/OSD applied revisions | Visible divergence, no fabricated shared state |
| T25-21 | Model supplies unbounded custom color/shader or QML provider method | Typed data only; no generic executor |
| T25-22 | HiDPI/multi-output resize clips dialogs/controls | Q10/Q11 visual/a11y failure |
| T25-23 | Snapshot screenshot is claimed as full interaction proof | Distinct reviewed interaction evidence required |
| T25-24 | Virtual image used to claim physical display/lock evidence | Q11 support remains unqualified |
| T25-25 | No-change bypasses policy for native appearance effect | Trusted policy/current resource still required |
| T25-26 | Saved preference success falsely equals renderer success | Separate stored and effective receipt required |

## 6. Requirements and proof trace

| Requirement | Evidence |
| --- | --- |
| R25-BASE-01 | Existing S10/S16 UI SDK tokens/imports unchanged; T25-07/19/20 |
| R25-STATE-01 | Owner-authenticated versioned atomic CAS/migration/restart; T25-02–05 |
| R25-PREVIEW-01 | Session/window preview generation and deterministic cancel; T25-06/18 |
| R25-THEME-01 | Contrast/role/focus/reduced-motion and accessible density; T25-07–09 |
| R25-ASSET-01 | Safe font/icon/image metadata/source/decoder constraints; T25-09–13 |
| R25-NATIVE-01 | Exact compositor/S21 output and independent wallpaper postcondition; T25-14–16/25 |
| R25-SEC-01 | No executable themes/lock owner changes/privileged bypass; T25-01/17/21 |
| R25-UX-01 | GUI/CLI/SDK/QML effective revision, offline/no-model and a11y; T25-19–23/26 |
| R25-QUAL-01 | Reviewed Q10 visual/diff/interaction and distinct physical Q11; T25-22–24 |

## 7. Phase 2 sequencing and ownership

1. Read scoped agents/visual-security instructions, S10 compiled SDK, S16 consumers and S17 secure owner; reproduce current CI/native baseline.
2. Formalize typed v1 preference data, semantic roles, strict migrations, provenance and owner-authenticated local CAS, still with **external effects disabled**.
3. Build bounded preview/commit/cancel/rollback and independent persisted-state readback, with crash/revision/foreign-session tests.
4. Add safe installed font/icon and user image asset intake with content-hash safe descriptors and adversarial decoder budgets.
5. Build a shared revisioned `LinuraTheme` presentation projection and first-party UI/CLI/SDK, preserving protected status roles and S17 fixed secure-input path.
6. Review actual native wallpaper/desktop provider and separately qualify narrow effect/executor, S21 output identity, independent verification and no-replay recovery.
7. Execute native Arch/Hyprland Q10 (real captures, reviewed baseline/failure diffs, accessibility) and physical Q11 (GPU/scale/hotplug/lock), negative security test matrix and inherited gates.
8. Extract implementation into an **adaptive dependency-ordered number of PRs** after trust/qualification boundaries are understood. WIP ADR numbering and branch-relative contracts are reconciled with then-current main; no predetermined PR count.

## 8. Nonclaims and checks

Run `python3 -m unittest discover -s tests/tooling -p test_v010_s25_design.py`, `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py`, `python3 tools/check_roadmap.py`, and applicable `cargo xtask check` in a prepared repository, then native compiled UI Q10/Q11/security gates. These are **not** claimed executed merely because design documents and contract tests exist. S25 remains planned and `interactive_workstation.evidence_ready` stays unpromoted.
