# S22 Phase 1 — source audit, architecture and requirements for protected desktop utilities

- **Status:** Proposed engineering architecture and acceptance. No native capture/history implementation, approved effect, support promotion, or physical acceptance.
- **Slice:** v0.10 S22, desktop utilities, screenshot/recording and clipboard history; `arch-hyprland-v1`; S16 dependency.
- **Source baseline audited:** `e867f5348f1a0b6833d0b622187e1213cac0039e` and S22's original engineering reference.
- **Architecture:** [proposed ADR 0051](../adr/0051-s22-protected-desktop-utilities.md), [inactive design contract](../../contracts/v010-s22-design.toml), [native qualification](../qualification/v0.10.0-s22.md), [security acceptance](../qualification/v0.10.0-s22-security.md), [WIP reference](v010-s22-utilities.md).
- **Boundary:** accepted ADRs and actual release gates take precedence; a WIP doc or proposed test alone cannot enable an operation.

## 1. Source-to-capability audit

| ID | Audited source | Concrete behavior and gap |
| --- | --- | --- |
| A22-01 | `workflows/screenshot-share.toml` | Declares steps `capture.region`, `annotation.edit`, `storage.upload`, `clipboard.write` and `notification.send`, **not** executors or consent grants. Do not interpret example as working screenshot/sharing. |
| A22-02 | `apps/linura-shell/shell.qml` | First-party Quickshell/Qt presentation uses `org.linura.ShellBridge 1.0` and Quick Settings/Control Center shell; no inspected native screenshot, recording or history plugin composition. |
| A22-03 | `apps/linura-shell/AGENTS.md` / `agents/skills/shell-ui.md` | Shell changes require compiled bridge/UI SDK and actual graphical/visual qualification; QML is presentation-only. |
| A22-04 | `docs/qualification/v0.10.0.md`, Q9–Q14 | v0.10 promises bounded desktop utilities, first-party UX, protected interaction and independent exact-source/physical acceptance; docs-only work is insufficient. |
| A22-05 | ADR 0042 / `docs/security-model.md` | S17 owns authenticated native secure lock, protected input and compositor/session identity. A screenshot helper cannot determine or release security-owner trust. |
| A22-06 | ADR 0045, S21 display authority | Display topology/output/first-frame protection is owned by S21; capture geometry and secure frame exclusion must revalidate those epochs. |
| A22-07 | `contracts/operation-semantics.toml` / ADR 0032 | Distinct query, ephemeral, Linura-owned local, transient and managed-effect classes and trusted Control registration; no inspected S22 effect registered. |
| A22-08 | `tools/verify_v010_slice_pr_evidence.py` | S22 implementation ownership names `apps/linura-shell/plugins/screenshot/`, `recording/` and `clipboard/`. Ownership is not qualification evidence. |
| A22-09 | `contracts/v010-workstation-slices.toml` | S22 planned, S16 predecessor, release-required; unchanged by proposed architecture. |
| A22-10 | `docs/qualification/v0.10.0.md` physical/Q10 | Real captured VM video aids diagnosis but is not frame-exclusion, protected-input, native correctness, or maintained physical Q11 proof. |

No claim is made that absent S22 production code has a reachable vulnerability; the missing protection mechanisms are **requirements for future effect enablement**. The source audit did not run native tools, unit tests or hardware.

## 2. Complete target inventory

| Capability | Audited baseline | Implementation completion requirement |
| --- | --- | --- |
| S22-01 session/portal/compositor and protected coverage | Infrastructure exists across S17/S21 | Exact authenticated session, native portal identity, source/lock/output generation; deny unknown |
| S22-02 screen/output screenshot | No qualified S22 code | Purpose-selected current output, protected exclusion, bounded buffer and private lifecycle |
| S22-03 window and region screenshot | No qualified S22 code | Actual target selection; transforms/scale; no stale focus, window or output substitution |
| S22-04 screenshot review and annotation | Declarative example only | Private bounded local editing, metadata sanitization and source/classification continuity |
| S22-05 screenshot save/copy/export | Declarative example only | Separate consented destination, safe fd/atomic publish and verified external clipboard handoff |
| S22-06 screen recording start/stop | No qualified S22 code | Exact owned live portal/PipeWire session, time/size budget, native stop supervision and honest indicator |
| S22-07 recording audio inclusion | Not established | Separate explicit S20 microphone/loopback authorization; disabled by default |
| S22-08 safe recording export | Not established | Owner/digest-bound staging, atomic destination, never automatic upload |
| S22-09 clipboard read/write and MIME | Not established | Seat/owner/offer epochs, consent-gated sensitive read, bounded safe payloads and explicit write verification |
| S22-10 clipboard history opt-in | Not established | Default-off, user-owned policy, secure key lifecycle or volatile-only alternative |
| S22-11 history search/restore/delete | Not established | Private bounded local browse; separately authorized re-copy; verified revisioned deletion and honest erasure |
| S22-12 protected surfaces/secrets | Not established | Compositor-enforced secure exclusion, no OTP/password/lock content retention |
| S22-13 first-party UX parity | No S22 feature UI | Qt/QML bridge/UI + Control Center/Quick Settings/CLI/SDK, shortcuts, keyboard/screen-reader/no-model |
| S22-14 exact-source A/B and physical C | Not established | Native compositor/portal/clipboard, crashes/hotplug/lock/a11y and independent Q11 proof |

Automatic screenshot-cloud sharing, remote desktop control, arbitrary source capture through untrusted Wayland globals, cross-user clipboard access, global clipboard keylogging and direct model access to sensitive buffers are explicitly unsupported until independently scoped and qualified.

## 3. Trust and provenance model

### 3.1 CaptureOrigin and ProtectedSessionEpoch

Bind kernel boot, authenticated principal/UID, current logind session/seat, native compositor identity/generation, S17 secure coverage and S21 display-topology snapshot. Control owns meaning/freshness; portal and compositor supply mechanism facts, not review/policy. A stale window handle, screen name, cursor coordinate, portal request token or same-UID environment variable cannot authorize capture.

### 3.2 Frame/RecordingEpoch and source integrity

Bind requested target type, selected output/window, composited buffer dimensions, transform and rotation, source acquisition generation, native frame lifecycle and actual protection state. If a trusted provider cannot prove **no** protected frame was delivered to the consumer—including source change between request and capture completion—return unavailable. Portal choice is not automatic proof of secure exclusion. For recording bind live PipeWire/portal session source, stop ownership, encoder, active native stream and startup/stop generations. Stop must survive GUI restart/crash through an independently supervised native owner.

### 3.3 ClipboardSelectionEpoch and local retained history

Bind exact selected seat, current offer owner/source, MIME representations, freshness, sensitive classification and permissions. Consent to reading one offer cannot be repurposed to monitor all offers. Persistent local history requires explicit revisioned enable policy, controlled encryption/key custody and exclusion of protected/secret content **before** store ingestion; if not provable remain volatile/no history. Source passwords and OTP cannot be reliably inferred from text patterns alone; deny persistent capture on uncertain protected sources.

### 3.4 Destination and retention identity

Capture staging/content class, selected destination descriptor, creation/ownership, content digest and post-publication verification are separate from taking a screenshot. Do not trust any pathname string supplied by a model or source app. Clipboard-history clear is a local revisioned state change, not filesystem secure shredding. No default network upload; example `storage.upload` requires independent future contract.

## 4. Typed operation classification and control

- **`ExperienceEphemeral`:** region picker, editor navigation, locally canceled draft (no content transfer).
- **Sensitive `AuthoritativeQuery`:** only purpose-authorized clipboard read/history browse/screenshot preview; no cached secret bytes, broad agent access or implied retention.
- **`LinuraOwnedState`:** owner-authenticated history opt-in/configure and clear/delete using revisioned local store and explicit privacy consent.
- **Proposed `ManagedExternalEffect`:** capture, save, recording start/stop/export, clipboard write and copy history entry to system clipboard. These are conservative **disabled** candidates because privacy, external effects and/or recovery are not yet qualified. No root executor is implied.
- **Possible `TransientExternalEffect` later:** only after reviewed native test establishes no privilege, bounded failure, trusted risk ≤ `UserState`, exact same Control policy binding, fresh independent verification and audit. No shortcut for sensitive screen/audio/clipboard access based on user-session locality.

All proposed external effects require exact registered operation identity, resource and change keys, trusted risk/policy, canonical plan, authenticated subject and domain-appropriate verification. Managed uncertainty retains durable attempt and observe-only reconciliation. Portal authorization, shared wl_data_device, `ext-data-control` or application event dispatch is not Linura Control authority. Agent proposals cannot directly read raw content or execute clipboard/capture effects.

## 5. Native protocol selection and compatibility

The first audited target is Arch/Hyprland, not generic Linux. Use pinned native portal screenshot/ScreenCast backend and current source availability; record supported interface versions, request/result/stop/grant lifetimes, and actual target types. `org.freedesktop.portal.Screenshot` and `org.freedesktop.portal.ScreenCast` have distinct request flows; ScreenCast permission/restore token must not be automatically persisted as a reusable screenshot privilege. `ext-image-copy-capture-v1` provides frame/cursor/source objects, but its availability does not guarantee compositor protected-frame policy or a stable cross-compositor API. `ext-data-control-v1` explicitly permits privileged clipboard managers, so possession of its interface must not authorize global secret monitoring. Avoid legacy `wlr-data-control-unstable-v1` fallback unless independently approved and scoped; the protocol itself marks it deprecated.

Validate real pinned compositor behavior for S17 `ext-session-lock-v1` coverage **before** enabling capture/recording. If the only available native API can capture authentication/lock data or cannot prove exclusion, the corresponding S22 feature stays unsupported. Failure must be explicit even when the operating system has other screenshot utilities.

## 6. Threat/negative test catalogue

| Case | Adversarial condition | Required oracle |
| --- | --- | --- |
| U22-01 | Portal service missing, only activatable, unauthenticated request or denied grant | Fail closed, no hidden fallback |
| U22-02 | Capture while S17 lock/secure authentication active | No protected data reaches frame buffers |
| U22-03 | Lock turns on between region selection and frame delivery | Source-side exclusion and abort |
| U22-04 | Hyprland/socket/session owner changes during capture | Original epoch invalid, no retarget |
| U22-05 | Output hotplug, rotation, transform/scale drift midframe | No wrong screen/region frame |
| U22-06 | Overlapping confidential surfaces, cursor, popup, multi-output crop | Exact supported exclusion or unsupported |
| U22-07 | Portal response, URI or restore token replay/spoof | Token not reusable Control authorization |
| U22-08 | Capture agent/CLI bypasses consent using direct grim/slurp/wf-recorder | No alternate executor |
| U22-09 | Screenshot destination symlink/hardlink/traversal, unsafe permissions | Fail closed, no arbitrary write |
| U22-10 | Partial file write, crash after buffer but before publish | Private staging recover/delete, no false success |
| U22-11 | Recording starts but GUI dies or protected lock begins | Independently supervised native Stop |
| U22-12 | Recording stop reply lost, stream remains active | Indeterminate until native stop confirmed |
| U22-13 | Different client's recording/portal stream used by Stop | Exact session ownership denies |
| U22-14 | Screen recording implicitly captures mic/desktop loopback | Deny without separate S20 consent |
| U22-15 | Excessive dimensions, fps, storage usage, huge MIME selection | Bounded quotas, no partial silent truncation |
| U22-16 | Clipboard read from foreign seat/selection or password prompt | Deny, no replay/privilege |
| U22-17 | Clipboard offer changes while reading large MIME content | Reject mixed offer, origin and revision |
| U22-18 | HTML/file URI/MIME confusion used to fetch remote/private content | Strict allowlist, no arbitrary open/fetch |
| U22-19 | Clipboard history enabled by default or without encryption/key proof | Off/volatile only, never plaintext persistent |
| U22-20 | OTP/password-manager content enters history despite filters | Source policy denies; no naive regex-only guarantee |
| U22-21 | Logout, lock, revoke and concurrent history ingestion | Stop producers, atomic revision, cleared state |
| U22-22 | History clear falsely promises SSD/Btrfs secure shredding | Honest logical/cryptographic deletion semantics |
| U22-23 | Agent/model requests raw clipboard or automatic upload | Separate consent; no general access/exfiltration |
| U22-24 | Logging/audit/Q10 video leaks raw clipboard/screenshot | Strict byte separation and evidence redaction |
| U22-25 | Native request accepted but no frame/stop not complete | Not verified, fresh independent observation |
| U22-26 | Qt screen reader, keyboard focus, HiDPI and reduced motion breaks | Accessibility and presentation negative test |
| U22-27 | Synthetic/VM capture used to claim physical Q11 proof | Evidence rejection |
| U22-28 | No-change/canceled selection used to bypass current policy | Current policy and native state still required |

## 7. Requirement-to-evidence matrix

| Requirement | Implementation contract | Minimum positive/negative evidence |
| --- | --- | --- |
| R22-AUTH-01 | Separate query/local/external classes with trusted Control risk and consent | U22-01/07/08/23/28; exact registry and denial tests |
| R22-OBS-01 | Session/compositor/lock/output source binding and freshness | U22-02–07; real native epoch/hotplug and frame checks |
| R22-CAP-01 | Targeted screen/window/region capture with protected exclusion | U22-02–06/08/15; independently inspected frame lineage |
| R22-CAP-02 | Safe private capture staging, user destination and atomic publication | U22-09/10/24/25; independent file/digest checks |
| R22-REC-01 | Bounded consented screen recording, separate audio, native stop | U22-11–15/25; real stream/stop/restart oracles |
| R22-CLIP-01 | Seat-bound consented clipboard read/write and MIME safety | U22-16–18/23/25; live Wayland selection fixtures |
| R22-HIST-01 | Default-off protected history, opt-in, bounded retention and key custody | U22-19–22; local store/key/revocation adversarial |
| R22-SEC-01 | No protected pixels/clipboard secrets in model/audit/media evidence | U22-02/03/16/20/23/24; security and privacy inspection |
| R22-UX-01 | First-party GUI/CLI/SDK, keyboard/pointer/a11y and no-model parity | U22-01/25/26, exact-source Q10 native/visual |
| R22-QUAL-01 | Distinct exact-source A/B/C evidence and no false physical promotion | U22-27 and preserved Q9–Q14 evidence |

## 8. Ownership, dependencies and adaptive implementation

- S17 retains native lock/security owner and protected input. S22 capture may require a **new** tightly reviewed compositor policy/portal integration, but may never weaken or take over S17's authority.
- S21 retains output topology/first-frame integrity. Coordinate exact output and geometry generation; never copy untrusted connector labels into a capture permit.
- S20 owns mic/capture audio permissions; S22 recording audio cannot bypass S20.
- S25 owns shared visual tokens/component SDK; S22 UI remains an unprivileged consumer.
- S26 Library cannot silently ingest clipboard/screenshot contents; any adoption is separately authorized.

**Implementation order:** (1) source baseline and pinned portal/compositor capability matrix; (2) typed session/lock/output/capture/selection observation and fail-closed provider absence; (3) protected-frame and clipboard secret controls with adversarial native proof before activation; (4) inactive reviewed operation/consent schemas and local history design; (5) narrow one-shot capture/file descriptor publication; (6) supervised bounded recording/stop; (7) optionally protected history/clipboard flows; (8) one-model/one-Control first-party GUI/CLI/SDK, visual accessibility; (9) exact-source A/B/physical C qualification and internal security review; (10) **adaptive PR extraction** according to real trust, storage and qualification boundaries.

No fixed PR quota; no premature runtime activation, branch-to-main merge or S22 release ledger update. A draft stage may remain unsupported when its security enforcement cannot be proven; a more permissive fallback is not an acceptable completion strategy.

## 9. Validation and nonclaims

Run root/scoped `AGENTS.md`, repo's environment preflight, `python3 -m unittest tests.tooling.test_v010_s22_design`, `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py`, `python3 tools/check_roadmap.py` and `cargo xtask check` in a prepared checkout. Run native Arch/Hyprland portal/Wayland/clipboard, S17/S21 protected capture and complete visual/security gates only when real implementation exists. No such native tests or CI are executed merely by recording architecture documents.
