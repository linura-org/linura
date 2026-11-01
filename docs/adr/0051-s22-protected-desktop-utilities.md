# ADR 0051 — S22 protects capture, clipboard and user-session utility state

- Status: Proposed
- Scope: v0.10 S22 desktop utilities on `arch-hyprland-v1`, with declared S16 dependency
- Refines: ADR 0012, 0017, 0018, 0024, 0031, 0032, 0033 and S17's ADR 0042
- Boundaries: S21 display/hotplug, S20 audio capture, S25 presentation and S26 local Library do not transfer authority to S22
- Contract: [inactive S22 design](../../contracts/v010-s22-design.toml)
- Acceptance: [domain](../qualification/v0.10.0-s22.md), [adversarial security](../qualification/v0.10.0-s22-security.md)
- Number is provisional to this WIP branch; reconcile with the append-only global ADR ledger before extracting the independent PR.

## Context

The repository has a declarative `workflows/screenshot-share.toml` example (`capture.region`, `annotation.edit`, `storage.upload`, `clipboard.write`, `notification.send`). This workflow is **not** a screenshot executor, a portal permission, a qualified upload or a clipboard-history implementation. Existing Quickshell/Hyprland ShellBridge, first-party QML SDK, S17 protected-session owner and S21 output security are foundations, not permission to capture protected content.

S22 requires a useful offline/no-model workstation experience for screenshots of supported targets, bounded recording with an unmistakable real status/stop path, safe clipboard copy/paste, and opt-in private history where securely implementable. The feature must not become an unrestricted screenshot/recording API for an agent, root process or unrelated session.

## Decision: separate sensitive access from external and local effects

Navigation, region picker drafts, annotation UI and transient local selection are `ExperienceEphemeral`. Reading clipboard data or a compositor frame is a **purpose-bound sensitive read**; it is not equivalent to a normal cacheable status `AuthoritativeQuery`. Permission to inspect an image, selection or MIME offer does not imply permission to retain, upload, display in model context or paste. Binding to a user-session portal consent is necessary where required, but a portal receipt, cursor position, selection serial or screenshot URI is never a Linura Control policy decision.

Acquiring a screenshot frame, saving/exporting it, creating/stopping a screencast or changing the external clipboard are separately proposed **external effects** with conservative `ManagedExternalEffect` classification and reviewed risk floor. This conservatism is an inactive planning stance, **not** a requirement to invoke a privileged executor for every user action: later native proof may establish a narrowly bounded unprivileged `TransientExternalEffect` where risk is at most `UserState`, no durable/ambiguous recovery is needed, and Control can independently reobserve/audit it. Privilege, privacy-sensitive scope, durable file/recording effects and indeterminate sessions remain managed or unsupported. No client/provider/model may choose a cheaper class.

History enable/disable, policy/retention configuration and logical entry deletion are `LinuraOwnedState`, **not** external OS mutations. They need authenticated user ownership, typed revisioned local persistence and appropriate privacy approval, without an invented privileged executor. Browsing a local history list is a purpose-bound read of sensitive retained content. Re-copying an entry into the system clipboard is a new separately authorized external effect.

The [S22 design TOML](../../contracts/v010-s22-design.toml) is **inert**: no operation is registered or implemented, no history is enabled, no portal/session grant is established, and no release evidence is promoted.

## Exact session/compositor/source binding and protected-content exclusion

Bind the true boot, logind session UID/seat, actual compositor session/instance and authenticated user bus/portal request origin. For output capture also bind the complete output topology and selected output/window/region, transform, buffer extent, scale, geometry generation and actual frame lifecycle. A monitor connector label, Wayland global name, window title, portal request handle, stale picker selection, coordinate or screenshot URI is *not* a transferable grant.

Use a reviewed user-session portal backend (e.g., `org.freedesktop.portal.Screenshot` and `org.freedesktop.portal.ScreenCast`, as actually exposed on the pinned Arch/Hyprland target), or another explicitly permissioned compositor-native capture route whose security behavior is proved. **Do not silently fall back to unrestricted `grim`, `slurp`, `wf-recorder`, raw wlroots screenshot, arbitrary shell commands or privileged Wayland socket forwarding** when portal consent or protected capture fails. ScreenCast sessions and portal restore tokens have their own native lifetime/revocation semantics; avoid default persistent permission and do not treat a restore token as an enduring Linura capability. Portal consent does not waive the separate protected-surface rule.

The *compositor/capture-provider enforcement boundary* must prove that S17 locked/authentication/protected surfaces and other classified confidential surfaces cannot enter a frame before the buffer or pipe reaches Linura. A client-only “is session locked?” check, stale lock flag, window title blacklist, posthoc pixel masking or hiding QML is insufficient. Check source and security epochs before and after native frame acquisition and on protected transitions. If trusted exclusion cannot be demonstrated on the exact pinned compositor/portal/protocol combination, **disable the affected capture/recording mode**; never claim that an arbitrary Wayland screenshot source is intrinsically secure. S17's native secure-lock coverage and S21 output/first-frame, hotplug and topology transitions remain owning authorities. A capture helper cannot control a lock, bypass secure coverage or become its own security owner.

### Screenshot

Select one explicit supported target (screen/output, user-selected window, region). Render physical/logical coordinates, scaling, transforms, rotation and crop from source-bound compositor facts; never capture a different output/window on focus/hotplug drift. Cursor inclusion, composited overlay/pointer or confidential window overlap require separate explicit policy. A frame-ready signal means a buffer is available, not that saving/sharing succeeded. Preserve one-shot capture's data classification through staging, annotations, optional clipboard copy and save. Source content is confidential by default and never automatically fed into an agent or uploaded.

### Recording

Screen recording is a *live, externally granted session* with a distinct start operation, exact portal/compositor capture session and PipeWire stream identity, bounded clock/size/frames/audio inclusion, visible independent native “recording active” indication and reliable Stop. Stop must address **only** an exact S22-owned session, not other apps' recording. Denial, timeout, screen lock, compositor/portal death, source reconfiguration, encoder crash and GUI restart must stop or revoke actual native capture and quarantine uncertain outputs. A red dot or OSD without native active-capture evidence is not proof that recording began or stopped.

Audio inclusion is always separate opt-in with S20's supported source privacy/permission boundaries. No audio stream may be enabled merely because video permission was granted. Recording remaining active after the UI crashes is a critical safety failure. If no independently supervised stop/revocation exists, do not enable long-lived recording on this profile.

## Clipboard and sensitive history

Treat per-seat selection ownership, offers, MIME types and data serial/epoch as *transient*, with bounded reads, cancellation and native provenance; data-control protocols are privileged compositor mechanisms, not blanket permission for any same-UID process to read all secrets. If a secure, user-scoped clipboard observer is not available on the pinned compositor, ordinary copy/paste can be supported without enabling background history. Never scrape unrelated seats, protected lock/authentication input or the primary selection without separate consent.

History is **off by default**. Separate explicit owner opt-in (and revocation) from simply running the UI. Strict MIME/type/byte/item/time quotas, encrypted-at-rest retention only with an independently reviewed key lifecycle, protection from secret/OTP/password-manager selections, and ownership/seat isolation are required. Encryption cannot be claimed when keys are accessible to an untrusted UI process or absent after logout; if strong encrypted persistence and policy cannot be proved, offer only volatile/no history, not a supposedly protected plaintext database.

History-list browse and search must stay local and bounded, with private previews, no ambient model/prompts/log/audit payloads, and no automatic sync/Library admission. Redaction rules are **defense in depth**, not proof that every password or OTP is detectable. Inability to reliably exclude protected sources or confidentiality-sensitive formats blocks persistent history. Stored deletion promises only logical inaccessibility and reviewed cryptographic erasure where actually proved; ordinary unlink on SSD/COW snapshots is not assured secure shredding. Clear on lock/logout/revoke as defined by user policy, with race-safe producer cancellation and terminal state.

## File destinations, output transport and data minimization

Captured/recorded bytes and clipboard contents never enter canonical plan, policy, audit, logs, IPC diagnostics, media evidence capture or model context as plaintext. Plans/audit carry safe content class, bounded hash/digest and ownership metadata where necessary, without making the hash an authorization token. For files use approved user-scoped destination selection, safe file-descriptor-based handling, reject symlinks/hardlinks/path traversal/unsafe targets, enforce quotas, controlled temporary lifecycle and verified atomic publication. Do not turn a file URI into an unrestricted filesystem read/write or export privilege. Annotations cannot smuggle script or untrusted markup. Metadata previews/notifications must not include sensitive pixels/text.

The sample workflow's `storage.upload` and “share” are **unsupported by default**: uploading confidential content is a distinct consented network/exfiltration operation and requires an independent typed contract before any provider implements it. S22 must not create a generic uploader or assume the screenshot workflow is executable.

## Ownership, verification and recovery

Linura Control owns trusted classification, typed intent and policy/authentication, provider and target evidence, and external-effect authority; the native user-session capture/clipboard adapter owns only narrow mechanism. A portal grant is not the same as a Linura approval; neither can be transformed into a privileged executor grant. A compositor, portal, clipboard manager or file writer cannot certify its own terminal success. Independently verify what can be verified: current recording session/stream state, file descriptor/digest and publication/ownership, clipboard offer/selection ownership and history revision, all scoped to the original request. When sensitive bytes cannot be safely re-read, distinguish an **accepted handoff** from an independently verified target-consumed value; do not falsely claim that a target application pasted or used the clipboard.

For managed effects, enforce request → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile with durable no-replay handling of indeterminate writes/session creation. For Linura-owned history, use revisioned authenticated local state and explicit privacy policy. For all paths: no direct QML privileged command, no model-selected authorization, no replay after compositor/portal/native session replacement or restart.

Control Center, Quick Settings, tray/notifications, shortcuts and CLI/SDK must converge on the same typed supported operations and same user-session privacy/security owner. Manual no-model, keyboard/pointer/assistive access, reduced motion, HiDPI, lock-safe UI, accurate recording status and explicit unknown/unavailable/error state are required.

## Qualification and consequence

[Domain acceptance](../qualification/v0.10.0-s22.md) and [security acceptance](../qualification/v0.10.0-s22-security.md) refine Q9–Q14. Exact-source Arch/Hyprland/portal/Wayland native proof must include protected S17 lock/authentication and S21 multi-output transitions, Q10 visual/a11y and separate Q11 physical GPU/input/seat proof. Synthetic screenshots or recordings of a qualification VM never establish protected-frame exclusion or real hardware support. This ADR is proposed, no effects enabled, no history opted in and S22 remains planned. Extract future PRs adaptively by security/ownership/evidence boundaries, not fixed count.

### Native protocol references, not automatic support claims

- [XDG Screenshot portal interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Screenshot.html)
- [XDG ScreenCast portal interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)
- [Wayland ext-image-copy-capture-v1](https://wayland.app/protocols/ext-image-copy-capture-v1)
- [Wayland ext-data-control-v1](https://wayland.app/protocols/ext-data-control-v1)
- [Wayland ext-session-lock-v1](https://wayland.app/protocols/ext-session-lock-v1)
