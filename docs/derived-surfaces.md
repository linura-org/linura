# Derived UI surfaces

Linura may derive UI from typed capabilities, but models and imported metadata must not directly install arbitrary privileged GUI code.

The preferred path is a constrained surface description over typed resources/actions, rendered by trusted UI components. Examples include resource tables, details, forms, status cards and safe action controls.

## Authority and maturity boundary

Derived UI is a presentation mechanism, never an authority mechanism. Effectful controls must resolve to registered typed Linura operations and authoritative state; a surface definition cannot carry shell text, approval evidence, policy overrides, executor permits, operation-class downgrades or private backend logic.

The current v0.9 release does not claim a generic generated-UI or plugin runtime. v0.10 activates a bounded first-party `linura-shell` candidate: one supervised Quickshell host containing shipped Qt Quick/QML surfaces such as the Control Center quick-settings panel and command palette. Those surfaces remain ordinary unprivileged clients over the versioned Linura protocol.

The command palette remains bounded experience chrome: its catalog contains explicit trusted presentation targets and consumes only plain descriptors projected by shell-integration adapters. The Hyprland controller owns workspace provider objects; the XDG application controller owns desktop-entry provider objects. Neither provider object, raw compositor command, desktop `Exec=` string nor parsed process command enters the presentation component. Search, selection, opening/closing surfaces, workspace switching and explicit visible desktop-application launch targets are bounded experience actions. The shell adapter re-resolves the exact current target before activation. Linura-managed transient/managed effects still resolve through registered operations and Control; the palette never assigns `OperationClass`, risk or approval semantics.

Application launching here is deliberately narrower than application supervision. It launches an existing visible desktop entry selected by exact ID and carries no desired running state, restart policy, resource limits or privileged lifetime management. The XDG adapter may consume the trusted desktop entry's parsed argv only to hand it to the fixed user-systemd transient-service broker; presentation QML never receives command material, and applications are created in `app.slice` rather than as descendants of the sandboxed shell service. Those stronger supervision semantics remain under the application-supervision contract.

A quick-settings/control-center surface belongs in the shell when it is transient desktop chrome analogous to a panel, OSD or launcher. Substantial management applications—Settings, machine inspection, agent/provider management and similar multi-page tools—may remain standalone Qt Quick/QML applications over the same client boundary.

Trusted first-party renderers should consume the shared Linura QML UI component layer rather than introducing per-surface raw Qt styling. This keeps typography, focus, semantic status treatment and geometry centrally reviewable while preserving the separate rule that visual components carry no authority.

The first-party shell surface model does **not** activate a generic extension runtime. Shipped QML may be organized as plugin-shaped components for lifecycle and composition, but arbitrary user QML is not loaded into the trusted shell process by this milestone.

Truly custom UI may be supported later through the isolated extension model with explicit capabilities. Until that extension runtime is separately activated and qualified, its existence as an architecture contract is not a support claim.
