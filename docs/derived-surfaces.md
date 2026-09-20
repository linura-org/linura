# Derived UI surfaces

Linura may derive UI from typed capabilities, but models and imported metadata must not directly install arbitrary privileged GUI code.

The preferred path is a constrained surface description over typed resources/actions, rendered by trusted UI components. Examples include resource tables, details, forms, status cards and safe action controls.

## Authority and maturity boundary

Derived UI is a presentation mechanism, never an authority mechanism. Effectful controls must resolve to registered typed Linura operations and authoritative state; a surface definition cannot carry shell text, approval evidence, policy overrides, executor permits, operation-class downgrades or private backend logic.

The current v0.9 release does not claim a generic generated-UI or plugin runtime. v0.10 qualifies a bounded set of first-party workstation surfaces—Control Center, command palette, quick settings, desktop integration and notifications/OSD—over the same machine model and Control authority path.

Truly custom UI may be supported later through the isolated extension model with explicit capabilities. Until that extension runtime is separately activated and qualified, its existence as an architecture contract is not a support claim.
