# Linura QML UI SDK

This directory is Linura's first-party visual component layer for workstation surfaces and future standalone QML applications.

The source is compiled and installed as the versioned internal QML module `org.linura.UI 1.0`. Qt Quick and Qt Quick Controls remain rendering/input infrastructure; first-party product surfaces import the Linura module instead of independently styling raw Qt controls or copying source-relative component directories.

## v0.10 component foundation

Foundation and semantic primitives:

- `LinuraTheme` — token-bound system palette, geometry, typography, motion-duration and focus metrics;
- `LinuraSurface` — semantic background/elevation/outline treatment;
- `LinuraText` — token-bound typography and muted/emphasis roles;
- `LinuraCard` — semantic card/status outline composition;
- `LinuraDivider` — token-bound structural separator;
- `LinuraStatus` — shared success/warning/danger/accent/neutral status language.

Interactive controls:

- `LinuraButton` — keyboard-focusable Linura action control;
- `LinuraIconButton` — compact accessible icon/glyph action control with tooltip support;
- `LinuraSlider` — token-bound range control with consistent focus and handle geometry;
- `LinuraSwitch` — keyboard/pointer toggle with RTL-aware visual position;
- `LinuraTextField` — shared input, selection, validation and focus treatment;
- `LinuraActionRow` — palette/list action row with title, description and shortcut affordance.

Composition primitives:

- `LinuraPopover` — non-modal first-party transient surface;
- `LinuraDialog` — modal first-party composition surface with explicit accept/reject helpers and no raw Qt standard-button styling.

These components own presentation only. They do not receive D-Bus handles, provider APIs, policy state, approval material, executor authority or operation-class selection. Effectful behavior remains in typed client/controller boundaries.

Raw Qt Quick Controls are allowed inside this SDK implementation. First-party product surfaces should import `org.linura.UI 1.0` so visual, accessibility and focus behavior remain centrally reviewable, build-validated and qualifiable.

This is an internal v0.10 first-party SDK, not yet a stable third-party API. Public compatibility/versioning is activated only when a separate SDK contract and qualification boundary say so.
