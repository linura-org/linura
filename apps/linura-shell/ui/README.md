# Linura QML UI SDK

This directory is the first-party visual component layer for Linura workstation surfaces.

Qt Quick and Qt Quick Controls are rendering/input infrastructure. Product surfaces should consume Linura components from this directory instead of independently styling raw Qt controls. The goal is one visual and interaction language shared by shell surfaces and future standalone QML applications such as Settings, Agent Manager and Machine Inspector.

The v0.10 foundation contains:

- `LinuraSurface` — semantic background/elevation/outline treatment;
- `LinuraText` — token-bound typography and muted/emphasis roles;
- `LinuraButton` — keyboard-focusable Linura action control;
- `LinuraSlider` — token-bound range control with consistent focus and handle geometry.

These components own presentation only. They do not receive D-Bus handles, provider APIs, policy state, executor authority or operation-class selection. Effectful behavior remains in typed client/controller boundaries.

Raw Qt Quick Controls are allowed inside this SDK implementation. First-party product surfaces should prefer the Linura components so visual, accessibility and focus behavior remain centrally reviewable and qualifiable.

This is an initial v0.10 SDK foundation, not yet a stable third-party API. Public compatibility/versioning is activated only when a separate SDK contract and qualification boundary say so.
