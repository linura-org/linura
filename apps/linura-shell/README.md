# Linura Shell

Linura Shell is the v0.10 desktop-shell candidate for the `arch-hyprland-v1` workstation profile.

The shell runs as one supervised, long-lived Quickshell process. First-party shell surfaces are Qt Quick/QML components hosted inside that process. The initial bounded surface is the Control Center audio panel.

## Architecture

```text
Hyprland / Wayland
        │
   Quickshell
        │
    Linura Shell
   Qt Quick / QML
        │
  org.linura.ShellBridge
        │
  Control1 / Session1
        │
 Rust Control authority
        │
 PipeWire / WirePlumber
```

The shell is presentation and interaction infrastructure, not an authority plane. The QML host does not import Quickshell provider-control modules, spawn `linuractl`, run `wpctl`, invoke shell commands, select policy/risk/operation class, or hold an executor handle.

The narrow compiled `org.linura.ShellBridge` QML module is the only first-party shell boundary that talks to Linura D-Bus APIs. It validates authoritative observation identity/freshness, binds user drafts to exact observed sink identity and state, re-observes immediately before dispatch, requests only the registered exact-node Session1 effect, validates receipt correlation, and independently re-observes before presenting final success.

## Linura QML UI SDK

The shell carries the first-party **Linura QML UI SDK** as the compiled internal module `org.linura.UI 1.0`. Product surfaces import that module rather than copying source-relative component directories or independently styling raw Qt visual controls. The v0.10 foundation covers surfaces/text, buttons/icon buttons, slider/switch/text input, action rows, cards/status/dividers and popover/dialog composition. Qt Quick remains the rendering/input engine; the Linura component layer owns product-facing geometry, typography, focus treatment and semantic visual roles.

The UI SDK is presentation-only. It receives no provider handles, D-Bus authority, executor permits, policy decisions or operation-class selection. Its current v0.10 form is an internal first-party foundation, not a stable public/third-party API.

## Surface model

v0.10 intentionally distinguishes trusted shipped shell surfaces from the future extension runtime.

- `shell.qml` is the single trusted Quickshell root.
- `plugins/control-center` is a first-party panel loaded by the trusted shell.
- the first-party manifest is descriptive metadata; it does not grant capabilities or authority.
- arbitrary user QML is **not** loaded into the trusted shell process in this slice.
- future third-party/custom UI remains governed by `docs/plugin-model.md`: isolated/out-of-process or otherwise capability-confined, never ambient shell authority.

This avoids conflating a coherent plugin-shaped UI architecture with a general in-process plugin security model.

## Control Center slice

The current Control Center panel provides current-session default-output volume:

- state comes from authenticated session-bus `Control1.Observe`;
- stale/expired/offline state disables mutation;
- the moving default-output alias is discovery-only;
- mutation is sent through `Session1.SetAudioOutputVolume` for the exact observed node;
- concurrent identity/volume/mute changes abort the draft;
- Session1 receipts are correlation evidence, not final truth;
- success appears only after independent authoritative post-effect observation.

The panel exposes keyboard and pointer operation, uses the shared Linura token vocabulary, and requires no animation to communicate state.

## Launch and idle behavior

The image installs a `Linura Control Center` desktop entry that calls the running shell through Quickshell IPC:

```sh
qs -p /usr/share/linura/shell ipc call -- linura.shell toggleControlCenter
```

The shell does not poll PipeWire while the panel is closed. Opening the panel activates the bridge, obtains fresh authoritative state, and arms refresh only from the returned freshness lifetime. Closing the panel disables future observation refreshes while allowing an already-dispatched effect to finish its post-effect verification path.

## Runtime and qualification boundary

The Arch workstation image includes the official Arch `quickshell` package and the shell runtime assets. The compiled bridge is independently build-validated in canonical CI. Exact Quickshell/Qt/Hyprland package identity remains part of v0.10 workstation qualification rather than being inferred from a rolling package name.

Shell supervision is attached to the systemd graphical-session lifecycle, not to a compositor child process. `linura-shell.service` is `WantedBy`, `BindsTo` and `PartOf` `graphical-session.target`. The qualified Hyprland startup path must activate `hyprland-session.target` / `graphical-session.target`, and Q11 must prove both activation and teardown. A workstation session that sets `HYPRLAND_NO_SD_TARGET` is outside this candidate profile unless a separately qualified session manager supplies the equivalent target lifecycle.

This implementation does **not** promote `arch-hyprland-v1`, Linura Shell, Control Center, Quickshell, or the PipeWire volume operation to release-qualified support. Q10/Q11 retained visual, accessibility, interaction, compositor, restart, package-identity and real-workstation evidence remain required.
