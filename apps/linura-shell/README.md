# Linura Shell

Linura Shell is the v0.10 desktop-shell candidate for the `arch-hyprland-v1` workstation profile.

The shell runs as one supervised, long-lived Quickshell process. First-party shell surfaces are Qt Quick/QML components hosted inside that process. The current bounded surfaces are the Control Center audio panel, compact Quick Settings over the same authoritative session-volume path, and a navigation-only command palette with typed Hyprland workspace discovery/switching.

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
- `plugins/control-center` is a first-party detailed panel loaded by the trusted shell.
- `plugins/quick-settings` is a first-party compact panel that reuses the same typed audio-session controller and registered Session1 operation; it owns no provider or executor authority.
- `plugins/command-palette` is a first-party overlay whose catalog contains bounded experience-navigation targets plus explicit visible desktop-application targets.
- first-party manifests are descriptive metadata; they do not grant capabilities or authority.
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

## Quick Settings slice

Quick Settings exposes the same current-session default-output volume operation in a compact shell panel. It does **not** introduce a second audio path: the shell owns one shared `AudioSessionController`, activates it only while Control Center or Quick Settings is open, and both surfaces bind to the same authenticated `Control1.Observe` and registered `Session1.SetAudioOutputVolume` flow.

The quick surface shows authoritative sink identity/state, explicit freshness/status, read-only mute state and a bounded 0–100% volume draft. Stale, unavailable or busy state disables apply. Applying a draft still performs fresh pre-dispatch re-observation, exact-node identity/state comparison, the registered transient effect, receipt correlation and independent post-effect verification. The manifest is descriptive and authority-free; QML cannot select operation class, risk, policy, provider or executor.

Control Center, Quick Settings and command palette are mutually exclusive transient surfaces. Switching between them cancels any undispatched audio draft before the next surface takes ownership. The shell root, rather than an individual panel, owns shared audio-observation activation so one consumer cannot deactivate the controller while another supported consumer is open.

The exact-source shell development gate exercises this surface against a real session authority stack. It builds the exact `linurad` source, installs the production root-owned WirePlumber helper and compiled ShellBridge module, starts PipeWire/WirePlumber in the disposable Arch user session, creates one deterministic qualification-only virtual sink, and drives the real `QuickSettingsPanel` through `AudioSessionController`. The gate proves authoritative observation, a verified Session1 volume effect, exact-node post-state, durable SQLite/WAL audit lineage, pre-dispatch state-drift rejection, service-loss fail-closed behavior, and recovery after `linurad` restart. Fixture-only sink creation/default selection and initial/concurrent volume setup are explicitly outside the product mutation path; the effect under qualification reaches PipeWire only through the registered Linura operation.

## Command palette slice

The command palette is an `ExperienceEphemeral` shell surface. Its static catalog contains the explicit `navigation:control-center` target, it receives plain workspace descriptors from the nonvisual `WorkspaceNavigationController` as `navigation:workspace` entries, and it receives sanitized visible desktop-entry descriptors from `ApplicationLauncherController` as `application:desktop-entry` targets. Search/filtering, keyboard selection and pointer activation remain presentation behavior; the palette owns no Hyprland or desktop-entry provider object.

`WorkspaceNavigationController` is the bounded shell integration adapter. It alone projects the live typed `Hyprland.workspaces` model into plain `{id, name, focused}` descriptors, uses the supported per-workspace `focused` state for current-workspace presentation, resolves an exact numeric workspace ID against the fresh live model immediately before activation, and then calls the typed `HyprlandWorkspace.activate()` API. The palette emits only `workspaceRequested(id)` navigation intent. It does not construct or dispatch Hyprland command strings, launch processes, carry shell text, hold provider/executor handles, or choose policy/risk/operation class. A stale/removed workspace fails closed and the palette refreshes instead of retargeting another workspace.

The shell also registers the Hyprland global-shortcut identity `linura:commandPalette`. The qualified profile may bind a compositor key chord to that identity; registering the shortcut does not mutate Hyprland configuration or grant shell authority.

`ApplicationLauncherController` owns Quickshell's visible `DesktopEntries.applications` index and projects only display/search metadata plus the immutable desktop-entry ID. Entries marked `NoDisplay` are filtered before they can enter the palette and are rechecked again immediately before launch. The palette never receives `Exec=`, parsed command arrays, working directories or executable handles. On activation the controller re-resolves the exact ID against the current visible index and rejects Linura's own launcher entries, stale/hidden targets and terminal-required entries.

The controller does **not** call `DesktopEntry.execute()`: Quickshell documents that path as equivalent to detached child-process execution, which would leave ordinary applications under the sandboxed `linura-shell.service` ancestry. Instead the controller passes Quickshell's parsed argv and optional working directory only to one fixed `/usr/bin/systemd-run --user` broker invocation. The user service manager creates a transient `Type=exec` service in `app.slice`, with `ExitType=cgroup`, environment expansion disabled and a unique bounded unit name. `ExitType=cgroup` keeps self-forking graphical applications alive until their application cgroup is empty. The launched application therefore does not inherit the shell unit's `RestrictAddressFamilies=AF_UNIX` sandbox or its service cgroup lifetime. The palette closes only after the broker reports successful service startup; broker failure remains visible. Each palette opening has a generation token carried through the asynchronous launch request, so completion from an older closed palette session is ignored after close/reopen. This is a bounded ordinary desktop launch target, not a generic shell/process API and not application supervision.

Effectful Linura-managed palette entries are not added as arbitrary QML callbacks. Transient or managed machine effects still resolve through the trusted registered operation/Control path. Durable desired application state, restart policy, resource limits or privileged supervision remain governed by `docs/application-supervision.md` and are not introduced by this launcher slice.

## Launch and idle behavior

The image installs `Linura Control Center`, `Linura Quick Settings` and `Linura Command Palette` desktop entries that call the running shell through Quickshell IPC:

```sh
qs -p /usr/share/linura/shell ipc call -- linura.shell toggleControlCenter
qs -p /usr/share/linura/shell ipc call -- linura.shell toggleQuickSettings
qs -p /usr/share/linura/shell ipc call -- linura.shell toggleCommandPalette
```

The shell keeps Control Center, Quick Settings and command palette mutually exclusive so keyboard focus is owned by at most one transient Linura surface. The shared audio controller is active only while Control Center or Quick Settings is open. When neither audio surface is open it stops future freshness/retry observation work, while an already-dispatched effect is still allowed to finish its independent post-effect verification path.

## Runtime and qualification boundary

The Arch workstation image includes the official Arch `quickshell` package and the shell runtime assets. Because this slice relies on typed `HyprlandWorkspace.activate()` behavior that is correct for named/special workspaces starting with Quickshell 0.3.1, `arch-hyprland-v1` now owns `quickshell >= 0.3.1` as a semantic minimum. The compiled bridge is independently build-validated in canonical CI. Exact Quickshell/Qt/Hyprland package identity remains part of v0.10 workstation qualification rather than being inferred from a rolling package name.

Shell supervision is attached to the systemd graphical-session lifecycle, not to a compositor child process. `linura-shell.service` is `WantedBy`, `BindsTo` and `PartOf` `graphical-session.target`. The qualified Hyprland startup path must activate `hyprland-session.target` / `graphical-session.target`, and Q11 must prove both activation and teardown. A workstation session that sets `HYPRLAND_NO_SD_TARGET` is outside this candidate profile unless a separately qualified session manager supplies the equivalent target lifecycle.

This implementation does **not** promote `arch-hyprland-v1`, Linura Shell, Control Center, Quick Settings, Quickshell, or the PipeWire volume operation to release-qualified support. Q10/Q11 retained visual, accessibility, interaction, compositor, restart, package-identity and real-workstation evidence remain required.
