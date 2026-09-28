# Design system

A polished intent-native Linux experience requires shared visual and interaction semantics, not per-panel styling.

## Token groups

- semantic colors: background/surface/foreground/muted/accent/success/warning/danger;
- spacing and type scales;
- radii, borders/elevation;
- motion duration/easing;
- density/control sizes;
- focus/selection states;
- shell geometry.

Themes provide tokens, not arbitrary code. Security, failure, verification and approval-required meaning use protected semantic roles so themes cannot visually disguise authority state.

## Linura QML UI Component SDK

The v0.10 shell now contains the initial **Linura QML UI Component SDK** under `apps/linura-shell/ui`. Qt Quick Controls are implementation infrastructure; first-party product surfaces should consume Linura-owned components instead of independently styling raw Qt controls.

The v0.10 first-party component layer is compiled as the internal `org.linura.UI 1.0` QML module rather than copied as per-surface source. Its integrated primitives now include:

- `LinuraTheme`, `LinuraSurface`, `LinuraText`, `LinuraCard`, `LinuraDivider` and `LinuraStatus` for shared semantic visual language;
- `LinuraButton`, `LinuraIconButton`, `LinuraSlider`, `LinuraSwitch` and `LinuraTextField` for shared accessible controls;
- `LinuraActionRow` for keyboard-first palette/list actions;
- `LinuraPopover` and `LinuraDialog` for shared transient/modal composition without raw Qt standard-button styling.

The Control Center slice imports the same module used by upcoming shell surfaces and standalone QML applications. Raw Qt Quick Controls remain permitted *inside* the SDK implementation because Qt is the rendering/input foundation; they are not the preferred visual API for first-party product surfaces.

The component layer is presentation-only. It does not receive D-Bus handles, provider APIs, executor permits, policy authority, approval material or operation-class selection. Those remain in typed client/controller boundaries and Linura Control.

The current component set is an integrated v0.10 foundation, **not yet a stable third-party API**. Compatibility/versioning for external consumers requires a separate public SDK contract. Product composites such as command palette, quick settings, notification/OSD stacks, Settings navigation and future Agent/Inspector surfaces are built on these primitives; implementing a primitive does not by itself activate or qualify the composite product surface.

## Current maturity and v0.10 scope

`design/tokens.json` establishes the initial semantic token vocabulary. v0.10 turns that foundation into a qualified cross-surface contract for First Boot, installer, Control Center, command palette, quick settings, the complete first-party workstation shell, notifications/OSD and the other required workstation interaction surfaces.

Shared tokens alone are **not** visual qualification. The v0.10 contract requires reviewed non-null baselines and representative captures for the required visual surfaces, representative resolutions/scales, executed comparisons, retained reviewed failure diffs, and digest-verified interaction/accessibility runner evidence.

The qualification checker binds the baseline manifest and artifacts by SHA-256, decodes PNG evidence under explicit byte/pixel/decompression bounds, rejects unsupported color-management semantics, compares rendered RGBA-equivalent pixels, and verifies that retained diffs correspond to the exact failed baseline/capture pair. Hand-authored pass booleans or unrelated screenshots cannot promote readiness.

## Cross-surface state language

The UI must clearly distinguish:

- **agent proposal** from accepted authoritative intent;
- **desired state** from **observed state**;
- **stale/unknown state** from verified current state;
- **drift/error/recovery** from successful convergence;
- **plan/policy state** from actual approval evidence;
- **execution dispatched** from **independently verified result**.

Policy and trusted risk determine ceremony. A policy `Allow` may make a low-risk operation feel immediate; the design system must not manufacture an approval prompt when none is required, and it must not hide approval/review when it is required.

## Signature first-boot experience

“What do you want this computer to become?” should be calm and minimal, but always offer deterministic/offline/default/import/recovery paths. The conversational surface is never the only route to system management.

## Accessibility and interaction

v0.10 evidence covers keyboard/pointer parity, screen-reader/semantic accessibility, focus/navigation semantics, reduced-motion behavior, representative display scaling, offline/error states and reconnect behavior for the required surfaces.

## Security UX

When policy requires review or approval, the UI shows the authenticated actor, originating intent, concrete material effects, resource/exposure scope, persistence, trusted risk, reversibility/recovery implications, verification plan and significant conflicts/shared-resource consequences.

Never use vague prompts such as “Linura wants to make changes,” and never allow generated UI to imitate authoritative approval chrome.
