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

## Current maturity and v0.10 scope

`design/tokens.json` establishes the initial semantic token vocabulary. v0.10 turns that foundation into a qualified cross-surface contract for First Boot, Control Center, command palette, quick settings, bounded desktop integration, notifications/OSD and the other required workstation interaction surfaces.

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
