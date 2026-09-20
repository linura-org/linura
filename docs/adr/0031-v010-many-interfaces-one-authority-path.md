# ADR 0031: v0.10 uses many interfaces over one machine model and one authority path

- Status: Accepted
- Date: 2026-09-18

## Context

Linura's existing architecture already separates human/model proposal from authoritative machine mutation, requires the canonical managed-mutation lifecycle, keeps agents proposal-only, and treats graphical clients as unprivileged consumers of typed contracts.

v0.10 expands Linura from a headless/reference-qualified foundation into its first meaningful interactive Arch/Hyprland workstation experience. That experience now includes multiple interaction styles: intent/state workflows, manual no-AI operation, Library/Setup/Profile workflows, Control Center, declarative configuration, keyboard shortcuts, command palette/launcher, quick settings, desktop/session integration, notifications/OSD and a shared visual system.

Without an explicit architectural decision, those surfaces could drift into separate implementations with different semantics—for example GUI code mutating the system directly, shortcuts invoking privileged shell commands, configuration files carrying executable authority, or quick settings trusting private UI state. That would undermine the core reason Linura has a control plane.

The repository also needs a clear boundary between the **bounded workstation integration required for v0.10** and a future complete Linura-owned desktop shell.

## Decision

v0.10 adopts the invariant:

> **Many interfaces, one machine model, one authority path.**

All interfaces that express or request a Linura-managed durable external machine-state change must converge on the same typed Linura state/action contracts and the same Control-owned authority architecture. For durable managed mutations, the canonical Control lifecycle remains authoritative. Lighter ephemeral or non-durable interactions may use proportionate typed paths, but they do not create a parallel authority path or privilege bypass.

```text
intent / config / GUI / keyboard / palette / quick settings / CLI / agent
                                  │
                                  ▼
                       typed Linura state/actions
                                  │
                                  ▼
                           Linura Control
                                  │
                                  ▼
                        verified machine state
```

The following rules apply:

1. **Interface is not authority.** Control Center, declarative configuration, shortcuts, command palette, quick settings, desktop surfaces, CLI, automation and agents cannot create an alternate privilege path.
2. **Declarative configuration is data.** It must be versioned/typed/validated and previewable before mutation. It may not embed arbitrary shell, executor permits, approvals, policy overrides or historical authority.
3. **Keyboard and palette actions are registered typed operations or navigation.** Arbitrary privileged shell execution is not a supported command-palette/shortcut capability.
4. **Quick settings use authoritative observation.** Unknown/stale state is represented explicitly; a toggle cannot treat cached UI state or executor self-report as final truth.
5. **Agent interaction remains proposal-only.** Model output never gains stronger authority than deterministic manual input.
6. **Manual/no-AI operation remains complete.** Required supported workstation workflows remain usable without a model provider.
7. **Risk controls ceremony, not architecture.** Low-risk actions may auto-authorize under policy and feel immediate; higher-risk actions may require review/approval, but both use the same authority semantics.
8. **Ephemeral desktop navigation is not forced into durable mutation semantics.** Opening a launcher, focusing a window or changing workspace may remain direct desktop behavior where it does not change Linura-managed durable machine state.
9. **v0.10 requires bounded desktop integration, not a full replacement shell.** Linura must provide the command palette/launcher, bounded quick settings, workstation status/entry points, lifecycle notifications/OSD, shared visual/theme foundations and keyboard/mouse parity required by the v0.10 contract. Existing qualified Hyprland/upstream components may continue to provide panel, lock-screen or other desktop functions outside the v0.10 support claim.
10. **A complete Linura-owned Shell may deepen later.** Later shell ownership must preserve this ADR rather than introducing a parallel control plane.

This ADR refines ADR 0030's statement that the first meaningful graphical experience remains subordinate to deterministic authority and recovery. It does not supersede ADR 0010 (constrained derived UI), ADR 0012 (canonical mutation lifecycle), ADR 0028 (proposal-only agent interpretation), or ADR 0030 (first interactive PlatformProfile).

## Consequences

- v0.10 qualification must exercise interface-convergence and adversarial cases, not merely visual UI acceptance.
- Equivalent supported mutations invoked through deterministic interfaces must converge on the same typed operation/intent and Control lifecycle.
- A polished UI surface is insufficient for v0.10 if configuration, keyboard/pointer, manual/no-AI and authority-convergence requirements are missing.
- Desktop UI components remain unprivileged clients and cannot own provider/executor authority.
- Configuration, shortcuts, quick settings and notification surfaces require typed contracts and negative tests proportional to their authority exposure.
- Full Linura Shell ownership is explicitly not a v0.10 release prerequisite; the bounded integration contract is.
- Future interfaces may be added without redesigning authority as long as they preserve the one-machine-model/one-authority-path invariant.
