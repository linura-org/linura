# First-boot product architecture

> **Maturity:** roadmap architecture, not a v0.6 product capability. `linura-firstboot` is a `roadmap-scaffold` with activation milestone `v0.9.0` in `contracts/components.toml` and is not a v0.6 release/image artifact.

The target Linura First Boot flow is:

> **What do you want this computer to become?**

When the v0.9 supported-reference-environment milestone activates this component, the First Boot app is intended to run after a minimal recoverable base is available. It will discover hardware/capabilities, collect user intent and constraints, produce/adopt typed intent material, resolve a machine profile and show a reviewable plan before mutation.

First Boot may also adopt reusable setups or a portable machine profile from a local Linura Library/export. Adoption is never direct application: Linura validates the bundle, resolves required local secret references, observes the target machine, resolves capabilities and generates a fresh reviewable plan through the normal authority path.

## Required future escape hatches

The activated First Boot experience must retain:

- a deterministic default/profile path;
- the ability to skip agents/model setup entirely;
- CLI/native recovery access independent of the graphical flow;
- TTY/recovery environment access;
- locally stored reusable setup/profile adoption;
- portable setup/profile import;
- documented snapshot/restore/recovery behavior appropriate to the supported reference environment.

First Boot must therefore remain useful with no network or model provider. A hosted sync/catalog service must never be required to reconstruct a machine from a locally available setup/profile export.

## Authority boundary

First Boot is a client/experience surface, not an authority plane. It must not receive root executor handles, bypass policy/approval, or directly replay an imported action transcript. Any future mutation requested from First Boot must enter the same canonical Control lifecycle and bounded executor boundaries as other clients.

## v0.6 non-claim

The v0.6 milestone deliberately does not implement or qualify this experience. Its bounded systemd managed-effect qualification does not imply:

- First Boot readiness;
- a supported installation path;
- hardware discovery/support;
- a supported distribution/desktop profile;
- Control Center/Shell readiness;
- agent interpretation.

Those remain later roadmap work. The early `apps/linura-firstboot` workspace placeholder exists to preserve architectural ownership, not to advertise a shipped application.
