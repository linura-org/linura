# Packaging

Packaging is a product/maturity claim, not merely a list of binaries that happen to compile. `contracts/components.toml` is the machine-readable source of truth for whether a component is intended to be a release artifact at its current maturity.

## Current v0.9.0 release boundary

The current published release is v0.9.0, Experimental, with `platform_support = "reference-experimental"`. Its release-qualified platform evidence is the exact QualificationEnvironment:

`qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless`

That is a reproducible reference/qualification substrate, **not** a generic Ubuntu PlatformProfile. No workstation/server/edge PlatformProfile is currently release-qualified.

The v0.9 sealed release payload includes the activated binaries declared by `contracts/components.toml`, including:

- `linurad` — non-privileged Control1 observation/planning/query service;
- `linuractl` — non-privileged CLI;
- `linura-authorityd` — unprivileged bounded managed-authority runtime for `Authority1`;
- `linura-firstboot` — non-privileged bounded First Boot client for the v0.9 reference environment;
- `linura-update-guard` — narrow fail-closed direct-update guard;
- `linura-executor-systemd` — separately hardened root executor for the exact bounded systemd effect.

Release artifacts are covered by the release build/provenance/SBOM/checksum/reproducibility and published-release verification contracts. A binary appearing in a release does not widen the supported platform or authority surface.

## Components not yet packaged as supported v0.9 product surfaces

- Control Center remains a v0.10 roadmap application;
- Agent UI remains a v0.10 roadmap application even though the underlying v0.8 proposal-only agent runtime is integrated;
- Shell remains a v0.10 roadmap integration surface;
- `linura-config` remains a v0.10 scaffold;
- library/domain crates and verifiers are linked/composed as required but are not automatically standalone user-facing packages.

## Package/trust separation

A native package layout may separate:

- ordinary non-privileged daemons/CLI, schemas, docs and profile data;
- bounded authority runtime plus its system-bus/Polkit/service-identity material;
- per-domain privileged executors with narrowly scoped policy;
- graphical clients only when their milestone activates and qualifies them.

Privileged executors install system D-Bus, Polkit and systemd policy separately from ordinary clients. Human Authority1 approval and root-executor authorization remain separate trust boundaries.

Do not make `/usr/share/linura` user-editable. User configuration belongs under appropriate XDG/config/state or protected service-state locations; packaged defaults, schemas and policy remain package-owned.

## Historical v0.6 boundary

v0.6 was the first release to package and qualify the complete eleven-stage managed mutation for one bounded systemd effect. Historical v0.6 release documents remain authoritative for that release; this living document describes the current packaging boundary and must not freeze later releases at v0.6 maturity.
