# Packaging

Packaging is a product/maturity claim, not merely a list of binaries that happen to compile. `contracts/components.toml` is the machine-readable source of truth for whether a component is intended to be a release artifact at its current maturity.

The first target remains native Arch packaging, but v0.6 does **not** claim an Arch (or any other distribution) as a supported platform profile. Repository packages/image layouts before the supported-reference-environment milestone are development/Experimental delivery infrastructure.

## v0.6 release-artifact boundary

The v0.6 sealed binary payload is expected to contain:

- `linurad` — non-privileged Control1 observation/planning/query service;
- `linuractl` — non-privileged CLI;
- `linura-authorityd` — unprivileged bounded managed-authority runtime for `Authority1`;
- `linura-update-guard` — narrow fail-closed update safety guard, not the future full update coordinator;
- `linura-executor-systemd` — separately hardened root executor for the exact bounded systemd effect.

`linura-authorityd` is security-sensitive release material and must be covered by the same SBOM, checksum, provenance, independent byte reproduction and published-release verification as the other distributable binaries.

## Components deliberately not packaged as v0.6 product artifacts

- `linura-firstboot` remains a workspace `roadmap-scaffold` owned by v0.9 and is not a v0.6 release/image artifact;
- `linura-agent-runtime`/Agent UI remain future proposal-only components;
- Control Center and Shell remain future planned applications;
- library crates/verifiers are linked/composed as needed but are not automatically standalone release artifacts merely because they are integrated or workspace members.

This distinction is enforced by component-maturity checks so a future scaffold cannot silently reappear in the release/image binary set.

## Package/trust separation

A future native package layout may split components such as:

- `linura` — non-privileged daemons/CLI, schemas, docs and profile data appropriate to the activated milestone;
- `linura-authority` — bounded authority runtime and its system-bus/Polkit/systemd identity material where distribution policy benefits from a separate package;
- `linura-executors` or per-domain executor packages — privileged executors and their narrowly scoped policy;
- `linura-control-center` / `linura-shell` only when those applications actually activate.

Exact package names are not a Stable v0.6 contract.

Privileged executors install system D-Bus, Polkit and systemd policy separately from ordinary clients. The v0.6 authority runtime also has explicit system-bus/Polkit/service-identity packaging; human Authority1 approval and root-executor authorization remain separate policy boundaries.

Do not make `/usr/share/linura` user-editable. User configuration belongs under the appropriate XDG/config/state or protected service-state locations; packaged defaults, schemas and policy remain package-owned.

## Release payload vs supported platform

A binary appearing in the GitHub Release does not imply the repository supports installing/running that binary on every Linux distribution or hardware profile. v0.6 has `Supported platform profiles: none`; its Ubuntu disposable guest is qualification infrastructure, not a product support declaration.
