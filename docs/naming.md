# Naming and product architecture

Linura is the only umbrella brand and repository namespace.

The name is inspired by **Linux + aura**: Linux underneath, with a coherent, intelligent, beautiful system layer around it. The construction is brand meaning, not an architectural dependency.

## Namespace authority

Linura controls `linura.org`. Public Linux/Freedesktop identifiers therefore use the canonical reverse-DNS root `org.linura`.

This is an ownership convention anchored in the project domain, not a claim that D-Bus, desktop files, AppStream, Polkit, or systemd provide one global namespace registry. External package/store ownership is tracked separately in [Ecosystem identity and reservation registry](ecosystem-registry.md).

The machine-readable source of truth for repository-owned Linux identifiers is [`contracts/namespaces.toml`](../contracts/namespaces.toml). New public identifiers must be added there in the same change that introduces the corresponding surface.

The canonical local roots are:

- bare project/package name: `linura`;
- component prefix: `linura-`;
- local daemon: `linurad`;
- deterministic control CLI: `linuractl`;
- reverse-DNS root: `org.linura`;
- D-Bus object-path root: `/org/linura/`;
- package-owned configuration: `/etc/linura`;
- package-owned libraries/helpers: `/usr/lib/linura`;
- package-owned shared data: `/usr/share/linura`;
- per-user XDG subdirectory: `linura` under the appropriate XDG base directory.

Do not introduce competing roots such as another reverse-DNS brand, a second product prefix, or an unrelated top-level filesystem directory for first-party Linura components.

## Identifier lifecycle

Repository identifiers have two states:

- **active** — the corresponding repository/runtime surface exists and is part of the current source contract;
- **reserved** — the canonical identity is allocated for a future or pre-publication surface, but reservation alone does not claim that an application, package, store listing, or supported product has shipped.

A source metadata file may define a reserved future identity without turning that identity into an external publication claim. External ownership must be recorded separately and only after it is actually secured.

D-Bus generation suffixes such as `Control1`, `Session1`, `Authority1`, and `Systemd1` are protocol generations, not product-version claims. Existing generation names are not renamed for branding consistency.

## Allocation rules

- D-Bus service/interface names use `org.linura.*`; object paths use `/org/linura/*`.
- Desktop and AppStream application IDs use `org.linura.*`.
- QML module URIs use `org.linura.*`.
- Polkit actions use `org.linura.*`.
- systemd units use `linura-*` or an established daemon unit such as `linurad.service`.
- first-party binaries/components use `linura-*`, `linurad`, or `linuractl` as defined by the component architecture.
- package-owned defaults and immutable assets stay under `/usr/share/linura` or `/usr/lib/linura`; user-editable state belongs under the appropriate XDG or protected service-state location.
- identifiers must not be created merely to imitate an external reservation. External registries are claimed by publishing or registering legitimate artifacts according to each registry's rules.

`cargo xtask check` validates the declared namespace contract against active D-Bus, desktop, AppStream, QML, Polkit, and systemd surfaces.

## Naming hierarchy

| Layer / surface | Canonical name | Code / namespace |
| --- | --- | --- |
| Umbrella project and ecosystem | **Linura** | `linura-*`, `org.linura.*` |
| Installable distribution | **Linura OS** | reserved until an installable supported OS product exists |
| Local authority subsystem | **Linura Control** | `linura-control`, `linurad`, `org.linura.Control1` |
| Agent experience/runtime | **Linura Agent** | `linura-agent-runtime`, `apps/linura-agent-ui` |
| Reusable setup/profile catalog | **Linura Library** | domain/protocol concept now; concrete app/storage surface later |
| Desktop shell | **Linura Shell** | `apps/linura-shell` |
| Graphical management client | **Linura Control Center** | `apps/linura-control-center` |
| First-boot experience | **Linura First Boot** | `linura-firstboot` |
| Developer-facing API facade | **Linura SDK** | `linura-sdk` |
| Deterministic CLI | `linuractl` | `linuractl` |
| Main local daemon | `linurad` | `linurad` |

## Architectural terminology

**System control plane**, **authority plane**, **intelligence plane**, **experience plane**, and **provider plane** are architecture terms, not separate brands.

Do not introduce a second proper-noun infrastructure brand for the control plane. Documentation may say:

> `linura-control` implements Linura's local system control plane.

The word **Library** refers to the user-facing reusable configuration catalog/storage abstraction. It is not an authority plane and must not become a separate product architecture with its own execution semantics.

## Product boundary

Linura may support two deployment forms without changing its core model:

1. **Linura OS** — an installable, opinionated distribution/profile with Linura integrated from first boot.
2. **Linura on another Linux platform** — Linura Control, Agent, Library, Control Center, SDK, and supported providers installed on a compatible Linux profile.

The first supported platform remains Arch/Hyprland, but the Linura brand and control-plane contracts must not encode Arch as a permanent assumption.

## Positioning

Official descriptor:

> **Linura — The intelligent system layer for Linux.**

Primary product promise:

> **Tell your computer what you want it to become.**

Technical promise:

> Agents propose; Linura turns approved intent into policy-controlled, verified system state.
