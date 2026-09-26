# Ecosystem identity and reservation registry

This document is the operational tracker for scarce or externally owned Linura names across package registries, stores, domains, container registries, and distribution ecosystems.

It is deliberately separate from [`contracts/namespaces.toml`](../contracts/namespaces.toml):

- `contracts/namespaces.toml` is the machine-readable authority for identifiers Linura itself uses.
- this document records whether names have actually been secured in external systems.

A name being **defined** or **prepared** here does not mean it is externally claimed. Do not mark an item **claimed** without evidence that the relevant provider/account/store actually grants Linura control of that identity.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| ✅ **Claimed** | Externally secured and controlled by Linura |
| ✅ **Established** | Canonical first-party namespace already in active repository/runtime use |
| 🟪 **In progress** | Concrete implementation or registration work is open but not complete |
| 🟦 **Defined** | Canonical identity has been chosen; external publication is intentionally not yet claimed |
| 🟨 **Blocked** | Desired action is known but currently cannot be completed |
| ⬜ **Pending** | Actionable and not completed |
| ⏸ **Deferred** | Intentionally postponed until a product/release condition exists |
| ❌ **Unavailable** | Desired identifier is confirmed controlled by another party and no supported acquisition path is available |

## Current registry

Last reviewed: **2026-09-25**

| Area | Canonical identity | Status | Priority | Evidence / blocker | Next action |
| --- | --- | --- | --- | --- | --- |
| GitHub | `linura-org` | ✅ Claimed | — | `https://github.com/linura-org` | Maintain organization ownership and recovery controls |
| Domains | `linura.org`, `linura.dev` | ✅ Claimed | — | Project-controlled domains | Keep `linura.org` canonical; maintain `.dev` redirect/defensive ownership |
| npm | `@linura` | ⬜ Pending | 🔴 Now | No completed registry claim recorded here | Claim the scope through a legitimate package/account flow |
| Docker Hub | `linura` organization | 🟪 In progress | 🔴 Now | Desired identity is not yet recorded as secured | Resolve availability/support path, then record proof |
| Snap Store | `linura` | ⬜ Pending | 🔴 Now | No completed store registration recorded here | Create/verify publisher identity and register the real snap name |
| crates.io | `linura` | 🟪 In progress | 🔴 High | Canonical crate and trusted-publishing workflow are on `main`; external publication/ownership is not yet recorded here | Verify the trusted publisher and record the first registry ownership/publication evidence |
| PyPI | `linura` | 🟪 In progress | 🟠 High | Canonical Python package and trusted-publishing configuration are on `main`; external publication/ownership remains to be evidenced | Verify the external PyPI project/publisher state before marking Claimed |
| Flathub / AppStream | `org.linura.Linura` | 🟦 Defined | 🟠 High | Canonical desktop/AppStream identity is on `main`; this is not a Flathub publication claim | Submit only when the graphical client is genuinely installable and release-qualified |
| Homebrew | `linura-org/homebrew-tap` | ⬜ Pending | 🟠 Soon | No tap recorded | Create when a supported Homebrew install path exists |
| Arch / AUR | `linura` | 🟨 Blocked | 🟠 High | New AUR account registration is currently unavailable | Keep a real Arch package ready; publish when account creation is available |
| Linux / Freedesktop namespace | `org.linura.*`, `linura-*` | ✅ Established | — | `contracts/namespaces.toml`, ADR 0011, active repository surfaces | Maintain through `cargo xtask check` |
| OCI / GHCR | `ghcr.io/linura-org/*` | 🟦 Defined | 🟠 Soon | GitHub organization provides the canonical owner root; no generic image publication implied | Define image names only when real container artifacts are ready |
| Package infrastructure | `packages.linura.org` | 🟦 Defined | 🟡 Later | Name is under the Linura-controlled DNS zone; service not activated | Create DNS/service only when a package repository exists |
| Downloads | `download.linura.org` | 🟦 Defined | 🟡 Later | Name is under the Linura-controlled DNS zone; service not activated | Activate only when direct artifact delivery needs a dedicated origin |
| Documentation | `docs.linura.org` | ⏸ Deferred | 🟡 Later | Current repository/site documentation remains sufficient | Activate if documentation needs an independent deployment surface |

## Evidence requirements

For a transition to **Claimed**, record enough evidence to distinguish actual external ownership from an internal naming decision. Prefer one or more of:

- provider-controlled organization/package/store URL;
- successful publisher or ownership verification;
- registry publication tied to the canonical Linura release process;
- account/store screenshot or administrative record when the provider has no public ownership page.

Do not commit secrets, recovery codes, private account identifiers, support transcripts containing personal data, or authentication material as evidence.

## Update rules

1. Update this document when an external identity changes state.
2. Keep the canonical spelling and casing aligned with [`docs/naming.md`](naming.md) and [`contracts/namespaces.toml`](../contracts/namespaces.toml).
3. `Defined` or repository metadata is never equivalent to `Claimed`.
4. Do not publish empty/placeholder artifacts solely to squat on names when the external registry prohibits that behavior.
5. If a desired name is unavailable, record the actual provider state before introducing an alternate public identity.
6. New registry work should preserve the release/security model: package publication must not bypass qualification, provenance, or verification simply to secure a name.

## Immediate queue

The current ordering is:

1. verify the crates.io publisher/publication state and finish the already-open PyPI and desktop-identity work;
2. secure npm, Docker Hub, and Snap identities where provider rules allow;
3. keep the AUR package ready while registration remains blocked;
4. add Homebrew/OCI distribution only when the corresponding installable artifact is real;
5. activate package/download/documentation subdomains only when they have an operational service behind them.
