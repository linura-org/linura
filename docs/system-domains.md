# System domain map

Linura is intended to become a general-purpose system control plane, not only a quick-settings shell. This document is the long-term domain inventory and sequencing map.

Domain sequencing is intentionally independent of product release numbers. Exact release inclusion belongs in milestone/release contracts, and support exists only where a published release explicitly claims and qualifies a bounded capability.

Shipping a domain requires more than UI or code presence: a provider contract, typed capability/resource model, trusted operation-class semantics, policy/risk semantics, authoritative observation, validation, recovery/verification appropriate to operation class and risk, tests, documentation and release evidence are required for the supported slice. A domain may expose query, Linura-owned, transient and managed operations independently; the presence of one class never grants another.

See [Roadmap](roadmap.md) for the canonical trust-boundary release spine and domain maturity levels, and [Machine profiles](machine-profiles.md) for the workstation/server/edge machine-class model.

## Sequencing classes

| Class | Meaning |
|---|---|
| Core proof | Used to prove Linura's generic trust/mutation lifecycle before broad domain expansion. |
| Early product | Valuable for the first coherent local experience after the core lifecycle is proven. |
| Product experience | Primarily user-environment/desktop experience work that depends on the trustworthy core. |
| High risk | Requires domain-specific recovery, verification and stricter policy before mutation support. |
| Later provider | General-purpose provider/domain that should reuse the mature lifecycle rather than define it. |
| Ecosystem | Extension/sharing capability built after local authority and lifecycle semantics are trustworthy. |
| Optional enterprise | Remote/fleet capability that must never become a prerequisite for local authority or recovery. |

## Domain inventory

| Domain | Representative resources/actions | Sequencing class |
|---|---|---|
| System identity | OS/kernel/hardware/profile/hostname/time | Early product |
| Health/readiness | provider health, degraded capabilities, reboot requirement | Early product |
| Network | interfaces, Wi-Fi, Ethernet, DNS, routes, VPN | Early product |
| Bluetooth | adapters, pairing, connect, trust, forget | Early product |
| Audio/media | devices, routes, profiles, volume, microphone | Early product |
| Displays | outputs, mode, scale, layout, HDR/VRR capabilities | Product experience |
| Input | keyboard, mouse, trackpad, layout, accessibility | Product experience |
| Power/session | profiles, battery, suspend, lock, reboot, shutdown | Early product |
| Storage | disks, partitions, mounts, filesystems, SMART, encryption metadata | High risk |
| Snapshots/recovery | Btrfs/Snapper snapshots, rollback, recovery status | High risk |
| Packages/apps | inventory, install/remove/update, provenance | Early product |
| Services | systemd units, enable/start/stop/restart, health | Core proof |
| Processes | inspection and constrained lifecycle operations | Later provider |
| Firewall | zones/rules/ports/provider state | Early product / high risk |
| Remote access | SSH service/config exposure | High risk |
| Users/sessions | local users, sessions, groups, login policy | High risk |
| Credentials | secret references, keyrings, hardware auth | High risk |
| Security posture | Secure Boot, TPM, LUKS, kernel lockdown, firewall, SSH | High risk |
| Updates | system packages, Linura, migrations, reboot/restart needs | High risk |
| Boot | boot entries, kernel/initramfs state, recovery selection | High risk |
| Containers | Docker/Podman runtime/inventory/ports | Later provider |
| Virtualization | provider-neutral VM inventory and lifecycle; possible libvirt/QEMU/KVM, Incus or other adapters | Later provider / high risk |
| Printers/scanners | CUPS/SANE resources | Later provider |
| Time/locale | timezone, locale, formats | Product experience |
| Accessibility | text scale, motion, contrast, input aids | Product experience |
| Desktop/session | compositor workspaces/windows/theme/background | Product experience |
| Notifications | notification service/preferences/history | Product experience |
| Diagnostics | logs, device/provider diagnostics, redacted support bundle | Early product |
| Audit | local mutation evidence, export, retention | Core proof / early product |
| Agent permissions | grants, approvals, revocation, history | Core proof |
| Extensions | manifests, capabilities, lifecycle, updates | Ecosystem |
| Remote/fleet | enrollment, inventory, desired state, central policy | Optional enterprise |

## Machine-class applicability

Workstation, server and edge are **machine classes**, not domains and not replacements for D0–D7. The table below records typical applicability only; it is not a support matrix and does not imply that a capability is implemented, qualified or supported on any class.

| Domain | Workstation | Server | Edge |
|---|---|---|---|
| System identity | core | core | core |
| Health/readiness | core | core | core |
| Network | core | core | core |
| Bluetooth | common | optional | optional/specialized |
| Audio/media | common | optional | specialized |
| Displays | common | rare | specialized |
| Input | common | rare | specialized |
| Power/session | common | important | critical |
| Storage | common | core | core/constraint-sensitive |
| Snapshots/recovery | important | important | critical |
| Packages/apps | common | core | core/image-dependent |
| Services | core | core | core |
| Processes | useful | useful | useful |
| Firewall | important | core | important |
| Remote access | optional | important | important |
| Users/sessions | common | common | deployment-specific |
| Credentials | common | core | core |
| Security posture | important | core | core |
| Updates | important | core | critical |
| Boot | important | important | critical |
| Containers | useful | common/core | possible |
| Virtualization | useful | common for hosts | possible/specialized |
| Printers/scanners | possible | rare | specialized |
| Time/locale | common | useful | useful |
| Accessibility | core UX | rare | specialized |
| Desktop/session | core UX | rare | specialized |
| Notifications | common | optional | specialized |
| Diagnostics | core | core | core |
| Audit | core | core | core |
| Agent permissions | core when agents enabled | core when agents enabled | core when agents enabled |
| Extensions | ecosystem | ecosystem | ecosystem/constraint-sensitive |
| Remote/fleet | optional overlay | optional overlay | optional overlay |

`core`, `common`, `important`, `optional`, `rare`, `possible` and `specialized` describe expected product relevance only. They are **not maturity or support levels**.

A domain capability can be at one D0–D7 maturity level while support differs across concrete machine/platform profiles. For example, a future `network.read` implementation may be D6 for one release-qualified workstation profile, D5 for one server profile, and D3 for an edge profile. The release contract and machine/platform qualification evidence determine those support boundaries.

Fleet is intentionally shown as an optional overlay for every class. It is not a fourth machine class and never replaces each node's local Linura authority.

## Current release-qualified slices

This inventory must not be read as a support matrix. Current published evidence is deliberately much narrower:

- v0.1.0 release-qualified authenticated authoritative read-only observation and causal-graph behavior for the bounded provider/scenario claims stated in its release contract;
- v0.2.0 release-qualified deterministic desired-state/planning behavior over the bounded authoritative observation route used by its plan-preview claim;
- no published release currently supports Linura-managed external mutation;
- no published release currently declares a supported workstation, server, edge, Linux distribution, desktop, hardware or virtualization product profile.

Future releases promote only the exact bounded slices they qualify.

## VM qualification versus VM management

Linura already has repository-owned disposable QEMU/KVM guest infrastructure for system acceptance and release qualification. That is **test infrastructure, not a product virtualization capability**.

Product virtualization is a future provider domain. Linura must represent virtual machines through provider-neutral typed resources/capabilities rather than binding its architecture to one backend. Potential adapters may include libvirt/QEMU/KVM, Incus or other local/remote implementations, but all remain optional providers.

A future VM lifecycle capability must preserve Linura's canonical eleven-stage lifecycle:

```text
request / intent
→ observe VM state
→ plan typed desired VM state / diff
→ validate
→ authorize
→ prepare
→ execute through a narrow provider executor
→ verify through independent re-observation
→ commit
→ audit
→ reconcile
```

Planning internals may resolve VM requirements, provider capabilities, images, networks, storage, devices and desired state, but those remain implementation details of `plan`/`validate`; they do not redefine the lifecycle.

Destructive operations such as VM deletion, disk replacement, snapshot rollback or host-device/GPU passthrough require explicit risk classification, authorization and recovery semantics; they must not be exposed through a generic privileged command path.

## Capability maturity

The roadmap defines the canonical domain maturity scale:

- **D0 identified** — inventory only;
- **D1 contracted** — typed resource/capability/provider contracts;
- **D2 implemented** — implementation exists without system qualification;
- **D3 integrated** — control/public integration plus negative-path coverage;
- **D4 system-tested** — disposable-machine/system evidence;
- **D5 release-qualified** — exact-source release evidence for the bounded claim;
- **D6 Experimental supported** — published release explicitly supports the bounded capability;
- **D7 Stable supported** — compatibility/support guarantees explicitly promoted and qualified.

A domain can have different maturity per capability. For example, `service.read` can be release-qualified while `service.start` remains unsupported. Do not assign one maturity level to an entire domain when only a subset is proven.

Machine-class applicability and platform qualification are orthogonal to this scale. Do not create a second D-like maturity ladder for workstation/server/edge.

## Boundary rule

Domains share core primitives but not implementation shortcuts. Package installation, firewall changes, storage operations and VM lifecycle may all require privilege, but they must not be routed through a generic privileged command runner.

Provider-specific execution stays behind narrow typed capabilities, and authoritative observation/verification remains independently defined from execution.

## Capability granularity

Prefer narrow capabilities:

```text
network.read
network.wifi.scan
network.wifi.connect
network.dns.read
network.dns.write
service.read
service.start
service.enable
package.read
package.plan
package.apply
virtualization.vm.read
virtualization.vm.plan
virtualization.vm.start
virtualization.vm.stop
virtualization.vm.create
virtualization.vm.delete
firewall.read
firewall.rule.write
```

Avoid monolithic grants such as `system.admin`, `virtualization.admin` or unrestricted shell execution in normal agent/plugin policy.

## Domain roadmap rules

1. Domain inventory entries do not imply implementation or support.
2. Machine-class applicability does not imply implementation or support.
3. Exact version targeting is recorded in active milestone contracts, not permanently baked into this long-term inventory.
4. Privileged, system-level, security-sensitive, destructive, ambiguity-sensitive or durable desired-state external mutation is a `ManagedExternalEffect` and requires the generic durable/recovery lifecycle plus domain-specific failure and recovery semantics.
5. A `TransientExternalEffect` is permitted only for a qualified unprivileged at-most-`UserState` slice with trusted classification, bounded execution, independent verification and audit; otherwise it is promoted to managed or unsupported.
6. New providers must not bypass operation classification, capability resolution, policy, authorization, required durability, verification or audit boundaries.
7. Backend adapters remain replaceable. Linura's source of truth is its typed intent/desired-state/evidence model, not libvirt, Incus, Docker, NetworkManager or any other external provider.
7. Remote/fleet providers and hosted services remain optional; loss of them must not destroy local authority, local recovery or the user's portable Library definitions.
8. Workstation, server and edge support claims require exact machine/platform profiles and evidence; never promote an entire class from one passing configuration.
