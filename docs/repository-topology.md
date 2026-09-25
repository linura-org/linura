# Repository topology

## Purpose

Linura uses a mixed repository topology: executable/runtime implementation, reusable Rust crates, language bindings, privileged boundaries, declarative product assets, qualification evidence, packaging, schemas, repository infrastructure, and documentation intentionally live in different roots.

A top-level directory is therefore **not** evidence that a separate implementation should exist there. The repository must nevertheless avoid empty or README-only "future" shells because they make implemented subsystems look unfinished and create ambiguous ownership.

`contracts/repository-topology.toml` is the machine-readable source of truth for all tracked top-level directory roots and their ownership, including hidden infrastructure roots such as `.cargo/` and `.github/`.

## Rules

1. Runtime/product implementation belongs under `apps/`, `bindings/`, `crates/`, `executors/`, `verifiers/`, or `tools/`.
2. Declarative/data roots may share a domain name with a crate only when their role is explicit in the topology contract.
3. README-only top-level placeholders are forbidden. A future subsystem belongs in roadmap/docs until it owns a real artifact.
4. Every new tracked top-level root, including dot-prefixed roots, requires an explicit topology-contract entry and a concrete purpose.
5. A concept may span implementation and declarative assets, but the mapping must be explicit and must not duplicate implementation.
6. Removing a stale root must not move working code merely to preserve an old directory name.

## Audit result

| Root | Classification | Decision | Canonical role |
| --- | --- | --- | --- |
| `.cargo/` | infrastructure | retain | Cargo workspace/toolchain configuration. |
| `.github/` | infrastructure | retain | Contribution metadata plus CI, security, qualification, and release automation. |
| `agents/` | declarative | retain | Agent skills and specialist declarations; runtime is `crates/linura-agent-runtime`. |
| `apps/` | implementation | retain | Runnable product entry points and daemons. |
| `bindings/` | implementation | retain | Language bindings and package-native non-privileged client surfaces. |
| `bootstrap/` | legacy placeholder | **remove** | Stale README-only shell. Bootstrap implementation is already split across First Boot/bootstrap/migration/update components. |
| `capabilities/` | declarative | retain | Capability blueprints/configuration; implementation is `crates/linura-capability-sdk`. |
| `contracts/` | contract | retain | Machine-readable repository/release/layering/stability contracts. |
| `crates/` | implementation | retain | Reusable Rust domain/runtime implementation. |
| `design/` | declarative | retain | Design tokens and non-runtime design assets. |
| `docs/` | documentation | retain | Architecture, operations, milestone, qualification, and release documentation. |
| `executors/` | implementation | retain | Narrow privileged executor processes. |
| `hardware/` | evidence | retain | Hardware fixtures/support matrix; runtime is `crates/linura-hardware`. |
| `interfaces/` | contract | retain | D-Bus and other external interface definitions; implementation is `crates/linura-dbus`. |
| `lifecycle/` | evidence | retain | Lifecycle examples/fixtures; runtime is `crates/linura-lifecycle`. |
| `migrations/` | declarative | retain | Versioned migration descriptors; runtime is `crates/linura-migrations`. |
| `packaging/` | packaging | retain | Distribution/image/package-manager/install assets. |
| `profiles/` | declarative | retain | Concrete PlatformProfile definitions. |
| `schemas/` | contract | retain | Versioned JSON schemas. |
| `scripts/` | tooling | retain | Small operational/repository scripts. |
| `supervision/` | declarative | retain | Application-supervision manifests. |
| `surfaces/` | declarative | retain | Derived-surface declarations. |
| `tests/` | test | retain | Repository-level contract/integration/qualification tests. |
| `tools/` | implementation/tooling | retain | Developer, VM, image, release, and repository tools. |
| `verifiers/` | implementation | retain | Independent verifier processes. |
| `visual/` | evidence | retain | Visual baseline manifests/evidence. |
| `workflows/` | declarative | retain | Linura workflow declarations; GitHub Actions remain under `.github/workflows/`. |

The audit found **one misleading top-level implementation placeholder**: `bootstrap/`. Other thin roots contain real declarative assets, contracts, fixtures, evidence, packaging, tooling, or repository infrastructure and are intentionally retained.

## Bootstrap ownership after cleanup

The obsolete top-level `bootstrap/` shell is removed. The subsystem remains implemented and documented through these canonical boundaries:

- `apps/linura-firstboot` — executable First Boot/product entry point;
- `crates/linura-bootstrap` — bootstrap sequencing, durable state, provisioning and restart semantics;
- `crates/linura-migrations` — migration/recovery implementation;
- `crates/linura-update` — update/reconciliation implementation;
- `schemas/bootstrap.v1.schema.json` — bootstrap declarative schema;
- `docs/bootstrap-recovery.md` and `docs/first-boot.md` — product/operational contract;
- `packaging/` and `profiles/` — platform-specific installation/profile assets where applicable.

This keeps the Rust workspace coherent and avoids duplicating implementation into a concept-named top-level directory.

## Adding a future subsystem

Do not create `future-feature/README.md` as a placeholder. Instead:

1. record the concept in roadmap/architecture documentation;
2. implement it in the appropriate canonical implementation root;
3. add declarative assets only when there are real assets to own;
4. update `contracts/repository-topology.toml` if a new top-level root is genuinely necessary, including hidden infrastructure roots;
5. extend the topology tooling test so ownership remains mechanically enforced.
