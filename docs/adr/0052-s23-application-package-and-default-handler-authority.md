# ADR 0052 — S23 application, package and default-handler authority

- Status: Proposed
- Scope: v0.10 S23, `arch-hyprland-v1`, S16 predecessor, S24 downstream
- Reuses: ADR 0017/0018/0031/0032/0033; existing S12/S14 launcher and v0.9 update guard
- Companion: [inactive design](../../contracts/v010-s23-design.toml), [qualification](../qualification/v0.10.0-s23.md), [adversarial security](../qualification/v0.10.0-s23-security.md)
- Number is provisional to this independent WIP branch; resolve against the append-only ADR ledger before extracting PRs.

## Context

The existing first-party `ApplicationLauncherController.qml` already filters `NoDisplay`/reserved/terminal entries, re-resolves the exact desktop-entry ID at activation, uses parsed command material only within its dedicated integration controller and runs applications with fixed `/usr/bin/systemd-run --user`, `--slice=app.slice` and `ExitType=cgroup`. This is a bounded application launch experience, **not** permission to install packages or a generic privileged process broker. Preserve its existing S12/S14 exact-source positive and negative behavior.

The Arch/Hyprland profile explicitly disables untrusted package sources, requires native pacman, uses Btrfs/Snapper and guards direct upgrades. `apps/linura-update-guard/src/main.rs` distinguishes a coordinator context (`LINURA_UPDATE_CONTEXT`) from explicit break-glass (`LINURA_ALLOW_DIRECT_PACMAN`); neither environment string is a Linura policy approval or executor grant. S24, which depends on S23, is responsible for coordinated updates, snapshots, migration and rollback/recovery UX.

**Decision:** Separate (1) read-only app/package/default-handler facts and ordinary app launch, (2) tightly constrained managed Arch package effects, (3) user-owned MIME/scheme default-association edits and (4) optional Linura-owned favorites. The design contract is inert. No operation is registered, package manager installed, privilege delegated, update guard bypassed or support level promoted by this ADR.

## Exact source and package identity

For desktop apps, bind authenticated user session, effective XDG desktop ID plus source precedence, safe-resolved file content revision and owning source, `Hidden`/`NoDisplay`/`TryExec`/`Terminal`/`Exec` semantics and current re-resolution generation. A title, icon, desktop ID or stale/overridden `Exec` never authorizes elevated execution, installation or MIME handling. Preserve launcher broker hardening and its separation from the shell's service sandbox.

For packages, bind `PackageUniverseEpoch` to exact Arch profile, boot, installed local ALPM database/lock generation, repository sync database and immutable snapshot hashes, keyring/signature policy, named package/epoch/version/release/architecture/repository, complete dependency/provides/conflicts/replaces/optional/remove closure and file/service ownership impact. For a privileged transaction also bind current native Polkit principal/subject, S24 coordinator/lock and protected system component set, disk/cache/snapshot capacity where relevant, and the exact approved plan/postcondition. A catalog search result or package name alone is not an authority target.

Package signatures attest authorized origin but do **not** ensure maintainer scriptlets/hooks are side-effect-free. Display their consequences and unknowns; do not promise complete predictability of arbitrary package code. Source/catalog drift, DB/keyring changes, changed transitive dependency closure, lock contention and protected Linura/kernel/PAM/Polkit/display/provider dependencies must fail closed.

## Arch rolling distribution and S24 boundary

Partial upgrades are unsupported by Arch. **Never issue `pacman -Sy package`, `pacman -Sy` followed by selected `-S`, or an isolated package update after sync database refresh.** No `--nodeps`, `--overwrite`, `--dbonly`, unreviewed `-U`, arbitrary `--assume-installed`, system repository/key import, AUR/PKGBUILD, command string or package script bypass. A request requiring catalog refresh, dependency upgrade, system library replacement, full upgrade or snapshot/rollback must be blocked and directed to a future **qualified** S24 coordinator. S23 must not implement its own general system update path.

S23 can design and, only after proof, enable narrowly safe install/reinstall/remove against a coherent already frozen package universe. Where dependency closure or recovery cannot be proven without S24, remain read-only/unsupported. This preserves S23 as S24's foundational predecessor without circularly claiming S24 is implemented. A transaction may modify many packages and run root scriptlets; users must review actual full impact, not just the requested top-level target. Shared Setup/Library ownership and protected package consequences remain explicit.

Use the full managed Control lifecycle: request → observe → plan → validate → authorize → durable prepare → narrowly constrained native ALPM dispatch → independently verify → commit → audit → reconcile. An actual authenticated subject is required for privileged effects. `policy allow != executor grant`, `reviewed plan != prepared mutation`, `executor != verification`. Never permit client/model/provider class, risk, flags or shell injection. ALPM return success is insufficient: check final installed versions, file ownership, dependency integrity and independently observable requested state. Crashes, lost receipts, disk exhaustion, interrupted scriptlets or power loss are **indeterminate**, with observe-only reconciliation and no blind replay. Do not claim pacman transaction atomicity implies whole-machine rollback; S24 owns snapshots/recovery.

## Exact XDG MIME/scheme handler model

`mimeapps.list` is user/system XDG configuration, separate from packages and from Linura-local state. Bind current user, desktop environment, ordered `XDG_CONFIG_HOME`/`XDG_CONFIG_DIRS` and `XDG_DATA_HOME`/`XDG_DATA_DIRS` precedence, exact MIME type/`x-scheme-handler/*` target, eligible current desktop-entry ID, file identity/content revision and effective resulting handler. Treat the groups `[Default Applications]`, `[Added Associations]` and `[Removed Associations]` distinctly. Resetting a user default may reveal a lower-priority system default and must **not** claim that no handler exists.

Set/reset default and add/remove user association use separately typed file effects with safe user-owned descriptor-based writes, no symlink/hardlink/path traversal, bounded parser, atomic revision replacement, preservation of unrelated entries and independent **effective** post-edit lookup. A changed handler can redirect confidential file/URL content: show provenance and exact MIME/scheme. No handler edit may install a package, launch an app, change systemwide configuration or authorize opening an arbitrary URI. Favorites are merely authenticated revisioned Linura-owned preferences, never installation or launch permits.

## Operation classes and product

Authoritative catalog/installed-package/default-handler reads are `AuthoritativeQuery`. Existing bounded ordinary app launch is `ExperienceEphemeral`; no new registration is needed. Package install/remove/reinstall/orphan cleanup are conservative disabled `ManagedExternalEffect` proposals (security-sensitive or destructive). XDG file associations are separate user-level conservative managed external effects pending class review. Favorites are `LinuraOwnedState`. A transient path requires a newly reviewed unprivileged, at-most-`UserState`, nondurable-bounded native proof and independent verification; it cannot process privileged ALPM packages.

Only Linura Control owns typed trusted registration/risk/policy, canonical plans, secure principals, lifecycle, audit and verification. Native ALPM/XDG adapters provide bounded mechanisms, not a second authority. First-party Control Center, app catalog, package transaction preview, MIME chooser, CLI/SDK, keyboard/accessibility and no-model/manual flows converge on that trusted operation/state; no QML-side pacman, shell or desktop `Exec` effect.

## Qualification and consequences

[Domain](../qualification/v0.10.0-s23.md) and [security](../qualification/v0.10.0-s23-security.md) dossiers specialize v0.10 Q9–Q14. Exact-source disposable Arch VM must exercise actual ALPM transactions against frozen signed sources and native XDG association behavior, with failure/restart/reconciliation; mocked fixtures are insufficient for native qualification. S24 coordinated update/rollback and true physical Q11 evidence remain separate. S23 stays planned. No runtime operation, build result, launch behavior, policy guard, release acceptance or recovery claim is changed by this proposed ADR.

References: [Arch system maintenance](https://wiki.archlinux.org/title/System_maintenance), [pacman manual](https://man.archlinux.org/man/pacman.8.en), [MIME Apps specification](https://specifications.freedesktop.org/mime-apps/latest-single/).
