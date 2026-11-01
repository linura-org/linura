# S23 Phase 1 — source audit, package authority and application/default-handler requirements

- **Status:** Proposed architecture only; no native package effects or physical acceptance.
- **Slice:** v0.10 S23, `arch-hyprland-v1`; predecessor S16; downstream S24.
- **Audited baseline:** `e867f5348f1a0b6833d0b622187e1213cac0039e` and [original S23 WIP reference](v010-s23-applications.md).
- **Contracts:** [ADR 0052](../adr/0052-s23-application-package-and-default-handler-authority.md), [inactive TOML](../../contracts/v010-s23-design.toml), [native](../qualification/v0.10.0-s23.md) and [security](../qualification/v0.10.0-s23-security.md) acceptance.
- Canonical accepted ADRs and actual operation registry take precedence; candidate contracts are not runtime configuration.

## 1. Source audit and existing authority

| ID | Source | Verified implementation / known gap |
| --- | --- | --- |
| A23-01 | `apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml` | Visible DesktopEntries catalog, exact ID re-resolution, NoDisplay/terminal rejection, fixed user systemd-run `app.slice` / `ExitType=cgroup`; **not** a package installer |
| A23-02 | `apps/linura-shell/README.md` and shell-runtime qualification | S12/S14 native launcher/cgroup/stale-palette tests must remain intact |
| A23-03 | `profiles/arch-hyprland-v1.toml` | Arch/systemd/Btrfs/Snapper target, untrusted sources disabled, native package manager and direct-upgrade guard |
| A23-04 | `apps/linura-update-guard/src/main.rs` | Distinguishes native coordinator from emergency break glass using env flags; flags are never Linura effect authority |
| A23-05 | `docs/update-release.md` | Update lifecycle names lock, disk, snapshot, package transaction and recovery; S24 owns coordinated upgrade experience |
| A23-06 | `contracts/operation-semantics.toml` and ADR 0032 | Trusted Control registration, operation/risk/plan bindings; no inspected registered S23 package/handler effect |
| A23-07 | `contracts/v010-workstation-slices.toml` | S23 planned, depends on S16; S24 depends on S23, not conversely |
| A23-08 | `docs/qualification/v0.10.0.md` / ADR 0033 | v0.10 product requires supported install/remove/default application, native Q9 and complete Q10–Q14 evidence |
| A23-09 | `tools/verify_v010_slice_pr_evidence.py` | S23 path owners: first-party applications, packages and default-app plugins; no docs-only acceptance |
| A23-10 | freedesktop MIME Apps spec / current production source search | MIME handler effective results require XDG file precedence and eligible desktop entry; no qualified native editor found |
| A23-11 | ArchWiki/pacman manual | Partial upgrades unsupported; signatures/dependencies/locks/hooks and native flags require exact handling |
| A23-12 | `AGENTS.md` / `docs/AGENTS.md` | Canonical plan, no privileged arbitrary shell, strict security/qualification and no false claims |

This is a source audit, not a claim that an unimplemented package endpoint is vulnerable or native tests are passed.

## 2. Capability inventory and completion targets

| Feature | Existing | S23 required state |
| --- | --- | --- |
| S23-01 visible application discovery | Partial/implemented | Reuse exact XDG ID/source, visibility and current user session |
| S23-02 bounded application launch | Existing S12/S14 | Preserve parsed argv, user-systemd broker, app.slice and restart semantics |
| S23-03 installed package inventory | Not established | Native ALPM local DB versions, reasons, architecture, package/file ownership |
| S23-04 signed repository catalog | Not established | Exact frozen snapshot/keyring, bounded freshness, metadata vs installed state |
| S23-05 package install | Not established | Reviewed complete dependency closure, no partial upgrade, secure managed effect |
| S23-06 package remove / orphan cleanup | Not established | Destructive review, protected/reverse dependencies and shared owners |
| S23-07 package reinstall | Not established | Same exact trusted version, scriptlet impact and independent verification |
| S23-08 update availability | Guard/coordinator foundation | Read-only facts; execution/recovery is S24 scope |
| S23-09 default MIME/scheme lookup | Not established | Effective handler from actual XDG precedence and eligible app |
| S23-10 set/reset default handler | Not established | Safe atomic user config, fresh effective postcondition and fallback display |
| S23-11 add/remove MIME association | Not established | Preserve Default/Added/Removed groups, exact association and revision |
| S23-12 optional app favorites | Not established | Revisioned local user state, no executor/launch grant |
| S23-13 complete package review | Not established | Actual dependency/removal/disk/keyring/scripts/unknown effects shown |
| S23-14 GUI/CLI/SDK and no-model | Partial launcher | Same Control path, accessible current states, typed outcomes |
| S23-15 native A/B/physical C | Not established | Actual disposable Arch package and XDG proof, Q11 and S24 separately |

Unsupported until independently scoped: AUR, arbitrary PKGBUILDs, untrusted repositories/local archives, generic Flatpak/Snap, privileged GUI pacman flags, systemwide default-handler edits, global updates and unsupervised rollback.

## 3. Exact identities and observation architecture

**DesktopEntryEpoch:** bind current UID/session/XDG lookup, desktop ID, actual source-owned file revision, validated parsed Exec and eligibility, re-resolution just before launch or assignment. Desktop IDs or user-facing titles alone do not grant executable authority.

**PackageUniverseEpoch:** bind Arch versionless rolling source *snapshot*, keyring/signature policy, sync DB hash, local ALPM DB+lock generation, boot/system root, complete installed/projected name/version/repo/arch/dependency/conflicts/replaces/owned-file graph. A frozen package source may still be incompatible with current local DB; missing verification blocks effects.

**TransactionEpoch:** bind exact full desired native change, authorized principal/Polkit subject, executable effect descriptor/risk floor, current coordinator/lock, protected services/other owners and safe disk/recovery preconditions. Source/catalog or dependency graph drift invalidates the original review/prepare, even for an apparent no-change.

**XdgHandlerRevision:** bind effective desktop environment/config/data ordered search, targeted per-user file content revision and exact MIME/`x-scheme-handler/*` / eligible desktop ID; after write re-resolve the effective handler, not merely local file contents. Reset may reveal system fallback.

## 4. Operation classification and cross-slice safety

Nine **disabled** candidates: ALPM install/remove/reinstall/orphans as managed; XDG set/reset/add/remove association as conservative managed; application favorites as local Linura-owned state. Existing application launching remains nonprivileged `ExperienceEphemeral` and is not added to the registry. Catalog/installed package/handler queries are `AuthoritativeQuery`.

Package operations are security-sensitive/destructive, so transient execution is not eligible. Full managed plan/approval/prepare/execution/verifier/audit/reconcile, real Polkit, exact signed frozen source, no arbitrary scripts/flags and no blind replay are mandatory. S24 owns coordinated upgrades/snapshots/repair; if an installation needs a refresh/dependency upgrade or recovery not qualified in S23, deny/defer to S24. This avoids a circular dependency: S23 can complete typed observation and trusted transaction foundations while upgrade-dependent effects remain inactive.

XDG edits change *external* per-user configuration, not Linura-local favorites. They require appropriate reviewed user-state effect authority, safe file-descriptor atomic revision, no symlink/hardlink/path traversal, no side-effect package install and independently verified effective result. A user default cannot be assumed to supersede a higher-priority desktop-specific config. Do not use `xdg-mime` shell passthrough as a general effect.

## 5. Adversarial and regression matrix

| Case | Fault/attack | Required outcome |
| --- | --- | --- |
| P23-01 | Hidden/NoDisplay/Terminal/reserved app in launcher | Existing rejection remains |
| P23-02 | Desktop ID/source/Exec changed between list and launch | Exact ID/source revalidation; no retarget |
| P23-03 | Model/GUI supplies arbitrary package shell text | Typed provider rejects |
| P23-04 | `pacman -Sy pkg` or refreshed sync DB with partial install | No unsupported partial upgrade |
| P23-05 | AUR/PKGBUILD/local unsigned archive or untrusted mirror | Deny untrusted source |
| P23-06 | Keyring/signature/snapshot replaced post-review | Replan and reapprove |
| P23-07 | Dependencies/conflicts/provides/replaces drift | Full closure mismatch denies |
| P23-08 | Root scriptlet introduces unreviewed side effects | No false bounded safety claim |
| P23-09 | Pacman DB/lock already owned by other process or S24 | Do not execute concurrently |
| P23-10 | Remove Linura/PAM/Polkit/kernel/session/shared resource | Protected resource denial |
| P23-11 | `--nodeps`/`--overwrite`/`--dbonly`/force option requested | Narrow adapter denies |
| P23-12 | Disk/cache/snapshot insufficient | Stop before mutation |
| P23-13 | Native effect applied partially, reply lost, daemon dies | Durable indeterminate and no replay |
| P23-14 | Pacman exit 0 but wrong installed version/file state | No verified success |
| P23-15 | UI/model injects update context/break-glass env | Env does not grant Control authority |
| P23-16 | Same package label but architecture/version changed | Exact identity rejection |
| P23-17 | Higher priority desktop-specific MIME file shadows chosen handler | Correct effective lookup |
| P23-18 | Desktop handler hidden/missing/unassociated | User handler assignment denied |
| P23-19 | Scheme handler redirects sensitive links to attacker | Source/impact review |
| P23-20 | User MIME config symlink/hardlink/wrong owner | Safe descriptor deny |
| P23-21 | Concurrent file change between preview and write | Revision conflict |
| P23-22 | Reset reveals lower-precedence fallback | Honest resultant handler |
| P23-23 | Association add/remove deletes unrelated file entries | Preserve/reject |
| P23-24 | Class/risk/target material spoofed by client/provider | Trusted Control registry denies |
| P23-25 | Foreign UID/session or Polkit subject | Deny |
| P23-26 | Reused old approval after shell restart | Reobserve; no implicit retry |
| P23-27 | VM package test claimed as Q11/power-cut physical proof | Reject false evidence |
| P23-28 | Secrets/desktop Exec/raw package stderr leak into model/audit | Sanitize/deny |
| P23-29 | Stale/offline package catalog represented as installable latest | Unknown/unsupported |
| P23-30 | No-change skips authorization/verification | Fail closed |

## 6. Traceability and work order

| Requirement | Acceptance |
| --- | --- |
| R23-APP-01 | Preserve S12/S14 launcher and app.slice; P23-01–03 |
| R23-OBS-01 | Typed native desktop, ALPM, catalog, XDG observations; P23-02/06/16–18/29 |
| R23-PKG-01 | Frozen trusted complete package closure/no partial upgrade; P23-04–08/11 |
| R23-PKG-02 | Native lock, S24 interlock, protected owner and Polkit; P23-09/10/12/15/25 |
| R23-PKG-03 | Durable effect, independent readback and no replay; P23-13/14/26/30 |
| R23-XDG-01 | Effective eligible MIME handler and precedence; P23-17–19/22 |
| R23-XDG-02 | User-owned atomic MIME edit and revision; P23-20/21/23 |
| R23-AUTH-01 | Distinct launch/query, managed ALPM/XDG and local favorites; P23-03/15/24 |
| R23-UX-01 | Typed first-party GUI/CLI/SDK, a11y/HiDPI and no-model; Q10 |
| R23-QUAL-01 | Actual native Arch A/B and separate Q11/S24 recovery; P23-27/28/29 |

**Phase 2 sequence:** (1) code/consumer baseline, existing S12/S14 and update-guard regressions; (2) typed bounded native ALPM/desktop/MIME read-only facts; (3) complete signed package-universe and dependency/impact preflight; (4) review and register exact managed effects only where qualified; (5) narrow authenticated native ALPM executor + independent verifier/observe-only recovery; (6) separate safe user XDG editor and local favorites; (7) GUI/CLI/SDK and accessible no-model parity; (8) native Arch/Hyprland A/B, physical C, security/recovery; (9) mature review then **adaptive PR decomposition**. There is no fixed PR quota or provisional promotion.

## 7. Validation and nonclaims

In a prepared repo checkout run `python3 -m unittest discover -s tests/tooling -p test_v010_s23_design.py`, `python3 scripts/check_repository.py`, `python3 tools/check_adrs.py`, `python3 tools/check_roadmap.py`, `cargo xtask check` and exact-head security/qualification. Real pacman tests belong only in isolated disposable Arch environments with retained true source/OS/signature and interruption evidence. This Phase 1 is source inspection and design only; those native/CI/physical tests are **not** claimed executed.


## 8. Implementation PR decomposition (proposed, not implementation evidence)

The explicit, **adaptive** six-PR implementation graph is recorded in
`contracts/v010-s23-design.toml` (`[pr_decomposition]` and
`[[implementation_pr]]`). Each boundary names its owned source areas,
prerequisites, traced requirements, positive/native acceptance, and
adversarial coverage. These identifiers are **not** GitHub PR numbers.

- **S23-1 — Application discovery and identity** (parallel with S23-2):
  bounded, read-only XDG inventory; preserve S12/S14 exact launch behavior.
- **S23-2 — ALPM package observation**: installed and frozen signed repository
  facts with explicit freshness and source/keyring identity.
- **S23-3 — Dependency and impact planning** (after S23-2):
  non-executable closure, protected resources and S24 upgrade handoff.
- **S23-4 — Managed package operations** (after S23-3): authenticated,
  durable prepared native ALPM effects and independent postconditions;
  effects remain disabled until genuinely qualified.
- **S23-5 — XDG handlers and favorites** (after S23-1): exact user-level
  revisioned MIME/scheme association and separate local preferences.
- **S23-6 — Integrated experience and qualification** (after S23-1..5):
  shared Control-backed UI/CLI/SDK, no-model/a11y, exact-head Arch A,
  interactive B, separate physical C/Q11 evidence and inherited regressions.

A first implementation PR starts on a clean, current `main` base and
imports **only its owned** contracts, tests and code from this WIP reference.
No placeholder PR, no unrelated ChatGPT/task metadata commits, no direct
merge of this WIP branch, and no premature roadmap status/evidence change.
Individually review, qualify, and merge each PR in dependency order;
unqualified effects and physical proof remain explicit blockers.

The six boundaries are an engineering starting point, not an artificial
quota: a real architecture finding may require a documented rebaseline
and tests, never a silent count change or a weaker safety gate.
