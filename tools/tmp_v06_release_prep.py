#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


workspace_packages = {
    "linura-agent-runtime", "linura-authorityd", "linura-bootstrap",
    "linura-capability-sdk", "linura-config", "linura-control",
    "linura-core", "linura-dbus", "linura-executor-systemd",
    "linura-firstboot", "linura-graph", "linura-hardware",
    "linura-intent", "linura-lifecycle", "linura-linux-observation",
    "linura-migrations", "linura-observation", "linura-observation-control",
    "linura-persistence-sqlite", "linura-planner", "linura-policy",
    "linura-protocol", "linura-provenance", "linura-provider-sdk",
    "linura-sdk", "linura-testkit", "linura-transaction", "linura-update",
    "linura-update-guard", "linura-verifier-systemd", "linuractl", "linurad",
    "xtask",
}

lock = Path("Cargo.lock")
text = lock.read_text(encoding="utf-8")
seen: set[str] = set()
blocks = text.split("[[package]]")
for index in range(1, len(blocks)):
    block = blocks[index]
    name_match = re.search(r'^\s*name = "([^"]+)"', block, re.MULTILINE)
    if not name_match or name_match.group(1) not in workspace_packages:
        continue
    name = name_match.group(1)
    old = 'version = "0.5.0"'
    if block.count(old) != 1:
        raise SystemExit(f"Cargo.lock: {name} does not contain exactly one {old}")
    blocks[index] = block.replace(old, 'version = "0.6.0"', 1)
    seen.add(name)
missing = sorted(workspace_packages - seen)
if missing:
    raise SystemExit(f"Cargo.lock: workspace packages not updated: {missing}")
lock.write_text("[[package]]".join(blocks), encoding="utf-8")

changelog_entry = '''## [0.6.0] - 2026-09-06

Experimental complete bounded managed mutation lifecycle for canonical `linura-managed-*.service` active/inactive convergence. Full release contract: [`docs/releases/v0.6.0.md`](docs/releases/v0.6.0.md).

### Added
- Experimental `org.linura.Authority1.ConvergeSystemdActiveState` managed-authority entry point and dedicated unprivileged `linura-authorityd` composition/runtime service.
- Complete canonical eleven-stage lifecycle for the exact bounded systemd active-state effect, including durable prepare/handoff/recovery, verified commit, audit and reconciliation.
- Stable operation/request-digest binding, exact candidate-bound administrator approval, separately authorized narrow root execution, and fresh independent native-systemd verification.
- Permanent deterministic eleven-case fault/recovery qualification plus disposable-system qualification with real systemd, D-Bus, Polkit and SQLite/WAL.

### Changed
- Trusted Release Proof now requires the v0.6 managed-lifecycle qualification in addition to inherited observation, plan-preview, v0.4 durability/ENOSPC and v0.5 executor/verifier gates before sealed construction or promotion.
- Release-artifact governance includes `linura-authorityd` and continues to exclude future `linura-firstboot` scaffolding.

### Boundaries
- v0.6 remains Experimental and supports only canonical `linura-managed-*.service` active/inactive convergence; no generic apply, shell, arbitrary systemd, package, file, network, storage, firewall, user, container or VM mutation is claimed.
- No supported distribution, machine class, hardware profile, agent/model execution authority, Stable mutation API or production-readiness claim is introduced.

'''
replace_once(
    "CHANGELOG.md",
    "## [Unreleased]\n\n## [0.5.0] - 2026-09-05",
    "## [Unreleased]\n\n" + changelog_entry + "## [0.5.0] - 2026-09-05",
)

replace_once(
    "README.md",
    'Status: `v0.5.0` released — Experimental first narrow privileged executor and independent verifier. The immutable release is independently verified. `executor_state = "isolated-qualified"`, `managed_mutation_support = "none"`, `complete_lifecycle = false` and `platform_support = "none"` remain the authoritative v0.5.0 boundary. Linura remains Experimental; the next roadmap milestone is `v0.6.0`.',
    'Status: `v0.6.0` release candidate — Experimental complete bounded managed-mutation lifecycle for canonical `linura-managed-*.service` active/inactive convergence. Publication remains pending the protected proof-first/tag-last lifecycle and independent release verification. `executor_state = "integrated-narrow"`, `managed_mutation_support = "narrow-experimental"`, `complete_lifecycle = true` and `platform_support = "none"` define the candidate boundary. Linura remains Experimental and is not production-ready.',
)

roadmap = Path("contracts/roadmap.toml")
roadmap_text = roadmap.read_text(encoding="utf-8")
marker = '''version = "v0.6.0"
title = "complete eleven-stage managed mutation"
status = "planned"
claim_class = "Experimental"
depends_on = ["v0.5.0"]
durable_recovery = true
executor_state = "integrated-narrow"
complete_lifecycle = true
managed_mutation_support = "narrow-experimental"
agent_role = "none"
platform_support = "none"
authority_state = "lifecycle-integrated"'''
replacement = marker + '''
milestone_contract = "docs/milestones/v0.6.0.md"
release_contract = "docs/releases/v0.6.0.md"
qualification = "docs/qualification/v0.6.0.md"'''
if roadmap_text.count(marker) != 1:
    raise SystemExit("contracts/roadmap.toml: v0.6 milestone marker mismatch")
roadmap.write_text(roadmap_text.replace(marker, replacement, 1), encoding="utf-8")

replace_once(
    "docs/milestones/v0.6.0.md",
    "**Status:** implementation candidate",
    "**Status:** release candidate; publication pending",
)

replace_once(
    "docs/releases/v0.6.0.md",
    "**Status:** implementation candidate; publication evidence remains pending the protected proof-first/tag-last release lifecycle.",
    "**Status:** implementation qualified; release candidate; publication evidence remains pending the protected proof-first/tag-last release lifecycle.",
)
replace_once(
    "docs/releases/v0.6.0.md",
    "Final compacted implementation head, guarded merge SHA and exact release-authorization source are intentionally not frozen here until those immutable identities actually exist.",
    "The final compacted implementation head is `b1bf22d7ad0722a2c58e21f4e35a1573052050fc`; it passed the complete exact-head gate set and was guarded squash-merged through PR #74 as `8169e533b09c8e41c6e4f86a5c7a82a58ff7b6e2`. The exact release-authorization source remains pending until this release-preparation tree is itself reviewed and merged.",
)

replace_once(
    "docs/qualification/v0.6.0.md",
    "**Status:** implementation qualification in progress; terminal release evidence pending final exact-source candidate.",
    "**Status:** implementation qualified; release-authorization and terminal publication evidence pending.",
)
replace_once(
    "docs/qualification/v0.6.0.md",
    "This dossier maps the v0.6 milestone contract to permanent tests/workflows and identifies which evidence must be regenerated after the final implementation history is compacted. It is not publication evidence and must not be read as a claim that the current development SHA is release-authorized.",
    "This dossier maps the v0.6 milestone contract to permanent tests/workflows. The compacted implementation has completed its exact-head and protected-main implementation gates; the later tree-identical release authorization must still regenerate protected release proof. This is not publication evidence and must not be read as a claim that v0.6 is already released.",
)
evidence = '''## Final implementation evidence

PR #74 was compacted to exact head `b1bf22d7ad0722a2c58e21f4e35a1573052050fc` with tested tree `412bfc67b9d12c9d5a2aa17f9a4430883ac0a23d`. That exact head passed CI `34038894661`, Security `34038894654`, CodeQL `34038894719`, authoritative-observation VM `34038894586`, Control1 plan-preview VM `34038894818`, v0.4 durability `34038894582`, v0.4 real ENOSPC `34038894725`, v0.5 executor/verifier `34038894579`, and v0.6 managed-lifecycle qualification `34038894791`. All valid review findings were resolved before merge.

The guarded squash merge produced protected-main source `8169e533b09c8e41c6e4f86a5c7a82a58ff7b6e2`, which then passed fresh CI `34039509061`, Security `34039509051`, and CodeQL `34039509048`. Those are implementation-closure facts; they do not substitute for the release-authorization proof graph.

'''
replace_once(
    "docs/qualification/v0.6.0.md",
    "## Claim under qualification\n",
    evidence + "## Claim under qualification\n",
)
replace_once(
    "docs/qualification/v0.6.0.md",
    "The matrix has passed during v0.6 development validation, but that success is **not** the final release proof. It must pass again on the final exact source after branch-history compaction and any documentation/contract integration that changes the candidate SHA.",
    "The matrix passed on the final compacted implementation head, but that success is **not** the final release proof. Trusted Release Proof must run it again on the exact tree-identical release authorization after release preparation is merged.",
)
replace_once(
    "docs/qualification/v0.6.0.md",
    "## Evidence state before final release candidate",
    "## Evidence state at release preparation",
)
replace_once(
    "docs/qualification/v0.6.0.md",
    "- the deterministic eleven-case matrix exists and has passed during development validation;",
    "- the deterministic eleven-case matrix exists and passed on the final compacted implementation head;",
)
replace_once(
    "docs/qualification/v0.6.0.md",
    "- final compacted PR exact-head CI/Security/CodeQL success;\n- final compacted PR exact-head v0.6 disposable-system success;\n- guarded merge to protected `main`;\n- tree-identical release-authorization exact-SHA permanent gates;",
    "- tree-identical release-authorization exact-SHA permanent gates;",
)

replace_once(
    "docs/qualification/v0.6.0-security.md",
    "**Status:** implementation security review; terminal exact-source evidence pending.",
    "**Status:** implementation security qualified; release-authorization and terminal publication evidence pending.",
)
security_evidence = '''## Implementation security evidence

The final compacted implementation head `b1bf22d7ad0722a2c58e21f4e35a1573052050fc` passed Security `34038894654`, CodeQL `34038894719`, the complete real v0.6 managed-lifecycle qualification `34038894791`, and all inherited authority/recovery qualifications. The guarded PR #74 merge produced protected-main source `8169e533b09c8e41c6e4f86a5c7a82a58ff7b6e2`, which passed fresh Security `34039509051` and CodeQL `34039509048` after merge. All valid P1/P2 authority findings were resolved before merge.

These results close implementation security review only. The release authorization must still pass fresh protected-main gates and the complete Trusted Release Proof graph before publication.

'''
replace_once(
    "docs/qualification/v0.6.0-security.md",
    "## Security claim\n",
    security_evidence + "## Security claim\n",
)

replace_once(
    "docs/qualification/v0.6.0-release-review.md",
    "**Status:** open until final compacted implementation source and protected release proof satisfy every release blocker.",
    "**Status:** implementation qualified; release-preparation candidate; protected publication evidence pending.",
)
replace_once(
    "docs/qualification/v0.6.0-release-review.md",
    "PR #74 may remain a development/draft implementation branch while this documentation is reviewed. Its eventual history compaction changes the candidate SHA and therefore requires fresh exact-head qualification afterward.",
    "PR #74 was compacted to exact head `b1bf22d7ad0722a2c58e21f4e35a1573052050fc` with tree `412bfc67b9d12c9d5a2aa17f9a4430883ac0a23d`, passed the complete exact-head qualification graph, and was guarded squash-merged as protected-main source `8169e533b09c8e41c6e4f86a5c7a82a58ff7b6e2`. Fresh protected-main CI `34039509061`, Security `34039509051`, and CodeQL `34039509048` then succeeded. Release-preparation changes now advance version/lockfile and freeze candidate-facing evidence without marking v0.6 published.",
)
gates_old = '''- [ ] CI success on compacted PR #74 exact head;
- [ ] Security success on exact head;
- [ ] CodeQL success on exact head;
- [ ] all required permanent VM/qualification workflows success on exact head;
- [ ] no unresolved review/blocker remains;
- [ ] PR diff matches v0.6 milestone with no future-scope drift.'''
replace_once(
    "docs/qualification/v0.6.0-release-review.md",
    gates_old,
    gates_old.replace("[ ]", "[x]"),
)
real_old = '''- [ ] final exact-head guest boots/provisions successfully;
- [ ] Authority1 live introspection matches contract;
- [ ] executor live introspection matches contract;
- [ ] unapproved human denied;
- [ ] ordinary/root direct managed-executor bypass denied;
- [ ] namespace/state negative paths denied before handoff;
- [ ] active success exactly one start dispatch;
- [ ] exact retry no duplicate start;
- [ ] changed same operation ID rejected without side effect;
- [ ] inactive success exactly one stop dispatch;
- [ ] no-change/already-satisfied path does not mutate;
- [ ] real verification-not-satisfied does not falsely commit/replay;
- [ ] executor loss + authority restart does not reconstruct dispatch;
- [ ] SQLite WAL/integrity assertions pass;
- [ ] deterministic eleven-case matrix passes inside guest.'''
replace_once(
    "docs/qualification/v0.6.0-release-review.md",
    real_old,
    real_old.replace("[ ]", "[x]"),
)
replace_once(
    "docs/qualification/v0.6.0-release-review.md",
    "- [ ] terminal PR/merge/source evidence is filled only after the final implementation merge exists;",
    "- [x] terminal PR/merge/source evidence records compacted head `b1bf22d7...` and guarded merge `8169e533...`;",
)
old_decision = '''**Current decision: NOT READY FOR RELEASE.**

Reason: the documentation/architecture closure can be completed now, but the implementation branch is intentionally waiting and must still reach a final compacted exact head with a green real-system v0.6 qualification and the complete protected release lifecycle.

This is expected pre-release state, not a defect in the claim. The review becomes release-ready only when every unchecked terminal evidence item is backed by an actual exact-source run/publication artifact.'''
new_decision = '''**Current decision: READY FOR RELEASE PREPARATION; PUBLICATION PENDING.**

The implementation boundary, exact-head review, guarded merge and protected-main implementation gates are complete. Publication remains fail-closed behind the release-preparation exact-head gates, a tree-identical release authorization, fresh protected-main CI/Security/CodeQL, Trusted Release Proof, sealed reproducible construction, promotion, tag-last publication and independent Release Verification. Unchecked publication items remain intentionally pending until those artifacts actually exist.'''
replace_once(
    "docs/qualification/v0.6.0-release-review.md",
    old_decision,
    new_decision,
)
