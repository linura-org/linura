"""Inert S23 application/ALPM/MIME architecture; not native package qualification."""

from __future__ import annotations

import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "contracts/v010-s23-design.toml"
SEMANTICS = ROOT / "contracts/operation-semantics.toml"
ALPM = {
    "operation:package.install",
    "operation:package.remove",
    "operation:package.reinstall",
    "operation:package.orphans.remove",
}
XDG = {
    "operation:application.default.set",
    "operation:application.default.reset",
    "operation:application.association.add",
    "operation:application.association.remove",
}
LOCAL = {"operation:application.favorite.configure"}
EXPECTED = ALPM | XDG | LOCAL


def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def validate_inert(doc: dict) -> None:
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("S23 design is active")
    false_flags = (
        "register_runtime_operations", "implements_effects", "runtime_support_promotion",
        "interactive_evidence_ready", "partial_upgrades_allowed",
        "new_system_upgrade_authority", "untrusted_package_sources_allowed",
        "break_glass_is_control_permission", "generic_root_pacman_shell",
        "unknown_package_effect_is_success", "assume_scriptlets_harmless",
        "native_exit_code_is_verification", "replay_indeterminate_transaction",
        "implicit_package_rollback_claim", "mime_edit_installs_package",
        "desktop_entry_alias_grants_authority",
    )
    true_flags = (
        "preserve_existing_launcher", "preserve_update_guard",
        "signed_frozen_repository_required", "complete_dependency_closure_required",
        "protect_system_components", "require_native_polkit_subject",
        "require_immutable_alpm_transaction_plan",
        "require_s24_lock_and_recovery_compatibility",
        "require_independent_package_and_xdg_postconditions",
        "offline_no_model_path_required",
    )
    if any(doc[key] is not False for key in false_flags):
        raise ValueError("unsafe S23 activation / authority")
    if any(doc[key] is not True for key in true_flags):
        raise ValueError("S12/S14/S24 boundary weakened")
    launcher = doc["existing_launcher"]
    if launcher["fixed_user_broker"] != "/usr/bin/systemd-run":
        raise ValueError("new launcher broker")
    for key in (
        "filter_nodisplay", "reject_terminal_required", "reresolve_exact_desktop_id",
        "not_package_install_authority",
    ):
        if launcher[key] is not True:
            raise ValueError("launcher permission widened")
    guard = doc["existing_update_guard"]
    if guard["coordinator_context"] != "LINURA_UPDATE_CONTEXT":
        raise ValueError("S24 coordinator context wrong")
    if guard["native_break_glass"] != "LINURA_ALLOW_DIRECT_PACMAN":
        raise ValueError("native break glass marker changed")
    if any(x is not True for key, x in guard.items() if isinstance(x, bool)):
        raise ValueError("direct pacman guard weakened")
    for section in ("proposed_observation", "package_authority", "xdg_authority"):
        for key, value in doc[section].items():
            if isinstance(value, bool) and value is not True:
                raise ValueError(f"missing {section}.{key}")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unsupported distribution/package/handler extension enabled")

    ops = doc["candidate_operation"]
    ids = [x["id"] for x in ops]
    if len(ids) != len(set(ids)) or set(ids) != EXPECTED:
        raise ValueError("unexpected or duplicate candidate")
    for x in ops:
        if x["enabled"] is not False or not x["resource"].startswith("exact-"):
            raise ValueError("candidate enabled or weak resource")
        if not x["requested_keys"] or not x["requires"]:
            raise ValueError("effect has no bounded material")
        if x["id"] in ALPM:
            if (x["provider"] != "alpm" or x["class"] != "managed-external-effect"
                    or x["observation"] != "alpm.transaction.preflight.observe"):
                raise ValueError("wrong package effect authority")
            if x["risk_floor"] not in {"security-sensitive", "destructive"}:
                raise ValueError("package risk downgraded")
            if "independent-reobserve" not in x["requires"]:
                raise ValueError("package lacks postcondition")
        elif x["id"] in XDG:
            if (x["provider"] != "xdg-mimeapps"
                    or x["observation"] != "xdg.mime.association.observe"
                    or x["class"] != "managed-external-effect"
                    or x["risk_floor"] != "user-state"):
                raise ValueError("MIME effect boundary changed")
            if not {"safe-atomic-user-config", "independent-reobserve"} <= set(
                x["requires"]
            ):
                raise ValueError("unsafe MIME file mutation")
        else:
            if (x["provider"] != "linura-local-application-preferences"
                    or x["class"] != "linura-owned-state"):
                raise ValueError("favorite became an external effect")
            if not {"atomic-local-commit", "revision-check"} <= set(x["requires"]):
                raise ValueError("local state lacks durable revision")
    for identity in ("operation:package.remove", "operation:package.orphans.remove"):
        x = next(op for op in ops if op["id"] == identity)
        if x["risk_floor"] != "destructive":
            raise ValueError("package deletion risk weakened")
    install = next(op for op in ops if op["id"] == "operation:package.install")
    if not {"no-partial-upgrade", "s24-recovery-compatibility"} <= set(
        install["requires"]
    ):
        raise ValueError("partial upgrade / unqualified S24 bypass")
    q = doc["qualification"]
    for key in (
        "synthetic_alpm_db_is_native_effect_proof",
        "vm_install_is_physical_recovery_proof",
        "video_is_correctness_oracle",
    ):
        if q[key] is not False:
            raise ValueError("mock promoted to support")
    for key, val in q.items():
        if key.startswith("require_") and val is not True:
            raise ValueError(f"missing qualification invariant {key}")


class S23InertArchitectureTests(unittest.TestCase):
    def test_scope_and_proposed_operation_semantics(self):
        d = read(DESIGN)
        self.assertEqual((d["schema_version"], d["slice"], d["milestone"]),
                         (1, "S23", "v0.10.0"))
        self.assertEqual((d["dependency"], d["downstream_slice"]), ("S16", "S24"))
        self.assertEqual(d["profile"], "arch-hyprland-v1")
        self.assertEqual(d["unsupported_behavior"], "fail-closed")
        validate_inert(d)

    def test_existing_launcher_and_update_guard_are_actual_files(self):
        d = read(DESIGN)
        launcher = (ROOT / d["existing_launcher"]["file"]).read_text()
        guard = (ROOT / d["existing_update_guard"]["file"]).read_text()
        for item in (
            "DesktopEntries.applications", "application.noDisplay",
            "/usr/bin/systemd-run", "--slice=app.slice",
            "--property=ExitType=cgroup",
        ):
            self.assertIn(item, launcher)
        for item in ("LINURA_UPDATE_CONTEXT", "LINURA_ALLOW_DIRECT_PACMAN"):
            self.assertIn(item, guard)

    def test_runtime_registration_not_created_by_proposal(self):
        s = read(SEMANTICS)
        self.assertEqual(
            s["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertFalse(s["client_classification_authority"])
        self.assertFalse(s["provider_classification_authority"])
        self.assertEqual(s["unknown_effect_behavior"], "fail-closed")
        registered = {x["operation_id"] for x in s["registered_operations"].values()}
        self.assertFalse(registered & EXPECTED)

    def test_adversarial_mutations_rejected(self):
        valid = read(DESIGN)
        for key, value in (
            ("activation", "enabled"),
            ("partial_upgrades_allowed", True),
            ("break_glass_is_control_permission", True),
            ("generic_root_pacman_shell", True),
            ("register_runtime_operations", True),
            ("preserve_update_guard", False),
        ):
            with self.subTest(flag=key):
                d = copy.deepcopy(valid)
                d[key] = value
                with self.assertRaises(ValueError):
                    validate_inert(d)
        for identity, field, value in (
            ("operation:package.install", "class", "transient-external-effect"),
            ("operation:package.install", "risk_floor", "user-state"),
            ("operation:package.remove", "risk_floor", "security-sensitive"),
            ("operation:package.reinstall", "resource", "pkg-name"),
            ("operation:application.default.set", "provider", "alpm"),
            ("operation:application.association.remove", "enabled", True),
            ("operation:application.favorite.configure", "class",
             "managed-external-effect"),
        ):
            with self.subTest(operation=identity, field=field):
                d = copy.deepcopy(valid)
                next(x for x in d["candidate_operation"] if x["id"] == identity)[field] = value
                with self.assertRaises(ValueError):
                    validate_inert(d)

    def test_proposal_document_and_ci_qualification_paths(self):
        d = read(DESIGN)
        for key in (
            "architecture", "source_audit", "qualification_document",
            "security_qualification",
        ):
            self.assertTrue((ROOT / d[key]).is_file(), key)
        self.assertIn(
            "0052-s23-application-package-and-default-handler-authority.md",
            (ROOT / "docs/adr/README.md").read_text(),
        )
        self.assertIn("v0.10.0-s23.md", (ROOT / "docs/milestones/v0.10.0.md").read_text())
        self.assertIn(
            "v0.10.0-s23-security.md",
            (ROOT / "docs/qualification/v0.10.0.md").read_text(),
        )
        self.assertIn("ADR 0052", (ROOT / "docs/threat-model.md").read_text())
        matrix = read(ROOT / "contracts/qualification-gate-matrix.toml")
        g = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        expected = {
            "contracts/v010-s23-design.toml", d["architecture"],
            d["qualification_document"], d["security_qualification"],
            "tests/tooling/test_v010_s23_design.py",
        }
        self.assertTrue(expected <= set(g["paths"]))
        routes = {x["path"]: x["gates"] for x in matrix["contract"]}
        self.assertIn("v010-workstation", routes["contracts/v010-s23-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_canonical_release_and_s24_dependency_not_promoted(self):
        d = read(DESIGN)
        ledger = {
            x["id"]: x
            for x in read(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(ledger["S23"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S23"]["status"], "planned")
        self.assertEqual(ledger["S23"]["evidence_prs"], [])
        self.assertEqual(ledger["S24"]["depends_on"], ["S23"])
        self.assertEqual(ledger["S16"]["status"], "complete")
        self.assertFalse(d["qualification"]["vm_install_is_physical_recovery_proof"])
        self.assertTrue(d["qualification"]["require_partial_upgrade_denial"])
        self.assertTrue(d["qualification"]["require_interruption_no_replay"])


if __name__ == "__main__":
    unittest.main()
