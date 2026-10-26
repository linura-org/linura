"""Proposed v0.10 S21 contracts must not grant runtime authority."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "contracts/v010-s21-design.toml"


class S21ProposedDesignTests(unittest.TestCase):
    def test_design_is_inert_and_cannot_claim_release_acceptance(self):
        doc = tomllib.loads(SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["milestone"], "v0.10.0")
        self.assertEqual(doc["slice"], "S21")
        self.assertEqual(doc["dependency"], "S17")
        self.assertEqual(doc["profile"], "arch-hyprland-v1")
        self.assertEqual(doc["status"], "proposed")
        self.assertEqual(doc["activation"], "none")
        for key in (
            "register_runtime_operations",
            "implements_effects",
            "runtime_support_promotion",
            "interactive_evidence_ready",
            "indeterminate_replay",
        ):
            self.assertIs(doc[key], False, key)
        for field in (
            "architecture",
            "qualification_document",
            "security_qualification",
        ):
            self.assertTrue((ROOT / doc[field]).is_file(), field)

    def test_no_duplicate_mutation_or_weakening_of_critical_controls(self):
        doc = tomllib.loads(SOURCE.read_text(encoding="utf-8"))
        candidates = doc["candidate_operation"]
        self.assertEqual(len(candidates), 6)
        ids = [item["id"] for item in candidates]
        self.assertEqual(len(ids), len(set(ids)))
        for item in candidates:
            with self.subTest(operation=item["id"]):
                self.assertFalse(item["enabled"])
                self.assertEqual(item["class"], "managed-external-effect")
                self.assertIn(
                    item["risk_floor"],
                    ("user-state", "security-sensitive", "destructive"),
                )
                self.assertTrue(item["requested_keys"])
                self.assertTrue(item["requires"])
                self.assertTrue(item["resource"])
                self.assertTrue(item["observation"])
                self.assertIn(item["source"], ("S21-2", "S21-3", "S21-4"))
        storage = [item for item in candidates if item["provider"] == "udisks2"]
        self.assertEqual(len(storage), 4)
        self.assertTrue(
            all(
                item["risk_floor"] in ("security-sensitive", "destructive")
                for item in storage
            )
        )
        self.assertIn("ext-session-lock-output-coverage", candidates[0]["requires"])
        backlight = next(
            item for item in candidates if item["provider"] == "logind-backlight"
        )
        self.assertEqual(backlight["risk_floor"], "security-sensitive")
        eject = next(
            item for item in candidates if item["id"] == "operation:storage.drive.eject"
        )
        power_off = next(
            item
            for item in candidates
            if item["id"] == "operation:storage.drive.power-off"
        )
        self.assertEqual(eject["requested_keys"], ["ejected"])
        self.assertEqual(power_off["requested_keys"], ["powered_off"])
        self.assertEqual(eject["risk_floor"], "destructive")
        self.assertEqual(power_off["risk_floor"], "destructive")
        self.assertIn("sibling-filesystem-review", eject["requires"])
        self.assertIn("sibling-filesystem-review", power_off["requires"])

    def test_s17_power_registry_is_not_reimplemented(self):
        design = tomllib.loads(SOURCE.read_text(encoding="utf-8"))
        authority = design["existing_authority"]
        self.assertTrue(authority["no_new_power_executor"])
        self.assertTrue(authority["no_skip_inhibitors"])
        self.assertEqual(authority["authorization_source"], "s17-managed-control")
        existing = tomllib.loads(
            (ROOT / "contracts/operation-semantics.toml").read_text(encoding="utf-8")
        )
        registered = {
            entry["operation_id"]
            for entry in existing["registered_operations"].values()
        }
        self.assertTrue(set(authority["reuse"]) <= registered)
        self.assertTrue(
            not set(authority["reuse"])
            & {item["id"] for item in design["candidate_operation"]}
        )

    def test_proposed_contract_cannot_grant_runtime_authority(self):
        design = tomllib.loads(SOURCE.read_text(encoding="utf-8"))
        runtime = tomllib.loads(
            (ROOT / "contracts/operation-semantics.toml").read_text(encoding="utf-8")
        )
        # Later qualified domain PRs may register one of these exact IDs.
        # This separate design file must never confer runtime authority.
        self.assertIs(design["register_runtime_operations"], False)
        self.assertEqual(design["activation"], "none")
        self.assertTrue(
            all(not item["enabled"] for item in design["candidate_operation"])
        )
        self.assertEqual(
            runtime["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertIs(runtime["client_classification_authority"], False)
        self.assertIs(runtime["provider_classification_authority"], False)
        self.assertEqual(runtime["unknown_effect_behavior"], "fail-closed")

    def test_qualification_and_security_docs_are_routed(self):
        design = tomllib.loads(SOURCE.read_text(encoding="utf-8"))
        adr = (ROOT / "docs/adr/README.md").read_text(encoding="utf-8")
        self.assertIn("0045-s21-workstation-device-authority.md", adr)
        milestone = (ROOT / "docs/milestones/v0.10.0.md").read_text(encoding="utf-8")
        qualification = (ROOT / "docs/qualification/v0.10.0.md").read_text(
            encoding="utf-8"
        )
        threat = (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")
        self.assertIn("v0.10.0-s21.md", milestone)
        self.assertIn("v0.10.0-s21-security.md", qualification)
        self.assertIn("ADR 0045", threat)
        matrix = tomllib.loads(
            (ROOT / "contracts/qualification-gate-matrix.toml").read_text(
                encoding="utf-8"
            )
        )
        expected = {
            "contracts/v010-s21-design.toml",
            design["architecture"],
            design["qualification_document"],
            design["security_qualification"],
            "tests/tooling/test_v010_s21_design.py",
        }
        gate = next(item for item in matrix["gate"] if item["id"] == "v010-workstation")
        self.assertTrue(expected <= set(gate["paths"]))
        routed = {item["path"]: item["gates"] for item in matrix["contract"]}
        self.assertIn("v010-workstation", routed[SOURCE.relative_to(ROOT).as_posix()])

    def test_s21_dependency_is_not_falsely_marked_complete(self):
        slices = tomllib.loads(
            (ROOT / "contracts/v010-workstation-slices.toml").read_text(
                encoding="utf-8"
            )
        )
        ledger = {item["id"]: item for item in slices["slice"]}
        self.assertEqual(ledger["S21"]["depends_on"], ["S17"])
        self.assertIn(ledger["S21"]["status"], ("planned", "complete"))
        if ledger["S21"]["status"] == "complete":
            self.assertEqual(ledger["S17"]["status"], "complete")
            self.assertTrue(ledger["S21"]["evidence_prs"])
        else:
            self.assertFalse(ledger["S21"]["evidence_prs"])
        self.assertFalse(
            tomllib.loads(SOURCE.read_text(encoding="utf-8"))["qualification"][
                "fixture_evidence_is_physical"
            ]
        )


if __name__ == "__main__":
    unittest.main()
