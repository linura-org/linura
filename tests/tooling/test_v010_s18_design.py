"""Proposed S18 network designs must not create or weaken machine authority."""

from __future__ import annotations

import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "contracts/v010-s18-design.toml"
EXPECTED = {
    "operation:network.wifi.scan",
    "operation:network.networking.set-enabled",
    "operation:network.wifi.set-enabled",
    "operation:network.connection.activate",
    "operation:network.connection.deactivate",
    "operation:network.wifi.join",
    "operation:network.profile.create",
    "operation:network.profile.update",
    "operation:network.profile.delete",
}


def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def enforce_architecture_gate(doc: dict) -> None:
    gate = doc["architecture_gate"]
    expected = {
        "phase": "contract-first",
        "owner_pr": 267,
        "native_identity_and_observation_owner_pr": 268,
        "review_base": "wip/v010-s18-network",
        "architecture_only": True,
        "enable_effects": False,
        "evidence_accepted": False,
        "identity_inputs_are_authorization": False,
        "native_api_support_claimed": False,
        "physical_q11_qualified": False,
        "native_identity_scope": "boot-bus-instance-unique-nm-owner-device-profile-activation-generation",
        "canonical_observation_authority": "linura-observation::ObservationEnvelope-and-Control",
        "require_real_authenticated_subject": True,
        "require_native_independent_postcondition": True,
        "require_offline_local_recovery": True,
        "require_durable_indeterminate_no_replay": True,
        "require_purpose_bound_protected_credentials": True,
        "require_native_decode_and_transport_budgets": True,
        "deny_nonlisted_network_effects": True,
    }
    if gate != expected:
        raise ValueError("S18-1 architecture/security gate changed or bypassed")


def enforce_inert(doc: dict) -> None:
    enforce_architecture_gate(doc)
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("design activated")
    false_flags = (
        "register_runtime_operations",
        "implements_effects",
        "runtime_support_promotion",
        "interactive_evidence_ready",
        "indeterminate_replay",
        "secrets_in_audit_or_intent",
        "allow_interface_name_as_effect_identity",
    )
    true_flags = (
        "no_generic_dbus_forwarding",
        "no_shell_executor",
        "require_local_recovery_for_connectivity_loss",
    )
    if any(doc[k] is not False for k in false_flags):
        raise ValueError("unsafe activation or identity")
    if any(doc[k] is not True for k in true_flags):
        raise ValueError("unsafe execution/recovery")
    observations = doc["proposed_observation"]
    for key in (
        "strict_single_owner_epoch",
        "bounded_device_enumeration",
        "bounded_access_point_enumeration",
        "bounded_profile_enumeration",
        "reject_duplicate_interface_aliases",
        "reject_mixed_owner_snapshots",
        "require_fresh_effect_preconditions",
        "control_owns_aggregation",
    ):
        if observations[key] is not True:
            raise ValueError(f"unsafe observation {key}")
    if doc["existing_read_only"]["aliases_grant_effect_authority"] is not False:
        raise ValueError("read-only alias granted effect authority")

    operations = doc["candidate_operation"]
    ids = [x["id"] for x in operations]
    if len(ids) != len(set(ids)) or set(ids) != EXPECTED:
        raise ValueError("unreviewed, duplicated or missing effect")
    for item in operations:
        if item["enabled"] is not False or item["class"] != "managed-external-effect":
            raise ValueError("effect registered or downgraded")
        if item["provider"] != "networkmanager":
            raise ValueError("unexpected provider")
        if not item["resource"].startswith("exact-provider-"):
            raise ValueError("weak resource identity")
        if not item["observation"].startswith("networkmanager."):
            raise ValueError("foreign observation")
        if (
            not item["requested_keys"]
            or "independent-reobserve" not in item["requires"]
        ):
            raise ValueError("missing effect material or independent proof")
        if item["id"] != "operation:network.wifi.scan":
            if item["risk_floor"] not in {"security-sensitive", "destructive"}:
                raise ValueError("network-disruptive risk downgraded")
        if (
            item["id"]
            in {
                "operation:network.networking.set-enabled",
                "operation:network.wifi.set-enabled",
                "operation:network.connection.activate",
                "operation:network.connection.deactivate",
                "operation:network.wifi.join",
                "operation:network.profile.delete",
            }
            and "offline-local-recovery" not in item["requires"]
        ):
            raise ValueError("offline recovery removed")
    scan = next(x for x in operations if x["id"].endswith(".wifi.scan"))
    if "active-scan-is-external-effect" not in scan["requires"]:
        raise ValueError("active scan is not passive observation")
    deletion = next(x for x in operations if x["id"].endswith(".profile.delete"))
    if deletion["risk_floor"] != "destructive":
        raise ValueError("destructive profile deletion downgraded")
    join = next(x for x in operations if x["id"].endswith(".wifi.join"))
    if not {"purpose-bound-secrets", "no-secret-audit"} <= set(join["requires"]):
        raise ValueError("credential protection removed")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unqualified feature activated")


class ProposedS18ContractTests(unittest.TestCase):
    def test_s18_1_is_contract_first_and_native_identity_belongs_to_s18_2(self):
        doc = read(SOURCE)
        enforce_architecture_gate(doc)
        plan = read(ROOT / "contracts/v010-s18-pr-decomposition.toml")
        self.assertEqual(plan["pull_request"][0]["reservation_pr"], 267)
        self.assertTrue(plan["pull_request"][0]["title"].startswith("docs(v0.10):"))
        self.assertTrue(
            all(
                not p.startswith(("crates/", "apps/", "executors/"))
                for p in plan["pull_request"][0]["owned_paths"]
            )
        )
        self.assertEqual(plan["pull_request"][1]["reservation_pr"], 268)
        self.assertIn("crates/linura-core/src/", plan["pull_request"][1]["owned_paths"])
        architecture_note = (
            ROOT / "docs/development/v010-s18-1-network-architecture-contracts.md"
        )
        self.assertTrue(architecture_note.is_file())
        self.assertIn(
            "Architecture-first", architecture_note.read_text(encoding="utf-8")
        )

    def test_s18_architecture_gate_mutations_are_rejected(self):
        doc = read(SOURCE)
        for key, unsafe in (
            ("owner_pr", 268),
            ("native_identity_and_observation_owner_pr", 267),
            ("architecture_only", False),
            ("enable_effects", True),
            ("identity_inputs_are_authorization", True),
            ("evidence_accepted", True),
            ("physical_q11_qualified", True),
            ("require_real_authenticated_subject", False),
            ("require_native_decode_and_transport_budgets", False),
            ("deny_nonlisted_network_effects", False),
            ("require_durable_indeterminate_no_replay", False),
        ):
            bad = copy.deepcopy(doc)
            bad["architecture_gate"][key] = unsafe
            with self.subTest(field=key), self.assertRaises(ValueError):
                enforce_inert(bad)

    def test_metadata_and_inert_semantics(self):
        doc = read(SOURCE)
        self.assertEqual(
            (doc["schema_version"], doc["milestone"], doc["slice"]),
            (1, "v0.10.0", "S18"),
        )
        self.assertEqual(
            (doc["dependency"], doc["profile"]), ("S16", "arch-hyprland-v1")
        )
        self.assertEqual(
            doc["provider_well_known_name"], "org.freedesktop.NetworkManager"
        )
        self.assertEqual(doc["provider_bus"], "system")
        self.assertEqual(doc["unsupported_behavior"], "fail-closed")
        enforce_inert(doc)

    def test_preserve_existing_observation_api(self):
        existing = read(SOURCE)["existing_read_only"]
        self.assertEqual(existing["manager_resource"], "networkmanager:manager")
        self.assertEqual(
            existing["manager_observation"], "networkmanager.manager.observe"
        )
        self.assertEqual(existing["device_resource_prefix"], "networkmanager:device:")
        self.assertEqual(
            existing["device_observation"], "networkmanager.device.observe"
        )
        self.assertTrue(existing["compatibility_required"])

    def test_trusted_registry_cannot_be_replaced_by_proposal(self):
        runtime = read(ROOT / "contracts/operation-semantics.toml")
        self.assertEqual(
            runtime["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertFalse(runtime["client_classification_authority"])
        self.assertFalse(runtime["provider_classification_authority"])
        self.assertEqual(runtime["unknown_effect_behavior"], "fail-closed")
        registered = {
            x["operation_id"] for x in runtime["registered_operations"].values()
        }
        # A future qualified PR must explicitly evolve this design/test if it registers an effect.
        self.assertFalse(EXPECTED & registered)

    def test_mutation_probes_fail_closed(self):
        doc = read(SOURCE)
        for key, value in (
            ("activation", "enabled"),
            ("register_runtime_operations", True),
            ("implements_effects", True),
            ("interactive_evidence_ready", True),
            ("no_shell_executor", False),
            ("secrets_in_audit_or_intent", True),
        ):
            with self.subTest(flag=key):
                bad = copy.deepcopy(doc)
                bad[key] = value
                with self.assertRaises(ValueError):
                    enforce_inert(bad)
        for name, field, value in (
            ("operation:network.wifi.scan", "class", "authoritative-query"),
            (
                "operation:network.connection.deactivate",
                "class",
                "transient-external-effect",
            ),
            ("operation:network.networking.set-enabled", "risk_floor", "user-state"),
            ("operation:network.profile.delete", "risk_floor", "user-state"),
            ("operation:network.connection.activate", "resource", "eth0"),
            ("operation:network.wifi.join", "enabled", True),
        ):
            with self.subTest(operation=name, field=field):
                bad = copy.deepcopy(doc)
                next(x for x in bad["candidate_operation"] if x["id"] == name)[
                    field
                ] = value
                with self.assertRaises(ValueError):
                    enforce_inert(bad)

    def test_all_design_and_qualification_surfaces_route_to_v010(self):
        doc = read(SOURCE)
        for field in (
            "architecture",
            "qualification_document",
            "security_qualification",
            "source_audit",
        ):
            self.assertTrue((ROOT / doc[field]).is_file(), field)
        self.assertIn(
            "0048-s18-networkmanager-authority.md",
            (ROOT / "docs/adr/README.md").read_text(),
        )
        self.assertIn(
            "v0.10.0-s18.md", (ROOT / "docs/milestones/v0.10.0.md").read_text()
        )
        self.assertIn(
            "v0.10.0-s18-security.md",
            (ROOT / "docs/qualification/v0.10.0.md").read_text(),
        )
        self.assertIn("ADR 0048", (ROOT / "docs/threat-model.md").read_text())
        expected = {
            "contracts/v010-s18-design.toml",
            doc["architecture"],
            doc["qualification_document"],
            doc["security_qualification"],
            "tests/tooling/test_v010_s18_design.py",
        }
        matrix = read(ROOT / "contracts/qualification-gate-matrix.toml")
        gate = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        self.assertTrue(expected <= set(gate["paths"]))
        route = {x["path"]: x["gates"] for x in matrix["contract"]}
        self.assertIn("v010-workstation", route["contracts/v010-s18-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_s18_architecture_cross_document_traceability(self):
        expected_markers = (
            ("docs/adr/README.md", "S18-1 architecture review"),
            ("docs/milestones/v0.10.0.md", "S18-1 contract-first milestone acceptance"),
            ("docs/qualification/v0.10.0.md", "S18-1 architecture-only gate"),
            ("docs/threat-model.md", "S18-1 architecture-stage threat gate"),
            (
                "docs/workstreams/v010-s18-network-phase1.md",
                "S18-1 contract-first evidence and extraction map",
            ),
        )
        for relative_path, marker in expected_markers:
            with self.subTest(path=relative_path):
                content = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(marker, content)
                self.assertIn("S18-2", content)
        scope = (
            ROOT / "docs/development/v010-s18-1-network-architecture-contracts.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Complete architecture review surfaces", scope)
        self.assertIn("S21-1", scope)

    def test_ledger_and_evidence_remain_unpromoted(self):
        ledger = {
            x["id"]: x
            for x in read(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(ledger["S18"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S18"]["status"], "planned")
        self.assertEqual(ledger["S18"]["evidence_prs"], [])
        self.assertEqual(ledger["S16"]["status"], "complete")
        qual = read(SOURCE)["qualification"]
        self.assertFalse(qual["fixture_evidence_is_physical"])
        self.assertFalse(qual["video_is_correctness_oracle"])
        self.assertTrue(qual["require_network_loss_recovery"])
        self.assertTrue(qual["require_indeterminate_no_replay"])


if __name__ == "__main__":
    unittest.main()
