"""Inert S20 audio/media design protects the registered S08 volume authority."""

from __future__ import annotations

import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "contracts/v010-s20-design.toml"
SEMANTICS = ROOT / "contracts/operation-semantics.toml"
VOLUME_ID = "operation:audio.output.set-session-volume"
CANDIDATES = {
    "operation:audio.output.set-mute",
    "operation:audio.output.set-default",
    "operation:audio.input.set-volume",
    "operation:audio.input.set-mute",
    "operation:audio.input.set-default",
    "operation:audio.stream.set-route",
    "operation:audio.device.set-profile",
    "operation:media.player.play",
    "operation:media.player.pause",
    "operation:media.player.next",
    "operation:media.player.previous",
    "operation:media.player.seek",
}
SECURITY_SENSITIVE = {
    "operation:audio.input.set-volume",
    "operation:audio.input.set-mute",
    "operation:audio.input.set-default",
    "operation:audio.stream.set-route",
    "operation:audio.device.set-profile",
}


def load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def check_inert(doc: dict) -> None:
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("S20 proposal activated")
    for key in (
        "register_runtime_operations", "implements_new_effects",
        "runtime_support_promotion", "interactive_evidence_ready", "indeterminate_replay",
        "untrusted_media_metadata_is_authority", "default_alias_grants_effect_authority",
        "microphone_mute_proves_no_capture", "unverified_reply_is_success",
    ):
        if doc[key] is not False:
            raise ValueError(f"unsafe activation or inference: {key}")
    for key in (
        "existing_operation_must_remain_unchanged", "no_generic_provider_relay",
        "no_shell_or_wpctl_executor", "no_qml_owned_mutation", "no_cross_uid_session_access",
    ):
        if doc[key] is not True:
            raise ValueError(f"weakened S20 invariant: {key}")
    existing = doc["existing_registered_operation"]
    if (
        existing["id"] != VOLUME_ID
        or existing["class"] != "transient-external-effect"
        or existing["risk_floor"] != "user-state"
        or existing["provider"] != "pipewire"
        or existing["observation"] != "audio.session.observe"
        or existing["resource_prefix"] != "audio:session:output:"
        or existing["change_keys"] != ["volume_percent"]
        or existing["min_volume_percent"] != 0
        or existing["max_volume_percent"] != 100
    ):
        raise ValueError("S08 exact-volume semantics changed")
    for key in (
        "reused_not_duplicated", "retain_exact_native_helper",
        "retain_same_uid_session1", "retain_durable_audit_reservation",
        "retain_strictly_newer_verification", "do_not_claim_physical_q11",
    ):
        if existing[key] is not True:
            raise ValueError(f"lost S08 invariant: {key}")
    for key in (
        "require_boot_session_and_real_bus_owner", "require_pipewire_core_generation",
        "require_node_id_serial_name_and_class", "require_default_alias_read_only",
        "require_exact_stream_links_for_route",
        "distinguish_output_input_stream_and_profile",
        "distinguish_hardware_mute_software_mute_and_capture",
        "bound_and_sanitize_mpris_metadata", "require_exact_mpris_owner_and_track",
        "control_owns_observation_and_aggregation",
    ):
        if doc["proposed_observation"][key] is not True:
            raise ValueError(f"missing graph/media observation invariant {key}")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unqualified raw media/capture path proposed")
    candidates = doc["candidate_operation"]
    ids = [x["id"] for x in candidates]
    if len(ids) != len(set(ids)) or set(ids) != CANDIDATES or VOLUME_ID in ids:
        raise ValueError("unreviewed/duplicate operation or S08 redefinition")
    for item in candidates:
        if item["enabled"] is not False or item["class"] != "managed-external-effect":
            raise ValueError("unreviewed new effect activated or downgraded")
        if item["provider"] not in ("pipewire", "mpris"):
            raise ValueError("unknown media provider")
        prefix = "mpris." if item["provider"] == "mpris" else "audio."
        if not item["observation"].startswith(prefix):
            raise ValueError("wrong native observation provider")
        if not item["resource"].startswith("exact-session-"):
            raise ValueError("weak target identity")
        if not item["requested_keys"] or "independent-reobserve" not in item["requires"]:
            raise ValueError("no bounded material or independent verifier")
        if item["id"] in SECURITY_SENSITIVE and item["risk_floor"] != "security-sensitive":
            raise ValueError("capture/routing security risk downgraded")
        if item["id"].startswith("operation:media.") and (
            "untrusted-metadata" not in item["requires"]
            or "owner-identity" not in item["requires"]
        ):
            raise ValueError("media player identity/metadata unsupported")
    microphone = next(
        x for x in candidates if x["id"] == "operation:audio.input.set-mute"
    )
    if "not-privacy-kill-switch" not in microphone["requires"]:
        raise ValueError("software mute cannot claim full capture inhibition")
    if doc["qualification"]["virtual_audio_is_physical"] is not False:
        raise ValueError("virtual source is not physical microphone evidence")
    if doc["qualification"]["video_is_correctness_oracle"] is not False:
        raise ValueError("video is not native audio evidence")


class S20ProposedDesignTests(unittest.TestCase):
    def test_metadata_and_s08_compatibility(self):
        design = load(SOURCE)
        self.assertEqual((design["schema_version"], design["slice"]), (1, "S20"))
        self.assertEqual((design["milestone"], design["dependency"]), ("v0.10.0", "S16"))
        self.assertEqual(design["profile"], "arch-hyprland-v1")
        self.assertEqual(design["unsupported_behavior"], "fail-closed")
        check_inert(design)

    def test_s08_registered_output_volume_remains_exact(self):
        design = load(SOURCE)["existing_registered_operation"]
        runtime = load(SEMANTICS)
        found = [
            x for x in runtime["registered_operations"].values()
            if x["operation_id"] == VOLUME_ID
        ]
        self.assertEqual(len(found), 1)
        entry = found[0]
        for design_key, runtime_key in (
            ("class", "class"), ("provider", "provider"),
            ("observation", "observation_capability"),
            ("risk_floor", "risk_floor"), ("resource_prefix", "resource_prefix"),
            ("change_keys", "change_keys"),
        ):
            self.assertEqual(design[design_key], entry[runtime_key])
        self.assertEqual(
            runtime["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertFalse(runtime["client_classification_authority"])
        self.assertFalse(runtime["provider_classification_authority"])
        self.assertEqual(runtime["unknown_effect_behavior"], "fail-closed")
        self.assertEqual(runtime["transient_executor_privilege"], "unprivileged-only")
        self.assertTrue(runtime["transient_post_effect_reobserve_required"])
        self.assertTrue(runtime["transient_audit_sink_required"])

    def test_new_candidates_do_not_get_s08_implicit_registration(self):
        runtime = load(SEMANTICS)
        registered = {x["operation_id"] for x in runtime["registered_operations"].values()}
        self.assertFalse(CANDIDATES & registered)
        self.assertNotIn(VOLUME_ID, CANDIDATES)
        check_inert(load(SOURCE))

    def test_mutation_probes_reject_weak_security_contracts(self):
        baseline = load(SOURCE)
        for key, value in (
            ("activation", "enabled"), ("register_runtime_operations", True),
            ("implements_new_effects", True), ("no_cross_uid_session_access", False),
            ("default_alias_grants_effect_authority", True),
            ("microphone_mute_proves_no_capture", True),
            ("untrusted_media_metadata_is_authority", True),
        ):
            with self.subTest(flag=key):
                changed = copy.deepcopy(baseline)
                changed[key] = value
                with self.assertRaises(ValueError):
                    check_inert(changed)
        for operation_id, field, value in (
            ("operation:audio.input.set-mute", "risk_floor", "user-state"),
            ("operation:audio.stream.set-route", "class", "transient-external-effect"),
            ("operation:audio.output.set-default", "resource", "default-output"),
            ("operation:media.player.play", "provider", "pipewire"),
            ("operation:media.player.seek", "enabled", True),
        ):
            with self.subTest(operation=operation_id, field=field):
                changed = copy.deepcopy(baseline)
                candidate = next(
                    x for x in changed["candidate_operation"]
                    if x["id"] == operation_id
                )
                candidate[field] = value
                with self.assertRaises(ValueError):
                    check_inert(changed)

    def test_adr_domain_security_docs_and_gate_routes_exist(self):
        doc = load(SOURCE)
        for key in (
            "architecture", "qualification_document", "security_qualification", "source_audit",
        ):
            self.assertTrue((ROOT / doc[key]).is_file(), key)
        self.assertIn(
            "0050-s20-audio-media-authority.md",
            (ROOT / "docs/adr/README.md").read_text(),
        )
        self.assertIn("v0.10.0-s20.md", (ROOT / "docs/milestones/v0.10.0.md").read_text())
        self.assertIn(
            "v0.10.0-s20-security.md",
            (ROOT / "docs/qualification/v0.10.0.md").read_text(),
        )
        self.assertIn("ADR 0050", (ROOT / "docs/threat-model.md").read_text())
        expected = {
            "contracts/v010-s20-design.toml", doc["architecture"],
            doc["qualification_document"], doc["security_qualification"],
            "tests/tooling/test_v010_s20_design.py",
        }
        matrix = load(ROOT / "contracts/qualification-gate-matrix.toml")
        gate = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        self.assertTrue(expected <= set(gate["paths"]))
        routed = {entry["path"]: entry["gates"] for entry in matrix["contract"]}
        self.assertIn("v010-workstation", routed["contracts/v010-s20-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_s20_product_and_hardware_not_promoted(self):
        design = load(SOURCE)
        ledger = {
            x["id"]: x
            for x in load(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(ledger["S20"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S20"]["status"], "planned")
        self.assertEqual(ledger["S20"]["evidence_prs"], [])
        self.assertEqual(ledger["S16"]["status"], "complete")
        self.assertFalse(design["qualification"]["virtual_audio_is_physical"])
        self.assertFalse(design["qualification"]["video_is_correctness_oracle"])
        self.assertTrue(design["qualification"]["require_s08_exact_source_regression"])
        self.assertTrue(design["qualification"]["require_microphone_privacy_state"])


if __name__ == "__main__":
    unittest.main()
