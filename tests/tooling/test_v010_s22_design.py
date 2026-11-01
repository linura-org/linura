"""Proposed S22 capture/clipboard design is inert and fails closed.

These are design-governance tests only, never proof of native capture safety.
"""

from __future__ import annotations

import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "contracts/v010-s22-design.toml"
RUNTIME = ROOT / "contracts/operation-semantics.toml"
EXPECTED_EXTERNAL = {
    "operation:utility.screenshot.capture",
    "operation:utility.screenshot.save",
    "operation:utility.recording.start",
    "operation:utility.recording.stop",
    "operation:utility.recording.export",
    "operation:utility.clipboard.write",
    "operation:utility.clipboard.history.restore",
}
EXPECTED_LOCAL = {
    "operation:utility.clipboard.history.configure",
    "operation:utility.clipboard.history.delete",
}
EXACT_IDS = EXPECTED_EXTERNAL | EXPECTED_LOCAL


def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def validate_inert(doc: dict) -> None:
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("unreviewed activation")
    for key in (
        "register_runtime_operations", "implements_effects",
        "runtime_support_promotion", "interactive_evidence_ready",
        "clipboard_history_enabled_by_default", "portal_grant_is_control_authority",
        "capture_without_compositor_protection", "recording_without_native_stop",
        "allow_sensitive_bytes_in_plan_audit_model", "allow_auto_upload_or_share",
        "allow_generic_capture_shell_fallback", "allow_untrusted_wayland_or_clipboard_access",
        "allow_restore_token_as_permanent_grant", "claim_secure_file_shredding_from_unlink",
        "indeterminate_replay",
    ):
        if doc[key] is not False:
            raise ValueError(f"unsafe proposed permission or readiness: {key}")
    for key in (
        "require_current_protected_session_epoch", "require_exact_user_session_and_seat",
        "require_compositor_enforced_protected_exclusion", "require_privacy_explicit_consent",
        "require_safe_destination_file_descriptors", "require_recording_native_activity_and_stop",
        "require_history_owner_opt_in_and_key_protection",
        "require_explicit_unknown_unavailable_states",
    ):
        if doc[key] is not True:
            raise ValueError(f"missing critical capture/privacy protection: {key}")
    if doc["existing_non_authorizing_example"]["runtime_executor_exists"] is not False:
        raise ValueError("example workflow misrepresented as an executor")
    if doc["existing_non_authorizing_example"]["allows_automatic_upload"] is not False:
        raise ValueError("automatic upload grant added")
    required_observation = (
        "require_current_compositor_and_lock_epoch",
        "require_output_topology_transform_scale", "require_exact_window_region_source",
        "require_recording_session_and_pipewire_stream",
        "require_clipboard_seat_offer_and_selection_epoch",
        "require_protected_content_exclusion_before_buffer",
        "require_actual_native_capture_activity_for_indicator",
        "reject_cross_user_or_stale_session", "control_owns_cross_provider_aggregation",
    )
    if any(doc["proposed_observation"][key] is not True for key in required_observation):
        raise ValueError("provider/capture observation weakened")
    protected_reads = doc["proposed_sensitive_reads"]
    if protected_reads["class"] != "authoritative-query":
        raise ValueError("sensitive reads classified as effects or navigation")
    for key in (
        "purpose_bound_access_required", "protected_session_required",
        "authorization_and_consent_required",
        "never_unrestricted_agent_or_model_access",
        "no_general_observation_cache_of_bytes", "no_secret_data_in_audit_or_logs",
    ):
        if protected_reads[key] is not True:
            raise ValueError("unprotected sensitive query")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unsupported/exfiltration feature enabled")

    operations = doc["candidate_operation"]
    ids = [op["id"] for op in operations]
    if len(ids) != len(set(ids)) or set(ids) != EXACT_IDS:
        raise ValueError("unreviewed or duplicated operation")
    for op in operations:
        if op["enabled"] is not False:
            raise ValueError("candidate enabled")
        if not op["resource"].startswith("exact-"):
            raise ValueError("unbound owner/target resource")
        if not op["observation"].startswith("utility."):
            raise ValueError("nonutility native observation")
        if not op["requested_keys"] or not op["requires"]:
            raise ValueError("unbounded requested state")
        if op["id"] in EXPECTED_EXTERNAL:
            if op["class"] != "managed-external-effect":
                raise ValueError("external privacy effect downgraded")
            if op["risk_floor"] != "security-sensitive":
                raise ValueError("external privacy risk downgraded")
            if "independent-reobserve" not in op["requires"]:
                raise ValueError("missing independently observed postcondition")
        else:
            if op["class"] != "linura-owned-state":
                raise ValueError("Linura-owned history misclassified")
            if not {
                "atomic-local-commit", "history-store-revision",
            } <= set(op["requires"]):
                raise ValueError("local history mutation lacks atomic revision")
    capture = next(
        x for x in operations if x["id"] == "operation:utility.screenshot.capture"
    )
    if "compositor-protected-content-exclusion" not in capture["requires"]:
        raise ValueError("protected screenshot restriction removed")
    start = next(
        x for x in operations if x["id"] == "operation:utility.recording.start"
    )
    if not {
        "separate-audio-consent", "supervised-stop",
        "compositor-protected-content-exclusion",
    } <= set(start["requires"]):
        raise ValueError("recording safety weakened")
    stop = next(
        x for x in operations if x["id"] == "operation:utility.recording.stop"
    )
    if "stop-owned-session-only" not in stop["requires"]:
        raise ValueError("recording stops a foreign session")
    history = next(
        x for x in operations if x["id"] == "operation:utility.clipboard.history.configure"
    )
    if "explicit-owner-opt-in" not in history["requires"]:
        raise ValueError("history configured without consent")
    deletion = next(
        x for x in operations if x["id"] == "operation:utility.clipboard.history.delete"
    )
    if deletion["risk_floor"] != "destructive":
        raise ValueError("history deletion risk weakened")
    q = doc["qualification"]
    if any(q[k] is not False for k in (
        "synthetic_screenshot_is_native_security_proof",
        "recorded_video_is_correctness_oracle",
        "virtual_display_is_physical_q11",
    )):
        raise ValueError("synthetic evidence falsely promoted")
    for key in (
        "require_protected_compositor_frame_exclusion",
        "require_portal_permission_denial_and_revoke",
        "require_multioutput_hidpi_geometry", "require_recording_supervised_native_stop",
        "require_history_explicit_opt_in", "require_secrets_and_content_redaction",
        "require_no_automatic_upload", "require_accessibility_keyboard_pointer",
        "require_indeterminate_no_replay",
    ):
        if q[key] is not True:
            raise ValueError("qualification requirement weakened")


class S22ProposedDesignTests(unittest.TestCase):
    def test_scope_and_inactive_design(self):
        doc = read(SOURCE)
        self.assertEqual((doc["schema_version"], doc["milestone"], doc["slice"]),
                         (1, "v0.10.0", "S22"))
        self.assertEqual((doc["profile"], doc["dependency"]),
                         ("arch-hyprland-v1", "S16"))
        self.assertEqual(doc["unsupported_behavior"], "fail-closed")
        validate_inert(doc)

    def test_example_is_not_an_automatic_upload_executor(self):
        doc = read(SOURCE)
        example = doc["existing_non_authorizing_example"]
        self.assertEqual(example["path"], "workflows/screenshot-share.toml")
        self.assertEqual(example["workflow_id"], "workflow.screenshot-share")
        self.assertFalse(example["runtime_executor_exists"])
        self.assertFalse(example["allows_automatic_upload"])
        text = (ROOT / example["path"]).read_text(encoding="utf-8")
        self.assertIn("capture.region", text)
        self.assertIn("storage.upload", text)
        self.assertFalse(doc["allow_auto_upload_or_share"])

    def test_no_runtime_authority_from_proposed_operations(self):
        doc = read(SOURCE)
        runtime = read(RUNTIME)
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
        self.assertFalse(EXACT_IDS & registered)
        self.assertFalse(doc["register_runtime_operations"])

    def test_mutation_probes_reject_privacy_and_class_downgrade(self):
        valid = read(SOURCE)
        for key, value in (
            ("activation", "enabled"),
            ("register_runtime_operations", True),
            ("clipboard_history_enabled_by_default", True),
            ("allow_auto_upload_or_share", True),
            ("capture_without_compositor_protection", True),
            ("require_compositor_enforced_protected_exclusion", False),
            ("require_recording_native_activity_and_stop", False),
        ):
            with self.subTest(flag=key):
                bad = copy.deepcopy(valid)
                bad[key] = value
                with self.assertRaises(ValueError):
                    validate_inert(bad)
        for operation_id, field, value in (
            ("operation:utility.screenshot.capture", "risk_floor", "user-state"),
            ("operation:utility.recording.start", "class", "transient-external-effect"),
            ("operation:utility.recording.stop", "resource", "current-recording"),
            ("operation:utility.clipboard.write", "enabled", True),
            ("operation:utility.clipboard.history.configure", "class",
             "managed-external-effect"),
            ("operation:utility.clipboard.history.delete", "risk_floor", "user-state"),
        ):
            with self.subTest(operation=operation_id, field=field):
                bad = copy.deepcopy(valid)
                item = next(
                    x for x in bad["candidate_operation"] if x["id"] == operation_id
                )
                item[field] = value
                with self.assertRaises(ValueError):
                    validate_inert(bad)

    def test_design_docs_security_and_ci_routing(self):
        doc = read(SOURCE)
        for field in (
            "architecture", "source_audit", "qualification_document",
            "security_qualification",
        ):
            self.assertTrue((ROOT / doc[field]).is_file(), field)
        adr = (ROOT / "docs/adr/README.md").read_text(encoding="utf-8")
        milestone = (ROOT / "docs/milestones/v0.10.0.md").read_text()
        qualification = (ROOT / "docs/qualification/v0.10.0.md").read_text()
        threat = (ROOT / "docs/threat-model.md").read_text()
        self.assertIn("0051-s22-protected-desktop-utilities.md", adr)
        self.assertIn("v0.10.0-s22.md", milestone)
        self.assertIn("v0.10.0-s22-security.md", qualification)
        self.assertIn("ADR 0051", threat)
        matrix = read(ROOT / "contracts/qualification-gate-matrix.toml")
        gate = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        expected = {
            "contracts/v010-s22-design.toml", doc["architecture"],
            doc["qualification_document"], doc["security_qualification"],
            "tests/tooling/test_v010_s22_design.py",
        }
        self.assertTrue(expected <= set(gate["paths"]))
        route = {x["path"]: x["gates"] for x in matrix["contract"]}
        self.assertIn("v010-workstation", route["contracts/v010-s22-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_s22_status_and_physical_evidence_unpromoted(self):
        doc = read(SOURCE)
        slices = {
            x["id"]: x
            for x in read(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(slices["S22"]["depends_on"], ["S16"])
        self.assertEqual(slices["S22"]["status"], "planned")
        self.assertEqual(slices["S22"]["evidence_prs"], [])
        self.assertEqual(slices["S16"]["status"], "complete")
        self.assertFalse(doc["qualification"]["virtual_display_is_physical_q11"])
        self.assertFalse(doc["qualification"]["recorded_video_is_correctness_oracle"])
        self.assertTrue(doc["qualification"]["require_indeterminate_no_replay"])


if __name__ == "__main__":
    unittest.main()
