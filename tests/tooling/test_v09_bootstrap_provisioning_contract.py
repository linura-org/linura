from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DURABLE_SECTIONS = (
    "state.rs",
    "manifest.rs",
    "store.rs",
    "codec.rs",
    "persistence.rs",
    "owner_enrollment.rs",
    "verification.rs",
    "anchor.rs",
    "recovery.rs",
    "tests.rs",
)


def durable_source() -> str:
    durable_root = ROOT / "crates/linura-bootstrap/src/durable"
    return "\n".join(
        (durable_root / name).read_text(encoding="utf-8") for name in DURABLE_SECTIONS
    )


class V09BootstrapProvisioningContractTests(unittest.TestCase):
    def test_threat_model_keeps_bootstrap_state_non_authorizing(self) -> None:
        threat_model = (
            ROOT / "docs/threat-model-v0.9-bootstrap-provisioning.md"
        ).read_text(encoding="utf-8")

        for phrase in [
            "state/evidence, never authority",
            "owner-enrollment-pending",
            "new authority generation",
            "must not blindly replay",
            "untrusted declarative input",
        ]:
            self.assertIn(phrase, threat_model)

    def test_manifest_contract_explicitly_rejects_authority_and_secrets(self) -> None:
        threat_model = (
            ROOT / "docs/threat-model-v0.9-bootstrap-provisioning.md"
        ).read_text(encoding="utf-8")

        for forbidden in [
            "shell snippets or generic commands",
            "executor permits or dispatch authority",
            "policy overrides or approval decisions",
            "passwords, private keys, recovery secrets, bearer tokens, or owner credentials",
            "model/provider authority",
        ]:
            self.assertIn(forbidden, threat_model)

    def test_milestone_and_qualification_keep_release_boundary_explicit(self) -> None:
        milestone = (ROOT / "docs/milestones/v0.9.0.md").read_text(encoding="utf-8").lower()
        qualification = (ROOT / "docs/qualification/v0.9.0.md").read_text(
            encoding="utf-8"
        ).lower()

        for phrase in [
            "provisioning manifest",
            "owner-enrollment-pending",
            "prepare for another owner",
        ]:
            self.assertIn(phrase, milestone)

        for phrase in [
            "durable bootstrap/provisioning and q11 recovery slice",
            "persistent bootstrap restart/resume qualification implemented and passed",
            "complete install/bootstrap integration rather than contract-only stage modeling",
            "remaining semantic-preservation coverage required for intent/library persistent state",
            "trusted release proof",
        ]:
            self.assertIn(phrase, qualification)

    def test_existing_bootstrap_contract_has_canonical_monotonic_stage_order(self) -> None:
        source = (ROOT / "crates/linura-bootstrap/src/lib.rs").read_text(encoding="utf-8")

        for contract in [
            "pub enum BootstrapStage",
            "pub const ORDERED: [Self; 13]",
            "pub struct BootstrapLedger",
            "pub fn from_completed_prefix",
            "pub fn complete_next",
            "pub fn next_stage",
            "pub fn validate_prefix",
            "PrepareForAnotherOwner,",
        ]:
            self.assertIn(contract, source)

    def test_durable_bootstrap_implementation_keeps_fail_closed_boundaries(self) -> None:
        root = (ROOT / "crates/linura-bootstrap/src/root.rs").read_text(encoding="utf-8")
        durable = durable_source()

        self.assertIn("pub mod durable", root)
        for contract in [
            'BOOTSTRAP_STATE_SCHEMA: &str = "linura-bootstrap-state-v1"',
            'PROVISIONING_MANIFEST_SCHEMA: &str = "linura-provisioning-manifest-v1"',
            "pub struct DurableBootstrapCoordinator",
            "pub struct BootstrapStateStore",
            "pub struct ProvisioningManifest",
            'Self::Pending => "owner-enrollment-pending"',
            "BootstrapResumeDecision::ReobserveBeforeContinuing",
            "preparer_authority_retired",
            "StaleCoordinator",
            "DurabilityUncertain",
            "O_NOFOLLOW",
            "file.lock()",
        ]:
            self.assertIn(contract, durable)

    def test_durable_state_has_no_authority_or_secret_fields(self) -> None:
        durable = durable_source()
        serialization_region = durable[durable.index("fn serialize_state"):]
        for forbidden in [
            "password=",
            "private_key=",
            "approval=",
            "permit=",
            "session_token=",
            "executor=",
        ]:
            # The strings occur only in negative tests; the canonical serializer
            # must not persist them as fields.
            self.assertNotIn(forbidden, serialization_region.split("#[cfg(test)]", 1)[0])

    def test_durable_sections_are_semantic_and_complete(self) -> None:
        durable_root = ROOT / "crates/linura-bootstrap/src/durable"
        self.assertEqual(
            sorted(path.name for path in durable_root.glob("*.rs")),
            sorted(DURABLE_SECTIONS),
        )
        self.assertFalse(list(durable_root.glob("part*.rs")))

    def test_firstboot_bounds_virtual_identity_payload_not_reported_stat_size(self) -> None:
        source = (ROOT / "apps/linura-firstboot/src/main.rs").read_text(encoding="utf-8")
        start = source.index("fn read_protected_identity_file(")
        end = source.index("fn verify_candidate_environment()", start)
        reader = source[start:end]

        self.assertIn("Read::by_ref(&mut file)", reader)
        self.assertIn(".take(read_limit)", reader)
        self.assertIn("bytes.len() as u64 > max_bytes", reader)
        self.assertNotIn("before.len() > max_bytes", reader)
        self.assertNotIn("opened.len() > max_bytes", reader)
        self.assertIn('DMI_PRODUCT_UUID: &str = "/sys/class/dmi/id/product_uuid"', source)


if __name__ == "__main__":
    unittest.main()
