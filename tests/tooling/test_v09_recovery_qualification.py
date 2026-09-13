from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class V09RecoveryQualificationTests(unittest.TestCase):
    def test_v09_qualification_cannot_drop_migration_or_update_recovery(self) -> None:
        workflow = (ROOT / ".github/workflows/v09-qualification.yml").read_text(encoding="utf-8")

        for path in [
            '"crates/linura-migrations/**"',
            '"crates/linura-update/**"',
            '"docs/threat-model-v0.9-update-migration.md"',
        ]:
            self.assertIn(path, workflow)

        for package in [
            "-p linura-migrations",
            "-p linura-update",
        ]:
            self.assertIn(package, workflow)

        for contract in [
            "migration-durable-ledger-and-independent-backup",
            "update-durable-prepare-dispatch-verify-and-no-blind-replay",
        ]:
            self.assertIn(contract, workflow)

    def test_v09_recovery_threat_model_keeps_persisted_state_non_authorizing(self) -> None:
        threat_model = (ROOT / "docs/threat-model-v0.9-update-migration.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("evidence and recovery state, not authority", threat_model)
        self.assertIn("re-observation rather than blind replay", threat_model)
        self.assertIn("must still be exercised end-to-end", threat_model)

    def test_v09_update_evidence_is_fixed_producer_and_dispatch_bound(self) -> None:
        update_source = (ROOT / "crates/linura-update/src/lib.rs").read_text(encoding="utf-8")
        threat_model = (ROOT / "docs/threat-model-v0.9-update-migration.md").read_text(
            encoding="utf-8"
        )

        for contract in [
            'V09_UPDATE_EVIDENCE_ROOT: &str = "/var/lib/linura-update/v0.9"',
            'V09_UPDATE_EVIDENCE_PRODUCER_ID: &str = "linura-update-evidence-v09"',
            "V09_UPDATE_EVIDENCE_PRODUCER_UID: u32 = 0",
            "dispatch_generation",
            "PACKAGE_VERIFICATION_MAX_AGE_MS",
            "validate_package_evidence_freshness",
        ]:
            self.assertIn(contract, update_source)

        for phrase in [
            "caller-selected evidence roots",
            "fixed trusted producer",
            "exact current durable dispatch generation",
            "verification freshness window",
        ]:
            self.assertIn(phrase, threat_model)

    def test_v09_migration_checkpoint_is_held_through_apply_boundary(self) -> None:
        migration_source = (ROOT / "crates/linura-migrations/src/lib.rs").read_text(
            encoding="utf-8"
        )
        threat_model = (ROOT / "docs/threat-model-v0.9-update-migration.md").read_text(
            encoding="utf-8"
        )

        for contract in [
            "struct BackupStabilityGuard",
            "hold_for_target",
            "checkpoint_guard",
            "guard.assert_stable()?",
        ]:
            self.assertIn(contract, migration_source)

        self.assertIn("held under exclusive advisory locks", threat_model)
        self.assertIn("immediately before `apply()`", threat_model)
        self.assertIn("checkpoint drift", threat_model)


if __name__ == "__main__":
    unittest.main()
