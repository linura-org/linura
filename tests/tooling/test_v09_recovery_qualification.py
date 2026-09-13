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


if __name__ == "__main__":
    unittest.main()
