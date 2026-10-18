from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.validate_assets import ValidationError, validate  # noqa: E402


class AssetSchemaCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "schemas/plan-preview.v1.schema.json").read_text(encoding="utf-8")
        )

    def preview(self, status: str) -> dict:
        result = {
            "plan_id": "plan:1",
            "request_id": "request:1",
            "actor": {"id": "actor:1", "kind": "service", "interactive": False},
            "provider": "systemd",
            "resource": "systemd:unit:fixture",
            "observation_capability": "systemd.unit.observe",
            "reason": {
                "summary": "Observe fixture",
                "intent_ids": ["intent:1"],
                "requirement_ids": [],
                "capability_ids": [],
            },
            "observed_evidence_id": "evidence:1",
            "prospective_risk": "read-only",
            "status": status,
            "execution_authorized": False,
            "changes": [],
            "findings": [
                {"code": "observation-current", "level": "pass", "message": "Current"}
            ],
        }
        if status == "change-proposed":
            result["prospective_risk"] = "system-mutation"
            result["changes"] = [
                {"key": "active_state", "current": "inactive", "desired": "active"}
            ]
        if status == "blocked":
            result["findings"] = [
                {"code": "unsupported", "level": "blocker", "message": "Denied"}
            ]
        return result

    def test_valid_statuses_follow_all_nested_contracts(self) -> None:
        for status in ("no-change", "change-proposed", "blocked"):
            with self.subTest(status=status):
                validate(self.preview(status), self.schema, "preview")

    def test_blocker_containment_controls_status(self) -> None:
        invalid = []
        no_change = self.preview("no-change")
        no_change["findings"].append(
            {"code": "denied", "level": "blocker", "message": "Denied"}
        )
        invalid.append(no_change)

        proposed = self.preview("change-proposed")
        proposed["findings"][0]["level"] = "blocker"
        invalid.append(proposed)

        blocked = self.preview("blocked")
        blocked["findings"][0]["level"] = "warning"
        invalid.append(blocked)

        proposed_without_change = self.preview("change-proposed")
        proposed_without_change["changes"] = []
        invalid.append(proposed_without_change)

        no_change_with_change = self.preview("no-change")
        no_change_with_change["changes"] = [
            {"key": "active_state", "current": None, "desired": "active"}
        ]
        invalid.append(no_change_with_change)

        for index, sample in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(ValidationError):
                    validate(sample, self.schema, "preview")

    def test_referenced_actor_and_semantic_reason_are_enforced(self) -> None:
        invalid_actor = self.preview("no-change")
        invalid_actor["actor"]["kind"] = "not-an-actor"
        invalid_reason = self.preview("no-change")
        invalid_reason["reason"]["intent_ids"] = []
        for sample in (invalid_actor, invalid_reason):
            with self.assertRaises(ValidationError):
                validate(sample, self.schema, "preview")

    def test_unknown_reference_is_not_treated_as_failed_negation(self) -> None:
        malformed = {"not": {"contains": {"$ref": "#/$defs/missing"}}}
        with self.assertRaises(ValueError):
            validate([{"level": "pass"}], malformed, "invalid-schema")

    def test_union_types_retain_all_sibling_constraints(self) -> None:
        schema = {"type": ["string", "null"], "minLength": 3}
        validate(None, schema, "union")
        validate("long", schema, "union")
        with self.assertRaises(ValidationError):
            validate("no", schema, "union")


if __name__ == "__main__":
    unittest.main()
