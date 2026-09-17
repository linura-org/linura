from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/probe_release_automation_authority.py"
SPEC = importlib.util.spec_from_file_location("probe_release_automation_authority_sources", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ReleaseAutomationCredentialSourceTests(unittest.TestCase):
    def test_obsolete_dedicated_token_source_is_not_supported(self) -> None:
        with mock.patch.object(probe, "_request") as request:
            with self.assertRaisesRegex(probe.AuthorityProbeError, "credential source must be"):
                probe.probe(
                    repository="linura-org/linura",
                    token="unused",
                    base="main",
                    head="main",
                    credential_source="dedicated",
                )
        request.assert_not_called()

    def test_current_tool_contains_no_release_automation_token_compatibility(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN", source)
        self.assertNotIn('"dedicated"', source)
        self.assertIn('"github-app"', source)


if __name__ == "__main__":
    unittest.main()
