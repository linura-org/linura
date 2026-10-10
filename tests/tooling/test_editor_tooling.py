from __future__ import annotations

from pathlib import Path
import json
import re
import stat
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


def version_contract() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (ROOT / "tools/codex/versions.env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


class EditorToolingTests(unittest.TestCase):
    def test_cli_entrypoints_retain_executable_modes(self) -> None:
        for relative in (
            "scripts/preflight_codex_environment.sh",
            "tools/make_checksums.py",
            "tools/visual.py",
            "tools/vm.py",
        ):
            with self.subTest(path=relative):
                self.assertTrue(
                    (ROOT / relative).stat().st_mode & stat.S_IXUSR,
                    f"{relative} lost its reviewed direct-execution permission",
                )

    def test_vscode_recommends_the_reviewed_language_tools(self) -> None:
        data = json.loads((ROOT / ".vscode/extensions.json").read_text(encoding="utf-8"))
        required = {
            "rust-lang.rust-analyzer",
            "ms-python.python",
            "ms-python.vscode-pylance",
            "charliermarsh.ruff",
        }
        self.assertTrue(required.issubset(set(data["recommendations"])))

    def test_language_rulers_and_editor_analysis_are_deliberate(self) -> None:
        data = json.loads((ROOT / ".vscode/settings.json").read_text(encoding="utf-8"))
        self.assertEqual(data["[rust]"]["editor.rulers"], [100, 120, 140])
        self.assertEqual(data["[python]"]["editor.rulers"], [88, 100, 120])
        self.assertEqual(data["python.analysis.typeCheckingMode"], "basic")
        self.assertTrue(data["[rust]"]["editor.formatOnSave"])
        self.assertFalse(data["[python]"]["editor.formatOnSave"])

    def test_ruff_rule_baseline_is_explicit_and_version_aligned(self) -> None:
        config = tomllib.loads((ROOT / "ruff.toml").read_text(encoding="utf-8"))
        self.assertEqual(config["line-length"], 88)
        self.assertEqual(config["target-version"], "py312")
        self.assertEqual(
            config["per-file-target-version"]["bindings/python/**/*.py"],
            "py310",
        )
        self.assertEqual(config["lint"]["select"], ["E4", "E7", "E9", "F"])

        lock = (ROOT / "tools/python/ruff-requirements.lock").read_text(encoding="utf-8")
        match = re.search(r"(?m)^ruff==([^ \\]+)", lock)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), version_contract()["RUFF_VERSION"])

    def test_ruff_is_wired_into_canonical_development_paths(self) -> None:
        xtask = (ROOT / "tools/xtask/src/main.rs").read_text(encoding="utf-8")
        self.assertIn('run("ruff", &["check", "."])?;', xtask)
        for path in (
            "scripts/setup_codex_environment.sh",
            "scripts/preflight_codex_environment.sh",
            ".github/workflows/ci.yml",
            ".github/workflows/reusable-release-build.yml",
        ):
            text = (ROOT / path).read_text(encoding="utf-8")
            self.assertIn("RUFF_VERSION", text, path)
            self.assertIn("ruff-requirements.lock", text, path)

    def test_future_python_type_checker_is_an_explicit_single_choice(self) -> None:
        text = (ROOT / "docs/development-infrastructure.md").read_text(encoding="utf-8")
        self.assertIn("Pyright versus mypy", text)
        self.assertIn("choose one canonical checker", text)


if __name__ == "__main__":
    unittest.main()
