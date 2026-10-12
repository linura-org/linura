"""Protect cross-language formatter inventory and fail-closed tool contract."""

from __future__ import annotations

from pathlib import Path
import subprocess
import hashlib
import tempfile
import unittest
from unittest import mock

from tools import check_multilanguage_formatting as formatting

ROOT = Path(__file__).resolve().parents[2]


class MultilanguageFormattingTests(unittest.TestCase):
    def test_real_source_inventory_covers_each_language(self):
        files = formatting.tracked_paths(ROOT)
        self.assertEqual(len(files), len(set(files)))
        for name in formatting.EXTENSIONLESS_SHELL:
            self.assertIn(Path(name), files)
        for ext in (".cpp", ".h", ".c", ".qml", ".lua", ".sh", ".mjs"):
            self.assertTrue(any(file.suffix == ext for file in files), ext)

    def test_tracked_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "unsafe.cpp"
            source.write_text("int x;\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "unsafe.cpp"], check=True)
            self.assertEqual(formatting.tracked_paths(root), [Path("unsafe.cpp")])
            source.unlink()
            source.symlink_to("outside.cpp")
            with self.assertRaisesRegex(RuntimeError, "unsafe tracked format input"):
                formatting.tracked_paths(root)

    def test_extensionless_shell_uses_shebang_detection(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "helper"
            source.write_text("#!/usr/bin/bash\necho ready\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "helper"], check=True)
            self.assertIn(Path("helper"), formatting.tracked_paths(root))

    def test_formatter_pin_set_and_editor_styles(self):
        self.assertEqual(formatting.REQUIRED_VERSION["prettier"], "3.6.2")
        self.assertEqual(formatting.REQUIRED_VERSION["qmlformat"], "qmlformat 6.4.2")
        for path in (
            ".clang-format",
            ".qmlformat.ini",
            ".stylua.toml",
            ".prettierrc.json",
        ):
            self.assertTrue((ROOT / path).is_file(), path)

    def test_exact_digest_format_exceptions_are_explicit(self):
        self.assertEqual(len(formatting.FROZEN_FORMAT_INPUTS), 16)
        for path, digest in formatting.FROZEN_FORMAT_INPUTS.items():
            self.assertEqual(len(digest), 64)
            self.assertIn(Path(path), formatting.tracked_paths(ROOT))
            self.assertEqual(
                hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                digest,
                path,
            )

    def test_canonical_ci_formatter_check_cannot_be_bypassed(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("      - name: Verify pinned multilingual formatting\n"), 1
        )
        step = workflow.split(
            "      - name: Verify pinned multilingual formatting\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn("set -euo pipefail", step)
        self.assertIn("python3 tools/check_multilanguage_formatting.py", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("|| true", step)
        self.assertNotIn("        if:", step)
        self.assertIn("npm ci --prefix", step)

    def test_tracked_language_variants_and_shell_shebangs(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            sources = {
                "script.in": "#!/usr/bin/env -S bash -eu\necho ready\n",
                "script.bash": "echo ready\n",
                "script.sh.in": "echo ready\n",
                "SCRIPT.SH": "echo ready\n",
                "widget.cxx": "int value;\n",
                "widget.hxx": "int value;\n",
                "module.mts": "export const value = 1;\n",
                "module.cts": "export const value = 1;\n",
                "not-shell.txt": "#!/usr/bin/env python3\nprint('ready')\n",
            }
            for name, content in sources.items():
                (root / name).write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            selected = set(formatting.tracked_paths(root))
            self.assertEqual(
                selected,
                {Path(name) for name in sources if name != "not-shell.txt"},
            )

    def test_parent_symlink_cannot_redirect_tracked_source(self):
        with tempfile.TemporaryDirectory() as path:
            parent = Path(path)
            root = parent / "repo"
            folder = root / "sources"
            folder.mkdir(parents=True)
            (folder / "unsafe.cpp").write_text("int value;\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "add", "sources/unsafe.cpp"], check=True
            )
            folder.rename(parent / "external")
            folder.symlink_to(parent / "external", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "unsafe tracked format input"):
                formatting.tracked_paths(root)

    def test_mutated_format_exception_fails_closed(self):
        path = next(iter(formatting.FROZEN_FORMAT_INPUTS))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / path
            source.parent.mkdir(parents=True)
            source.write_bytes(b"unauthorized change\n")
            with (
                mock.patch.object(
                    formatting, "tracked_paths", return_value=[Path(path)]
                ),
                mock.patch.object(formatting.shutil, "which", return_value=None),
            ):
                errors = formatting.check(root)
            self.assertTrue(
                any(
                    "protected format-exception source digest changed" in error
                    for error in errors
                )
            )

    def test_shfmt_drift_fails_even_on_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "script.sh").write_text("echo ready\n", encoding="utf-8")

            def fake_command(program, *args, **kwargs):
                if args == ("--version",):
                    return subprocess.CompletedProcess(
                        args, 0, formatting.REQUIRED_VERSION[program], ""
                    )
                if program == "shfmt":
                    return subprocess.CompletedProcess(args, 0, "format drift", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(
                    formatting, "tracked_paths", return_value=[Path("script.sh")]
                ),
                mock.patch.object(formatting.shutil, "which", side_effect=lambda p: p),
                mock.patch.object(formatting, "command", side_effect=fake_command),
            ):
                errors = formatting.check(root)
            self.assertTrue(any(error.startswith("shfmt:") for error in errors))

    def test_qmlformat_uses_source_relative_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "ui" / "Screen.qml"
            source.parent.mkdir()
            source.write_text("import QtQuick\nItem {}\n", encoding="utf-8")
            (root / ".qmlformat.ini").write_bytes(
                (ROOT / ".qmlformat.ini").read_bytes()
            )
            inspected: list[bool] = []

            def fake_command(program, *args, **kwargs):
                if args == ("--version",):
                    return subprocess.CompletedProcess(
                        args, 0, formatting.REQUIRED_VERSION[program], ""
                    )
                if program == "qmlformat":
                    candidate = Path(args[-1])
                    config = candidate.parent.parent / ".qmlformat.ini"
                    inspected.append(
                        config.read_bytes() == (root / ".qmlformat.ini").read_bytes()
                    )
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(
                    formatting, "tracked_paths", return_value=[Path("ui/Screen.qml")]
                ),
                mock.patch.object(formatting.shutil, "which", side_effect=lambda p: p),
                mock.patch.object(formatting, "command", side_effect=fake_command),
            ):
                self.assertEqual(formatting.check(root), [])
            self.assertEqual(inspected, [True])

    def test_prettier_cannot_interpret_tracked_filename_as_option(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("--write=.js", "CAPS.JS"):
                (root / name).write_text("const x=1;\n", encoding="utf-8")
            captured = []

            def fake_command(program, *args, **kwargs):
                if args == ("--version",):
                    return subprocess.CompletedProcess(
                        args, 0, formatting.REQUIRED_VERSION[program], ""
                    )
                if program == "prettier":
                    captured.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(
                    formatting,
                    "tracked_paths",
                    return_value=[Path("--write=.js"), Path("CAPS.JS")],
                ),
                mock.patch.object(formatting.shutil, "which", side_effect=lambda p: p),
                mock.patch.object(formatting, "command", side_effect=fake_command),
            ):
                self.assertEqual(formatting.check(root), [])
            self.assertEqual(len(captured), 1)
            self.assertEqual(
                captured[0][:5],
                (
                    "--check",
                    "--config=.prettierrc.json",
                    "--ignore-path=/dev/null",
                    "--with-node-modules",
                    "--",
                ),
            )
            self.assertIn("--write=.js", captured[0][5:])
            self.assertIn("CAPS.JS", captured[0][5:])

    def test_uppercase_shell_suffix_reaches_shfmt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SCRIPT.SH").write_text("echo ready\n", encoding="utf-8")
            inspected = []

            def fake_command(program, *args, **kwargs):
                if args == ("--version",):
                    return subprocess.CompletedProcess(
                        args, 0, formatting.REQUIRED_VERSION[program], ""
                    )
                if program == "shfmt":
                    inspected.extend(args)
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(
                    formatting,
                    "tracked_paths",
                    return_value=[Path("SCRIPT.SH")],
                ),
                mock.patch.object(formatting.shutil, "which", side_effect=lambda p: p),
                mock.patch.object(formatting, "command", side_effect=fake_command),
            ):
                self.assertEqual(formatting.check(root), [])
            self.assertIn("SCRIPT.SH", inspected)


if __name__ == "__main__":
    unittest.main()
