"""Adversarial tests for complete tracked-format classification and parser routing."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import check_tracked_formats as formats

ROOT = Path(__file__).resolve().parents[2]


def fixture(files: dict[str, bytes], root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for name, data in files.items():
        source = root / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(data)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)


class TrackedFormatsTests(unittest.TestCase):
    def test_real_repository_has_no_unclassified_tracked_files(self) -> None:
        inventory = formats.tracked(ROOT)
        self.assertTrue(inventory)
        for path in inventory:
            with self.subTest(path=path):
                self.assertNotEqual(
                    formats.classify(path, (ROOT / path).read_bytes()),
                    "unclassified",
                )

    def test_unknown_extension_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture({"new.unknown": b"arbitrary\n"}, root)
            errors = formats.check(root, "/missing/prettier")
            self.assertTrue(any("unclassified tracked format" in e for e in errors))

    def test_symlinked_source_and_parent_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            fixture({"dir/a.json": b"{}\n"}, root)
            outside = Path(temp) / "outside"
            (root / "dir").rename(outside)
            (root / "dir").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinked tracked source"):
                formats.tracked(root)

    def test_executable_toolchain_contract_is_rejected_from_git_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = "tools/codex/versions.env"
            fixture({contract: b"RUST_VERSION=1.98.0\n"}, root)
            (root / contract).chmod(0o755)
            subprocess.run(["git", "-C", str(root), "add", contract], check=True)
            with self.assertRaisesRegex(ValueError, "executable tracked toolchain"):
                formats.tracked(root)

    def test_protected_digest_tamper_fails(self) -> None:
        name = next(iter(formats.FROZEN_FORMAT_INPUTS))
        result = formats.format_errors(Path(name), b"changed\n", "protected")
        self.assertTrue(any("digest changed" in error for error in result))

    def test_structured_format_parsers_reject_corruption(self) -> None:
        examples = (
            ("broken.json", b"{not json}\n", "json"),
            ("duplicate.json", b'{"key": 1, "key": 2}\n', "json"),
            ("nan.json", b'{"value": NaN}\n', "json"),
            ("infinity.json", b'{"value": Infinity}\n', "json"),
            ("negative_infinity.json", b'{"value": -Infinity}\n', "json"),
            ("broken.toml", b"a = [\n", "toml"),
            ("broken.xml", b"<root>\n", "xml"),
            ("broken.ini", b"this is not ini\n", "ini"),
            ("invalid.service", b"[Service]\nExecStart /bin/true\n", "ini"),
            ("invalid.desktop", b"[Desktop Entry]\nExec /bin/true\n", "ini"),
            ("invalid.hook", b"[Action]\nExec /bin/true\n", "arch-hook"),
            (
                "continuation.service",
                b"[Service]\nExecStart=/bin/true\n BadDirective no equals\n",
                "ini",
            ),
            (
                "continuation.desktop",
                b"[Desktop Entry]\nExec=/bin/true\n Undeclared flag\n",
                "ini",
            ),
            (
                "continuation.editorconfig",
                b"root = true\n[*]\nindent_style = tab\n invalid continuation\n",
                "editorconfig",
            ),
            (
                "continuation.hook",
                b"[Action]\nExec=/bin/true\n PretendFlag\n",
                "arch-hook",
            ),
            (
                "indented_assignment.service",
                b"[Service]\nExecStart=/bin/true\n User=root\n",
                "ini",
            ),
            (
                "repeated_section.service",
                b"[Service]\nUser=one\n[Service]\nUser=two\n",
                "ini",
            ),
            (
                "repeated.service",
                b"[Service]\nExecStart=/bin/true\nExecStart=/bin/false\n",
                "ini",
            ),
            ("versions.env", b"A=1\nA=2\n", "env"),
            ("packages.linura", b"valid\nvalid\n", "packages"),
            ("linura-authority.conf", b"u unauthorized extra\n", "sysusers"),
        )
        for name, data, kind in examples:
            with self.subTest(name=name):
                self.assertTrue(formats.format_errors(Path(name), data, kind))

    def test_structured_json_accepts_distinct_nested_keys(self) -> None:
        data = b'{"left": {"id": 1}, "right": {"id": 2}}\n'
        self.assertEqual(formats.format_errors(Path("good.json"), data, "json"), [])

    def test_systemd_multivalue_directives_are_explicit(self) -> None:
        unit = (
            b"[Service]\nEnvironment=APP=one\nEnvironment=MODE=two\n"
            b"LoadCredential=token:/run/one\nLoadCredential=key:/run/two\n"
        )
        self.assertEqual(
            formats.format_errors(Path("example.service"), unit, "ini"), []
        )
        for key in ("ExecStart", "User", "Group"):
            invalid = f"[Service]\n{key}=first\n{key}=second\n".encode()
            with self.subTest(key=key):
                self.assertTrue(
                    formats.format_errors(Path("example.service"), invalid, "ini")
                )

    def test_pacman_only_allows_explicit_valueless_options(self) -> None:
        content = b"[options]\nColor\nArchitecture = auto\n"
        self.assertEqual(
            formats.format_errors(Path("pacman.conf"), content, "pacman"), []
        )
        self.assertTrue(formats.format_errors(Path("example.service"), content, "ini"))

    def test_arch_hook_allows_only_reviewed_bare_directive(self) -> None:
        valid = b"[Trigger]\nOperation = Upgrade\n[Action]\nAbortOnFail\n"
        self.assertEqual(
            formats.format_errors(Path("upgrade.hook"), valid, "arch-hook"), []
        )
        corrupt = valid.replace(b"AbortOnFail", b"Exec /bin/true")
        self.assertTrue(
            formats.format_errors(Path("upgrade.hook"), corrupt, "arch-hook")
        )

    def test_existing_policy_and_conf_formats_are_explicit(self) -> None:
        for path, expected in {
            **formats.CONF_KINDS,
            **dict.fromkeys(formats.POLKIT_RULES, "babel"),
        }.items():
            with self.subTest(path=path):
                self.assertEqual(
                    formats.classify(Path(path), (ROOT / path).read_bytes()),
                    expected,
                )
        self.assertEqual(
            formats.classify(
                Path("packaging/arch/archiso/pacman.conf"),
                (ROOT / "packaging/arch/archiso/pacman.conf").read_bytes(),
            ),
            "pacman",
        )
        self.assertEqual(
            formats.classify(Path("unreviewed.conf"), b"[Unit]\nTest=1\n"),
            "unclassified",
        )
        self.assertEqual(
            formats.classify(Path("unreviewed.rules"), b"polkit.addRule(() => {});\n"),
            "unclassified",
        )

    def test_sql_schema_inputs_are_explicit_text(self) -> None:
        for path in [
            "crates/linura-persistence-sqlite/src/protective_lock_settings_schema.sql",
            "crates/linura-persistence-sqlite/src/request_journal_schema.sql",
        ]:
            with self.subTest(path=path):
                self.assertEqual(
                    formats.classify(Path(path), (ROOT / path).read_bytes()),
                    "text",
                )

    def test_sysusers_identity_is_policy_bound(self) -> None:
        valid = (
            b'u linura-authority - "Linura managed mutation authority" '
            b"/var/lib/linura-authority /usr/sbin/nologin\n"
        )
        self.assertEqual(
            formats.format_errors(Path("linura-authority.conf"), valid, "sysusers"),
            [],
        )
        wrong = valid.replace(b"linura-authority", b"other-authority")
        self.assertTrue(
            formats.format_errors(Path("linura-authority.conf"), wrong, "sysusers")
        )

    def test_module_entrypoint_can_be_imported(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "tools.check_tracked_formats", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--prettier", result.stdout)

    def test_tracked_bytes_are_not_mutated(self) -> None:
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = b"hello   \n"
            fixture({"README.md": data}, root)
            with (
                mock.patch.object(
                    formats.shutil, "which", return_value="/tool/prettier"
                ),
                mock.patch.object(formats, "prettier_errors", return_value=[]),
                mock.patch.object(
                    formats.subprocess, "run", wraps=subprocess.run
                ) as run,
            ):

                def version_or_git(*args, **kwargs):
                    if args[0][0] == "/tool/prettier":
                        return subprocess.CompletedProcess(args[0], 0, "3.6.2\n", "")
                    return real_run(*args, **kwargs)

                run.side_effect = version_or_git
                self.assertEqual(formats.check(root, "prettier"), [])
            self.assertEqual((root / "README.md").read_bytes(), data)

    def test_prettier_command_denies_ignore_and_option_injection(self) -> None:
        with mock.patch.object(formats.subprocess, "run") as call:
            call.return_value = subprocess.CompletedProcess([], 0, "", "")
            formats.prettier_errors(
                Path("/tmp"),
                "/pinned/prettier",
                [Path("--write=.md"), Path("nested/doc.md")],
                "markdown",
            )
            args, kwargs = call.call_args
            self.assertIn("--ignore-path=/dev/null", args[0])
            self.assertIn("--with-node-modules", args[0])
            self.assertEqual(args[0][-2:], ["./--write=.md", "./nested/doc.md"])
            self.assertEqual(args[0][args[0].index("--") + 1 :], args[0][-2:])
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertNotIn("--write", args[0])
            self.assertNotIn("--check", args[0])

    def test_prettier_nonzero_exit_fails(self) -> None:
        with mock.patch.object(formats.subprocess, "run") as call:
            call.return_value = subprocess.CompletedProcess([], 2, "", "parse error")
            errors = formats.prettier_errors(
                Path("/tmp"), "/pinned/prettier", [Path("bad.yml")], "yaml"
            )
            self.assertTrue(any("rejected" in error for error in errors))

    def test_required_canonical_ci_step_is_non_optional(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("python3 -m tools.check_tracked_formats"), 1)
        body = workflow.split(
            "      - name: Verify pinned multilingual formatting\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn("python3 tools/check_multilanguage_formatting.py", body)
        self.assertIn("python3 -m tools.check_tracked_formats", body)
        self.assertIn("set -euo pipefail", body)
        self.assertNotIn("continue-on-error", body)
        self.assertNotIn("|| true", body)
        self.assertNotIn("        if:", body)


if __name__ == "__main__":
    unittest.main()
