"""Verify that source formatting checks reject changed and malformed tracked bytes."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from tools import check_source_formatting as formatting

ROOT = Path(__file__).resolve().parents[2]


class SourceFormattingTests(unittest.TestCase):
    def test_tracked_repository_passes(self):
        self.assertEqual(formatting.check(ROOT), [])

    def test_extensionless_shell_is_always_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            fixture = root / "qualification/v010/shell-runtime/fixtures/forking-app"
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(b"#!/usr/bin/bash\necho ready\n")
            future = root / "future-command"
            future.write_bytes(b"#!/usr/bin/env -S bash\necho ready\n")
            other = root / "NOTICE"
            other.write_bytes(b"intentionally missing final newline")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual(formatting.check(root), [])
            for path in (fixture, future):
                with self.subTest(path=path.name):
                    path.write_bytes(path.read_bytes() + b"unsafe trailing space  \n")
                    self.assertTrue(
                        any(
                            "trailing whitespace" in message
                            for message in formatting.check(root)
                        )
                    )
                    path.write_bytes(b"#!/usr/bin/bash\necho ready\n")
            fixture.write_bytes(b"missing shebang without final newline")
            self.assertTrue(
                any(
                    "missing final newline" in message
                    for message in formatting.check(root)
                )
            )

    def test_future_recognized_language_suffix_is_covered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name in (
                "a.ts",
                "b.tsx",
                "c.jsx",
                "d.cjs",
                "e.cxx",
                "f.hh",
                "g.bash",
                "h.cmake",
                "i.pyi",
                "j.mts",
                "k.cts",
            ):
                (root / name).write_bytes(b"bad   \n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            violations = formatting.check(root)
            for name in (
                "a.ts",
                "b.tsx",
                "c.jsx",
                "d.cjs",
                "e.cxx",
                "f.hh",
                "g.bash",
                "h.cmake",
                "i.pyi",
                "j.mts",
                "k.cts",
            ):
                with self.subTest(name=name):
                    self.assertTrue(
                        any(message.startswith(f"{name}:") for message in violations),
                        violations,
                    )

    def test_env_shebang_options_and_assignments_cannot_bypass_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            script = root / "future-shell"
            script.write_bytes(b"#!/usr/bin/env -S bash\necho ready\n")
            subprocess.run(["git", "-C", str(root), "add", "future-shell"], check=True)
            shebangs = (
                b"#!/usr/bin/env -S FOO=bar bash\n",
                b"#!/usr/bin/env -S -i bash\n",
                b"#!/usr/bin/env -S -u FOO bash\n",
                b"#!/usr/bin/env -S --ignore-environment bash\n",
                b"#!/usr/bin/env -S python3\n",
            )
            for shebang in shebangs:
                with self.subTest(shebang=shebang):
                    script.write_bytes(shebang + b"echo ready\n")
                    self.assertEqual(formatting.check(root), [])
                    script.write_bytes(shebang + b"echo unsafe  \n")
                    self.assertTrue(
                        any(
                            error.startswith("future-shell:")
                            and "trailing whitespace" in error
                            for error in formatting.check(root)
                        )
                    )

    def test_uppercase_language_suffixes_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name in ("SOURCE.CPP", "MODULE.PY", "STUB.PYI", "BUNDLE.MJS"):
                (root / name).write_bytes(b"value = 1  \n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            violations = formatting.check(root)
            for name in ("SOURCE.CPP", "MODULE.PY", "STUB.PYI", "BUNDLE.MJS"):
                with self.subTest(name=name):
                    self.assertTrue(
                        any(
                            error.startswith(f"{name}:")
                            and "trailing whitespace" in error
                            for error in violations
                        ),
                        violations,
                    )

    def test_shebang_scripts_with_unknown_suffixes_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            scripts = (
                "launcher.in",
                "bootstrap.template",
                "runner.config",
                "entrypoint",
            )
            for name in scripts:
                (root / name).write_bytes(
                    b"#!/usr/bin/env -S FOO=bar bash\necho ready\n"
                )
            metadata = root / "regular-data.txt"
            metadata.write_bytes(b"unrelated data with whitespace  \n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual(formatting.check(root), [])
            for name in scripts:
                with self.subTest(name=name):
                    path = root / name
                    path.write_bytes(b"#!/usr/bin/bash\necho ready  \n")
                    self.assertTrue(
                        any(
                            error.startswith(f"{name}:")
                            and "trailing whitespace" in error
                            for error in formatting.check(root)
                        )
                    )
                    path.write_bytes(b"#!/usr/bin/bash\necho ready\n")
            self.assertEqual(formatting.check(root), [])

    def test_shebang_script_symlink_with_unknown_suffix_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "launcher.in"
            source.write_bytes(b"#!/bin/sh\necho ready\n")
            subprocess.run(["git", "-C", str(root), "add", "launcher.in"], check=True)
            self.assertEqual(formatting.check(root), [])
            source.unlink()
            source.symlink_to(root / "not-a-script")
            self.assertTrue(
                any(
                    error.startswith("launcher.in:") and "symlinked" in error
                    for error in formatting.check(root)
                )
            )

    def test_symlinked_ancestor_cannot_redirect_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "src" / "example.ts"
            source.parent.mkdir()
            source.write_text("export const safe = true;\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual(formatting.check(root), [])
            relocated = Path(directory) / "untrusted"
            source.parent.rename(relocated)
            (root / "src").symlink_to(relocated, target_is_directory=True)
            self.assertTrue(
                any("symlinked" in error for error in formatting.check(root))
            )

    def test_python_multiline_string_preserves_only_literal_whitespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "example.py"
            stub = root / "example.pyi"
            preserved = b'value = """first  \nsecond trailing  \nlast"""\n'
            source.write_bytes(preserved)
            stub.write_bytes(preserved)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual(formatting.check(root), [])
            cases = (
                b'value = """first\nlast"""   \n',
                b'value = """first\nlast"""\t\n',
                b'value = """first\nlast"""  # comment  \n',
                b'first = """a\nb"""\nsecond = """c\nd"""   \n',
            )
            for candidate in (source, stub):
                for value in cases:
                    with self.subTest(path=candidate.name, content=value):
                        candidate.write_bytes(value)
                        errors = formatting.check(root)
                        self.assertTrue(
                            any(
                                message.startswith(f"{candidate.name}:")
                                and "trailing whitespace" in message
                                for message in errors
                            ),
                            errors,
                        )
                candidate.write_bytes(preserved)
            self.assertEqual(formatting.check(root), [])

    def test_invalid_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            target = root / "example.cpp"
            target.write_text("int main() { return 0; }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "example.cpp"], check=True)
            cases = (
                (b"int x;\r\n", "non-LF line ending"),
                (b"int x;  \n", "trailing whitespace"),
                (b"\tint x;\n", "tab indentation/content"),
                (b"int x;", "missing final newline"),
                (b"int x;\0\n", "NUL byte"),
                (b"\xff\n", "non-UTF-8 source bytes"),
            )
            for content, expected in cases:
                with self.subTest(expected=expected):
                    target.write_bytes(content)
                    self.assertTrue(
                        any(expected in error for error in formatting.check(root))
                    )
            target.unlink()
            target.symlink_to(root / "outside.txt")
            self.assertTrue(
                any("symlinked" in error for error in formatting.check(root))
            )


if __name__ == "__main__":
    unittest.main()
