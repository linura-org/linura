"""Adversarial validation for the v0.10 Arch substrate data-only loader."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "qualification/v010/shell-runtime/prepare-substrate.sh"
CONTRACT = ROOT / "contracts/v010-shell-runtime-substrate.toml"


def parser_source() -> str:
    builder = BUILDER.read_text(encoding="utf-8")
    start = "python3 -I -S - \"$contract_path\" <<'PY'\n"
    return builder.split(start, 1)[1].split("\nPY\n", 1)[0] + "\n"


class SubstrateContractLoadingTests(unittest.TestCase):
    def run_loader(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-S", "-", str(path)],
            input=parser_source(),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_reviewed_substrate_is_data_only(self) -> None:
        script = BUILDER.read_text(encoding="utf-8")
        self.assertNotIn('eval "$(', script)
        self.assertIn("substrate contract rejected before data loading", script)
        result = self.run_loader(CONTRACT)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        fields = lines[0].split("\t")
        self.assertEqual(len(fields), 4)
        self.assertTrue(fields[0].startswith("https://"))
        self.assertIn("$repo/os/$arch", fields[1])
        self.assertEqual(fields[2], "16")
        self.assertIn("base-devel", fields[3].split())

    def test_invalid_inputs_emit_no_shell_data(self) -> None:
        original = CONTRACT.read_text(encoding="utf-8")
        replacements = (
            ("vm_disk_size_gib = 16", "vm_disk_size_gib = -1"),
            ("vm_disk_size_gib = 16", "vm_disk_size_gib = true"),
            ('"base-devel",', '"base-devel;touch-injected",'),
            ('"base-devel",', '"base-devel",\n  "base-devel",'),
            ('"base-devel",', '["malformed"],'),
            (
                "https://archive.archlinux.org/repos/",
                "https://archive.archlinux.org;evil/repos/",
            ),
            (
                "https://geo.mirror.pkgbuild.com/images/",
                "file://geo.mirror.pkgbuild.com/images/",
            ),
            (
                "arch_archive_url = ",
                'arch_archive_url = "duplicated"\narch_archive_url = ',
            ),
            ("vm_disk_size_gib = 16", "vm_disk_size_gib = 0"),
        )
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "substrate.toml"
            for old, new in replacements:
                with self.subTest(replacement=new):
                    self.assertIn(old, original)
                    contract.write_text(original.replace(old, new, 1), encoding="utf-8")
                    result = self.run_loader(contract)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")

    def test_option_shaped_and_dot_prefixed_packages_are_rejected(self) -> None:
        original = CONTRACT.read_text(encoding="utf-8")
        marker = '"base-devel",'
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "substrate.toml"
            for package in (
                "--disable-sandbox",
                "--ignore",
                "--noconfirm",
                "--",
                "-Syu",
                "-",
                ".hidden",
                ".",
            ):
                for declaration in (
                    f'"{package}",',
                    f'"base-devel", "{package}",',
                ):
                    with self.subTest(declaration=declaration):
                        contract.write_text(
                            original.replace(marker, declaration, 1), encoding="utf-8"
                        )
                        result = self.run_loader(contract)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")
                        self.assertIn(
                            "unsafe substrate package declaration", result.stderr
                        )

    def test_valid_package_punctuation_is_preserved(self) -> None:
        original = CONTRACT.read_text(encoding="utf-8")
        packages = (
            "a",
            "7zip",
            "libstdc++",
            "foo.bar",
            "foo@bar",
            "_foo",
            "+foo",
            "@foo",
        )
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "substrate.toml"
            for package in packages:
                with self.subTest(package=package):
                    contract.write_text(
                        original.replace('"base-devel",', f'"{package}",', 1),
                        encoding="utf-8",
                    )
                    result = self.run_loader(contract)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.split("\t")[3].split()[0], package)

    def test_install_command_separates_options_from_package_targets(self) -> None:
        script = BUILDER.read_text(encoding="utf-8")
        install = script.split("install_succeeded=0\n", 1)[1].split(
            '[[ "$install_succeeded" -eq 1 ]]', 1
        )[0]
        # Execute the actual retry/SSH block with harmless command adapters.
        # Inject option-shaped targets independently of parser rejection to
        # prove the second boundary: they must follow pacman's option terminator.
        harness = r"""set -euo pipefail
timeout() {
    [[ "$1" == --signal=TERM && "$2" == --kill-after=10s && "$3" == 720 ]] || return 1
    shift 3
    "$@"
}
sudo() {
    [[ "$1" == -n ]] || return 1
    shift
    "$@"
}
pacman() { printf 'PACMAN_ARG:%s\n' "$@"; }
export -f timeout sudo pacman
ssh() { bash --noprofile --norc -c "${!#}"; }
ssh_common=()
install_succeeded=0
"""
        loaded = self.run_loader(CONTRACT)
        self.assertEqual(loaded.returncode, 0, loaded.stderr)
        for packages in (
            loaded.stdout.split("\t")[3].strip(),
            "base-devel --disable-sandbox --ignore",
        ):
            with self.subTest(packages=packages):
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-s"],
                    input=harness + install,
                    env={"PATH": os.defpath, "RUNTIME_PACKAGES": packages},
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = [
                    line.removeprefix("PACMAN_ARG:")
                    for line in result.stdout.splitlines()
                    if line.startswith("PACMAN_ARG:")
                ]
                self.assertEqual(
                    arguments,
                    [
                        "-Syu",
                        "--noconfirm",
                        "--needed",
                        "--disable-download-timeout",
                        "--",
                        *packages.split(),
                    ],
                )

    def test_symlink_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "source.toml"
            target.write_bytes(CONTRACT.read_bytes())
            alias = root / "contract.toml"
            alias.symlink_to(target)
            result = self.run_loader(alias)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
