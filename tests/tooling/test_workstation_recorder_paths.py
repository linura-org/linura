from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RECORDER = ROOT / "qualification/v010/workstation-acceptance/record-session.sh"
CAPTURE = ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"


class RecorderStoragePathTests(unittest.TestCase):
    def test_guarded_recording_requires_exact_checked_private_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch = (
                root
                / "volume with spaces"
                / "qualification"
                / "runs"
                / "identity"
                / "arch-hyprland-hardware"
                / "physical-001"
                / "source-sha"
                / "scratch"
            )
            scratch.mkdir(parents=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                r"""#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
    */tools/development_storage.py)
        [[ "$*" == *" --environment arch-hyprland-hardware "* ]] || exit 81
        [[ "$*" == *" --run physical-001 "* ]] || exit 82
        [[ "$*" == *" check --role temporary --path $LINURA_TEST_SCRATCH" ]] || exit 83
        [[ "${LINURA_TEST_STORAGE_DENY:-0}" == 0 ]] || exit 84
        printf '%s\n' "${LINURA_TEST_STORAGE_REPLY:-$LINURA_TEST_SCRATCH}"
        ;;
    */tools/workstation_acceptance.py)
        printf '{"sha256":"test"}\n'
        ;;
    *) exit 85 ;;
esac
""",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            path = scratch / "hardware-test.mkv"
            base_env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                "LINURA_SOURCE_ROOT": str(ROOT),
                "LINURA_RUN_ID": "physical-001",
                "TMPDIR": str(scratch),
                "LINURA_TEST_SCRATCH": str(scratch),
            }

            def check(
                candidate: Path,
                overrides: Mapping[str, str | None] | None = None,
            ):
                env = base_env.copy()
                for key, value in (overrides or {}).items():
                    if value is None:
                        env.pop(key, None)
                    else:
                        env[key] = value
                return subprocess.run(
                    ["bash", str(RECORDER), "verify", str(candidate)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

            success = check(path)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertIn('"sha256":"test"', success.stdout)
            aliases = root / "alias"
            aliases.symlink_to(scratch, target_is_directory=True)
            legacy_alias = root / "legacy-alias"
            legacy_alias.symlink_to(
                Path("/tmp/linura-workstation-live"), target_is_directory=True
            )
            denied = (
                (path, {"LINURA_RUN_ID": None}, "prepared run identity"),
                (path, {"TMPDIR": None}, "prepared run identity"),
                (path, {"LINURA_TEST_STORAGE_DENY": "1"}, "storage validation"),
                (
                    path,
                    {"LINURA_TEST_STORAGE_REPLY": str(root / "wrong-scratch")},
                    "canonical namespace",
                ),
                (scratch / "child" / "hardware-test.mkv", {}, "directly under"),
                (aliases / "hardware-test.mkv", {}, "symlinks"),
                (legacy_alias / "hardware-test.mkv", {}, "symlinks"),
                (scratch / ".." / "hardware-test.mkv", {}, "traverse"),
            )
            for candidate, overrides, error in denied:
                with self.subTest(candidate=candidate, overrides=overrides):
                    result = check(candidate, overrides)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)
                    self.assertNotIn('"sha256":"test"', result.stdout)

    def test_every_recorder_phase_validates_and_capture_exports_run(self) -> None:
        recorder = RECORDER.read_text(encoding="utf-8")
        capture = CAPTURE.read_text(encoding="utf-8")
        phases = ("start", "stop", "abort", "verify")
        for index, phase in enumerate(phases):
            start = recorder.index(f"    {phase})\n")
            end = (
                recorder.index(f"    {phases[index + 1]})\n")
                if index + 1 < len(phases)
                else recorder.index("    *)\n", start)
            )
            self.assertIn(
                'path="$(safe_recording_path "$recording_path")"',
                recorder[start:end],
            )
        self.assertEqual(capture.count('export LINURA_RUN_ID="$run_id"'), 1)
        self.assertLess(
            capture.index('export LINURA_RUN_ID="$run_id"'),
            capture.index('"$recorder" start "$recording"'),
        )


if __name__ == "__main__":
    unittest.main()
