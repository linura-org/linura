from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import tomllib
import unittest

from tools import workstation_acceptance

ROOT = Path(__file__).resolve().parents[2]


class WorkstationAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = tomllib.loads(
            (ROOT / "contracts/v010-workstation-acceptance.toml").read_text(encoding="utf-8")
        )

    def test_repository_contract_is_valid(self) -> None:
        self.assertEqual(workstation_acceptance.validate_contract(self.contract), [])

    def test_automated_mode_is_headless_and_recorded(self) -> None:
        payload = workstation_acceptance.plan_payload(
            self.contract, "automated", "none", False
        )
        self.assertEqual(payload["display"], "none")
        self.assertTrue(payload["recording"])
        self.assertFalse(payload["release_support_promotion"])

    def test_interactive_mode_supports_live_recording(self) -> None:
        payload = workstation_acceptance.plan_payload(
            self.contract, "interactive", "gtk", True
        )
        self.assertEqual(payload["launcher"], self.contract["interactive_launcher"])
        self.assertTrue(payload["recording"])

    def test_hardware_mode_never_routes_through_vm_launcher(self) -> None:
        payload = workstation_acceptance.plan_payload(
            self.contract, "hardware", "none", True
        )
        self.assertEqual(payload["launcher"], self.contract["hardware_capture"])
        self.assertNotEqual(payload["launcher"], self.contract["vm_launcher"])

    def test_automated_mode_rejects_visible_host_display(self) -> None:
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "automated mode requires display=none",
        ):
            workstation_acceptance.plan_payload(
                self.contract, "automated", "gtk", False
            )

    def test_recording_probe_requires_exact_bounded_video_shape(self) -> None:
        recording = self.contract["recording"]
        probe = {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "ffv1",
                    "width": 1280,
                    "height": 800,
                }
            ],
            "format": {"format_name": "matroska,webm", "duration": "3.25"},
        }
        summary = workstation_acceptance.validate_probe_payload(
            probe,
            file_size=4096,
            recording_contract=recording,
        )
        self.assertEqual(summary["codec"], "ffv1")
        self.assertEqual(summary["width"], 1280)
        self.assertEqual(summary["duration_seconds"], 3.25)

    def test_recording_probe_rejects_audio(self) -> None:
        probe = {
            "streams": [
                {"codec_type": "video", "codec_name": "ffv1", "width": 1280, "height": 800},
                {"codec_type": "audio", "codec_name": "opus"},
            ],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "must not contain audio",
        ):
            workstation_acceptance.validate_probe_payload(
                probe,
                file_size=4096,
                recording_contract=self.contract["recording"],
            )

    def test_recording_probe_rejects_unbounded_dimensions(self) -> None:
        recording = copy.deepcopy(self.contract["recording"])
        probe = {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "ffv1",
                    "width": recording["maximum_width"] + 1,
                    "height": 800,
                }
            ],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "dimensions exceed",
        ):
            workstation_acceptance.validate_probe_payload(
                probe,
                file_size=4096,
                recording_contract=recording,
            )

    def test_recording_file_rejects_symlink_before_ffprobe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.mkv"
            target.write_bytes(b"x" * 4096)
            link = root / "recording.mkv"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                workstation_acceptance.AcceptanceError,
                "missing or unsafe",
            ):
                workstation_acceptance.verify_recording(
                    link,
                    contract=self.contract,
                )


if __name__ == "__main__":
    unittest.main()
