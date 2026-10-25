from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_gpu_pm",
    ROOT / "qualification/v010/shell-runtime/check-gpu-pm.py",
)
assert SPEC is not None and SPEC.loader is not None
GPU_PM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GPU_PM)


def endpoint() -> bytearray:
    config = bytearray(256)
    config[:4] = bytes.fromhex("f41a5010")
    config[0x06] = 0x10
    config[0x34] = 0x40
    config[0x40:0x44] = bytes((0x10, 0x60, 0x02, 0))
    config[0x60:0x66] = bytes((0x01, 0, 0x03, 0, 0x08, 0))
    return config


class GpuPowerManagementTests(unittest.TestCase):
    def test_preserved_express_endpoint(self) -> None:
        GPU_PM.validate_config(bytes(endpoint()))

    def test_missing_reset_preservation_or_nonactive_endpoint(self) -> None:
        for control in (0, 1, 2, 3, 9, 10, 11):
            with self.subTest(control=control):
                config = endpoint()
                config[0x64] = control
                with self.assertRaises(ValueError):
                    GPU_PM.validate_config(bytes(config))

    def test_truncated_or_substituted_device(self) -> None:
        for config in (bytes(256), bytes(endpoint()[:255]), bytes(endpoint()) + b"0"):
            with self.subTest(length=len(config)):
                with self.assertRaises(ValueError):
                    GPU_PM.validate_config(config)
        for offset, value in ((0, 0), (2, 0), (6, 0), (0x0E, 1), (0x42, 0x42)):
            with self.subTest(offset=offset):
                config = endpoint()
                config[offset] = value
                with self.assertRaises(ValueError):
                    GPU_PM.validate_config(bytes(config))

    def test_missing_or_ambiguous_capabilities(self) -> None:
        for offset, value in (
            (0x34, 0),
            (0x40, 0),
            (0x60, 0),
            (0x61, 0x80),
        ):
            with self.subTest(offset=offset):
                config = endpoint()
                config[offset] = value
                if offset == 0x61:
                    config[0x80:0x86] = bytes((0x01, 0, 0x03, 0, 0x08, 0))
                with self.assertRaises(ValueError):
                    GPU_PM.validate_config(bytes(config))

    def test_capability_links_are_bounded_aligned_and_acyclic(self) -> None:
        for pointer in (1, 0x3C, 0x41, 0x40, 0xFD, 0xFF):
            with self.subTest(pointer=pointer):
                config = endpoint()
                config[0x61] = pointer
                with self.assertRaises(ValueError):
                    GPU_PM.validate_config(bytes(config))
        config = endpoint()
        config[0x41] = 0xFC
        config[0xFC] = 0x01
        with self.assertRaises(ValueError):
            GPU_PM.validate_config(bytes(config))


if __name__ == "__main__":
    unittest.main()
