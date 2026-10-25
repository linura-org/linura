#!/usr/bin/env python3
"""Read only the qualification GPU's bounded PCI power-management facts."""

from __future__ import annotations

from pathlib import Path


def validate_config(config: bytes) -> None:
    if (
        len(config) != 256
        or config[:4] != bytes.fromhex("f41a5010")
        or config[0x0E] & 0x7F != 0
        or not config[0x06] & 0x10
    ):
        raise ValueError("unexpected PCI endpoint")

    pointer = config[0x34]
    seen: set[int] = set()
    power_management = 0
    express = 0
    while pointer:
        if pointer < 0x40 or pointer > 0xFC or pointer % 4 or pointer in seen:
            raise ValueError("malformed PCI capability chain")
        seen.add(pointer)
        capability = config[pointer]
        if capability == 0x01:
            power_management += 1
            if pointer > 0xF8:
                raise ValueError("truncated PCI power management")
            control = int.from_bytes(config[pointer + 4 : pointer + 6], "little")
            if not control & 0x08 or control & 0x03:
                raise ValueError("PCI suspend preservation is unavailable")
        elif capability == 0x10:
            express += 1
            flags = int.from_bytes(config[pointer + 2 : pointer + 4], "little")
            if flags & 0xF0 or not flags & 0x0F:
                raise ValueError("unexpected PCI Express endpoint")
        pointer = config[pointer + 1]

    if power_management != 1 or express != 1:
        raise ValueError("missing or ambiguous PCI power management")


def main() -> None:
    try:
        with Path("/sys/bus/pci/devices/0000:01:00.0/config").open("rb") as stream:
            validate_config(stream.read(256))
    except (OSError, ValueError):
        raise SystemExit(
            "qualification GPU power-management preflight failed"
        ) from None
    print("pci_pm_no_soft_reset=1")


if __name__ == "__main__":
    main()
