from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
QUALIFICATION = ROOT / ".github/workflows/v09-qualification.yml"
GUEST = ROOT / "scripts/qualification/v09-adversarial-guest.sh"

BINARIES = (
    "linura-firstboot",
    "linura-bootstrap-qualification",
    "linura-bootstrap-transition-qualification",
    "linura-migrations-qualification",
    "linura-update-qualification",
    "linura-update-evidence-verifier-qualification",
)


class V09AdversarialBinaryContractTests(unittest.TestCase):
    def test_artifact_producer_and_guest_bind_the_same_required_binary_set(self) -> None:
        qualification = QUALIFICATION.read_text(encoding="utf-8")
        guest = GUEST.read_text(encoding="utf-8")
        for binary in BINARIES:
            self.assertIn(f"target/release/{binary}", qualification)
            self.assertIn(binary, guest)

    def test_guest_normalizes_artifact_modes_for_every_required_binary(self) -> None:
        guest = GUEST.read_text(encoding="utf-8")
        self.assertIn('test -f "target/release/$binary"', guest)
        self.assertIn('chmod 0755 "target/release/$binary"', guest)
        self.assertNotIn('test -x "target/release/$binary"', guest)


if __name__ == "__main__":
    unittest.main()
