from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualification/v09-adversarial-guest.sh"


class V09AdversarialFastForwardContractTests(unittest.TestCase):
    def test_fast_forward_isolates_boundary_four_from_qualification_sshd(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("if (( V09_BOUNDARY_START > 1 )); then")
        end = source.index("printf 'qualification_fast_forwarded_through=", start)
        fast_forward = source[start:end]
        self.assertIn('if [[ "$boundary" -eq 4 ]]; then', fast_forward)
        self.assertIn(
            "systemctl disable --now linura-qualification-transport.service",
            fast_forward,
        )
        self.assertIn(
            "systemctl enable --now linura-qualification-transport.service",
            fast_forward,
        )
        self.assertIn("linura-firstboot --durable-bootstrap-step", fast_forward)

    def test_real_and_fast_forward_boundary_four_use_isolation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertGreaterEqual(
            source.count(
                "systemctl disable --now linura-qualification-transport.service"
            ),
            2,
        )
        self.assertGreaterEqual(
            source.count(
                "systemctl enable --now linura-qualification-transport.service"
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()
