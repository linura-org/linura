from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualification/v09-adversarial-guest.sh"


class V09AdversarialTransportContractTests(unittest.TestCase):
    def test_ssh_and_scp_share_the_canonical_qualification_identity(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("SSH_USER=linura-qualification", source)
        self.assertIn('ssh "${SSH_COMMON[@]}" -p "$SSH_PORT" "$SSH_USER@127.0.0.1" "$1"', source)
        self.assertIn('scp "${SSH_COMMON[@]}" -P "$SSH_PORT" "target/release/$binary" "$SSH_USER@127.0.0.1:/tmp/"', source)
        self.assertNotIn("linura@127.0.0.1:/tmp/", source)
        self.assertIn("linura-preparer@127.0.0.1 true", source)


if __name__ == "__main__":
    unittest.main()
