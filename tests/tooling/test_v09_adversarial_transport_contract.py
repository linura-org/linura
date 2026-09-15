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

    def test_non_primary_transport_handoff_crosses_a_power_cycle(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("# Non-primary shards fast-forward")
        end = source.index("\nfi\n\nif ! remote 'command -v nft", start)
        handoff = source[start:end]
        persistent_mask = (
            "systemctl mask --force ssh.service sshd.service "
            "ssh.socket sshd.socket"
        )

        self.assertIn(persistent_mask, source)
        self.assertLess(source.index(persistent_mask), start)
        self.assertIn('power_cycle "qualification-transport-handoff"', handoff)
        self.assertIn(
            "systemctl is-active --quiet linura-qualification-transport.service",
            handoff,
        )
        self.assertIn(
            'if sudo -n systemctl is-active --quiet "$unit"',
            handoff,
        )
        self.assertIn("canonical SSH unit remained active after handoff", handoff)
        self.assertIn("exit 1", handoff)
        self.assertNotIn("systemctl stop", handoff)
        self.assertNotIn("enable --now", handoff)


if __name__ == "__main__":
    unittest.main()
