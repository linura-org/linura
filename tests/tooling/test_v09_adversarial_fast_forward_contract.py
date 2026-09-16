from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualification/v09-adversarial-guest.sh"


class V09AdversarialFastForwardContractTests(unittest.TestCase):
    def test_q8_helper_is_genuinely_out_of_band_from_qualification_ssh(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("run_security_baseline_step() {")
        end = source.index("\n}\n\nstart_guest()", start)
        helper = source[start:end]

        self.assertIn("systemd-run --quiet", helper)
        self.assertIn("--no-block", helper)
        self.assertIn("--on-active=10s", helper)
        self.assertIn("--property=StandardInput=null", helper)
        self.assertIn("--property=StandardOutput=journal", helper)
        self.assertIn("--property=StandardError=journal", helper)
        self.assertIn("</dev/null >/dev/null 2>&1", helper)
        systemd_run = next(line for line in helper.splitlines() if "systemd-run" in line)
        self.assertIn("'$Q8_OBSERVER'", systemd_run)
        self.assertNotIn("/bin/bash -c", systemd_run)
        self.assertNotIn("ssh.service", systemd_run)
        self.assertNotIn("sshd.service", systemd_run)
        self.assertNotIn("linura-qualification-transport.service", systemd_run)
        self.assertIn(
            "systemctl disable --now linura-qualification-transport.service",
            source,
        )
        self.assertIn(
            "systemctl mask --runtime ssh.service sshd.service ssh.socket sshd.socket",
            source,
        )
        self.assertNotIn("systemctl unmask --runtime", helper)
        self.assertIn("linura-firstboot --durable-bootstrap-step", source)
        self.assertIn(
            "systemctl enable --now linura-qualification-transport.service",
            source,
        )
        self.assertIn("systemctl is-active --quiet linura-qualification-transport.service", source)
        self.assertIn("install_text_file \"$Q8_OBSERVER\" 0755", source)
        self.assertIn("stable=", source)
        self.assertIn("test -s", helper)
        self.assertIn("__LINURA_Q8_OUTPUT__", helper)

    def test_fast_forward_and_real_boundary_four_use_the_isolated_helper(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("if (( V09_BOUNDARY_START > 1 )); then", source.index("durable-bootstrap-init"))
        end = source.index("printf 'qualification_fast_forwarded_through=", start)
        fast_forward = source[start:end]

        self.assertIn('if [[ "$boundary" -eq 4 ]]; then', fast_forward)
        self.assertIn("run_security_baseline_step >/dev/null", fast_forward)
        self.assertIn(
            'run_security_baseline_step | tee -a "$TRANSCRIPT"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
