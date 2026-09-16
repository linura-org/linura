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
        self.assertIn('"$PREPARER_SSH_USER@127.0.0.1" true', source)

    def test_non_primary_transport_handoff_crosses_a_durable_power_cycle(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index('if (( V09_BOUNDARY_START > 1 )); then\n  power_cycle "qualification-transport-handoff"')
        end = source.index("\nfi\n\nif ! remote 'command -v nft", start)
        handoff = source[start:end]
        persistent_mask = (
            "systemctl mask --force ssh.service sshd.service "
            "ssh.socket sshd.socket"
        )
        generator_mask = (
            "ln -sfn /dev/null "
            "/etc/systemd/system-generators/sshd-socket-generator"
        )

        self.assertIn(persistent_mask, source)
        self.assertLess(source.index(persistent_mask), start)
        self.assertIn(generator_mask, source)
        self.assertLess(source.index(generator_mask), start)
        barrier_anchor = "systemctl is-enabled --quiet linura-qualification-transport.service"
        self.assertIn(barrier_anchor, source)
        barrier_start = source.index(barrier_anchor)
        barrier_end = source.index('SSH_GUEST_PORT="$QUALIFICATION_SSH_GUEST_PORT"', barrier_start)
        durability_barrier = source[barrier_start:barrier_end]
        self.assertIn("sudo -n sync", durability_barrier)
        self.assertIn(
            'test "$(readlink "/etc/systemd/system/$unit")" = /dev/null',
            durability_barrier,
        )
        self.assertLess(source.index(persistent_mask), barrier_start)
        self.assertLess(barrier_start, start)
        self.assertIn(
            'test "$(readlink /etc/systemd/system-generators/sshd-socket-generator)" = /dev/null',
            durability_barrier,
        )
        self.assertIn("After=network.target", source)
        self.assertIn("Wants=network.target", source)
        self.assertIn("WantedBy=network.target", source)
        self.assertNotIn("After=network-online.target", source)
        self.assertNotIn("Wants=network-online.target", source)
        self.assertNotIn("WantedBy=multi-user.target", source)
        self.assertIn("QUALIFICATION_SSH_GUEST_PORT=2222", source)
        self.assertIn('--ssh-guest-port "$SSH_GUEST_PORT"', source)
        self.assertIn("/usr/sbin/sshd -D -e -p 2222", source)
        self.assertIn("StandardOutput=journal+console", source)
        self.assertIn("StandardError=journal+console", source)
        self.assertIn('SSH_GUEST_PORT="$QUALIFICATION_SSH_GUEST_PORT"', source)
        self.assertLess(
            source.index('SSH_GUEST_PORT="$QUALIFICATION_SSH_GUEST_PORT"'),
            source.index('power_cycle "qualification-transport-handoff"'),
        )
        self.assertIn("isolate_canonical_ssh()", source)
        self.assertIn('systemctl disable --now "$unit"', source)
        self.assertIn(
            'if [[ "$SSH_GUEST_PORT" == "$QUALIFICATION_SSH_GUEST_PORT" ]]',
            source,
        )
        self.assertIn("isolate_canonical_ssh", source[source.index("start_guest()") : start])
        self.assertIn('power_cycle "qualification-transport-handoff"', handoff)
        self.assertNotIn("systemctl stop", handoff)
        self.assertNotIn("enable --now", handoff)

    def test_product_bootstrap_uses_the_revocable_preparer_until_handoff(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PREPARER_SSH_USER=linura-preparer", source)
        self.assertIn("PREPARER_ACTIVE=true", source)
        self.assertIn("preparer_remote() {", source)
        self.assertIn("product_remote() {", source)
        router_start = source.index("product_remote() {")
        router_end = source.index("\n}\n\nisolate_canonical_ssh", router_start) + 2
        router = source[router_start:router_end]
        self.assertIn('if [[ "$PREPARER_ACTIVE" == true ]]', router)
        self.assertIn('preparer_remote "$1"', router)
        self.assertIn('remote "$1"', router)
        self.assertIn(
            "sudo -u linura-preparer sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step",
            source,
        )
        self.assertIn(
            'product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-init',
            source,
        )
        self.assertIn(
            'product_remote "sudo -n /usr/local/bin/linura-bootstrap-transition-qualification prepare',
            source,
        )
        self.assertIn(
            'product_remote "sudo -n /usr/local/bin/linura-bootstrap-transition-qualification effect-start',
            source,
        )
        revoke_start = source.index("revoke_preparer_authority() {")
        revoke_end = source.index("\n}\n\nmkdir -p", revoke_start)
        revoke = source[revoke_start:revoke_end]
        self.assertNotIn("authorize-preparer-revocation", revoke)
        self.assertIn("PREPARER_ACTIVE=false", revoke)
        self.assertIn("preparer_authority_revoked=actual-preparation-principal", revoke)
        self.assertIn("preparer_execution_identity=%s", source)
        self.assertIn(
            "The next production First Boot step must re-observe the real OS post-state",
            revoke,
        )

    def test_release_facing_bootstrap_is_exercised_and_reobserved_after_restart(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--bootstrap '$PRODUCTION_ROOT'", source)
        self.assertIn("production_bootstrap_entry=release-facing", source)
        self.assertIn('power_cycle \'production-bootstrap-restart\'', source)
        self.assertIn(
            "production_bootstrap_restart=reobserved-after-power-cycle",
            source,
        )


if __name__ == "__main__":
    unittest.main()
