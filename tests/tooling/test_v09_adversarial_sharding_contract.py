from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/v09-adversarial-security.yml"
SCRIPT = ROOT / "scripts/qualification/v09-adversarial-guest.sh"
CONTRACT = ROOT / "contracts/qualification-execution-envelopes.toml"

EXPECTED = [
    ("primary", 1, 2, True, False),
    ("persistence", 3, 3, False, False),
    ("security", 4, 4, False, False),
    ("connectivity", 5, 6, False, False),
    ("discovery-source", 7, 8, False, False),
    ("observation-plan", 9, 10, False, False),
    ("checkpoint", 11, 11, False, False),
    ("owner-final", 12, 13, False, True),
]


class V09AdversarialShardingContractTests(unittest.TestCase):
    def test_matrix_is_parallel_complete_and_non_overlapping(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        start = source.index("      matrix:\n        include:")
        end = source.index("    steps:", start)
        matrix = source[start:end]
        rows = re.findall(
            r"          - shard_id: ([a-z0-9-]+)\n"
            r"            boundary_start: (\d+)\n"
            r"            boundary_end: (\d+)\n"
            r"            primary: (true|false)\n"
            r"            final: (true|false)",
            matrix,
        )
        parsed = [
            (name, int(first), int(last), primary == "true", final == "true")
            for name, first, last, primary, final in rows
        ]
        self.assertEqual(parsed, EXPECTED)
        contract = tomllib.loads(CONTRACT.read_text(encoding="utf-8"))
        reviewed = [
            (
                item["id"],
                item["boundary_start"],
                item["boundary_end"],
                item["primary"],
                item["final"],
            )
            for item in contract["v09_adversarial_shard"]
        ]
        self.assertEqual(reviewed, EXPECTED)
        covered = [
            boundary
            for _, first, last, _, _ in parsed
            for boundary in range(first, last + 1)
        ]
        self.assertEqual(covered, list(range(1, 14)))
        self.assertEqual(sum(primary for _, _, _, primary, _ in parsed), 1)
        self.assertEqual(sum(final for _, _, _, _, final in parsed), 1)
        self.assertIn("fail-fast: false", source[source.index("strategy:"):start])

    def test_assembler_binds_every_parallel_shard(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        for shard_id, _first, _last, _primary, _final in EXPECTED:
            self.assertIn(
                f"name: linura-v09-adversarial-shard-{shard_id}-${{{{ inputs.source_sha || github.sha }}}}",
                source,
            )
            self.assertIn(
                f"path: /tmp/linura-v09-adversarial-shards/{shard_id}",
                source,
            )
        self.assertIn("Bind executing shard qualification envelope", source)
        self.assertIn("lane: v09-adversarial-security-shard", source)
        self.assertIn(
            "execution-subject-file: ${{ runner.temp }}/linura-v09-adversarial-artifacts/guest-execution-identity.json",
            source,
        )
        self.assertIn(
            '"/usr/bin/python3", "-I", "tools/qualification_envelope.py"',
            source,
        )
        self.assertIn('component_envelopes.append({', source)
        self.assertIn('"sha256": envelope["envelope_sha256"]', source)
        self.assertIn("COMPONENT_ENVELOPE_SET_SHA256=", source)
        self.assertIn('component_envelopes.sort(key=lambda item: item["id"])', source)
        self.assertIn("adversarial component-envelope inventory mismatch", source)
        self.assertIn("shard envelope qualification environment mismatch", source)
        self.assertIn('execution_contract.get("v09_adversarial_shard")', source)
        self.assertIn("qualification-execution-components.json", source)
        self.assertIn('"kind": "qualification-execution-component-set"', source)
        self.assertNotIn(
            '"execution_envelopes": {"sha256": component_envelope_set_sha256, "components": component_envelopes}',
            source,
        )

    def test_each_shard_captures_guest_execution_identity_before_shutdown(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        capture = source.index("qualification_guest_identity.py capture-ssh")
        evidence = source.index("evidence = {", capture)
        hard_stop = source.rindex("hard_stop")
        self.assertLess(capture, evidence)
        self.assertLess(evidence, hard_stop)
        self.assertNotIn("'guest_execution_identity': {", source)
        self.assertIn("GUEST_IDENTITY=", source)
        self.assertIn("--package-manager dpkg", source)

    def test_final_shard_qualifies_production_owned_boundary_twelve_revocation(self) -> None:
        final = next(row for row in EXPECTED if row[4])
        self.assertLessEqual(final[1], 12)
        self.assertGreaterEqual(final[2], 12)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PREPARER_SUDOERS=/etc/sudoers.d/99-linura-preparer", source)
        self.assertIn('install_text_file "$PREPARER_SUDOERS" 0440', source)
        self.assertNotIn("revoke_preparer_authority()", source)
        self.assertIn("verify_preparer_authority_revoked()", source)
        boundary = source[source.index('if [[ "$boundary" -eq 12 ]]'):]
        self.assertLess(
            boundary.index("/usr/local/bin/linura-firstboot --durable-bootstrap-step"),
            boundary.index('verify_preparer_authority_revoked "$PRODUCTION_ROOT"'),
        )
        self.assertIn("preparer_revocation_producer=production-firstboot", boundary)
        self.assertIn(
            "preparer_revocation_verifier=independent-qualification-observation",
            source,
        )
        verifier_start = source.index("verify_preparer_authority_revoked() {")
        verifier_end = source.index("\n}\n\nprovision_preparer_authority_fixture", verifier_start)
        verifier = source[verifier_start:verifier_end]
        for mutator in (
            "pkill -KILL",
            "usermod -G ''",
            "passwd -l",
            "rm -rf /home/linura-preparer/.ssh",
            "rm -f /etc/sudoers.d/99-linura-preparer",
        ):
            self.assertNotIn(mutator, verifier)
        preparer = source[
            source.index("  - name: linura-preparer") : source.index("ssh_pwauth: false")
        ]
        self.assertNotIn("    sudo:", preparer)
        self.assertIn(
            "remote \"set -euo pipefail; sudo -n rm -rf '$PUBLIC_BOOTSTRAP_ROOT';",
            source,
        )
        self.assertIn('--accel "$VM_ACCELERATION"', source)
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  VM_ACCELERATION: tcg", workflow)


if __name__ == "__main__":
    unittest.main()
