from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/v09-adversarial-security.yml"
SCRIPT = ROOT / "scripts/qualification/v09-adversarial-guest.sh"

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
        for shard_id, first, last, primary, final in EXPECTED:
            self.assertIn(
                f'"{shard_id}": ({first}, {last}, {primary}, {final})',
                source,
            )
            self.assertIn(
                f"name: linura-v09-adversarial-shard-{shard_id}-${{{{ inputs.source_sha || github.sha }}}}",
                source,
            )
            self.assertIn(
                f"path: /tmp/linura-v09-adversarial-shards/{shard_id}",
                source,
            )

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
        self.assertIn("--accel tcg", source)


if __name__ == "__main__":
    unittest.main()
