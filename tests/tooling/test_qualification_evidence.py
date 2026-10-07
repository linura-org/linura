from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools import qualification_envelope as envelopes  # noqa: E402
from tools import qualification_evidence as evidence  # noqa: E402
from tools import qualification_evidence_verifiers as semantic_verifier  # noqa: E402

RUNNER_ENV = {
    "RUNNER_OS": "Linux",
    "RUNNER_ARCH": "X64",
    "ImageOS": "ubuntu24",
    "ImageVersion": "20261001.1",
}


class QualificationEvidenceTests(unittest.TestCase):
    def _v07_bundle(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="v07-library",
            source_sha=source_sha,
            digests={},
            observations={},
            verified_cache_specs=[],
            environment=RUNNER_ENV,
        )
        envelopes.write_envelope(
            directory / "qualification-execution-envelope.json", envelope
        )
        roundtrip = "a" * 64
        crash = (
            "passed: child was SIGKILLed after the uncommitted history write and before "
            "projection/operation commit; reopen exposed only the old complete state, then an "
            "exact retry committed/replayed the new complete state"
        )
        (directory / "portable-roundtrip.sha256").write_text(
            roundtrip + "\n", encoding="utf-8"
        )
        (directory / "process-crash-atomicity.txt").write_text(
            crash + "\n", encoding="utf-8"
        )
        cargo_logs = {
            "library-unit-tests.txt": (
                "Running unittests src/lib.rs (target/debug/deps/linura_library-deadbeef)\n"
            ),
            "v07-qualification-tests.txt": (
                "Running tests/v07_qualification.rs "
                "(target/debug/deps/v07_qualification-deadbeef)\n"
            ),
            "sdk-tests.txt": (
                "Running unittests src/lib.rs (target/debug/deps/linura_sdk-deadbeef)\n"
            ),
        }
        cargo_result = (
            "running 1 test\n"
            "test reviewed_semantic_witness ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; "
            "finished in 0.00s\n"
        )
        for filename, runner in cargo_logs.items():
            (directory / filename).write_text(
                runner + cargo_result, encoding="utf-8"
            )
        scenarios = [
            {"name": f"reviewed-v07-scenario-{index:02d}", "result": "passed"}
            for index in range(1, 24)
        ]
        (directory / "qualification.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": "linura-org/linura",
                    "source_sha": source_sha,
                    "result": "passed",
                    "portable_roundtrip_sha256": roundtrip,
                    "database_integrity_after_restart_recovery": "ok",
                    "process_crash_atomicity": crash,
                    "imported_approval_or_executor_authority": False,
                    "qualified_scenarios": scenarios,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return envelope

    def test_validator_is_standalone_and_integrations_are_complete(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/qualification_evidence.py"),
                "--root",
                str(ROOT),
                "validate",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode, 0, completed.stderr or completed.stdout
        )
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["schema_version"], 3)

    def test_contract_classifies_every_execution_lane_exactly_once(self):
        contract = evidence.load_contract(ROOT)
        envelope_contract = envelopes.load_contract(ROOT)
        lanes = {lane["id"] for lane in envelope_contract["lane"]}
        profiled = {profile["lane_id"] for profile in contract["profile"]}
        non_evidence = set(contract["non_evidence_lanes"])
        self.assertEqual(profiled | non_evidence, lanes)
        self.assertTrue(profiled.isdisjoint(non_evidence))
        self.assertIn("trusted-release-proof", non_evidence)
        self.assertIn("v010-maintained-hardware", non_evidence)

    def test_admission_binds_exact_reviewed_artifact_set(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            envelope = self._v07_bundle(directory)
            verifier = evidence.attest(
                root=ROOT,
                lane_id="v07-library",
                bundle=directory,
                output=directory / "verifier-result.json",
            )
            binding = evidence.bind(
                root=ROOT,
                lane_id="v07-library",
                bundle=directory,
                verifier_path=directory / "verifier-result.json",
                output=directory / "evidence-binding.json",
            )
            verified = evidence.verify_binding(
                ROOT, directory / "evidence-binding.json"
            )
            self.assertEqual(
                binding["binding_sha256"], verified["binding_sha256"]
            )
            self.assertEqual(
                verifier["artifact_set_sha256"],
                binding["artifact_set_sha256"],
            )
            self.assertEqual(
                binding["execution_envelope"]["sha256"],
                envelope["envelope_sha256"],
            )
            self.assertTrue(verifier["independent"])
            self.assertTrue(verifier["verification"]["environment_verified"])
            self.assertEqual(
                verifier["verification"]["adapter"],
                "v07-library-semantic-v1",
            )
            self.assertTrue(verifier["verification"]["verified_claims"])
            self.assertEqual(
                {
                    item["role"]
                    for item in binding["artifacts"]
                    if item["required"]
                },
                {
                    "result",
                    "portable_roundtrip_digest",
                    "process_crash_atomicity",
                    "library_unit_transcript",
                    "qualification_matrix_transcript",
                    "sdk_transcript",
                },
            )

    def test_artifact_substitution_after_verification_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            evidence.attest(
                root=ROOT,
                lane_id="v07-library",
                bundle=directory,
                output=directory / "verifier-result.json",
            )
            (directory / "process-crash-atomicity.txt").write_text(
                "substituted\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                evidence.EvidenceError, "artifact-set mismatch"
            ):
                evidence.bind(
                    root=ROOT,
                    lane_id="v07-library",
                    bundle=directory,
                    verifier_path=directory / "verifier-result.json",
                    output=directory / "evidence-binding.json",
                )

    def test_auxiliary_retained_files_are_bound_without_becoming_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            auxiliary = directory / "diagnostic.log"
            auxiliary.write_text("diagnostic\n", encoding="utf-8")
            evidence.attest(
                root=ROOT,
                lane_id="v07-library",
                bundle=directory,
                output=directory / "verifier-result.json",
            )
            binding = evidence.bind(
                root=ROOT,
                lane_id="v07-library",
                bundle=directory,
                verifier_path=directory / "verifier-result.json",
                output=directory / "evidence-binding.json",
            )
            entry = next(
                item for item in binding["artifacts"]
                if item["path"] == "diagnostic.log"
            )
            self.assertEqual(entry["role"], "retained-auxiliary")
            self.assertFalse(entry["required"])
            auxiliary.write_text("substituted\n", encoding="utf-8")
            with self.assertRaises(evidence.EvidenceError):
                evidence.verify_binding(
                    ROOT, directory / "evidence-binding.json"
                )

    def test_missing_required_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            (directory / "portable-roundtrip.sha256").unlink()
            with self.assertRaisesRegex(
                evidence.EvidenceError, "missing or unsafe"
            ):
                evidence.attest(
                    root=ROOT,
                    lane_id="v07-library",
                    bundle=directory,
                    output=directory / "verifier-result.json",
                )

    def test_unreviewed_primary_claim_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            payload = json.loads(
                (directory / "qualification.json").read_text(encoding="utf-8")
            )
            payload["database_integrity_after_restart_recovery"] = "unknown"
            (directory / "qualification.json").write_text(
                json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                evidence.EvidenceError, "reviewed claim mismatch"
            ):
                evidence.attest(
                    root=ROOT,
                    lane_id="v07-library",
                    bundle=directory,
                    output=directory / "verifier-result.json",
                )

    def test_reviewed_test_and_contract_ids_are_authoritative(self):
        contract = evidence.load_contract(ROOT)
        for profile in contract["profile"]:
            with self.subTest(profile=profile["id"]):
                self.assertTrue(profile["test_ids"])
                self.assertTrue(profile["contract_ids"])
                self.assertEqual(
                    len(profile["test_ids"]), len(set(profile["test_ids"]))
                )
                self.assertEqual(
                    len(profile["contract_ids"]),
                    len(set(profile["contract_ids"])),
                )

    def test_verifier_provenance_is_repository_bound(self):
        contract = evidence.load_contract(ROOT)
        profile = evidence.profile_for_lane(contract, "v07-library")
        provenance = evidence._verifier_provenance(ROOT, contract, profile)
        self.assertEqual(provenance["adapter"], "v07-library-semantic-v1")
        self.assertEqual(
            provenance["semantic_verifier"]["path"],
            "tools/qualification_evidence_verifiers.py",
        )
        self.assertRegex(
            provenance["semantic_verifier"]["sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertEqual(
            provenance["binder"]["path"], "tools/qualification_evidence.py"
        )
        self.assertRegex(provenance["binder"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(provenance["contract_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            provenance["admission_action"],
            ".github/actions/qualification-evidence/action.yml",
        )
        self.assertRegex(
            provenance["admission_action_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_repository_artifact_digest_accepts_cargo_hardlinks_but_binds_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release = root / "target" / "release"
            deps = release / "deps"
            deps.mkdir(parents=True)
            binary = release / "linura-authorityd"
            alias = deps / "linura-authorityd-hardlink"
            payload = b"reviewed-cargo-output\n"
            binary.write_bytes(payload)
            os.link(binary, alias)
            self.assertGreater(binary.stat().st_nlink, 1)
            record = {
                "path": binary.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
            semantic_verifier._artifact_digest_record(
                root, record, "cargo-style hardlinked output"
            )
            tampered = dict(record)
            tampered["sha256"] = "0" * 64
            with self.assertRaisesRegex(
                semantic_verifier.VerificationError,
                "repository digest mismatch",
            ):
                semantic_verifier._artifact_digest_record(
                    root, tampered, "cargo-style hardlinked output"
                )

    def test_trusted_release_separates_preseal_and_prepared_v010_source_roots(self):
        workflow = (
            ROOT / ".github/workflows/trusted-release-proof.yml"
        ).read_text(encoding="utf-8")
        self.assertTrue(
            evidence._trusted_release_has_split_v010_source_roots(workflow)
        )
        self.assertFalse(
            evidence._trusted_release_has_split_v010_source_roots(
                workflow.replace(
                    '"$V010_QUALIFICATION_SOURCE_ROOT" "$QUALIFICATION_SOURCE_SHA"',
                    '"$V010_QUALIFICATION_SOURCE_ROOT" "$SOURCE_SHA"',
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._trusted_release_has_split_v010_source_roots(
                workflow.replace(
                    '--root "$V010_QUALIFICATION_SOURCE_ROOT" verify --structural-only',
                    '--root "$V010_PREPARED_SOURCE_ROOT" verify --structural-only',
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._trusted_release_has_split_v010_source_roots(
                workflow.replace(
                    'git -C "$V010_QUALIFICATION_SOURCE_ROOT" rev-parse \'HEAD^{tree}\'',
                    'git -C "$V010_QUALIFICATION_SOURCE_ROOT" rev-parse HEAD',
                    1,
                )
            )
        )

    def test_self_declared_pass_without_semantic_witness_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            for filename in (
                "library-unit-tests.txt",
                "v07-qualification-tests.txt",
                "sdk-tests.txt",
            ):
                (directory / filename).write_text("ok\n", encoding="utf-8")
            with self.assertRaisesRegex(
                evidence.EvidenceError, "semantic evidence verification failed"
            ):
                evidence.attest(
                    root=ROOT,
                    lane_id="v07-library",
                    bundle=directory,
                    output=directory / "verifier-result.json",
                )

    def test_sealed_archive_is_exact_and_original_mutation_cannot_change_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "bundle"
            self._v07_bundle(bundle)
            evidence.attest(
                root=ROOT,
                lane_id="v07-library",
                bundle=bundle,
                output=bundle / "verifier-result.json",
            )
            binding = evidence.bind(
                root=ROOT,
                lane_id="v07-library",
                bundle=bundle,
                verifier_path=bundle / "verifier-result.json",
                output=bundle / "evidence-binding.json",
            )
            archive = root / "qualification-evidence.tar"
            archive_sha, binding_sha = evidence.seal_bundle(
                ROOT, bundle, bundle / "evidence-binding.json", archive
            )
            self.assertRegex(archive_sha, r"^[0-9a-f]{64}$")
            self.assertEqual(binding_sha, binding["binding_sha256"])
            sealed_bytes = archive.read_bytes()

            (bundle / "process-crash-atomicity.txt").write_text(
                "late mutable write\n", encoding="utf-8"
            )
            self.assertEqual(archive.read_bytes(), sealed_bytes)

            unsealed = root / "unsealed"
            unsealed_archive_sha, unsealed_binding_sha = evidence.unseal_archive(
                ROOT, archive, unsealed, semantic=True
            )
            self.assertEqual(unsealed_archive_sha, archive_sha)
            self.assertEqual(unsealed_binding_sha, binding_sha)
            self.assertEqual(
                (unsealed / "process-crash-atomicity.txt").read_text(
                    encoding="utf-8"
                ),
                (
                    "passed: child was SIGKILLed after the uncommitted history write and "
                    "before projection/operation commit; reopen exposed only the old complete "
                    "state, then an exact retry committed/replayed the new complete state\n"
                ),
            )

    def test_integration_validation_is_action_scoped_and_seals_before_upload(self):
        valid = """
jobs:
  proof:
    steps:
      - name: Bind execution
        uses: ./.github/actions/qualification-envelope
        with:
          lane: v07-library
      - name: Admit and upload sealed evidence
        uses: ./.github/actions/qualification-evidence
        with:
          lane: v07-library
          artifact-root: ${{ env.ARTIFACT_DIR }}
          artifact-name: linura-v07-library-example
      - name: Upload unqualified diagnostics
        if: failure()
        uses: actions/upload-artifact@deadbeef
        with:
          name: linura-v07-library-example-unqualified-diagnostics
          path: ${{ env.ARTIFACT_DIR }}
"""
        self.assertTrue(evidence._ordered_evidence_admission(valid, "v07-library"))
        self.assertFalse(
            evidence._ordered_evidence_admission(
                valid.replace(
                    "      - name: Admit and upload sealed evidence\n"
                    "        uses: ./.github/actions/qualification-evidence\n",
                    "      - name: Admit and upload sealed evidence\n"
                    "        if: always()\n"
                    "        uses: ./.github/actions/qualification-evidence\n",
                    1,
                ),
                "v07-library",
            )
        )
        self.assertFalse(
            evidence._ordered_evidence_admission(
                valid.replace("artifact-name: linura-v07-library-example", "", 1),
                "v07-library",
            )
        )
        self.assertFalse(
            evidence._ordered_evidence_admission(
                valid.replace(
                    "      - name: Upload unqualified diagnostics\n"
                    "        if: failure()\n",
                    "      - name: Upload accepted mutable directory\n",
                ),
                "v07-library",
            )
        )
        conditional_envelope = valid.replace(
            "      - name: Bind execution\n"
            "        uses: ./.github/actions/qualification-envelope\n",
            "      - name: Bind execution\n"
            "        if: always()\n"
            "        uses: ./.github/actions/qualification-envelope\n",
            1,
        )
        self.assertFalse(
            evidence._ordered_evidence_admission(
                conditional_envelope, "v07-library"
            )
        )
        cross_job = valid.replace(
            "      - name: Admit and upload sealed evidence",
            "  other:\n"
            "    steps:\n"
            "      - name: Admit and upload sealed evidence",
            1,
        )
        self.assertFalse(
            evidence._ordered_evidence_admission(cross_job, "v07-library")
        )
        accepted_before = valid.replace(
            "      - name: Bind execution\n",
            "      - name: Upload accepted mutable evidence\n"
            "        uses: actions/upload-artifact@deadbeef\n"
            "        with:\n"
            "          name: linura-v07-library-example\n"
            "          path: ${{ env.ARTIFACT_DIR }}\n"
            "      - name: Bind execution\n",
            1,
        )
        self.assertFalse(
            evidence._ordered_evidence_admission(
                accepted_before, "v07-library"
            )
        )
        disguised_failure = valid.replace(
            "name: linura-v07-library-example-unqualified-diagnostics",
            "name: linura-v07-library-example",
            1,
        )
        self.assertFalse(
            evidence._ordered_evidence_admission(
                disguised_failure, "v07-library"
            )
        )

    def test_composite_admission_upload_is_structurally_sealed_and_success_gated(self):
        action = (
            ROOT / ".github/actions/qualification-evidence/action.yml"
        ).read_text(encoding="utf-8")
        self.assertTrue(evidence._admission_action_has_sealed_upload(action))
        self.assertFalse(
            evidence._admission_action_has_sealed_upload(
                action.replace(
                    "path: ${{ steps.seal.outputs.archive }}",
                    "path: ${{ inputs.artifact-root }}",
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._admission_action_has_sealed_upload(
                action.replace(
                    "    - name: Upload exact sealed qualification evidence\n",
                    "    - name: Mutate sealed object after verification\n"
                    "      shell: bash\n"
                    "      run: echo drift >> \"$RUNNER_TEMP/qualification-evidence.tar\"\n\n"
                    "    - name: Upload exact sealed qualification evidence\n",
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._admission_action_has_sealed_upload(
                action.replace(
                    "    - id: seal\n"
                    "      name: Deterministically seal the exact verified bundle\n",
                    "    - id: seal\n"
                    "      name: Deterministically seal the exact verified bundle\n"
                    "      if: always()\n",
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._admission_action_has_sealed_upload(
                action.replace(
                    "      with:\n"
                    "        name: ${{ inputs.artifact-name }}",
                    "      if: always()\n"
                    "      with:\n"
                    "        name: ${{ inputs.artifact-name }}",
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._admission_action_has_sealed_upload(
                action.replace(
                    "name: Read back stored sealed qualification evidence",
                    "name: Removed readback",
                    1,
                ).replace(
                    "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
                    "run: true",
                    1,
                )
            )
        )
        self.assertFalse(
            evidence._admission_action_has_sealed_upload(
                action.replace(
                    'test "$actual" = "$LINURA_EXPECTED_ARCHIVE_SHA256"',
                    'test -n "$actual"',
                    1,
                )
            )
        )

    def test_nested_reserved_control_filename_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            nested = directory / "nested"
            nested.mkdir()
            (nested / "verifier-result.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(evidence.EvidenceError, "reserved control filename"):
                evidence.attest(
                    root=ROOT,
                    lane_id="v07-library",
                    bundle=directory,
                    output=directory / "verifier-result.json",
                )

    def test_hardlinked_retained_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self._v07_bundle(directory)
            artifact = directory / "process-crash-atomicity.txt"
            alias = directory.parent / f"{directory.name}-evidence-alias.txt"
            try:
                os.link(artifact, alias)
                with self.assertRaisesRegex(
                    evidence.EvidenceError, "single link"
                ):
                    evidence.attest(
                        root=ROOT,
                        lane_id="v07-library",
                        bundle=directory,
                        output=directory / "verifier-result.json",
                    )
            finally:
                alias.unlink(missing_ok=True)

    def test_visual_profile_binds_reviewed_observation_identity_and_full_core_inventory(self):
        contract = evidence.load_contract(ROOT)
        profile = evidence.profile_for_lane(contract, "v010-shell-runtime")
        self.assertTrue(profile["require_observation_identity"])
        self.assertIn("workstation_recording.sha256", profile["observation_identity_fields"])
        self.assertIn("release_support_promotion=false", profile["required_json_values"])
        filenames = {item["filename"] for item in profile["artifact"]}
        for required in (
            "cases.tsv",
            "prepared-substrate-manifest.json",
            "native-keyboard.sha256",
            "workstation-runtime.mkv",
            "workstation-runtime.metadata.json",
            "workstation-runtime.sha256",
        ):
            self.assertIn(required, filenames)

    def test_v04_machine_profiles_require_semantic_witness_bytes(self):
        contract = evidence.load_contract(ROOT)
        durability = evidence.profile_for_lane(contract, "v04-durability")
        durability_files = {
            item["filename"] for item in durability["artifact"]
        }
        self.assertIn("v04-fault-probe.bin", durability_files)
        self.assertIn("durability-verifier.log", durability_files)

        enospc = evidence.profile_for_lane(contract, "v04-enospc")
        enospc_files = {item["filename"] for item in enospc["artifact"]}
        self.assertIn("enospc-qualification.log", enospc_files)
        self.assertIn("enospc-verifier.log", enospc_files)

    def test_non_evidence_lanes_cannot_self_promote(self):
        contract = evidence.load_contract(ROOT)
        for lane in contract["non_evidence_lanes"]:
            with self.subTest(lane=lane):
                with self.assertRaisesRegex(
                    evidence.EvidenceError, "not evidence-bearing"
                ):
                    evidence.profile_for_lane(contract, lane)


if __name__ == "__main__":
    unittest.main()
