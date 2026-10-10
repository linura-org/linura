from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import time
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import workstation_q11_runner


class WorkstationQ11RunnerTests(unittest.TestCase):
    def test_candidate_contract_patch_is_temporary_readiness_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "qualification.toml"
            path.write_text(
                """
[interactive_workstation]
evidence_ready = false
evidence_manifest = "qualification/v010/interactive-workstation-evidence.json"
evidence_manifest_sha256 = ""

[update_recovery_qualification]
evidence_ready = false
""".lstrip(),
                encoding="utf-8",
            )
            digest = "a" * 64
            workstation_q11_runner._patch_contract(path, digest)
            text = path.read_text(encoding="utf-8")
            self.assertIn("evidence_ready = true", text)
            self.assertIn(f'evidence_manifest_sha256 = "{digest}"', text)
            self.assertEqual(text.count("evidence_ready = true"), 1)
            self.assertIn("[update_recovery_qualification]\nevidence_ready = false", text)

    def test_begin_run_enrolls_fixture_and_all_case_requests(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            state_root = root / "private-q11-run"
            fixture_contract = root / "maintained-fixture.json"
            fixture_contract.write_text(
                '{"fixture_id": "linura-workstation-01"}\n', encoding="utf-8"
            )
            fixture_bytes = fixture_contract.read_bytes()
            fixture_digest = hashlib.sha256(fixture_bytes).hexdigest()
            fixture = {"fixture_id": "linura-workstation-01"}
            requests = [
                {"case": f"physical-case-{index:02d}", "mechanism": "physical-observation"}
                for index in range(9)
            ]
            with (
                mock.patch.object(
                    workstation_q11_runner, "_exact_source", return_value=source_root
                ),
                mock.patch.object(
                    workstation_q11_runner.workstation_acceptance,
                    "load_contract",
                    return_value={},
                ),
                mock.patch.object(
                    workstation_q11_runner.workstation_acceptance,
                    "hardware_run_requests",
                    return_value=requests,
                ),
                mock.patch.object(
                    workstation_q11_runner.workstation_acceptance,
                    "read_hardware_fixture",
                    return_value=(fixture, fixture_digest),
                ),
                mock.patch.object(
                    workstation_q11_runner.workstation_acceptance,
                    "hardware_doctor",
                    return_value=[],
                ),
            ):
                enrolled = workstation_q11_runner.begin_run(
                    source_root,
                    state_root,
                    "q11-enrollment-test",
                    fixture["fixture_id"],
                    "a" * 40,
                    fixture_contract,
                )

            self.assertEqual(enrolled["status"], "collecting")
            self.assertFalse(enrolled["evidence_ready"])
            self.assertFalse(enrolled["release_support_promotion"])
            self.assertEqual(enrolled["fixture_contract_sha256"], fixture_digest)
            self.assertEqual(enrolled["required_cases"], [r["case"] for r in requests])
            self.assertEqual(
                (state_root / "bundle" / workstation_q11_runner.FIXTURE_EVIDENCE).read_bytes(),
                fixture_bytes,
            )
            self.assertEqual(
                workstation_q11_runner._load_state(state_root), enrolled
            )
            self.assertEqual(
                workstation_q11_runner._request_set(state_root, enrolled),
                {r["case"]: r for r in requests},
            )
            workstation_q11_runner._bundle_tree(state_root / "bundle")

    def test_record_case_transactions_preserve_concurrent_case_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            state_root = root / "private-q11-run"
            state_root.mkdir(mode=0o700)
            bundle = state_root / "bundle"
            cases = ("physical-case-a", "physical-case-b")
            attestations = {}
            for case in cases:
                path = bundle / workstation_q11_runner.Q11_PREFIX / "cases" / f"{case}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
                attestations[case] = path
            state = {
                "schema_version": 1,
                "artifact_type": workstation_q11_runner.STATE_ARTIFACT_TYPE,
                "source_commit_sha": "a" * 40,
                "fixture_id": "fixture-01",
                "required_cases": list(cases),
                "accepted_cases": {},
                "status": "collecting",
                "evidence_ready": False,
                "release_support_promotion": False,
            }
            workstation_q11_runner._atomic_json(state_root / "run-state.json", state)
            first_validating = Event()
            release_first = Event()

            def validate(_bundle, path, _request, _state):
                if path == attestations[cases[0]]:
                    first_validating.set()
                    if not release_first.wait(10):
                        raise AssertionError("second controller did not start in time")
                return hashlib.sha256(path.name.encode()).hexdigest()

            with (
                mock.patch.object(
                    workstation_q11_runner, "_exact_source", return_value=source_root
                ),
                mock.patch.object(workstation_q11_runner, "_enrolled_fixture_matches"),
                mock.patch.object(workstation_q11_runner, "_bundle_tree"),
                mock.patch.object(
                    workstation_q11_runner,
                    "_request_set",
                    return_value={case: {"case": case} for case in cases},
                ),
                mock.patch.object(workstation_q11_runner, "_validate_case", side_effect=validate),
                ThreadPoolExecutor(max_workers=2) as pool,
            ):
                first = pool.submit(
                    workstation_q11_runner.record_case,
                    source_root, state_root, cases[0], attestations[cases[0]],
                )
                self.assertTrue(first_validating.wait(10))
                second = pool.submit(
                    workstation_q11_runner.record_case,
                    source_root, state_root, cases[1], attestations[cases[1]],
                )
                # The second caller must never replace the state loaded by the first.
                time.sleep(0.1)
                release_first.set()
                self.assertEqual(
                    first.result(timeout=15)["path"],
                    attestations[cases[0]].relative_to(bundle).as_posix(),
                )
                self.assertEqual(
                    second.result(timeout=15)["path"],
                    attestations[cases[1]].relative_to(bundle).as_posix(),
                )
            accepted = workstation_q11_runner._load_state(state_root)["accepted_cases"]
            self.assertEqual(set(accepted), set(cases))

    def test_q11_state_lock_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_root = Path(temp_dir)
            target = state_root / "other-file"
            target.write_text("unchanged", encoding="utf-8")
            (state_root / ".run-state.lock").symlink_to(target)
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError, "cannot safely open Q11 state lock"
            ):
                with workstation_q11_runner._locked_state(state_root):
                    self.fail("unsafe state lock must never be acquired")
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    def test_bundle_tree_rejects_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "bundle"
            bundle.mkdir()
            target = root / "outside"
            target.mkdir()
            (bundle / "unsafe").symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError,
                "unsafe or out-of-namespace directory",
            ):
                workstation_q11_runner._bundle_tree(bundle)

    def test_bundle_tree_rejects_verifier_or_contract_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle = Path(temp_dir) / "bundle"
            forbidden = bundle / "tools"
            forbidden.mkdir(parents=True)
            (forbidden / "check_v010_workstation_qualification.py").write_text(
                "print('forged')\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError,
                "namespace",
            ):
                workstation_q11_runner._bundle_tree(bundle)

    def test_manifest_case_registry_rejects_duplicates(self) -> None:
        with self.assertRaisesRegex(
            workstation_q11_runner.RunnerError,
            "duplicate cases",
        ):
            workstation_q11_runner._manifest_cases(
                {
                    "cases": [
                        {"name": "physical-session-start"},
                        {"name": "physical-session-start"},
                    ]
                }
            )

    def test_enrolled_fixture_must_remain_root_owned_and_digest_bound(self) -> None:
        state = {
            "fixture_id": "linura-workstation-01",
            "fixture_contract_sha256": "f" * 64,
            "fixture_contract_path": "/etc/linura/qualification-fixture.json",
            "fixture": {"fixture_id": "linura-workstation-01"},
        }
        with mock.patch.object(
            workstation_q11_runner.workstation_acceptance,
            "read_hardware_fixture",
            return_value=(state["fixture"], "a" * 64),
        ):
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError, "enrollment changed"
            ):
                workstation_q11_runner._enrolled_fixture_matches(state)

    def test_case_attestation_binds_request_and_external_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "bundle"
            case_dir = bundle / "qualification/v010/interactive-workstation/cases"
            provenance_dir = bundle / "qualification/v010/interactive-workstation/provenance"
            case_dir.mkdir(parents=True)
            provenance_dir.mkdir(parents=True)

            source = "b" * 40
            fixture_id = "linura-workstation-01"
            fixture_digest = "f" * 64
            environment = "c" * 64
            boot_id = "12345678-1234-1234-1234-123456789abc"
            run_id = "q11-test"
            case_id = "physical-session-start"
            mechanism = "physical-session-observation"
            controller = "maintainer-console"

            event = provenance_dir / "physical-session-start.log"
            event.write_text(
                "\n".join(
                    [
                        f"case={case_id}",
                        f"controller={controller}",
                        f"mechanism={mechanism}",
                        f"environment_sha256={environment}",
                        f"fixture_id={fixture_id}",
                        f"fixture_contract_sha256={fixture_digest}",
                        f"source_commit_sha={source}",
                        f"run_id={run_id}",
                        "scope=machine",
                        f"boot_id={boot_id}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            event_rel = event.relative_to(bundle).as_posix()
            event_sha = hashlib.sha256(event.read_bytes()).hexdigest()

            provenance = provenance_dir / "physical-session-start.json"
            provenance.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifact_type": "linura-v010-physical-workstation-case-provenance",
                        "source_commit_sha": source,
                        "run_id": run_id,
                        "case": case_id,
                        "fixture_id": fixture_id,
                        "fixture_contract_sha256": fixture_digest,
                        "environment_sha256": environment,
                        "boot_id": boot_id,
                        "scope": "machine",
                        "controller": controller,
                        "mechanism": mechanism,
                        "external_controller": True,
                        "process_local_mock": False,
                        "event_log": {"path": event_rel, "sha256": event_sha},
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            provenance_rel = provenance.relative_to(bundle).as_posix()
            provenance_sha = hashlib.sha256(provenance.read_bytes()).hexdigest()

            attestation = case_dir / "physical-session-start.json"
            attestation.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "attestation_type": "linura-v010-qualification-case",
                        "case": case_id,
                        "result": "passed",
                        "run_id": run_id,
                        "captured_at_utc": "2026-10-01T00:00:00Z",
                        "runner": {
                            "id": "qualification/v010/workstation-runner",
                            "commit_sha": source,
                            "linurad_sha256": "d" * 64,
                            "shell_bridge_sha256": "e" * 64,
                        },
                        "observations": [
                            {"name": "physical-hardware-present", "result": "passed", "value": True},
                            {"name": "wayland-session-active", "result": "passed", "value": True},
                            {"name": "hyprland-session-active", "result": "passed", "value": True},
                        ],
                        "machine_execution": {
                            "scope": "machine",
                            "controller": controller,
                            "mechanism": mechanism,
                            "fixture_id": fixture_id,
                            "fixture_contract_sha256": fixture_digest,
                            "environment_sha256": environment,
                            "boot_id": boot_id,
                            "provenance": {
                                "path": provenance_rel,
                                "sha256": provenance_sha,
                            },
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            request = {
                "case": case_id,
                "mechanism": mechanism,
                "required_observations": [
                    "physical-hardware-present",
                    "wayland-session-active",
                    "hyprland-session-active",
                ],
            }
            state = {
                "run_id": run_id,
                "source_commit_sha": source,
                "fixture_id": fixture_id,
                "fixture_contract_sha256": fixture_digest,
            }

            workstation_q11_runner._bundle_tree(bundle)
            digest = workstation_q11_runner._validate_case(
                bundle, attestation, request, state
            )
            self.assertEqual(digest, hashlib.sha256(attestation.read_bytes()).hexdigest())

            altered_attestation = json.loads(attestation.read_text(encoding="utf-8"))
            altered_attestation["machine_execution"]["fixture_contract_sha256"] = "a" * 64
            attestation.write_text(
                json.dumps(altered_attestation, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError, "fixture enrollment digest mismatch"
            ):
                workstation_q11_runner._validate_case(bundle, attestation, request, state)

            altered = dict(request)
            altered["mechanism"] = "physical-input-observation"
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError,
                "mechanism",
            ):
                workstation_q11_runner._validate_case(
                    bundle, attestation, altered, state
                )

    def test_frozen_bundle_is_the_digest_manifest_and_verifier_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "mutable"
            manifest = bundle / workstation_q11_runner.MANIFEST
            fixture = bundle / workstation_q11_runner.FIXTURE_EVIDENCE
            manifest.parent.mkdir(parents=True)
            fixture.parent.mkdir(parents=True)
            manifest.write_text('{"run_id": "frozen-a"}\n', encoding="utf-8")
            fixture.write_text('{"fixture_id": "fixture-a"}\n', encoding="utf-8")
            frozen = root / "frozen"
            workstation_q11_runner._freeze_bundle(bundle, frozen)
            original_digest = workstation_q11_runner._bundle_snapshot_digest(frozen)
            self.assertEqual(
                workstation_q11_runner._bundle_snapshot_digest(bundle), original_digest
            )

            # A controller can swap the live tree after acquisition; neither
            # the manifest nor verifier input from the frozen tree may follow.
            manifest.write_text('{"run_id": "mutable-b"}\n', encoding="utf-8")
            self.assertEqual(
                (frozen / workstation_q11_runner.MANIFEST).read_text(encoding="utf-8"),
                '{"run_id": "frozen-a"}\n',
            )
            self.assertEqual(
                workstation_q11_runner._bundle_snapshot_digest(frozen), original_digest
            )
            self.assertNotEqual(
                workstation_q11_runner._bundle_snapshot_digest(bundle), original_digest
            )

    def test_frozen_bundle_rejects_symlink_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bundle = root / "bundle"
            manifest = bundle / workstation_q11_runner.MANIFEST
            manifest.parent.mkdir(parents=True)
            manifest.symlink_to(root / "external.json")
            with self.assertRaisesRegex(
                workstation_q11_runner.RunnerError,
                "out(?:side|[- ]of[- ]namespace)|unsafe|single-link",
            ):
                workstation_q11_runner._freeze_bundle(bundle, root / "frozen")

    def test_finalize_rejects_bundle_mutation_during_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            state_root = root / "private-q11-run"
            state_root.mkdir(mode=0o700)
            bundle = state_root / "bundle"
            fixture_path = bundle / workstation_q11_runner.FIXTURE_EVIDENCE
            fixture_path.parent.mkdir(parents=True)
            fixture = {"fixture_id": "fixture-01"}
            fixture_data = workstation_q11_runner._canonical_json(fixture)
            fixture_path.write_bytes(fixture_data)
            fixture_digest = hashlib.sha256(fixture_data).hexdigest()
            manifest = bundle / workstation_q11_runner.MANIFEST
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_bytes(workstation_q11_runner._canonical_json({
                "run_id": "q11-finalization-race",
                "source": {"commit_sha": "a" * 40},
                "fixture": {
                    "fixture_id": "fixture-01",
                    "contract": {
                        "path": workstation_q11_runner.FIXTURE_EVIDENCE.as_posix(),
                        "sha256": fixture_digest,
                    },
                },
                "cases": [],
            }))
            state = {
                "schema_version": 1,
                "artifact_type": workstation_q11_runner.STATE_ARTIFACT_TYPE,
                "run_id": "q11-finalization-race",
                "source_commit_sha": "a" * 40,
                "fixture_id": "fixture-01",
                "fixture_contract_sha256": fixture_digest,
                "fixture": fixture,
                "required_cases": [],
                "request_sha256": {},
                "accepted_cases": {},
                "status": "collecting",
                "release_support_promotion": False,
                "evidence_ready": False,
            }
            real_atomic_json = workstation_q11_runner._atomic_json
            real_atomic_json(state_root / "run-state.json", state)
            injected = False

            def mutate_during_publication(path, document):
                nonlocal injected
                real_atomic_json(path, document)
                if (path == state_root / "run-state.json" and
                        document["status"] == "validated-candidate" and
                        not injected):
                    injected = True
                    manifest.write_bytes(b'{"tampered": true}\n')

            with (
                mock.patch.object(
                    workstation_q11_runner, "_exact_source", return_value=source_root
                ),
                mock.patch.object(workstation_q11_runner, "_enrolled_fixture_matches"),
                mock.patch.object(
                    workstation_q11_runner, "_request_set", return_value={}
                ),
                mock.patch.object(workstation_q11_runner, "_extract_source",
                                  side_effect=lambda _src, _sha, dest: dest.mkdir()),
                mock.patch.object(workstation_q11_runner, "_patch_contract"),
                mock.patch.object(workstation_q11_runner.subprocess, "run",
                                  return_value=mock.Mock(returncode=0)),
                mock.patch.object(workstation_q11_runner, "_atomic_json",
                                  side_effect=mutate_during_publication),
            ):
                with self.assertRaisesRegex(
                    workstation_q11_runner.RunnerError,
                    "bundle changed during finalization publication",
                ):
                    workstation_q11_runner.finalize_run(source_root, state_root)

            self.assertTrue(injected)
            self.assertEqual(
                workstation_q11_runner._load_state(state_root)["status"], "collecting"
            )
            self.assertFalse((state_root / "candidate-finalization.json").exists())

    def test_validated_status_rejects_mutated_candidate_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "source"
            source_root.mkdir()
            state_root = root / "private-q11-run"
            state_root.mkdir(mode=0o700)
            bundle = state_root / "bundle"
            manifest = bundle / workstation_q11_runner.MANIFEST
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"run_id": "q11-status-test"}\n', encoding="utf-8")

            bundle_digest = workstation_q11_runner._bundle_snapshot_digest(bundle)
            finalization = {
                "schema_version": 1,
                "artifact_type": workstation_q11_runner.FINALIZATION_ARTIFACT_TYPE,
                "run_id": "q11-status-test",
                "source_commit_sha": "a" * 40,
                "fixture_id": "fixture-01",
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "bundle_sha256": bundle_digest,
                "result": "validated-candidate",
                "release_support_promotion": False,
                "evidence_ready": False,
            }
            workstation_q11_runner._atomic_json(
                state_root / "candidate-finalization.json", finalization
            )
            finalization_digest = hashlib.sha256(
                workstation_q11_runner._canonical_json(finalization)
            ).hexdigest()
            state = {
                "schema_version": 1,
                "artifact_type": workstation_q11_runner.STATE_ARTIFACT_TYPE,
                "run_id": "q11-status-test",
                "source_commit_sha": "a" * 40,
                "fixture_id": "fixture-01",
                "required_cases": [],
                "request_sha256": {},
                "accepted_cases": {},
                "status": "validated-candidate",
                "candidate_manifest_sha256": finalization["manifest_sha256"],
                "candidate_bundle_sha256": bundle_digest,
                "candidate_finalization_sha256": finalization_digest,
                "release_support_promotion": False,
                "evidence_ready": False,
            }
            workstation_q11_runner._atomic_json(state_root / "run-state.json", state)

            with mock.patch.object(
                workstation_q11_runner, "_exact_source", return_value=source_root
            ):
                current = workstation_q11_runner.status(source_root, state_root)
            self.assertEqual(current["status"], "validated-candidate")

            manifest.write_text(
                '{"run_id": "q11-status-test", "tampered": true}\n',
                encoding="utf-8",
            )
            with mock.patch.object(
                workstation_q11_runner, "_exact_source", return_value=source_root
            ):
                with self.assertRaisesRegex(
                    workstation_q11_runner.RunnerError,
                    "bundle changed after finalization",
                ):
                    workstation_q11_runner.status(source_root, state_root)

            # Even if the bundle digest/receipt were relabeled to the new
            # bytes, the original accepted manifest digest must remain bound.
            new_bundle_digest = workstation_q11_runner._bundle_snapshot_digest(bundle)
            finalization["bundle_sha256"] = new_bundle_digest
            workstation_q11_runner._atomic_json(
                state_root / "candidate-finalization.json", finalization
            )
            state["candidate_bundle_sha256"] = new_bundle_digest
            state["candidate_finalization_sha256"] = hashlib.sha256(
                workstation_q11_runner._canonical_json(finalization)
            ).hexdigest()
            workstation_q11_runner._atomic_json(state_root / "run-state.json", state)
            with mock.patch.object(
                workstation_q11_runner, "_exact_source", return_value=source_root
            ):
                with self.assertRaisesRegex(
                    workstation_q11_runner.RunnerError,
                    "candidate manifest changed after finalization",
                ):
                    workstation_q11_runner.status(source_root, state_root)


if __name__ == "__main__":
    unittest.main()
