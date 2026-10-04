from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest import mock

from tools import check_v010_workstation_qualification
from tools import workstation_acceptance

ROOT = Path(__file__).resolve().parents[2]


class WorkstationAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = tomllib.loads(
            (ROOT / "contracts/v010-workstation-acceptance.toml").read_text(encoding="utf-8")
        )

    def test_repository_contract_is_valid(self) -> None:
        self.assertEqual(workstation_acceptance.validate_contract(self.contract), [])

    def test_automated_mode_is_headless_and_recorded(self) -> None:
        payload = workstation_acceptance.plan_payload(
            self.contract, "automated", "none", False
        )
        self.assertEqual(payload["display"], "none")
        self.assertTrue(payload["recording"])
        self.assertFalse(payload["release_support_promotion"])

    def test_interactive_mode_supports_live_recording(self) -> None:
        payload = workstation_acceptance.plan_payload(
            self.contract, "interactive", "gtk", True
        )
        self.assertEqual(payload["launcher"], self.contract["interactive_launcher"])
        self.assertTrue(payload["recording"])

    def test_hardware_mode_never_routes_through_vm_launcher(self) -> None:
        payload = workstation_acceptance.plan_payload(
            self.contract, "hardware", "none", True
        )
        self.assertEqual(payload["launcher"], self.contract["hardware_runner"])
        self.assertEqual(payload["capture"], self.contract["hardware_capture"])
        self.assertNotEqual(payload["launcher"], self.contract["vm_launcher"])
        qualification = tomllib.loads(
            (ROOT / "contracts/v010-workstation-qualification.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            payload["required_q11_cases"],
            qualification["interactive_workstation"]["required_cases"],
        )
        self.assertTrue(payload["full_q11_case_set_required"])
        self.assertFalse(payload["runner_may_promote_support"])

    def test_level_c_case_registry_matches_release_q11_verifier(self) -> None:
        registry = self.contract["level_c_case"]
        self.assertEqual(
            [item["id"] for item in registry],
            check_v010_workstation_qualification.EXPECTED_INTERACTIVE_WORKSTATION[
                "required_cases"
            ],
        )
        for item in registry:
            case_id = item["id"]
            self.assertEqual(
                item["mechanism"],
                check_v010_workstation_qualification.EXPECTED_Q11_EXECUTION_MECHANISMS[
                    case_id
                ],
            )
            self.assertEqual(
                item["required_observations"],
                check_v010_workstation_qualification.EXPECTED_Q11_CASE_OBSERVATIONS[
                    case_id
                ],
            )

    def test_level_c_case_requests_are_bounded_and_never_accept_commands(self) -> None:
        request = workstation_acceptance.hardware_case_request(
            self.contract,
            case_id="physical-session-start",
            run_id="q11-test-run",
            fixture_id="linura-workstation-01",
            source_sha="a" * 40,
        )
        self.assertEqual(request["case"], "physical-session-start")
        self.assertEqual(request["mechanism"], "physical-session-observation")
        self.assertTrue(request["external_controller_required"])
        self.assertFalse(request["arbitrary_command_allowed"])
        self.assertFalse(request["release_support_promotion"])
        self.assertNotIn("command", request)
        self.assertNotIn("argv", request)

    def test_level_c_case_request_fails_closed_on_incomplete_product_slice(self) -> None:
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "bounded-installer-lane prerequisite S28 is planned, not complete",
        ):
            workstation_acceptance.hardware_case_request(
                self.contract,
                case_id="bounded-installer-lane",
                run_id="q11-test-run",
                fixture_id="linura-workstation-01",
                source_sha="b" * 40,
            )

    def test_level_c_full_run_refuses_before_partial_execution(self) -> None:
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "full run is blocked before execution",
        ):
            workstation_acceptance.hardware_run_requests(
                self.contract,
                run_id="q11-test-run",
                fixture_id="linura-workstation-01",
                source_sha="c" * 40,
            )

    def test_automated_mode_rejects_visible_host_display(self) -> None:
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "automated mode requires display=none",
        ):
            workstation_acceptance.plan_payload(
                self.contract, "automated", "gtk", False
            )

    def test_doctor_rejects_unsupported_mode_display_pairs_before_host_probes(self) -> None:
        self.assertEqual(
            workstation_acceptance.doctor("automated", "gtk"),
            ["automated mode requires display=none"],
        )
        self.assertEqual(
            workstation_acceptance.doctor("interactive", "none"),
            ["interactive mode requires display=gtk or display=vnc"],
        )
        self.assertEqual(
            workstation_acceptance.doctor("hardware", "vnc"),
            ["hardware mode does not use a VM display backend"],
        )

    def test_recording_doctor_adds_only_recording_specific_prerequisites(self) -> None:
        available = {
            "qemu-system-x86_64",
            "qemu-img",
            "ssh",
            "scp",
            "ssh-keygen",
            "cloud-localds",
            "git",
            "cargo",
            "rustup",
        }
        with mock.patch.object(
            workstation_acceptance,
            "_which",
            side_effect=lambda command: command in available,
        ):
            self.assertNotIn(
                "ffprobe",
                workstation_acceptance.doctor("interactive", "vnc", record=False),
            )
            self.assertIn(
                "ffprobe",
                workstation_acceptance.doctor("interactive", "vnc", record=True),
            )

    def test_automated_doctor_requires_mandatory_recording_verifier(self) -> None:
        available = {
            "qemu-system-x86_64",
            "qemu-img",
            "ssh",
            "scp",
            "ssh-keygen",
            "cloud-localds",
            "git",
        }
        with mock.patch.object(
            workstation_acceptance,
            "_which",
            side_effect=lambda command: command in available,
        ):
            self.assertEqual(
                workstation_acceptance.doctor("automated", "none", record=False),
                ["ffprobe"],
            )

    def test_maintained_fixture_schema_matches_runtime_contract(self) -> None:
        import json

        schema = json.loads(
            (ROOT / "schemas/v010-maintained-workstation-fixture.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        expected_fields = {
            "schema_version",
            "fixture_id",
            "profile_id",
            "machine_class",
            "evidence_tier",
            "physical_hardware",
        }
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), expected_fields)
        self.assertEqual(set(schema["properties"]), expected_fields)
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertEqual(
            schema["properties"]["profile_id"]["const"], "arch-hyprland-v1"
        )
        self.assertEqual(schema["properties"]["machine_class"]["const"], "workstation")
        self.assertEqual(
            schema["properties"]["evidence_tier"]["const"], "maintainer_hardware"
        )
        self.assertIs(schema["properties"]["physical_hardware"]["const"], True)

    def test_maintained_fixture_contract_is_strict_and_physical(self) -> None:
        fixture = {
            "schema_version": 1,
            "fixture_id": "linura-workstation-01",
            "profile_id": "arch-hyprland-v1",
            "machine_class": "workstation",
            "evidence_tier": "maintainer_hardware",
            "physical_hardware": True,
        }
        self.assertEqual(
            workstation_acceptance.validate_fixture_payload(
                fixture,
                fixture_id="linura-workstation-01",
            ),
            [],
        )
        virtual = copy.deepcopy(fixture)
        virtual["physical_hardware"] = False
        self.assertTrue(
            any(
                "physical_hardware" in failure
                for failure in workstation_acceptance.validate_fixture_payload(virtual)
            )
        )
        polluted = copy.deepcopy(fixture)
        polluted["hostname"] = "secret-host"
        self.assertTrue(
            any(
                "fields must be exactly" in failure
                for failure in workstation_acceptance.validate_fixture_payload(polluted)
            )
        )

    def test_maintained_fixture_id_cannot_be_substituted(self) -> None:
        fixture = {
            "schema_version": 1,
            "fixture_id": "linura-workstation-01",
            "profile_id": "arch-hyprland-v1",
            "machine_class": "workstation",
            "evidence_tier": "maintainer_hardware",
            "physical_hardware": True,
        }
        failures = workstation_acceptance.validate_fixture_payload(
            fixture,
            fixture_id="linura-workstation-02",
        )
        self.assertTrue(any("does not match" in failure for failure in failures))

    def test_hyprland_monitor_sanitizer_drops_serial_bearing_fields(self) -> None:
        payload = [
            {
                "name": "DP-1",
                "description": "Vendor Model SERIAL-SECRET",
                "make": "Vendor",
                "model": "Model",
                "serial": "SERIAL-SECRET",
                "width": 3840,
                "height": 2160,
                "refreshRate": 120.0,
                "x": 0,
                "y": 0,
                "scale": 1.5,
                "transform": 0,
                "focused": True,
                "availableModes": ["3840x2160@120"],
            }
        ]
        sanitized = workstation_acceptance.sanitize_hyprland_monitors(payload)
        self.assertEqual(
            sanitized,
            [
                {
                    "name": "DP-1",
                    "make": "Vendor",
                    "model": "Model",
                    "width": 3840,
                    "height": 2160,
                    "refreshRate": 120.0,
                    "x": 0,
                    "y": 0,
                    "scale": 1.5,
                    "transform": 0,
                    "focused": True,
                }
            ],
        )
        self.assertNotIn("serial", sanitized[0])
        self.assertNotIn("description", sanitized[0])

    def test_hyprland_monitor_sanitizer_fails_closed_on_incomplete_geometry(self) -> None:
        with self.assertRaisesRegex(workstation_acceptance.AcceptanceError, "missing scale"):
            workstation_acceptance.sanitize_hyprland_monitors(
                [
                    {
                        "name": "DP-1",
                        "width": 1920,
                        "height": 1080,
                        "refreshRate": 60.0,
                        "x": 0,
                        "y": 0,
                    }
                ]
            )

    def test_level_c_virtualization_probe_fails_closed(self) -> None:
        self.assertEqual(
            workstation_acceptance.validate_virtualization_probe(1, "none\n"),
            [],
        )
        self.assertTrue(
            any(
                "virtualization detected" in failure
                for failure in workstation_acceptance.validate_virtualization_probe(
                    0, "qemu\n"
                )
            )
        )
        self.assertTrue(
            workstation_acceptance.validate_virtualization_probe(1, "mystery\n")
        )
        self.assertTrue(
            any(
                "failed with status 2" in failure
                for failure in workstation_acceptance.validate_virtualization_probe(2, "")
            )
        )

    def test_recording_probe_requires_exact_bounded_video_shape(self) -> None:
        recording = self.contract["recording"]
        probe = {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "ffv1",
                    "width": 1280,
                    "height": 800,
                }
            ],
            "format": {"format_name": "matroska,webm", "duration": "3.25"},
        }
        summary = workstation_acceptance.validate_probe_payload(
            probe,
            file_size=4096,
            recording_contract=recording,
        )
        self.assertEqual(summary["codec"], "ffv1")
        self.assertEqual(summary["width"], 1280)
        self.assertEqual(summary["duration_seconds"], 3.25)

    def test_recording_probe_rejects_audio(self) -> None:
        probe = {
            "streams": [
                {"codec_type": "video", "codec_name": "ffv1", "width": 1280, "height": 800},
                {"codec_type": "audio", "codec_name": "opus"},
            ],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "must not contain audio",
        ):
            workstation_acceptance.validate_probe_payload(
                probe,
                file_size=4096,
                recording_contract=self.contract["recording"],
            )

    def test_recording_probe_rejects_unbounded_dimensions(self) -> None:
        recording = copy.deepcopy(self.contract["recording"])
        probe = {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "ffv1",
                    "width": recording["maximum_width"] + 1,
                    "height": 800,
                }
            ],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with self.assertRaisesRegex(
            workstation_acceptance.AcceptanceError,
            "dimensions exceed",
        ):
            workstation_acceptance.validate_probe_payload(
                probe,
                file_size=4096,
                recording_contract=recording,
            )

    def test_recording_verifier_rejects_concurrent_source_mutation(self) -> None:
        probe = {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "ffv1",
                    "width": 1280,
                    "height": 800,
                }
            ],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            recording = Path(temp_dir) / "recording.mkv"
            recording.write_bytes(b"x" * 4096)

            def fake_probe(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
                command = args[0]
                self.assertNotEqual(Path(command[-1]), recording)
                recording.write_bytes(recording.read_bytes() + b"changed")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(probe),
                    stderr="",
                )

            with mock.patch.object(
                workstation_acceptance.shutil,
                "which",
                return_value="/usr/bin/ffprobe",
            ), mock.patch.object(
                workstation_acceptance.subprocess,
                "run",
                side_effect=fake_probe,
            ):
                with self.assertRaisesRegex(
                    workstation_acceptance.AcceptanceError,
                    "changed while it was being verified",
                ):
                    workstation_acceptance.verify_recording(
                        recording,
                        contract=self.contract,
                    )

    def test_recording_file_rejects_symlink_before_ffprobe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.mkv"
            target.write_bytes(b"x" * 4096)
            link = root / "recording.mkv"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                workstation_acceptance.AcceptanceError,
                "missing or unsafe",
            ):
                workstation_acceptance.verify_recording(
                    link,
                    contract=self.contract,
                )



    def test_recorder_start_failure_stops_service_and_clears_partial_evidence(self) -> None:
        recorder = (
            ROOT / "qualification/v010/workstation-acceptance/record-session.sh"
        ).read_text(encoding="utf-8")
        start = recorder.index('    start)\n')
        stop = recorder.index('    stop)\n', start)
        start_path = recorder[start:stop]
        cleanup = start_path[
            start_path.index('        startup_cleanup() {'):
            start_path.index('        trap startup_cleanup EXIT')
        ]
        self.assertIn('systemctl --user kill --kill-who=main --signal=INT "$unit"', cleanup)
        self.assertIn('systemctl --user stop "$unit"', cleanup)
        self.assertIn('wait "$helper_pid"', cleanup)
        self.assertIn('rm -f -- "$status_file" "$helper_pid_file" "$path"', cleanup)
        self.assertLess(
            start_path.index('        trap startup_cleanup EXIT'),
            start_path.index('        (\n'),
        )
        self.assertIn('                trap - EXIT\n                exit 0', start_path)
        self.assertLess(
            start_path.index('        trap startup_cleanup EXIT'),
            start_path.index('        fail "workstation recorder did not become active"'),
        )

    def test_level_c_snapshot_publication_refuses_links_and_uses_private_temporaries(self) -> None:
        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'snapshot_names=(virtualization.txt fixture-contract.sha256 hardware-session.txt)',
            capture,
        )
        self.assertIn('[[ ! -L "$destination" ]] || fail', capture)
        self.assertIn('[[ -f "$destination" ]]', capture)
        self.assertIn('stat -c %h -- "$destination"', capture)
        self.assertIn('mktemp -d "$evidence_root/.linura-snapshot.XXXXXXXX"', capture)
        self.assertIn('mv -fT -- "$snapshot_temporary_dir/$snapshot_name"', capture)
        self.assertIn('source_checkout_matches || fail "Level C source checkout changed before snapshot publication"', capture)
        check = capture.index('for snapshot_name in "${snapshot_names[@]}"; do')
        purge = capture.index('stale_recordings=()', check)
        self.assertLess(check, purge)
        self.assertNotIn('> "$evidence_root/hardware-session.txt"', capture)
        self.assertNotIn('> "$evidence_root/virtualization.txt"', capture)
        self.assertNotIn('> "$evidence_root/fixture-contract.sha256"', capture)

    def test_level_c_publication_is_bound_to_the_recorder_verified_digest(self) -> None:
        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        recorder_stop = capture.index('recording_verification="$(')
        expected_digest = capture.index('verified_recording_sha256="$(', recorder_stop)
        temporary_copy = capture.index(
            'publication_tmp="$(mktemp "$evidence_root/.${evidence_basename}.mkv.XXXXXXXX")"',
            expected_digest,
        )
        copied_digest = capture.index('sha256sum -- "$publication_tmp"', temporary_copy)
        digest_match = capture.index(
            '[[ "$publication_digest" != "$verified_recording_sha256" ]]',
            copied_digest,
        )
        atomic_publish = capture.index(
            'mv -fT -- "$publication_tmp" "$evidence_root/$evidence_basename.mkv"',
            digest_match,
        )
        final_verify = capture.index(
            'python3 "$source_root/tools/workstation_acceptance.py" verify-recording',
            atomic_publish,
        )
        final_match = capture.index(
            '[[ "$publication_sha256" != "$verified_recording_sha256" ]]',
            final_verify,
        )
        self.assertLess(recorder_stop, expected_digest)
        self.assertLess(expected_digest, temporary_copy)
        self.assertLess(temporary_copy, copied_digest)
        self.assertLess(copied_digest, digest_match)
        self.assertLess(digest_match, atomic_publish)
        self.assertLess(atomic_publish, final_verify)
        self.assertLess(final_verify, final_match)
        self.assertNotIn(
            'cp --reflink=never "$recording" "$evidence_root/$evidence_basename.mkv"',
            capture,
        )
        self.assertIn(
            "Level C recording changed after recorder verification",
            capture,
        )

    def test_recording_sidecar_paths_must_not_alias_the_video(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            recording = root / "recording.mkv"
            recording.write_bytes(b"x" * 4096)
            original_bytes = recording.read_bytes()
            for kwargs in (
                {"metadata_path": recording},
                {"digest_path": recording},
                {"metadata_path": root / "subdir" / ".." / "recording.mkv"},
            ):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaisesRegex(
                        workstation_acceptance.AcceptanceError, "alias"
                    ):
                        workstation_acceptance.verify_recording(
                            recording, contract=self.contract, **kwargs
                        )
                    self.assertEqual(recording.read_bytes(), original_bytes)
            self.assertFalse((root / "recording.sha256").exists())

    def test_metadata_and_digest_paths_must_not_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            recording = root / "recording.mkv"
            recording.write_bytes(b"x" * 4096)
            metadata = root / "recording.metadata.json"
            with self.assertRaisesRegex(
                workstation_acceptance.AcceptanceError, "alias"
            ):
                workstation_acceptance.verify_recording(
                    recording, contract=self.contract,
                    metadata_path=metadata, digest_path=metadata,
                )
            self.assertFalse(metadata.exists())

            metadata.write_text("original metadata", encoding="utf-8")
            digest = root / "recording.sha256"
            digest.hardlink_to(metadata)
            with self.assertRaisesRegex(
                workstation_acceptance.AcceptanceError, "single-link|alias"
            ):
                workstation_acceptance.verify_recording(
                    recording, contract=self.contract,
                    metadata_path=metadata, digest_path=digest,
                )
            self.assertEqual(metadata.read_text(encoding="utf-8"), "original metadata")
            self.assertEqual(digest.read_text(encoding="utf-8"), "original metadata")

    def test_sidecar_symlinked_parent_cannot_alias_recording(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            recording = root / "recording.mkv"
            recording.write_bytes(b"x" * 4096)
            (root / "alias").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(
                workstation_acceptance.AcceptanceError, "alias"
            ):
                workstation_acceptance.verify_recording(
                    recording, contract=self.contract,
                    metadata_path=root / "alias" / "recording.mkv",
                )
            self.assertEqual(recording.read_bytes(), b"x" * 4096)

    def test_recording_mutated_during_sidecar_write_is_rejected(self) -> None:
        probe = {
            "streams": [{"codec_type": "video", "codec_name": "ffv1", "width": 1280, "height": 800}],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            recording = root / "recording.mkv"
            metadata = root / "recording.metadata.json"
            digest_file = root / "recording.sha256"
            recording.write_bytes(b"x" * 4096)
            original_publish = workstation_acceptance._publish_recording_sidecar

            def mutate_when_publishing_sidecar(
                path: Path, content: str, *, directory_fd: int | None = None,
            ) -> tuple[int, int]:
                result = original_publish(path, content, directory_fd=directory_fd)
                if path == digest_file:
                    recording.write_bytes(b"y" * 4096)
                return result

            with mock.patch.object(
                workstation_acceptance.shutil, "which", return_value="/usr/bin/ffprobe"
            ), mock.patch.object(
                workstation_acceptance.subprocess, "run",
                return_value=subprocess.CompletedProcess(
                    ["/usr/bin/ffprobe"], 0, stdout=json.dumps(probe), stderr=""
                ),
            ), mock.patch.object(
                workstation_acceptance, "_publish_recording_sidecar",
                side_effect=mutate_when_publishing_sidecar,
            ):
                with self.assertRaisesRegex(
                    workstation_acceptance.AcceptanceError, "changed while it was being verified"
                ):
                    workstation_acceptance.verify_recording(
                        recording, contract=self.contract,
                        metadata_path=metadata, digest_path=digest_file,
                    )
            self.assertFalse(metadata.exists())
            self.assertFalse(digest_file.exists())

    def test_sidecar_path_swaps_cannot_modify_other_files(self) -> None:
        probe = {
            "streams": [{"codec_type": "video", "codec_name": "ffv1", "width": 1280, "height": 800}],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            recording = root / "recording.mkv"
            metadata = root / "recording.metadata.json"
            digest_file = root / "recording.sha256"
            victim = root / "victim.txt"
            victim.write_text("untouched", encoding="utf-8")
            recording.write_bytes(b"x" * 4096)
            original_publish = workstation_acceptance._publish_recording_sidecar

            def swap_before_publish(
                path: Path, content: str, *, directory_fd: int | None = None,
            ) -> tuple[int, int]:
                if path == metadata:
                    path.symlink_to(victim)
                if path == digest_file:
                    path.hardlink_to(metadata)
                return original_publish(path, content, directory_fd=directory_fd)

            with mock.patch.object(
                workstation_acceptance.shutil, "which", return_value="/usr/bin/ffprobe"
            ), mock.patch.object(
                workstation_acceptance.subprocess, "run",
                return_value=subprocess.CompletedProcess(
                    ["/usr/bin/ffprobe"], 0, stdout=json.dumps(probe), stderr=""
                ),
            ), mock.patch.object(
                workstation_acceptance, "_publish_recording_sidecar",
                side_effect=swap_before_publish,
            ):
                result = workstation_acceptance.verify_recording(
                    recording, contract=self.contract,
                    metadata_path=metadata, digest_path=digest_file,
                )
            self.assertEqual(victim.read_text(encoding="utf-8"), "untouched")
            self.assertFalse(metadata.is_symlink())
            self.assertEqual(os.stat(metadata).st_nlink, 1)
            self.assertEqual(json.loads(metadata.read_text(encoding="utf-8"))["sha256"], result["sha256"])
            self.assertEqual(digest_file.read_text(encoding="utf-8"), f"{result['sha256']}  recording.mkv\n")

    def test_sidecar_cross_parent_swap_fails_without_overwriting_metadata(self) -> None:
        # The two sidecars deliberately use the same basename in different
        # writable directories. Moving their parents after the first write
        # must not let the second write reopen and clobber the first.
        probe = {
            "streams": [{"codec_type": "video", "codec_name": "ffv1", "width": 1280, "height": 800}],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            recording = root / "recording.mkv"
            recording.write_bytes(b"x" * 4096)
            metadata = first / "result"
            digest = second / "result"
            original_publish = workstation_acceptance._publish_recording_sidecar
            swapped = False

            def swap_after_first(
                path: Path, content: str, *, directory_fd: int | None = None,
            ) -> tuple[int, int]:
                nonlocal swapped
                result = original_publish(path, content, directory_fd=directory_fd)
                if path == metadata and not swapped:
                    swapped = True
                    first.rename(root / "temporary")
                    second.rename(first)
                    (root / "temporary").rename(second)
                return result

            with mock.patch.object(
                workstation_acceptance.shutil, "which", return_value="/usr/bin/ffprobe"
            ), mock.patch.object(
                workstation_acceptance.subprocess, "run",
                return_value=subprocess.CompletedProcess(
                    ["/usr/bin/ffprobe"], 0, stdout=json.dumps(probe), stderr=""
                ),
            ), mock.patch.object(
                workstation_acceptance, "_publish_recording_sidecar",
                side_effect=swap_after_first,
            ):
                with self.assertRaisesRegex(
                    workstation_acceptance.AcceptanceError,
                    "sidecar directory changed",
                ):
                    workstation_acceptance.verify_recording(
                        recording, contract=self.contract,
                        metadata_path=metadata, digest_path=digest,
                    )
            self.assertTrue(swapped)
            self.assertFalse((first / "result").exists())
            self.assertFalse((second / "result").exists())
            self.assertEqual(recording.read_bytes(), b"x" * 4096)

    def test_level_c_abort_waits_before_releasing_global_lock(self) -> None:
        recorder = (
            ROOT / "qualification/v010/workstation-acceptance/record-session.sh"
        ).read_text(encoding="utf-8")
        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        abort_helper = recorder[
            recorder.index('abort_recorder_state() {'):
            recorder.index('\n}\n\ncase "$command_name" in')
        ]
        self.assertIn('read -r helper_pid helper_start < "$helper_pid_file"', abort_helper)
        self.assertIn('recorder_helper_is_live', abort_helper)
        self.assertIn('kill -KILL "$helper_pid"', abort_helper)
        self.assertLess(
            abort_helper.index('fail "recorder helper remains alive; refusing to clear its shared state"'),
            abort_helper.index('rm -f -- "$status_file" "$helper_pid_file" "$path"'),
        )
        abort_case = recorder[
            recorder.index('    abort)\n'):recorder.index('    verify)\n')
        ]
        self.assertIn('abort_recorder_state "$path"', abort_case)
        self.assertIn('"$recorder" abort "$recording" "$output_name"', capture)
        self.assertIn('trap cleanup EXIT', capture)
        self.assertIn('previous workstation recorder helper has not exited', recorder)

    def test_recorder_stop_timeout_uses_bounded_abort_cleanup(self) -> None:
        recorder = (
            ROOT / "qualification/v010/workstation-acceptance/record-session.sh"
        ).read_text(encoding="utf-8")
        stop = recorder[recorder.index('    stop)\n'):recorder.index('    abort)\n')]
        timeout = stop[
            stop.index('        if [[ ! -f "$status_file" ]]; then'):
            stop.index('        recorder_status="$(cat "$status_file")"')
        ]
        self.assertIn('abort_recorder_state "$path"', timeout)
        self.assertLess(
            timeout.index('abort_recorder_state "$path"'),
            timeout.index('fail "workstation recorder did not publish its final exit status"'),
        )
        abort_case = recorder[
            recorder.index('    abort)\n'):recorder.index('    verify)\n')
        ]
        self.assertIn('abort_recorder_state "$path"', abort_case)
        abort_helper = recorder[
            recorder.index('abort_recorder_state() {'):
            recorder.index('\n}\n\ncase "$command_name" in')
        ]
        self.assertIn('systemctl --user stop "$unit"', abort_helper)
        self.assertIn('kill -TERM "$helper_pid"', abort_helper)
        self.assertIn('kill -KILL "$helper_pid"', abort_helper)
        self.assertLess(
            abort_helper.index('systemctl --user stop "$unit"'),
            abort_helper.index('rm -f -- "$status_file" "$helper_pid_file" "$path"'),
        )

    def test_level_b_qemu_log_publication_replaces_symlink_without_following_it(self) -> None:
        import sys

        if sys.platform != "linux":
            self.skipTest("Linux-only interactive qualification runner")

        launcher = (
            ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh"
        ).read_text(encoding="utf-8")
        start = launcher.index('publish_qemu_log() {')
        end = launcher.index('\n}\n\ncleanup()', start) + 2
        publish = launcher[start:end]
        self.assertNotIn('cp "$vm_log" "$evidence_dir/qemu.log"', launcher)
        self.assertIn('mktemp "$evidence_dir/.qemu.log.XXXXXXXX"', publish)
        self.assertIn('mv -fT -- "$temporary_log" "$evidence_dir/qemu.log"', publish)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence = root / "evidence"
            evidence.mkdir()
            vm_log = root / "source.log"
            vm_log.write_text("new qemu diagnostics\n", encoding="utf-8")
            victim = root / "victim.txt"
            victim.write_text("must remain unchanged\n", encoding="utf-8")
            destination = evidence / "qemu.log"
            destination.symlink_to(victim)

            script = (
                "set -euo pipefail\n"
                + publish
                + "\nvm_log=\"$1\"\nevidence_dir=\"$2\"\npublish_qemu_log\n"
            )
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(vm_log), str(evidence)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "must remain unchanged\n")
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_text(encoding="utf-8"), "new qemu diagnostics\n")

    def test_level_b_guest_evidence_publication_replaces_symlink_without_following_it(self) -> None:
        import sys

        if sys.platform != "linux":
            self.skipTest("Linux-only interactive qualification runner")

        launcher = (
            ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            'linura@127.0.0.1:/tmp/linura-workstation-live/. "$evidence_dir/"',
            launcher,
        )
        start = launcher.index("publish_guest_evidence_file() {")
        end = launcher.index("\n}\n\nstage_guest_evidence_file()", start) + 2
        publish = launcher[start:end]
        self.assertIn('mktemp "$evidence_dir/.${output_name}.XXXXXXXX"', publish)
        self.assertIn('mv -fT -- "$temporary" "$evidence_dir/$output_name"', publish)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence = root / "evidence"
            evidence.mkdir()
            staged = root / "live-session.txt"
            staged.write_text("fresh guest evidence\n", encoding="utf-8")
            victim = root / "victim.txt"
            victim.write_text("must remain unchanged\n", encoding="utf-8")
            destination = evidence / "live-session.txt"
            destination.symlink_to(victim)

            script = (
                "set -euo pipefail\n"
                + publish
                + "\n"
                + 'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
                + 'evidence_directory_matches() { return 0; }\n'
                + 'evidence_dir="$1"\nstaged="$2"\n'
                + 'publish_guest_evidence_file "$staged" "live-session.txt"\n'
            )
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(evidence), str(staged)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                victim.read_text(encoding="utf-8"), "must remain unchanged\n"
            )
            self.assertFalse(destination.is_symlink())
            self.assertEqual(
                destination.read_text(encoding="utf-8"), "fresh guest evidence\n"
            )

    def test_level_b_private_substrate_copy_is_checked_before_resize(self) -> None:
        import sys

        if sys.platform != "linux":
            self.skipTest("Linux-only VM qualification runner")

        import hashlib

        launcher = (
            ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh"
        ).read_text(encoding="utf-8")
        copy_command = 'cp --reflink=auto "$prepared_image" "$vm_image"'
        resize_command = 'qemu-img resize "$vm_image" 16G'
        start = launcher.index(copy_command)
        verify = launcher.index('[[ "$copied_sha" == "$prepared_sha" ]] || fail', start)
        resize = launcher.index(resize_command, start)
        self.assertLess(start, verify)
        self.assertLess(verify, resize)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            prepared = root / "prepared.qcow2"
            copied = root / "private.qcow2"
            prepared.write_bytes(b"unexpected concurrently refreshed image")
            expected_digest = hashlib.sha256(b"verified original image").hexdigest()
            fragment = launcher[start:resize + len(resize_command)]
            script = (
                "set -euo pipefail\n"
                'prepared_image="$1"\nvm_image="$2"\nprepared_sha="$3"\n'
                'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
                + fragment
            )
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(prepared), str(copied), expected_digest],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("copied substrate differs", result.stderr)
            self.assertEqual(copied.read_bytes(), prepared.read_bytes())

    def test_level_c_concurrent_capture_is_refused_before_evidence_deletion(self) -> None:
        import sys

        if sys.platform != "linux":
            self.skipTest("Linux-only no-follow flock helper")

        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        lock_check = capture.index("coproc capture_lock_holder {")
        lock_ack = capture.index('case "$capture_lock_state" in', lock_check)
        retained_purge = capture.index("for stale_recording in", lock_ack)
        old_recording_purge = capture.index('rm -f "$recording"', lock_ack)
        recorder_preflight = capture.index('recorder_unit="linura-workstation-recorder.service"')
        self.assertLess(lock_ack, recorder_preflight)
        self.assertLess(lock_ack, retained_purge)
        self.assertLess(lock_ack, old_recording_purge)
        self.assertIn('python3 -u "$source_root/tools/workstation_capture_lock.py"', capture)

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "private"
            directory.mkdir(mode=0o700)
            lock = directory / "hardware-capture.lock"
            helper = ROOT / "tools/workstation_capture_lock.py"
            holder = subprocess.Popen(
                [sys.executable, "-u", str(helper), str(lock)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            try:
                self.assertEqual(holder.stdout.readline().strip(), "LOCKED")
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
                second = subprocess.run(
                    [sys.executable, "-u", str(helper), str(lock)],
                    input="", text=True, capture_output=True,
                    timeout=5, check=False,
                )
                self.assertNotEqual(second.returncode, 0)
                self.assertEqual(second.stdout.strip(), "BUSY")
            finally:
                if holder.stdin and not holder.stdin.closed:
                    holder.stdin.close()
                holder.wait(timeout=5)
                if holder.stdout:
                    holder.stdout.close()
                if holder.stderr:
                    holder.stderr.close()
            self.assertEqual(holder.returncode, 0)
            acquired_again = subprocess.run(
                [sys.executable, "-u", str(helper), str(lock)],
                input="", text=True, capture_output=True,
                timeout=5, check=False,
            )
            self.assertEqual(acquired_again.returncode, 0, acquired_again.stderr)
            self.assertEqual(acquired_again.stdout.strip(), "LOCKED")

    def test_level_c_capture_lock_refuses_hardlinks_and_symlinks_without_modification(self) -> None:
        import sys

        if sys.platform != "linux":
            self.skipTest("Linux-only no-follow lock helper")
        helper = ROOT / "tools/workstation_capture_lock.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            directory = root / "private"
            directory.mkdir(mode=0o700)
            victim = root / "victim.txt"
            victim.write_bytes(b"never truncate another file")
            lock = directory / "hardware-capture.lock"
            for alias in ("hardlink", "symlink"):
                with self.subTest(alias=alias):
                    if alias == "hardlink":
                        os.link(victim, lock)
                    else:
                        lock.symlink_to(victim)
                    result = subprocess.run(
                        [sys.executable, "-u", str(helper), str(lock)],
                        input="", text=True, capture_output=True,
                        timeout=5, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout.strip(), "UNSAFE")
                    self.assertEqual(victim.read_bytes(), b"never truncate another file")
                    lock.unlink()

    def test_level_c_capture_lock_refuses_unsafe_file_and_directory_modes(self) -> None:
        import sys

        if sys.platform != "linux":
            self.skipTest("Linux-only no-follow lock helper")
        helper = ROOT / "tools/workstation_capture_lock.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "private"
            directory.mkdir(mode=0o700)
            lock = directory / "hardware-capture.lock"
            lock.touch(mode=0o600)
            lock.chmod(0o644)
            wrong_lock = subprocess.run(
                [sys.executable, "-u", str(helper), str(lock)],
                input="", text=True, capture_output=True,
                timeout=5, check=False,
            )
            self.assertNotEqual(wrong_lock.returncode, 0)
            self.assertEqual(wrong_lock.stdout.strip(), "UNSAFE")
            lock.chmod(0o600)
            directory.chmod(0o755)
            wrong_directory = subprocess.run(
                [sys.executable, "-u", str(helper), str(lock)],
                input="", text=True, capture_output=True,
                timeout=5, check=False,
            )
            self.assertNotEqual(wrong_directory.returncode, 0)
            self.assertEqual(wrong_directory.stdout.strip(), "UNSAFE")

    def test_level_c_reused_evidence_root_clears_every_fixture_bundle(self) -> None:
        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        purge = capture.index("stale_recordings=()")
        self.assertIn("for stale_recording in", capture)
        self.assertLess(purge, capture.index("# Generate all snapshot data", purge))
        self.assertIn('"$evidence_root"/hardware-*.metadata.json', capture)
        self.assertIn('"$evidence_root"/hardware-*.sha256', capture)
        fragment = capture[purge:capture.index("# Generate all snapshot data", purge)]
        script = (
            "set -euo pipefail\n"
            'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
            'evidence_root="$1"\n'
            + fragment
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence = root / "evidence"
            evidence.mkdir()
            for filename in (
                "hardware-A.mkv", "hardware-A.metadata.json", "hardware-A.sha256",
                "hardware-B.mkv", "hardware-B.metadata.json", "hardware-B.sha256",
            ):
                (evidence / filename).write_bytes(b"stale")
            preserved = root / "unrelated.txt"
            preserved.write_bytes(b"must stay intact")
            (evidence / "hardware-alias.mkv").symlink_to(preserved)
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(evidence)],
                capture_output=True, text=True, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(evidence.glob("hardware-*")), [])
            self.assertEqual(preserved.read_bytes(), b"must stay intact")

            # An unsafe directory must not cause partial deletion of other
            # stale evidence before the capture refuses the reused root.
            (evidence / "hardware-A.mkv").write_bytes(b"retain on failure")
            (evidence / "hardware-Z.mkv").mkdir()
            rejected = subprocess.run(
                ["bash", "-c", script, "bash", str(evidence)],
                capture_output=True, text=True, timeout=5, check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((evidence / "hardware-A.mkv").read_bytes(), b"retain on failure")

    def test_level_c_capture_auto_stops_before_recording_duration_limit(self) -> None:
        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('maximum_duration_seconds', capture)
        self.assertIn('capture_start_seconds="$SECONDS"', capture)
        self.assertIn('SECONDS - capture_start_seconds >= recording_duration_budget', capture)
        fragment = capture[capture.rindex("while true; do"):]
        script = (
            "set -euo pipefail\n"
            "systemctl() { return 0; }\n"
            "capture_start_seconds=0\n"
            "recording_duration_budget=1\n"
            "SECONDS=2\n"
            + fragment
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True,
            text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("recording budget reached", result.stdout)

    def test_level_c_recorder_preflight_accepts_absent_and_rejects_active_or_unknown(self) -> None:
        capture = (
            ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh"
        ).read_text(encoding="utf-8")
        start = capture.index('recorder_unit="linura-workstation-recorder.service"')
        end = capture.index('\n\nif [[ -L "$evidence_root" ]]', start)
        fragment = capture[start:end]
        script = (
            "set -euo pipefail\n"
            'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
            'systemctl() {\n'
            '    case "$2" in\n'
            '        list-units)\n'
            '            if [[ "$SCENARIO" == manager-error ]]; then return 1; fi\n'
            '            if [[ "$SCENARIO" != absent ]]; then\n'
            '                printf "%s\\n" "linura-workstation-recorder.service loaded active running"\n'
            '            fi\n'
            '            ;;\n'
            '        show)\n'
            '            if [[ "$SCENARIO" == absent ]]; then return 99; fi\n'
            '            if [[ "$SCENARIO" == inactive ]]; then echo inactive; else echo active; fi\n'
            '            ;;\n'
            '        *) return 98 ;;\n'
            '    esac\n'
            '}\n'
            + fragment + "\n"
        )
        for scenario, should_succeed in (
            ("absent", True),
            ("inactive", True),
            ("active", False),
            ("manager-error", False),
        ):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "SCENARIO": scenario},
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, should_succeed)
                if not should_succeed:
                    self.assertIn("FAIL:", result.stderr)

    def test_level_b_clears_stale_recordings_on_every_invocation(self) -> None:
        launcher = (ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh").read_text(encoding="utf-8")
        purge = launcher.index('rm -f -- "$evidence_dir/live-session.txt"')
        guest = launcher.index('bash "$build_root/qualification/v010/shell-runtime/start-vm.sh"')
        self.assertLess(purge, guest)
        self.assertIn('"$evidence_dir/workstation-live.metadata.json"', launcher)
        self.assertIn('"$evidence_dir/workstation-live.sha256"', launcher)
        self.assertIn('"$evidence_dir/live-session.txt"', launcher)
        self.assertIn('"$evidence_dir/qemu.log"', launcher)
        self.assertLess(launcher.index('"$evidence_dir/live-session.txt"'), guest)

    def test_level_b_concurrent_launch_cannot_purge_shared_evidence(self) -> None:
        import sys
        from contextlib import ExitStack

        if sys.platform != "linux":
            self.skipTest("Linux-only interactive qualification runner")

        import fcntl

        launcher = (
            ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh"
        ).read_text(encoding="utf-8")
        start = launcher.index('if [[ -z "$evidence_dir" ]]; then')
        purge = launcher.index('rm -f -- "$evidence_dir/live-session.txt"', start)
        guest = launcher.index(
            'bash "$build_root/qualification/v010/shell-runtime/start-vm.sh"',
            purge,
        )
        lock_open = launcher.index('exec {evidence_lock_fd}<"$evidence_dir"', start)
        lock_check = launcher.index('flock -n "$evidence_lock_fd"', lock_open)
        self.assertLess(lock_open, lock_check)
        self.assertLess(lock_check, purge)
        self.assertLess(lock_check, guest)
        self.assertIn("flock", launcher.split("for command_name in", 1)[1].split("; do", 1)[0])

        # Exercise the exact preflight and purge, without starting a VM. Both
        # the default SHA path and an explicit alias must contend on the inode.
        fragment = launcher[start:launcher.index("\ncleanup() {", start)]
        script = (
            "set -euo pipefail\n"
            'source_root="$1"\n'
            'source_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
            'evidence_dir="$2"\n'
            'ssh_port="$3"\n'
            'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
            + fragment
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = root / ".artifacts" / ("workstation-live-" + "a" * 40)
            destination.mkdir(parents=True)
            existing = destination / "workstation-live.mkv"
            existing.write_bytes(b"active run must not be erased")
            old_session = destination / "live-session.txt"
            old_session.write_text("previous session must not be retained")
            old_log = destination / "qemu.log"
            old_log.write_text("previous boot")
            unrelated = destination / "operator-notes.txt"
            unrelated.write_text("keep operator notes")
            # Python's buffered file opener rejects directory descriptors; use
            # the same Linux directory-inode locking primitive as Bash.
            with ExitStack() as stack:
                holder = os.open(
                    destination,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                stack.callback(os.close, holder)
                fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for supplied_dir, port in (
                    ("", 2224),
                    (str(destination.parent / "." / destination.name), 2225),
                ):
                    with self.subTest(supplied_dir=supplied_dir, port=port):
                        result = subprocess.run(
                            ["bash", "-c", script, "bash", str(root), supplied_dir, str(port)],
                            capture_output=True, text=True, timeout=10, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("evidence directory already in use", result.stderr)
                        self.assertEqual(existing.read_bytes(), b"active run must not be erased")
                        self.assertTrue(old_session.exists())
                        self.assertTrue(old_log.exists())
            success = subprocess.run(
                ["bash", "-c", script, "bash", str(root), "", "2224"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertFalse(existing.exists())
            self.assertFalse(old_session.exists())
            self.assertFalse(old_log.exists())
            self.assertEqual(unrelated.read_text(), "keep operator notes")

    def test_level_b_recording_auto_stops_with_finalization_margin(self) -> None:
        live = (ROOT / "qualification/v010/workstation-acceptance/run-live-session.sh").read_text(encoding="utf-8")
        self.assertIn('maximum_duration_seconds', live)
        self.assertIn('recording_start_seconds="$SECONDS"', live)
        self.assertIn('SECONDS - recording_start_seconds >= recording_duration_budget', live)
        fragment = live[live.rindex("while true; do"):]
        script = (
            "set -euo pipefail\n"
            "systemctl() { return 0; }\n"
            "recording_started=1\n"
            "recording_start_seconds=0\n"
            "recording_duration_budget=1\n"
            "SECONDS=2\n"
            + fragment
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True,
            text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Level B recording budget reached", result.stdout)

    def test_level_b_renamed_directory_cannot_redirect_evidence_publication(self) -> None:
        import sys
        if sys.platform != "linux":
            self.skipTest("Linux-only directory descriptor evidence contract")
        launcher = (ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh").read_text(encoding="utf-8")
        start = launcher.index('if [[ -z "$evidence_dir" ]]; then')
        fragment = launcher[start:launcher.index("\ncleanup() {", start)]
        script = (
            "set -euo pipefail\n"
            'source_root="$1"\n'
            'source_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
            'evidence_dir="$2"\n'
            'staged="$3"\n'
            'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
            + fragment
            + '\nmv -- "$evidence_path" "$evidence_path.moved"\n'
            + 'mkdir "$evidence_path"\n'
            + 'printf "replacement" > "$evidence_path/live-session.txt"\n'
            + 'publish_guest_evidence_file "$staged" "live-session.txt"\n'
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = root / "evidence"
            destination.mkdir()
            staged = root / "staged.txt"
            staged.write_text("genuine data", encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(root), str(destination), str(staged)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("directory was replaced", result.stderr)
            self.assertEqual((destination / "live-session.txt").read_text(), "replacement")
            self.assertFalse((root / "evidence.moved" / "live-session.txt").exists())

    def test_level_a_fails_closed_before_mandatory_video_expires(self) -> None:
        runtime = (ROOT / "qualification/v010/shell-runtime/run-shell-runtime.sh").read_text(encoding="utf-8")
        self.assertIn('maximum_duration_seconds', runtime)
        self.assertIn('print(int(maximum) - 60)', runtime)
        self.assertIn('trap - EXIT USR1', runtime)
        self.assertIn('recording_deadline_pid=""', runtime)
        start = runtime.index("trap 'fail \"Level A recording budget exceeded")
        end = runtime.index("systemctl --user daemon-reload", start)
        fragment = runtime[start:end]
        script = (
            "set -euo pipefail\n"
            'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
            'source_root=/tmp\nsource_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
            'workstation_recorder=/bin/true\nworkstation_recording=/tmp/nonexistent.mkv\n'
            'recording_duration_budget=1\n'
            + fragment
            + '\nsleep 3\n'
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True,
            text=True, timeout=6, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Level A recording budget exceeded", result.stderr)

    def test_level_c_directory_rename_cannot_redirect_snapshots(self) -> None:
        import sys
        if sys.platform != "linux":
            self.skipTest("Linux-only directory descriptor evidence contract")
        capture = (ROOT / "qualification/v010/workstation-acceptance/capture-hardware-session.sh").read_text(encoding="utf-8")
        start = capture.index('evidence_root="$(cd "$evidence_root" && pwd -P)"')
        end = capture.index('evidence_basename="hardware-$fixture_id"', start)
        fragment = capture[start:end]
        self.assertIn('evidence_root="/proc/self/fd/$evidence_root_fd"', fragment)
        self.assertIn('evidence_directory_matches || fail "Level C evidence directory changed before snapshot publication"', capture)
        self.assertIn('if ! source_checkout_matches || ! evidence_directory_matches; then', capture)
        self.assertIn("Level C evidence directory changed during recording publication", capture)
        script = (
            "set -euo pipefail\n"
            'fail() { printf "FAIL: %s\\n" "$*" >&2; exit 1; }\n'
            'evidence_root="$1"\n'
            + fragment
            + '\nmv -- "$evidence_path" "$evidence_path.moved"\n'
            + 'mkdir "$evidence_path"\n'
            + 'printf "locked inode" > "$evidence_root/hardware-session.txt"\n'
            + 'if evidence_directory_matches; then exit 91; fi\n'
            + 'test ! -e "$evidence_path/hardware-session.txt"\n'
            + 'test -f "$evidence_path.moved/hardware-session.txt"\n'
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            evidence = Path(temp_dir) / "evidence"
            evidence.mkdir()
            result = subprocess.run(
                ["bash", "-c", script, "bash", str(evidence)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((evidence / "hardware-session.txt").exists())
            self.assertEqual(
                (Path(temp_dir) / "evidence.moved" / "hardware-session.txt").read_text(),
                "locked inode",
            )

    def test_recording_digest_file_uses_verified_snapshot_digest(self) -> None:
        probe = {
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "ffv1",
                    "width": 1280,
                    "height": 800,
                }
            ],
            "format": {"format_name": "matroska", "duration": "1.0"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            recording = root / "recording.mkv"
            metadata = root / "recording.metadata.json"
            digest_file = root / "recording.sha256"
            recording.write_bytes(b"x" * 4096)
            completed = subprocess.CompletedProcess(
                ["/usr/bin/ffprobe"],
                0,
                stdout=json.dumps(probe),
                stderr="",
            )
            with mock.patch.object(
                workstation_acceptance.shutil,
                "which",
                return_value="/usr/bin/ffprobe",
            ), mock.patch.object(
                workstation_acceptance.subprocess,
                "run",
                return_value=completed,
            ):
                result = workstation_acceptance.verify_recording(
                    recording,
                    contract=self.contract,
                    metadata_path=metadata,
                    digest_path=digest_file,
                    source_sha="f" * 40,
                )
            self.assertEqual(
                digest_file.read_text(encoding="utf-8"),
                f"{result['sha256']}  recording.mkv\n",
            )
            self.assertEqual(
                json.loads(metadata.read_text(encoding="utf-8"))["sha256"],
                result["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
