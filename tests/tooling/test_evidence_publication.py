from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import tomllib
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("evidence_publication", ROOT / "tools/evidence_publication.py")
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)
REAL_VERIFY_VIDEO = publication.verify_video
SOURCE = "a" * 40
RUN_ID = 12345
ATTEMPT = 2
DATE = datetime(2026, 10, 1, tzinfo=timezone.utc).isoformat()
PUBLICATION = {
    "run_id": 87654,
    "run_attempt": 1,
    "head_sha": "b" * 40,
    "workflow_ref": "linura-org/linura/.github/workflows/publish-qualification-evidence.yml@refs/heads/main",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidencePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.policy = publication.load_policy()
        self.recording = b"synthetic video validated by mocked ffprobe" * 60
        self.meta = {
            "schema_version": 1, "recording": "workstation-runtime.mkv",
            "source_sha": SOURCE, "sha256": digest(self.recording),
            "size": len(self.recording), "codec": "ffv1", "container": "matroska",
            "width": 1280, "height": 800, "duration_seconds": 3.0,
        }
        self.bindings = {}
        runtime_contract_file = ROOT / "contracts/v010-shell-runtime-qualification.toml"
        self.runtime_contract_sha256 = digest(runtime_contract_file.read_bytes())
        self.case_ids = tomllib.loads(runtime_contract_file.read_text(encoding="utf-8"))["required_cases"]
        self.put("workstation-runtime.mkv", self.recording, bound=False)
        self.put("workstation-runtime.metadata.json", publication.canonical(self.meta), bound=False)
        self.put("workstation-runtime.sha256", f"{digest(self.recording)}  workstation-runtime.mkv\n".encode(), bound=False)
        self.put(
            "cases.tsv",
            "".join(f"{case_id}\tpassed\n" for case_id in self.case_ids).encode(),
        )
        self.manifest = {
            "schema_version": 1, "repository": "linura-org/linura", "source_sha": SOURCE,
            "result": "passed", "claim": "development-runtime-evidence-only",
            "target_profile": "arch-hyprland-v1", "release_support_promotion": False,
            "cases": dict.fromkeys(self.case_ids, "passed"), "artifacts": self.bindings,
            "runtime_contract": {
                "path": "contracts/v010-shell-runtime-qualification.toml",
                "sha256": self.runtime_contract_sha256,
            },
            "workstation_recording": {"path": "workstation-runtime.mkv", "sha256": digest(self.recording),
                                      "metadata_sha256": digest(publication.canonical(self.meta)),
                                      "digest_file_sha256": digest(f"{digest(self.recording)}  workstation-runtime.mkv\n".encode()),
                                      "scope": "captured-automated-wayland-session"},
            "workflow": {"path": ".github/workflows/v010-shell-runtime-qualification.yml", "run_id": RUN_ID,
                         "run_attempt": ATTEMPT, "event": "workflow_dispatch"},
        }
        self.run = {
            "id": RUN_ID, "run_attempt": ATTEMPT, "head_sha": SOURCE, "head_branch": "main",
            "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
            "path": ".github/workflows/v010-shell-runtime-qualification.yml",
            "repository": {"full_name": "linura-org/linura"},
        }
        self.approvals = [{"state": "approved", "user": {"login": "Ehsan-Azari"},
                           "environments": [{"name": "qualification-archive"}]}]
        self.write_manifest()
        self.ffprobe = patch.object(publication, "verify_video", return_value={
            "codec": "ffv1", "container": "matroska",
            "width": 1280, "height": 800, "duration_seconds": 3.0,
        })
        self.ffprobe.start()
        self.addCleanup(self.ffprobe.stop)

    def put(self, name, data, *, bound=True):
        (self.bundle / name).write_bytes(data)
        if bound:
            self.bindings[name] = {"sha256": digest(data), "size": len(data)}

    def write_manifest(self):
        value = publication.canonical(self.manifest)
        (self.bundle / publication.MANIFEST).write_bytes(value)
        (self.bundle / publication.SIDECAR).write_text(f"{digest(value)}  {publication.MANIFEST}\n")

    def admit(self):
        publication.github_run(self.run, SOURCE, RUN_ID, ATTEMPT)
        reviewer = publication.github_approval(
            self.approvals, "Ehsan-Azari", PUBLICATION["run_attempt"]
        )
        manifest, files = publication.verified_bundle(self.bundle, SOURCE, RUN_ID, ATTEMPT, self.policy)
        prefix, record = publication.make_record(manifest, files, "baselines", "Ehsan-Azari",
                                                  "Selected merged workstation baseline", DATE, self.policy,
                                                  reviewer=reviewer, publication_run=PUBLICATION)
        return prefix, record, files

    def test_publication_threat_model_and_adr_are_registered_and_routed(self):
        guide = (ROOT / "docs/qualification/evidence-publication.md").read_text(encoding="utf-8")
        model = (ROOT / "docs/qualification/evidence-publication-threat-model.md").read_text(encoding="utf-8")
        security = (ROOT / "docs/security-model.md").read_text(encoding="utf-8")
        adr = (ROOT / "docs/adr/0034-private-qualification-evidence-publication.md").read_text(encoding="utf-8")
        index = (ROOT / "docs/adr/README.md").read_text(encoding="utf-8")
        checks = (ROOT / ".github/workflows/evidence-publication-checks.yml").read_text(encoding="utf-8")
        self.assertIn("evidence-publication-threat-model.md", guide)
        self.assertIn("0034-private-qualification-evidence-publication.md", guide)
        self.assertIn("evidence-publication-threat-model.md", security)
        self.assertIn("0034-private-qualification-evidence-publication.md", security)
        self.assertIn("# ADR 0034", adr)
        self.assertIn("**Status:** Accepted", adr)
        self.assertIn("0034-private-qualification-evidence-publication.md", index)
        for boundary in (
            "compromised credential-bearing runner", "GitHub environment settings",
            "index", "failed", "Level B", "Level C",
            "Read & Write", "approved", "privacy",
        ):
            self.assertIn(boundary.lower(), model.lower())
        for path in (
            "docs/qualification/evidence-publication-threat-model.md",
            "docs/security-model.md",
            "docs/adr/0034-private-qualification-evidence-publication.md",
            "docs/adr/README.md",
        ):
            self.assertEqual(checks.count(f'"{path}"'), 2)

    def test_publisher_and_real_level_a_producer_agree_on_recording_and_attempt(self):
        producer = (ROOT / ".github/workflows/v010-shell-runtime-qualification.yml").read_text(encoding="utf-8")
        publisher = (ROOT / ".github/workflows/publish-qualification-evidence.yml").read_text(encoding="utf-8")
        for marker in (
            'workstation_recording = artifacts / "workstation-runtime.mkv"',
            'workstation_recording_metadata = artifacts / "workstation-runtime.metadata.json"',
            'workstation_recording_sha256 = artifacts / "workstation-runtime.sha256"',
            '"workstation_recording": {',
            '"metadata_sha256": digest(workstation_recording_metadata)',
            '"digest_file_sha256": digest(workstation_recording_sha256)',
            'name: linura-v010-shell-runtime-${{ inputs.source_sha || github.sha }}-attempt-${{ github.run_attempt }}',
        ):
            self.assertIn(marker, producer)
        self.assertIn(
            'name: linura-v010-shell-runtime-${{ needs.preflight.outputs.source_sha }}-attempt-${{ inputs.attempt }}',
            publisher,
        )

    def test_rerun_cannot_reuse_historical_environment_approval(self):
        self.assertEqual(
            publication.github_approval(self.approvals, "Ehsan-Azari", 1),
            "Ehsan-Azari",
        )
        with self.assertRaisesRegex(publication.AdmissionError, "fresh dispatch"):
            publication.github_approval(self.approvals, "Ehsan-Azari", 2)
        env = {
            "GITHUB_RUN_ID": "87654", "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SHA": "b" * 40,
            "GITHUB_WORKFLOW_REF": PUBLICATION["workflow_ref"],
        }
        with patch.dict(os.environ, env):
            with self.assertRaisesRegex(publication.AdmissionError, "publication-run identity"):
                publication.publication_identity()
        publisher = (ROOT / ".github/workflows/publish-qualification-evidence.yml").read_text(encoding="utf-8")
        self.assertIn('[[ "$GITHUB_RUN_ATTEMPT" = 1 ]]', publisher)

    def test_manifest_cannot_omit_qualified_runtime_cases(self):
        self.manifest["cases"].pop(self.case_ids[-1])
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "runtime case set"):
            self.admit()

    def test_retained_case_results_must_match_manifest_even_with_valid_digest(self):
        self.put(
            "cases.tsv",
            "".join(
                f"{case_id}\t{'failed' if i == 0 else 'passed'}\n"
                for i, case_id in enumerate(self.case_ids)
            ).encode(),
        )
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "retained runtime cases"):
            self.admit()

    def test_runtime_contract_binding_must_be_current_and_exact(self):
        self.manifest["runtime_contract"]["sha256"] = "f" * 64
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "qualification contract binding"):
            self.admit()

    def test_untrusted_r2_endpoint_is_rejected_before_credentials_are_used(self):
        valid = "https://" + "a" * 32 + ".r2.cloudflarestorage.com"
        env = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "Ehsan-Azari",
            "GITHUB_WORKFLOW_REF": PUBLICATION["workflow_ref"],
            "R2_BUCKET": self.policy["bucket"],
            "AWS_ACCESS_KEY_ID": "dummy",
            "AWS_SECRET_ACCESS_KEY": "dummy",
        }
        bad = (
            "https://attacker.example/?redirect=.r2.cloudflarestorage.com",
            "https://attacker.example/path.r2.cloudflarestorage.com",
            valid + "/wrong-prefix",
            valid + ":443",
            "http://" + "a" * 32 + ".r2.cloudflarestorage.com",
        )
        for endpoint in bad:
            with self.subTest(endpoint=endpoint), patch.dict(
                os.environ, {**env, "R2_ENDPOINT": endpoint}
            ):
                with self.assertRaisesRegex(publication.AdmissionError, "untrusted R2 endpoint"):
                    publication.publish(
                        self.bundle, self.root / "nonexistent-run.json",
                        self.root / "nonexistent-approval.json", "baselines",
                        SOURCE, RUN_ID, ATTEMPT, "Ehsan-Azari",
                        "Selected baseline for archive", DATE, self.policy,
                    )
        # Explicitly permit jurisdictional account endpoints.
        for endpoint in (valid, valid.replace(".r2.", ".eu.r2.")):
            with self.subTest(endpoint=endpoint), patch.dict(
                os.environ, {**env, "R2_ENDPOINT": endpoint}
            ):
                with self.assertRaises(FileNotFoundError):
                    publication.publish(
                        self.bundle, self.root / "nonexistent-run.json",
                        self.root / "nonexistent-approval.json", "baselines",
                        SOURCE, RUN_ID, ATTEMPT, "Ehsan-Azari",
                        "Selected baseline for archive", DATE, self.policy,
                    )

    def test_r2_subprocess_timeout_fails_closed(self):
        with patch.dict(os.environ, {"R2_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com"}):
            with patch.object(
                publication.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["aws", "s3api"], 300),
            ):
                with self.assertRaisesRegex(publication.AdmissionError, "timed out"):
                    publication.aws(["head-object", "--bucket", "example"])

    def admitted_snapshot(self):
        source_run = self.root / "source-run.json"
        source_run.write_bytes(publication.canonical(self.run))
        staged = self.root / "admitted-evidence"
        env = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "Ehsan-Azari",
            "GITHUB_RUN_ID": str(PUBLICATION["run_id"]),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": PUBLICATION["head_sha"],
            "GITHUB_WORKFLOW_REF": PUBLICATION["workflow_ref"],
        }
        with patch.dict(os.environ, env):
            receipt_sha = publication.admit(
                self.bundle, staged, source_run, "baselines", SOURCE,
                RUN_ID, ATTEMPT, "Ehsan-Azari",
                "Selected merged workstation baseline", self.policy
            )
        return staged, receipt_sha, source_run, env

    def test_admission_snapshot_receipt_is_bound_to_a_secret_free_job(self):
        staged, receipt_sha, _, env = self.admitted_snapshot()
        receipt_file = staged / publication.ADMISSION
        self.assertEqual(publication.sha256(receipt_file), receipt_sha)
        with patch.dict(os.environ, env):
            with patch.object(publication, "verify_video",
                              side_effect=AssertionError("media probe in secret job")):
                manifest, files = publication.read_admission(
                    staged, receipt_sha, SOURCE, RUN_ID, ATTEMPT,
                    "baselines", "Ehsan-Azari",
                    "Selected merged workstation baseline", self.policy,
                )
        self.assertEqual(manifest, self.manifest)
        self.assertIn("workstation-runtime.mkv", files)
        self.assertNotIn(publication.ADMISSION, files)

    def test_admission_tampering_is_refused_without_media_probe(self):
        staged, receipt_sha, _, env = self.admitted_snapshot()
        receipt_file = staged / publication.ADMISSION
        receipt_file.write_bytes(receipt_file.read_bytes() + b" ")
        with patch.dict(os.environ, env):
            with patch.object(publication, "verify_video",
                              side_effect=AssertionError("media probe in secret job")):
                with self.assertRaisesRegex(publication.AdmissionError, "digest mismatch"):
                    publication.read_admission(
                        staged, receipt_sha, SOURCE, RUN_ID, ATTEMPT,
                        "baselines", "Ehsan-Azari",
                        "Selected merged workstation baseline", self.policy,
                    )

    def test_admitted_video_substitution_fails_before_remote_upload(self):
        staged, receipt_sha, _, env = self.admitted_snapshot()
        (staged / "workstation-runtime.mkv").write_bytes(b"wrong" * 500)
        env.update({
            "R2_BUCKET": self.policy["bucket"],
            "R2_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            "AWS_ACCESS_KEY_ID": "dummy", "AWS_SECRET_ACCESS_KEY": "dummy",
        })
        run_file = self.root / "source-run.json"
        approval_file = self.root / "publication-approvals.json"
        approval_file.write_bytes(publication.canonical(self.approvals))
        with patch.dict(os.environ, env):
            with patch.object(publication, "verify_video",
                              side_effect=AssertionError("media probe in secret job")):
                with patch.object(publication, "put_new",
                                  side_effect=AssertionError("remote write before snapshot")):
                    with self.assertRaisesRegex(
                        publication.AdmissionError, "unsafe|snapshot|changed"
                    ):
                        publication.publish(
                            staged, run_file, approval_file, "baselines",
                            SOURCE, RUN_ID, ATTEMPT, "Ehsan-Azari",
                            "Selected merged workstation baseline", DATE,
                            self.policy, admission_sha=receipt_sha,
                        )

    def test_publish_never_probes_media_with_r2_credentials(self):
        staged, receipt_sha, _, env = self.admitted_snapshot()
        env.update({
            "R2_BUCKET": self.policy["bucket"],
            "R2_ENDPOINT": "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
            "AWS_ACCESS_KEY_ID": "dummy", "AWS_SECRET_ACCESS_KEY": "dummy",
        })
        approval_file = self.root / "publication-approvals.json"
        approval_file.write_bytes(publication.canonical(self.approvals))
        uploaded = []
        with patch.dict(os.environ, env):
            with patch.object(publication, "verify_video",
                              side_effect=AssertionError("media probe in secret job")):
                with patch.object(publication, "put_new",
                                  side_effect=lambda *a: uploaded.append(a)):
                    with patch.object(publication, "put_index", return_value=None):
                        result = publication.publish(
                            staged, self.root / "source-run.json", approval_file,
                            "baselines", SOURCE, RUN_ID, ATTEMPT,
                            "Ehsan-Azari", "Selected merged workstation baseline",
                            DATE, self.policy, admission_sha=receipt_sha,
                        )
        self.assertTrue(result.startswith("index/baselines/"))
        self.assertEqual(len(uploaded), len(self.bindings) + 5)

    def test_workflow_media_and_r2_credentials_use_different_jobs(self):
        workflow = (ROOT / ".github/workflows/publish-qualification-evidence.yml").read_text(encoding="utf-8")
        self.assertIn("\n  admission:\n", workflow)
        self.assertIn("\n  archive:\n    needs: [preflight, admission]", workflow)
        admission, archive = workflow.split("\n  archive:", 1)
        self.assertIn("tools/evidence_publication.py admit", admission)
        self.assertIn("ffmpeg", admission)
        self.assertNotIn("AWS_ACCESS_KEY_ID:", admission)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY:", admission)
        self.assertIn("tools/evidence_publication.py publish", archive)
        self.assertIn("--admission-sha256", archive)
        self.assertNotIn("ffmpeg", archive)
        self.assertNotIn("tools/evidence_publication.py admit", archive)
        self.assertIn("AWS_SECRET_ACCESS_KEY:", archive)

    def test_existing_index_requires_valid_original_approval_provenance(self):
        _, record, _ = self.admit()
        variants = [
            {"selected_by": ""},
            {"approved_by": "?invalid"},
            {"approval_reason": "short"},
            {"admitted_at": "2026-09-30T00:00:00"},
            {"admitted_at": "not a time"},
            {"publication_run": {**PUBLICATION, "run_id": 0}},
            {"publication_run": {**PUBLICATION, "run_attempt": 0}},
            {"publication_run": {**PUBLICATION, "head_sha": "invalid"}},
            {"publication_run": {**PUBLICATION, "workflow_ref": "unsafe"}},
        ]
        path = self.root / "index-retry.json"
        path.write_bytes(publication.canonical(record))
        for change in variants:
            with self.subTest(change=change):
                previous = {**record, **change}
                old = publication.canonical(previous)
                def fake_aws(args, output=False):
                    if args[0] == "head-object":
                        return json.dumps({
                            "Metadata": {"sha256": digest(old)},
                            "ContentLength": len(old),
                        })
                    if args[0] == "get-object":
                        Path(args[-1]).write_bytes(old)
                    return ""
                with patch.object(publication, "put_new",
                                  side_effect=publication.AdmissionError("already exists")):
                    with patch.object(publication, "aws", side_effect=fake_aws):
                        with self.assertRaisesRegex(
                            publication.AdmissionError, "approval provenance"
                        ):
                            publication.put_index("bucket", "index/record", path, record)

    def test_good_record_has_immutable_identity_and_manifest_binding(self):
        prefix, record, files = self.admit()
        self.assertEqual(prefix, f"baselines/{SOURCE}/{RUN_ID}/{ATTEMPT}")
        self.assertEqual(record["objects"][f"{prefix}/{publication.MANIFEST}"]["sha256"], files[publication.MANIFEST]["sha256"])
        self.assertEqual(record["retention_days"], 180)
        self.assertEqual(record["publication_run"], PUBLICATION)

    def test_actual_level_a_manifest_binds_recording_separately_from_artifacts(self):
        for name in (
            "workstation-runtime.mkv",
            "workstation-runtime.metadata.json",
            "workstation-runtime.sha256",
        ):
            self.assertNotIn(name, self.bindings)
        _, record, files = self.admit()
        for name in (
            "workstation-runtime.mkv",
            "workstation-runtime.metadata.json",
            "workstation-runtime.sha256",
        ):
            self.assertIn(name, files)
            self.assertTrue(any(key.endswith("/" + name) for key in record["objects"]))

    def test_recording_metadata_must_match_independent_media_probe(self):
        self.meta["width"] = 999
        metadata = publication.canonical(self.meta)
        self.put("workstation-runtime.metadata.json", metadata, bound=False)
        self.manifest["workstation_recording"]["metadata_sha256"] = digest(metadata)
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "recording metadata mismatch"):
            self.admit()

    def test_missing_or_modified_recording_sidecars_fail_closed(self):
        metadata = self.bundle / "workstation-runtime.metadata.json"
        metadata.unlink()
        with self.assertRaisesRegex(publication.AdmissionError, "unsafe evidence"):
            self.admit()
        metadata.write_bytes(publication.canonical(self.meta))
        sidecar = self.bundle / "workstation-runtime.sha256"
        sidecar.write_text("0" * 64 + "  workstation-runtime.mkv\\n")
        with self.assertRaisesRegex(publication.AdmissionError, "recording binding mismatch"):
            self.admit()

    def test_publication_identity_requires_exact_approved_workflow(self):
        env = {
            "GITHUB_RUN_ID": "87654", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "b" * 40,
            "GITHUB_WORKFLOW_REF": PUBLICATION["workflow_ref"],
        }
        with patch.dict(os.environ, env):
            self.assertEqual(publication.publication_identity(), PUBLICATION)
        env["GITHUB_WORKFLOW_REF"] = (
            "linura-org/linura/.github/workflows/unsafe.yml@refs/heads/main"
        )
        with patch.dict(os.environ, env):
            with self.assertRaisesRegex(publication.AdmissionError, "publication-run identity"):
                publication.publication_identity()

    def test_missing_publication_run_provenance_is_rejected(self):
        manifest, files = publication.verified_bundle(self.bundle, SOURCE, RUN_ID, ATTEMPT, self.policy)
        with self.assertRaisesRegex(publication.AdmissionError, "publication run provenance"):
            publication.make_record(manifest, files, "baselines", "Ehsan-Azari",
                                    "Selected merged workstation baseline", DATE, self.policy,
                                    reviewer="Ehsan-Azari")

    def test_ci_extra_logs_are_never_admitted(self):
        (self.bundle / "potentially-private.log").write_text("unreviewed")
        _, record, _ = self.admit()
        self.assertFalse(any("potentially-private" in key for key in record["objects"]))

    def test_manifest_checksum_mismatch(self):
        (self.bundle / publication.MANIFEST).write_bytes(b"{}")
        with self.assertRaisesRegex(publication.AdmissionError, "checksum"):
            self.admit()

    def test_source_substitution(self):
        self.manifest["source_sha"] = "b" * 40
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "source mismatch"):
            self.admit()

    def test_qualification_failure(self):
        self.manifest["cases"][self.case_ids[0]] = "failed"
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "cases"):
            self.admit()

    def test_release_promotion_refused(self):
        self.manifest["release_support_promotion"] = True
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "candidate evidence"):
            self.admit()

    def test_modified_video_refused(self):
        (self.bundle / "workstation-runtime.mkv").write_bytes(b"tampered" * 200)
        with self.assertRaisesRegex(publication.AdmissionError, "recording binding"):
            self.admit()

    def test_unbound_recording_metadata_refused(self):
        self.meta["source_sha"] = "b" * 40
        data = publication.canonical(self.meta)
        self.put("workstation-runtime.metadata.json", data)
        self.manifest["workstation_recording"]["metadata_sha256"] = digest(data)
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "recording metadata mismatch"):
            self.admit()

    def test_symlink_refused(self):
        p = self.bundle / "cases.tsv"
        p.unlink()
        p.symlink_to(self.bundle / "workstation-runtime.mkv")
        with self.assertRaisesRegex(publication.AdmissionError, "unsafe evidence"):
            self.admit()

    def test_hardlink_refused(self):
        os.link(self.bundle / "cases.tsv", self.root / "hardlinked")
        with self.assertRaisesRegex(publication.AdmissionError, "unsafe evidence"):
            self.admit()

    def test_absolute_or_traversal_filename_refused(self):
        self.put("independent.txt", b"verified general evidence")
        self.bindings["../stolen"] = self.bindings.pop("independent.txt")
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "unsafe file name"):
            self.admit()

    def test_duplicate_json_manifest_keys_refused(self):
        p = self.bundle / publication.MANIFEST
        data = p.read_text().replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        p.write_text(data)
        (self.bundle / publication.SIDECAR).write_text(f"{digest(data.encode())}  {publication.MANIFEST}\n")
        with self.assertRaisesRegex(publication.AdmissionError, "duplicate JSON key"):
            self.admit()

    def test_failed_remote_run_refused(self):
        self.run["conclusion"] = "failure"
        with self.assertRaisesRegex(publication.AdmissionError, "not successful"):
            self.admit()

    def test_pr_run_refused(self):
        self.run["head_branch"] = "feat/untrusted"
        with self.assertRaisesRegex(publication.AdmissionError, "main source"):
            self.admit()

    def test_unrelated_successful_workflow_cannot_be_used_as_origin(self):
        for path in (
            ".github/workflows/v010-qualification.yml",
            ".github/workflows/v010-shell-runtime-qualification.yml@other-branch",
            ".github/workflows/v010-shell-runtime-qualification.yml@main/other",
        ):
            with self.subTest(path=path):
                self.run["path"] = path
                with self.assertRaisesRegex(publication.AdmissionError, "untrusted workflow origin"):
                    self.admit()

    def test_ref_qualified_main_workflow_paths_are_accepted(self):
        for path in (
            ".github/workflows/v010-shell-runtime-qualification.yml",
            ".github/workflows/v010-shell-runtime-qualification.yml@main",
            ".github/workflows/v010-shell-runtime-qualification.yml@refs/heads/main",
        ):
            with self.subTest(path=path):
                self.run["path"] = path
                self.admit()

    def test_publication_preflight_workflow_path_matches_python_admission(self):
        workflow = (ROOT / ".github/workflows/publish-qualification-evidence.yml").read_text(encoding="utf-8")
        marker = 'python3 - "$RUNNER_TEMP/source-run.json" "$SOURCE_SHA" "$RUN_ID" "$ATTEMPT" <<\'PY\'\n'
        self.assertIn(marker, workflow)
        script = textwrap.dedent(workflow.split(marker, 1)[1].split("\n          PY", 1)[0])
        run_file = self.root / "preflight-run.json"
        for path, permitted in (
            (".github/workflows/v010-shell-runtime-qualification.yml", True),
            (".github/workflows/v010-shell-runtime-qualification.yml@main", True),
            (".github/workflows/v010-shell-runtime-qualification.yml@refs/heads/main", True),
            (".github/workflows/v010-shell-runtime-qualification.yml@other-branch", False),
            (".github/workflows/v010-qualification.yml@main", False),
        ):
            with self.subTest(path=path):
                run_file.write_text(json.dumps({**self.run, "path": path}), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-c", script, str(run_file), SOURCE, str(RUN_ID), str(ATTEMPT)],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode == 0, permitted, result.stderr)


    def test_wrong_run_attempt_refused(self):
        self.run["run_attempt"] = 1
        with self.assertRaisesRegex(publication.AdmissionError, "run/attempt mismatch"):
            self.admit()

    def test_missing_environment_approval_refused(self):
        self.approvals = []
        with self.assertRaisesRegex(publication.AdmissionError, "environment approval"):
            self.admit()

    def test_other_environment_approval_refused(self):
        self.approvals[0]["environments"][0]["name"] = "linura-production"
        with self.assertRaisesRegex(publication.AdmissionError, "environment approval"):
            self.admit()

    def test_independent_environment_reviewer_is_accepted_and_recorded(self):
        self.approvals[0]["user"]["login"] = "other"
        _, record, _ = self.admit()
        self.assertEqual(record["selected_by"], "Ehsan-Azari")
        self.assertEqual(record["approved_by"], "other")

    def test_unapproved_category_refused(self):
        manifest, files = publication.verified_bundle(self.bundle, SOURCE, RUN_ID, ATTEMPT, self.policy)
        with self.assertRaisesRegex(publication.AdmissionError, "only selected"):
            publication.make_record(manifest, files, "physical", "Ehsan-Azari", "approval for archive", DATE, self.policy, reviewer="Ehsan-Azari", publication_run=PUBLICATION)

    def test_inadequate_reason_refused(self):
        manifest, files = publication.verified_bundle(self.bundle, SOURCE, RUN_ID, ATTEMPT, self.policy)
        with self.assertRaisesRegex(publication.AdmissionError, "approval reason"):
            publication.make_record(manifest, files, "baselines", "Ehsan-Azari", "yes", DATE, self.policy)

    def test_upload_verifies_readback_and_conditional_write(self):
        src = self.bundle / "workstation-runtime.mkv"
        content = src.read_bytes()
        calls = []
        def fake_aws(args, output=False):
            calls.append(args)
            if args[0] == "head-object":
                return json.dumps({"Metadata": {"sha256": digest(content)}, "ContentLength": len(content)})
            if args[0] == "get-object":
                Path(args[-1]).write_bytes(content)
            return ""
        with patch.object(publication, "aws", side_effect=fake_aws):
            publication.put_new("bucket", "baselines/a", src, digest(content))
        self.assertEqual([call[0] for call in calls], ["put-object", "head-object", "get-object"])
        self.assertEqual(calls[0][calls[0].index("--if-none-match") + 1], "*")

    def test_upload_readback_corruption_refused(self):
        src = self.bundle / "workstation-runtime.mkv"
        content = src.read_bytes()
        def fake_aws(args, output=False):
            if args[0] == "head-object":
                return json.dumps({"Metadata": {"sha256": digest(content)}, "ContentLength": len(content)})
            if args[0] == "get-object":
                Path(args[-1]).write_bytes(b"x" * len(content))
            return ""
        with patch.object(publication, "aws", side_effect=fake_aws):
            with self.assertRaisesRegex(publication.AdmissionError, "remote object bytes mismatch"):
                publication.put_new("bucket", "baselines/a", src, digest(content))

    def test_existing_index_retries_with_first_approval_record_intact(self):
        _, record, _ = self.admit()
        original = dict(record)
        original["admitted_at"] = "2026-09-30T00:00:00+00:00"
        original["approved_by"] = "independent-reviewer"
        original_bytes = publication.canonical(original)
        path = self.root / "new-index.json"
        path.write_bytes(publication.canonical(record))
        def fake_aws(args, output=False):
            if args[0] == "head-object":
                return json.dumps({
                    "Metadata": {"sha256": digest(original_bytes)},
                    "ContentLength": len(original_bytes),
                })
            if args[0] == "get-object":
                Path(args[-1]).write_bytes(original_bytes)
            return ""
        with patch.object(publication, "put_new", side_effect=publication.AdmissionError("already exists")):
            with patch.object(publication, "aws", side_effect=fake_aws):
                publication.put_index("bucket", "index/baselines/record", path, record)
        self.assertEqual(path.read_bytes(), publication.canonical(record))

    def test_existing_index_conflict_is_rejected_without_overwrite(self):
        _, record, _ = self.admit()
        conflict = dict(record)
        conflict["objects"] = {}
        conflict_bytes = publication.canonical(conflict)
        path = self.root / "new-index.json"
        path.write_bytes(publication.canonical(record))
        def fake_aws(args, output=False):
            if args[0] == "head-object":
                return json.dumps({
                    "Metadata": {"sha256": digest(conflict_bytes)},
                    "ContentLength": len(conflict_bytes),
                })
            if args[0] == "get-object":
                Path(args[-1]).write_bytes(conflict_bytes)
            return ""
        with patch.object(publication, "put_new", side_effect=publication.AdmissionError("already exists")):
            with patch.object(publication, "aws", side_effect=fake_aws):
                with self.assertRaisesRegex(publication.AdmissionError, "conflicts"):
                    publication.put_index("bucket", "index/baselines/record", path, record)

    def test_publication_snapshot_uses_verified_single_link_bytes(self):
        original = self.bundle / "workstation-runtime.mkv"
        target = self.root / "approved-video.mkv"
        publication.snapshot_file(original, target, digest(self.recording), len(self.recording))
        self.assertEqual(target.read_bytes(), self.recording)

    def test_publication_snapshot_refuses_symlink_substitution(self):
        original = self.bundle / "workstation-runtime.mkv"
        original.unlink()
        original.symlink_to(self.root / "not-approved")
        with self.assertRaisesRegex(publication.AdmissionError, "unsafe before publication"):
            publication.snapshot_file(original, self.root / "approved-video.mkv",
                                      digest(self.recording), len(self.recording))
        self.assertFalse((self.root / "approved-video.mkv").exists())

    def test_publication_snapshot_refuses_mutated_bytes_before_remote_upload(self):
        original = self.bundle / "workstation-runtime.mkv"
        original.write_bytes(b"unexpectedly changed private material".ljust(len(self.recording), b"x"))
        with self.assertRaisesRegex(publication.AdmissionError, "private publication snapshot"):
            publication.snapshot_file(original, self.root / "approved-video.mkv",
                                      digest(self.recording), len(self.recording))

    def test_unexpected_qualification_claim_is_rejected(self):
        self.manifest["claim"] = "release-support-promotion"
        self.write_manifest()
        with self.assertRaisesRegex(publication.AdmissionError, "unexpected qualification claim"):
            self.admit()

    def test_video_ffprobe_rejects_audio(self):
        from types import SimpleNamespace
        with patch.object(publication.subprocess, "run", return_value=SimpleNamespace(returncode=0,stdout=json.dumps({"streams":[{"codec_type":"video","codec_name":"ffv1","width":640,"height":480},{"codec_type":"audio","codec_name":"aac"}],"format":{"format_name":"matroska","duration":"3"}}))):
            with self.assertRaisesRegex(publication.AdmissionError, "stream contract"):
                REAL_VERIFY_VIDEO(self.bundle / "workstation-runtime.mkv")

    def test_video_ffprobe_rejects_wrong_container(self):
        from types import SimpleNamespace
        with patch.object(publication.subprocess, "run", return_value=SimpleNamespace(returncode=0,stdout=json.dumps({"streams":[{"codec_type":"video","codec_name":"ffv1","width":640,"height":480}],"format":{"format_name":"mp4","duration":"3"}}))):
            with self.assertRaisesRegex(publication.AdmissionError, "container"):
                REAL_VERIFY_VIDEO(self.bundle / "workstation-runtime.mkv")


if __name__ == "__main__":
    unittest.main()
