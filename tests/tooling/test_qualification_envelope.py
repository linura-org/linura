from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools import qualification_envelope as envelopes  # noqa: E402
from tools import qualification_guest_identity as guest_identity  # noqa: E402


def _ubuntu_guest_capture() -> dict:
    return {
        "schema_version": 1,
        "kind": "virtual-machine",
        "architecture": "x86_64",
        "kernel_release": "6.8.0-test",
        "os_release_sha256": "c" * 64,
        "distribution_id": "ubuntu",
        "distribution_version": "24.04",
        "package_manager": "dpkg",
        "package_manifest_sha256": "b" * 64,
        "package_count": 42,
        "virtualization": "qemu",
    }


class QualificationEnvelopeTests(unittest.TestCase):
    def test_contract_inventory_is_reviewed_and_unique(self):
        contract = envelopes.load_contract(ROOT)
        ids = [lane["id"] for lane in contract["lane"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            set(ids),
            {
                "canonical-ci",
                "security-rustsec",
                "codeql",
                "codex-environment",
                "evidence-publication",
                "vm-acceptance",
                "control1-plan-preview-vm",
                "v04-durability",
                "v04-enospc",
                "v05-executor-verifier",
                "v06-managed-lifecycle",
                "v07-library",
                "v08-agent",
                "v09-qualification-contract",
                "v09-qualification",
                "v09-adversarial-security",
                "v09-adversarial-security-shard",
                "v010-workstation-contract",
                "v010-shell-runtime",
                "trusted-release-proof",
                "v010-maintained-hardware",
            },
        )

    def test_lane_execution_subjects_are_explicit(self):
        contract = envelopes.load_contract(ROOT)
        by_id = {lane["id"]: lane for lane in contract["lane"]}
        self.assertEqual(by_id["canonical-ci"]["execution_subject"], "runner")
        self.assertEqual(by_id["v010-maintained-hardware"]["execution_subject"], "runner")
        self.assertEqual(by_id["vm-acceptance"]["execution_subject"], "guest")
        self.assertEqual(by_id["v010-shell-runtime"]["guest_profile"], "arch_rolling_qemu")
        self.assertEqual(by_id["v09-qualification-contract"]["execution_subject"], "runner")
        self.assertEqual(by_id["v09-adversarial-security"]["execution_subject"], "aggregate")
        self.assertEqual(by_id["v09-qualification"]["execution_subject"], "aggregate")
        self.assertEqual(by_id["v09-adversarial-security-shard"]["execution_subject"], "guest")
        self.assertEqual(
            [
                (
                    item["id"],
                    item["boundary_start"],
                    item["boundary_end"],
                    item["primary"],
                    item["final"],
                )
                for item in contract["v09_adversarial_shard"]
            ],
            list(envelopes.V09_ADVERSARIAL_SHARDS),
        )

    def test_rustsec_observation_types_fail_closed(self):
        valid = {
            "advisory_db_identity": "a" * 40,
            "advisory_retrieved_at": "2026-10-07T00:00:00Z",
        }
        self.assertEqual(
            envelopes._validate_observations(valid, set(valid), "security-rustsec"),
            valid,
        )
        for field, value in (
            ("advisory_db_identity", "not-a-git-sha"),
            ("advisory_retrieved_at", "yesterday"),
            ("advisory_retrieved_at", "2026-13-99T99:99:99Z"),
        ):
            candidate = dict(valid)
            candidate[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(envelopes.EnvelopeError):
                    envelopes._validate_observations(
                        candidate, set(candidate), "security-rustsec"
                    )

    def test_qualification_environment_observation_is_reviewed(self):
        valid = {"qualification_environment_id": "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless"}
        self.assertEqual(
            envelopes._validate_observations(valid, set(valid), "v09-qualification-contract"),
            valid,
        )
        with self.assertRaisesRegex(envelopes.EnvelopeError, "qualification environment id is not reviewed"):
            envelopes._validate_observations(
                {"qualification_environment_id": "qualification/forged"},
                {"qualification_environment_id"},
                "v09-qualification-contract",
            )
        shard_observations = {
            "qualification_environment_id": "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless",
            "shard_id": "primary",
        }
        self.assertEqual(
            envelopes._validate_observations(
                shard_observations,
                set(shard_observations),
                "v09-adversarial-security-shard",
            ),
            shard_observations,
        )
        forged_shard = dict(shard_observations)
        forged_shard["shard_id"] = "future-but-unreviewed"
        with self.assertRaisesRegex(
            envelopes.EnvelopeError, "adversarial shard id is not reviewed"
        ):
            envelopes._validate_observations(
                forged_shard,
                set(forged_shard),
                "v09-adversarial-security-shard",
            )

    def test_guest_identity_capture_parser_is_typed(self):
        output = "\n".join(
            [
                "architecture=x86_64",
                "kernel_release=6.8.0-test",
                "os_release_sha256=" + "c" * 64,
                "distribution_id=ubuntu",
                "distribution_version=24.04",
                "package_manager=dpkg",
                "package_manifest_sha256=" + "b" * 64,
                "package_count=42",
                "virtualization=qemu",
            ]
        )
        parsed = guest_identity._parse_capture_output(output, "dpkg")
        self.assertEqual(parsed, _ubuntu_guest_capture())
        remote_script = guest_identity._remote_script("dpkg")
        self.assertIn("${binary:Package}", remote_script)
        self.assertIn("${Version}", remote_script)
        with self.assertRaises(guest_identity.GuestIdentityError):
            guest_identity._parse_capture_output(output + "\nextra=forbidden", "dpkg")

    def test_guest_execution_subject_cross_binds_base_image_and_package_manifest(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="vm-acceptance",
            source_sha=source_sha,
            digests={"base_image_sha256": "a" * 64},
            observations={"guest_package_manifest_sha256": "b" * 64},
            verified_cache_specs=[],
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
            },
            execution_subject=_ubuntu_guest_capture(),
        )
        subject = envelope["execution_subject"]
        self.assertEqual(subject["kind"], "virtual-machine")
        self.assertEqual(subject["acceleration"], "tcg")
        self.assertEqual(subject["image_digests"], {"base_image_sha256": "a" * 64})
        self.assertEqual(subject["package_manifest_sha256"], "b" * 64)

        forged = json.loads(json.dumps(envelope))
        forged["execution_subject"]["package_manifest_sha256"] = "d" * 64
        body = dict(forged)
        body.pop("envelope_sha256")
        forged["envelope_sha256"] = envelopes._sha256_bytes(
            envelopes._canonical_json(body)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, forged)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError,
                "guest_package_manifest_sha256 does not match guest execution subject",
            ):
                envelopes.verify_envelope(ROOT, path)

    def test_aggregate_execution_subject_binds_component_set(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="v09-qualification",
            source_sha=source_sha,
            digests={},
            observations={
                "qualification_environment_id": "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless",
                "component_envelope_set_sha256": "e" * 64,
            },
            verified_cache_specs=[],
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
            },
        )
        self.assertEqual(
            envelope["execution_subject"],
            {
                "kind": "aggregate",
                "component_envelope_set_sha256": "e" * 64,
            },
        )

    def test_v09_routes_bind_contract_and_final_execution_envelopes(self):
        workflow = (ROOT / ".github/workflows/v09-qualification.yml").read_text(encoding="utf-8")
        self.assertIn("lane: v09-qualification-contract", workflow)
        self.assertIn("artifact-suffix: contract", workflow)
        self.assertIn("Upload stable v0.9 contract envelope hand-off", workflow)
        self.assertEqual(workflow.count("name: linura-v09-contract-envelope-${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}"), 3)
        self.assertNotIn("qualification-envelope-v09-qualification-contract-${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}-contract-attempt-${{ github.run_attempt }}", workflow)
        envelope_steps = envelopes.workflow_action_steps(
            workflow, "./.github/actions/qualification-envelope"
        )
        self.assertEqual(
            sum(
                envelopes.workflow_step_has_value(
                    block, "lane", "v09-qualification"
                )
                for _, block in envelope_steps
            ),
            2,
        )
        self.assertIn("artifact-suffix: regression", workflow)
        self.assertIn("CONTRACT_ENVELOPE_ROOT: /tmp/linura-v09-contract-envelope", workflow)
        self.assertIn("for item in (contract_envelope, vm_envelope, adversarial_envelope)", workflow)
        self.assertIn("COMPONENT_ENVELOPE_SET_SHA256=", workflow)
        self.assertGreaterEqual(workflow.count("qualification-execution-components.json"), 3)
        self.assertIn('"route": "exact-source-regression"', workflow)
        self.assertIn('"route": "full"', workflow)
        self.assertIn("Upload exact-source regression execution context", workflow)
        self.assertIn("canonical_adversarial_component_digest", workflow)
        self.assertIn("normalized_adversarial_components.sort(key=lambda item: item[\"id\"])", workflow)
        self.assertIn("execution_components = sorted(", workflow)
        self.assertIn("v0.9 adversarial aggregate environment mismatch", workflow)
        self.assertNotIn("V09-REGRESSION-EVIDENCE.json", workflow)
        self.assertNotIn('"execution_envelopes":', workflow)

    def test_execution_context_layer_never_accepts_evidence(self):
        qualification = (ROOT / ".github/workflows/v09-qualification.yml").read_text(encoding="utf-8")
        adversarial = (ROOT / ".github/workflows/v09-adversarial-security.yml").read_text(encoding="utf-8")
        vm = (ROOT / ".github/workflows/vm-acceptance.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/trusted-release-proof.yml").read_text(encoding="utf-8")
        shard = (ROOT / "scripts/qualification/v09-adversarial-guest.sh").read_text(encoding="utf-8")

        self.assertNotIn('"execution_envelopes":', qualification)
        self.assertNotIn('"execution_envelopes":', adversarial)
        self.assertNotIn('"guest_execution_identity": {', vm)
        self.assertNotIn("'guest_execution_identity': {", shard)
        self.assertNotIn("Bind execution-envelope digest into release proof receipt", release)
        self.assertNotIn('receipt["execution_envelope"]', release)
        self.assertIn("qualification-execution-components.json", adversarial)
        self.assertIn("Bind trusted-release execution envelope", release)

    def test_v09_aggregate_lanes_do_not_claim_unexecuted_base_images(self):
        contract = envelopes.load_contract(ROOT)
        for lane_id in ("v09-qualification", "v09-adversarial-security"):
            with self.subTest(lane=lane_id):
                lane = envelopes.lane_by_id(contract, lane_id)
                self.assertEqual(lane["execution_subject"], "aggregate")
                self.assertEqual(lane["required_digests"], [])
                self.assertIn("component_envelope_set_sha256", lane["required_observations"])

    def test_rustsec_producer_binds_canonical_repository_under_isolated_git(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", workflow)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", workflow)
        self.assertIn("https://github.com/RustSec/advisory-db.git", workflow)
        self.assertIn("/usr/bin/git --no-replace-objects", workflow)
        self.assertIn("test ! -L \"$advisory_db\"", workflow)
        self.assertIn("test ! -L \"$advisory_db/.git\"", workflow)

    def test_cache_policy_never_promotes_a_cache_hit_to_qualification(self):
        contract = envelopes.load_contract(ROOT)
        self.assertEqual(
            contract["cache_policy"],
            {
                "cache_hit_is_qualification": False,
                "content_digest_required": True,
                "independent_verification_required": True,
                "source_pass_reuse_allowed": False,
                "qualification_evidence_cache_allowed": False,
                "build_output_cache_allowed": False,
            },
        )

    def test_security_freshness_is_observation_not_frozen_input(self):
        contract = envelopes.load_contract(ROOT)
        lane = envelopes.lane_by_id(contract, "security-rustsec")
        self.assertTrue(lane["freshness_is_nondeterministic"])
        self.assertEqual(
            set(lane["required_observations"]),
            {"advisory_db_identity", "advisory_retrieved_at"},
        )
        self.assertEqual(lane["required_digests"], ["cargo_audit_sha256"])
        self.assertNotIn("advisory_db_identity", lane["required_digests"])

    def test_security_rebuilds_audit_tool_instead_of_trusting_binary_cache(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertNotIn("actions/cache@", workflow)
        self.assertIn('audit_bin="$HOME/.cargo/bin/cargo-audit"', workflow)
        self.assertIn('rm -f "$audit_bin"', workflow)
        self.assertIn("cargo install cargo-audit --locked", workflow)
        self.assertIn("CARGO_AUDIT_SHA256=", workflow)
        self.assertIn('test ! -L "$audit_bin"', workflow)
        self.assertIn('"$HOME/.cargo/bin/cargo-audit" audit', workflow)

    def test_trusted_release_auxiliary_source_stays_outside_primary_worktree(self):
        workflow = (ROOT / ".github/workflows/trusted-release-proof.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "V010_SOURCE_ROOT: /tmp/linura-v010-source", workflow
        )
        self.assertNotIn("path: v010-source", workflow)
        self.assertIn(
            'worktree add --detach "$V010_SOURCE_ROOT" "$SOURCE_SHA"', workflow
        )

    def test_round_trip_binds_exact_source_tree_runner_and_repo_inputs(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        environment = {
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "ImageOS": "ubuntu24",
            "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
        }
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="canonical-ci",
            source_sha=source_sha,
            digests={},
            observations={},
            verified_cache_specs=[],
            environment=environment,
        )
        self.assertEqual(envelope["source"]["commit_sha"], source_sha)
        self.assertRegex(envelope["source"]["tree_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(envelope["runner"]["image_version"], "20261001.1")
        self.assertRegex(envelope["runner"]["os_release_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(envelope["runner"]["package_manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(envelope["runner"]["package_count"], 0)
        self.assertIn("Cargo.lock", envelope["repository_inputs"])
        self.assertIn(
            "contracts/qualification-execution-envelopes.toml",
            envelope["repository_inputs"],
        )
        self.assertIn(".github/workflows/ci.yml", envelope["repository_inputs"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            verified = envelopes.verify_envelope(ROOT, path, source_sha=source_sha)
            self.assertEqual(verified["envelope_sha256"], envelope["envelope_sha256"])

            forged = json.loads(json.dumps(envelope))
            forged["runner"]["package_manager"] = "pacman"
            body = dict(forged)
            body.pop("envelope_sha256")
            forged["envelope_sha256"] = envelopes._sha256_bytes(
                envelopes._canonical_json(body)
            )
            forged_path = Path(directory) / "forged-package-manager.json"
            envelopes.write_envelope(forged_path, forged)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError,
                "package manager does not match runner profile",
            ):
                envelopes.verify_envelope(
                    ROOT, forged_path, source_sha=source_sha
                )

    def test_wrong_source_is_rejected_before_envelope_creation(self):
        with self.assertRaisesRegex(envelopes.EnvelopeError, "exact checked-out source"):
            envelopes.create_envelope(
                root=ROOT,
                lane_id="canonical-ci",
                source_sha="0" * 40,
                digests={},
                observations={},
                verified_cache_specs=[],
                environment={
                    "RUNNER_OS": "Linux",
                    "RUNNER_ARCH": "X64",
                    "ImageOS": "ubuntu24",
                    "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
                },
            )

    def test_lane_dynamic_inputs_fail_closed(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        with self.assertRaisesRegex(envelopes.EnvelopeError, "digest set mismatch"):
            envelopes.create_envelope(
                root=ROOT,
                lane_id="vm-acceptance",
                source_sha=source_sha,
                digests={},
                observations={"guest_package_manifest_sha256": "a" * 64},
                verified_cache_specs=[],
                environment={
                    "RUNNER_OS": "Linux",
                    "RUNNER_ARCH": "X64",
                    "ImageOS": "ubuntu24",
                    "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
                },
            )

    def test_verified_cache_requires_actual_byte_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.bin"
            path.write_bytes(b"verified-cache")
            actual = envelopes._sha256_file(path)
            accepted = envelopes._verified_caches([f"prepared_substrate={path}@{actual}"])
            self.assertEqual(accepted["prepared_substrate"]["sha256"], actual)
            self.assertFalse(accepted["prepared_substrate"]["qualification_authority"])
            with self.assertRaisesRegex(envelopes.EnvelopeError, "digest mismatch"):
                envelopes._verified_caches(
                    [f"prepared_substrate={path}@{'0' * 64}"]
                )

    def test_tampering_breaks_canonical_digest(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="canonical-ci",
            source_sha=source_sha,
            digests={},
            observations={},
            verified_cache_specs=[],
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["runner"]["image_version"] = "substituted"
            path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(envelopes.EnvelopeError, "canonical digest mismatch"):
                envelopes.verify_envelope(ROOT, path)

    def test_eol_normalization_cannot_hide_raw_worktree_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@linura.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Linura Test"],
                check=True,
            )
            (root / ".gitattributes").write_text("* text=auto eol=lf\n", encoding="utf-8")
            tracked = root / "outside-lane-input.sh"
            tracked.write_bytes(b"#!/bin/sh\necho clean\n")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitattributes", tracked.name],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            source_sha = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()

            tracked.write_bytes(b"#!/bin/sh\r\necho clean\r\n")
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(root), "diff", "--quiet", source_sha, "--"],
                    check=False,
                ).returncode,
                0,
            )
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "raw bytes differ"
            ):
                envelopes._require_clean_tracked_checkout(root, source_sha)

    def test_composite_action_integration_is_structurally_enforced(self):
        action = (
            ROOT / ".github/actions/qualification-envelope/action.yml"
        ).read_text(encoding="utf-8")
        self.assertTrue(envelopes._hosted_action_has_integration(action))

        create_spoof = action.replace(
            " create-from-environment \\\n",
            " disconnected-create \\\n",
            1,
        ) + "\n# create-from-environment qualification_envelope.py\n"
        self.assertFalse(
            envelopes._hosted_action_has_integration(create_spoof)
        )

        verify_spoof = action.replace(
            " tools/qualification_envelope.py verify \\\n",
            " tools/qualification_envelope.py disconnected-verify \\\n",
            1,
        ) + "\n# qualification_envelope.py verify \n"
        self.assertFalse(
            envelopes._hosted_action_has_integration(verify_spoof)
        )

        output_spoof = action.replace(
            "    value: ${{ steps.envelope.outputs.sha256 }}",
            "    value: ${{ steps.disconnected.outputs.sha256 }}",
            1,
        ) + "\n# value: ${{ steps.envelope.outputs.sha256 }}\n"
        self.assertFalse(
            envelopes._hosted_action_has_integration(output_spoof)
        )

        upload_spoof = action.replace(
            "uses: actions/upload-artifact@",
            "uses: actions/checkout@",
            1,
        ) + "\n# actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n"
        self.assertFalse(
            envelopes._hosted_action_has_integration(upload_spoof)
        )

        subject_spoof = action.replace(
            "  execution-subject-file:\n",
            "  disconnected-execution-subject-file:\n",
            1,
        ) + "\n# execution-subject-file:\n"
        self.assertFalse(
            envelopes._hosted_action_has_integration(subject_spoof)
        )

    def test_declared_targets_have_enforced_envelope_integration(self):
        contract = envelopes.load_contract(ROOT)
        envelopes.validate_lane_integrations(ROOT, contract)
        canonical = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertTrue(
            envelopes._hosted_target_has_integration("canonical-ci", canonical)
        )
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "canonical-ci",
                canonical.replace("lane: canonical-ci", "lane: disconnected", 1),
            )
        )
        scalar_spoof = """
jobs:
  canonical:
    runs-on: ubuntu-24.04
    steps:
      - name: Inert embedded workflow text
        run: |
          cat <<'EOF'
          - uses: ./.github/actions/qualification-envelope
            with:
              lane: canonical-ci
          EOF
"""
        self.assertEqual(len(envelopes.workflow_step_blocks(scalar_spoof)), 1)
        self.assertEqual(
            envelopes.workflow_action_steps(
                scalar_spoof, "./.github/actions/qualification-envelope"
            ),
            [],
        )
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "canonical-ci", scalar_spoof
            )
        )
        disabled_step = """
jobs:
  canonical:
    runs-on: ubuntu-24.04
    steps:
      - name: Disabled envelope
        if: ${{ false }}
        uses: ./.github/actions/qualification-envelope
        with:
          lane: canonical-ci
"""
        self.assertFalse(
            envelopes._hosted_target_has_integration("canonical-ci", disabled_step)
        )
        disabled_job = """
jobs:
  canonical:
    if: ${{ false }}
    runs-on: ubuntu-24.04
    steps:
      - name: Apparently connected envelope
        uses: ./.github/actions/qualification-envelope
        with:
          lane: canonical-ci
"""
        self.assertFalse(
            envelopes._hosted_target_has_integration("canonical-ci", disabled_job)
        )
        runtime_gated_job = """
jobs:
  canonical:
    if: ${{ github.event_name == 'pull_request' }}
    runs-on: ubuntu-24.04
    steps:
      - name: Connected envelope
        uses: ./.github/actions/qualification-envelope
        with:
          lane: canonical-ci
"""
        self.assertTrue(
            envelopes._hosted_target_has_integration("canonical-ci", runtime_gated_job)
        )
        error_tolerant_step = """
jobs:
  canonical:
    runs-on: ubuntu-24.04
    steps:
      - name: Error-tolerant envelope
        continue-on-error: true
        uses: ./.github/actions/qualification-envelope
        with:
          lane: canonical-ci
"""
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "canonical-ci", error_tolerant_step
            )
        )
        explicit_fail_closed_step = error_tolerant_step.replace(
            "continue-on-error: true", "continue-on-error: false"
        )
        self.assertTrue(
            envelopes._hosted_target_has_integration(
                "canonical-ci", explicit_fail_closed_step
            )
        )
        error_tolerant_job = """
jobs:
  canonical:
    continue-on-error: true
    runs-on: ubuntu-24.04
    steps:
      - name: Apparently connected envelope
        uses: ./.github/actions/qualification-envelope
        with:
          lane: canonical-ci
"""
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "canonical-ci", error_tolerant_job
            )
        )
        with_spoof = """
jobs:
  canonical:
    runs-on: ubuntu-24.04
    steps:
      - name: Inert embedded inputs
        run: |
          with:
            lane: canonical-ci
      - name: Real disconnected envelope
        uses: ./.github/actions/qualification-envelope
        with:
          lane: disconnected
"""
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "canonical-ci", with_spoof
            )
        )
        reusable_vm = (ROOT / ".github/workflows/vm-acceptance.yml").read_text(
            encoding="utf-8"
        )
        self.assertTrue(
            envelopes._hosted_target_has_integration("vm-acceptance", reusable_vm)
        )
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "vm-acceptance",
                reusable_vm.replace(
                    "lane: ${{ inputs.envelope_lane || 'vm-acceptance' }}",
                    "lane: disconnected",
                    1,
                ),
            )
        )
        evidence_consumer = reusable_vm + """
      - name: Downstream evidence consumer
        uses: ./.github/actions/qualification-evidence
        with:
          lane: ${{ inputs.envelope_lane || 'vm-acceptance' }}
          artifact-root: ${{ env.ARTIFACT_DIR }}
"""
        disconnected_execution = evidence_consumer.replace(
            "lane: ${{ inputs.envelope_lane || 'vm-acceptance' }}",
            "lane: disconnected",
            1,
        )
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "vm-acceptance", disconnected_execution
            )
        )
        control1 = (
            ROOT / ".github/workflows/control1-plan-preview-vm.yml"
        ).read_text(encoding="utf-8")
        self.assertTrue(
            envelopes._hosted_target_has_integration(
                "control1-plan-preview-vm", control1
            )
        )
        disconnected_control1 = control1.replace(
            "envelope_lane: control1-plan-preview-vm",
            "envelope_lane: disconnected",
            1,
        ) + "\n# envelope_lane: control1-plan-preview-vm\n"
        self.assertFalse(
            envelopes._hosted_target_has_integration(
                "control1-plan-preview-vm", disconnected_control1
            )
        )
        adversarial = (
            ROOT / ".github/workflows/v09-adversarial-security.yml"
        ).read_text(encoding="utf-8")
        self.assertTrue(
            envelopes._hosted_target_has_integration(
                "v09-adversarial-security-shard", adversarial
            )
        )

        physical = (
            ROOT
            / "qualification/v010/workstation-acceptance/run-hardware-qualification.sh"
        ).read_text(encoding="utf-8")
        self.assertTrue(envelopes._physical_target_has_integration(physical))
        physical_spoof = r"""
case "$command_name" in
    finalize-run)
        printf '%s\n' '/usr/bin/env -i /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" create-physical --state-root "$state_root" --output "$envelope"'
        # /usr/bin/env -i /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" verify --envelope "$envelope" --source-sha "$source_sha"
        cat <<'EOF'
        /usr/bin/env -i /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" create-physical --state-root "$state_root" --output "$envelope"
        /usr/bin/env -i /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" verify --envelope "$envelope" --source-sha "$source_sha"
EOF
        ;;
esac
"""
        self.assertFalse(
            envelopes._physical_target_has_integration(physical_spoof)
        )
        unreachable_physical_spoof = r"""
case "$command_name" in
    finalize-run)
        if false; then
            /usr/bin/env -i /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" create-physical --state-root "$state_root" --output "$envelope"
            /usr/bin/env -i /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" verify --envelope "$envelope" --source-sha "$source_sha"
        fi
        ;;
esac
"""
        self.assertFalse(
            envelopes._physical_target_has_integration(
                unreachable_physical_spoof
            )
        )

    def test_hardware_finalize_rejects_duplicate_state_roots_before_execution(self):
        runner = (
            ROOT
            / "qualification/v010/workstation-acceptance/run-hardware-qualification.sh"
        )
        cases = (
            ["--state-root", "/tmp/linura-q11-a", "--state-root", "/tmp/linura-q11-b"],
            ["--state-root=/tmp/linura-q11-a", "--state-root", "/tmp/linura-q11-b"],
            ["--state-root", "/tmp/linura-q11-a", "--state-root=/tmp/linura-q11-b"],
            ["--state-root=/tmp/linura-q11-a", "--state-root=/tmp/linura-q11-b"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    ["bash", str(runner), "finalize-run", *arguments],
                    cwd=ROOT,
                    env={**os.environ, "LINURA_SOURCE_ROOT": str(ROOT)},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn(
                    "finalize-run accepts exactly one --state-root",
                    completed.stderr,
                )

    def test_any_dirty_tracked_file_rejects_clean_source_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@linura.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Linura Test"],
                check=True,
            )
            tracked = root / "outside-lane-input.rs"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", tracked.name], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            source_sha = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()

            envelopes._require_clean_tracked_checkout(root, source_sha)

            tracked.write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "tracked worktree raw bytes differ"
            ):
                envelopes._require_clean_tracked_checkout(root, source_sha)

            subprocess.run(["git", "-C", str(root), "add", tracked.name], check=True)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "tracked index differs"
            ):
                envelopes._require_clean_tracked_checkout(root, source_sha)

    def test_untracked_or_ignored_source_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@linura.invalid"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Linura Test"], check=True)
            (root / ".gitignore").write_text("/target/\n.env\n__pycache__/\n", encoding="utf-8")
            tracked = root / "tracked.rs"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", ".gitignore", tracked.name], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "fixture"], check=True)
            source_sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

            (root / "target").mkdir()
            (root / "target/generated.bin").write_bytes(b"generated")
            (root / "__pycache__").mkdir()
            (root / "__pycache__/generated.pyc").write_bytes(b"generated")
            envelopes._require_clean_tracked_checkout(root, source_sha)

            build_script = root / "build.rs"
            build_script.write_text("fn main() {}\n", encoding="utf-8")
            with self.assertRaisesRegex(envelopes.EnvelopeError, "untracked or ignored source inputs"):
                envelopes._require_clean_tracked_checkout(root, source_sha)
            build_script.unlink()

            (root / ".env").write_text("RUSTFLAGS=--cfg injected\n", encoding="utf-8")
            with self.assertRaisesRegex(envelopes.EnvelopeError, "untracked or ignored source inputs"):
                envelopes._require_clean_tracked_checkout(root, source_sha)

    def test_security_identity_commands_ignore_caller_path(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "systemd-detect-virt"
            fake.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": directory}, clear=False):
                resolved = envelopes._trusted_executable("systemd-detect-virt")
                self.assertNotEqual(Path(resolved), fake)
                self.assertTrue(Path(resolved).is_absolute())
            environment = envelopes._trusted_command_environment()
            self.assertEqual(environment["PATH"], envelopes.TRUSTED_COMMAND_PATH)
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertNotIn("PYTHONPATH", environment)

    def test_all_envelope_identity_commands_use_reviewed_absolute_paths(self):
        for name, candidates in envelopes.TRUSTED_EXECUTABLES.items():
            with self.subTest(command=name):
                self.assertTrue(candidates)
                self.assertTrue(all(candidate.is_absolute() for candidate in candidates))

    def test_executable_bit_drift_rejects_clean_source_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@linura.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Linura Test"],
                check=True,
            )
            regular = root / "regular.sh"
            executable = root / "executable.sh"
            regular.write_bytes(b"#!/bin/sh\necho regular\n")
            executable.write_bytes(b"#!/bin/sh\necho executable\n")
            regular.chmod(0o644)
            executable.chmod(0o755)
            subprocess.run(
                ["git", "-C", str(root), "add", regular.name, executable.name],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            source_sha = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()

            envelopes._require_clean_tracked_checkout(root, source_sha)

            for path, drifted_mode in (
                (regular, 0o755),
                (executable, 0o644),
            ):
                with self.subTest(path=path.name, drifted_mode=oct(drifted_mode)):
                    original_mode = path.stat().st_mode & 0o777
                    path.chmod(drifted_mode)
                    with self.assertRaisesRegex(
                        envelopes.EnvelopeError,
                        "tracked worktree executable bit differs",
                    ):
                        envelopes._require_clean_tracked_checkout(root, source_sha)
                    path.chmod(original_mode)

    def test_repository_redirecting_git_environment_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            mirror = Path(directory) / "mirror"
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@linura.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Linura Test"],
                check=True,
            )
            tracked = root / "tracked.rs"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", tracked.name], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            source_sha = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(
                ["git", "clone", "-q", "--no-hardlinks", str(root), str(mirror)],
                check=True,
            )
            tracked.write_text("dirty\n", encoding="utf-8")

            for name, value in (
                ("GIT_WORK_TREE", str(mirror)),
                ("GIT_DIR", str(mirror / ".git")),
                ("GIT_INDEX_FILE", str(mirror / ".git" / "index")),
                ("GIT_OBJECT_DIRECTORY", str(mirror / ".git" / "objects")),
                ("GIT_CONFIG_COUNT", "1"),
                ("GIT_CONFIG_KEY_0", "core.worktree"),
            ):
                with self.subTest(environment=name):
                    with mock.patch.dict(os.environ, {name: value}, clear=False):
                        with self.assertRaisesRegex(
                            envelopes.EnvelopeError,
                            "repository-redirecting Git environment variables are forbidden",
                        ):
                            envelopes._require_clean_tracked_checkout(root, source_sha)

    def test_pinned_git_context_supports_linked_worktrees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            linked = Path(directory) / "linked"
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@linura.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Linura Test"],
                check=True,
            )
            tracked = root / "tracked.rs"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", tracked.name], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            source_sha = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "worktree",
                    "add",
                    "-q",
                    "--detach",
                    str(linked),
                    source_sha,
                ],
                check=True,
            )

            self.assertTrue((linked / ".git").is_file())
            self.assertEqual(envelopes._git(linked, "rev-parse", "HEAD"), source_sha)
            envelopes._require_clean_tracked_checkout(linked, source_sha)

            (linked / tracked.name).write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "tracked worktree raw bytes differ"
            ):
                envelopes._require_clean_tracked_checkout(linked, source_sha)

    def test_hidden_index_flags_cannot_suppress_dirty_tracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@linura.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Linura Test"],
                check=True,
            )
            tracked = root / "outside-lane-input.rs"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", tracked.name], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            source_sha = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()

            for enable, disable in (
                ("--assume-unchanged", "--no-assume-unchanged"),
                ("--skip-worktree", "--no-skip-worktree"),
            ):
                with self.subTest(index_flag=enable):
                    tracked.write_text("clean\n", encoding="utf-8")
                    subprocess.run(
                        ["git", "-C", str(root), "update-index", disable, tracked.name],
                        check=True,
                    )
                    subprocess.run(
                        ["git", "-C", str(root), "update-index", enable, tracked.name],
                        check=True,
                    )
                    tracked.write_text("dirty\n", encoding="utf-8")
                    with self.assertRaisesRegex(
                        envelopes.EnvelopeError,
                        "git index flags that suppress worktree checks",
                    ):
                        envelopes._require_clean_tracked_checkout(root, source_sha)
                    subprocess.run(
                        ["git", "-C", str(root), "update-index", disable, tracked.name],
                        check=True,
                    )

    def test_digest_named_observation_requires_lowercase_sha256(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        environment = {
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "ImageOS": "ubuntu24",
            "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
        }
        with self.assertRaisesRegex(
            envelopes.EnvelopeError,
            "observation guest_package_manifest_sha256 must be a lowercase sha256 digest",
        ):
            envelopes.create_envelope(
                root=ROOT,
                lane_id="vm-acceptance",
                source_sha=source_sha,
                digests={"base_image_sha256": "a" * 64},
                observations={"guest_package_manifest_sha256": "not-a-digest"},
                verified_cache_specs=[],
                environment=environment,
            )

        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="vm-acceptance",
            source_sha=source_sha,
            digests={"base_image_sha256": "a" * 64},
            observations={"guest_package_manifest_sha256": "b" * 64},
            verified_cache_specs=[],
            environment=environment,
            execution_subject=_ubuntu_guest_capture(),
        )
        envelope["observations"]["guest_package_manifest_sha256"] = "not-a-digest"
        body = dict(envelope)
        body.pop("envelope_sha256")
        envelope["envelope_sha256"] = envelopes._sha256_bytes(
            envelopes._canonical_json(body)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError,
                "observation guest_package_manifest_sha256 must be a lowercase sha256 digest",
            ):
                envelopes.verify_envelope(ROOT, path)

    def test_dirty_repository_input_cannot_claim_clean_source(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        with mock.patch.object(
            envelopes, "_git_blob_bytes", return_value=b"not-the-checked-out-bytes"
        ):
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "working-tree input differs"
            ):
                envelopes.create_envelope(
                    root=ROOT,
                    lane_id="canonical-ci",
                    source_sha=source_sha,
                    digests={},
                    observations={},
                    verified_cache_specs=[],
                    environment={
                        "RUNNER_OS": "Linux",
                        "RUNNER_ARCH": "X64",
                        "ImageOS": "ubuntu24",
                        "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
                    },
                )

    def test_verification_requires_exact_source_checkout(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="canonical-ci",
            source_sha=source_sha,
            digests={},
            observations={},
            verified_cache_specs=[],
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            original_git = envelopes._git

            def mismatched_head(root: Path, *args: str) -> str:
                if args == ("rev-parse", "HEAD"):
                    return "0" * 40
                return original_git(root, *args)

            with mock.patch.object(envelopes, "_git", side_effect=mismatched_head):
                with self.assertRaisesRegex(
                    envelopes.EnvelopeError, "exact source checkout"
                ):
                    envelopes.verify_envelope(ROOT, path)

    def test_recomputed_digest_cannot_hide_invalid_runner_binding(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="canonical-ci",
            source_sha=source_sha,
            digests={},
            observations={},
            verified_cache_specs=[],
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
            },
        )
        envelope["runner"]["kind"] = "physical"
        body = dict(envelope)
        body.pop("envelope_sha256")
        envelope["envelope_sha256"] = envelopes._sha256_bytes(
            envelopes._canonical_json(body)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "runner kind mismatch"
            ):
                envelopes.verify_envelope(ROOT, path)

    def test_recomputed_digest_cannot_hide_unsupported_hosted_runner_architecture(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        envelope = envelopes.create_envelope(
            root=ROOT,
            lane_id="canonical-ci",
            source_sha=source_sha,
            digests={},
            observations={},
            verified_cache_specs=[],
            environment={
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
                "ImageOS": "ubuntu24",
                "ImageVersion": "20261001.1",
                "VM_ACCELERATION": "tcg",
            },
        )
        envelope["runner"]["runner_architecture"] = "BOGUS"
        envelope["runner"]["architecture"] = "mips-is-not-hosted"
        body = dict(envelope)
        body.pop("envelope_sha256")
        envelope["envelope_sha256"] = envelopes._sha256_bytes(
            envelopes._canonical_json(body)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "hosted runner architecture is unsupported"
            ):
                envelopes.verify_envelope(ROOT, path)

    def test_physical_os_release_digest_is_bound_on_create_and_verify(self):
        source_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        runner = {
            "kind": "physical",
            "architecture": "x86_64",
            "runner_architecture": "X64",
            "runner_os": "Linux",
            "kernel_release": "test-kernel",
            "os_release_sha256": "a" * 64,
            "package_manager": "pacman",
            "package_manifest_sha256": "b" * 64,
            "package_count": 1,
            "virtualization": "none",
        }
        digests = {
            "machine_fixture_sha256": "c" * 64,
            "os_release_sha256": "a" * 64,
            "provider_manifest_sha256": "d" * 64,
        }
        observations = {
            "kernel_release": "test-kernel",
            "machine_class": "maintained",
            "virtualization": "none",
        }
        with mock.patch.object(envelopes, "_runner_identity", return_value=runner):
            bad_digests = dict(digests)
            bad_digests["os_release_sha256"] = "e" * 64
            with self.assertRaisesRegex(
                envelopes.EnvelopeError,
                "physical os-release digest does not match executing runner",
            ):
                envelopes.create_envelope(
                    root=ROOT,
                    lane_id="v010-maintained-hardware",
                    source_sha=source_sha,
                    digests=bad_digests,
                    observations=observations,
                    verified_cache_specs=[],
                    environment={},
                )

            envelope = envelopes.create_envelope(
                root=ROOT,
                lane_id="v010-maintained-hardware",
                source_sha=source_sha,
                digests=digests,
                observations=observations,
                verified_cache_specs=[],
                environment={},
            )

        envelope["dynamic_digests"]["os_release_sha256"] = "e" * 64
        body = dict(envelope)
        body.pop("envelope_sha256")
        envelope["envelope_sha256"] = envelopes._sha256_bytes(
            envelopes._canonical_json(body)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            envelopes.write_envelope(path, envelope)
            with self.assertRaisesRegex(
                envelopes.EnvelopeError,
                "physical os-release digest does not match runner binding",
            ):
                envelopes.verify_envelope(ROOT, path)

    def test_guest_package_identity_uses_single_typed_capture_path(self):
        workflows = (
            ".github/workflows/vm-acceptance.yml",
            ".github/workflows/v04-durability-vm.yml",
            ".github/workflows/v04-enospc-recovery-vm.yml",
            ".github/workflows/v05-executor-verifier-vm.yml",
            ".github/workflows/v06-managed-lifecycle-vm.yml",
        )
        for relative in workflows:
            with self.subTest(workflow=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(source.count("qualification_guest_identity.py capture-ssh"), 1)
                self.assertNotIn('guest_package_manifest_sha256="$(ssh ', source)
        remote_script = guest_identity._remote_script("dpkg")
        self.assertIn("/usr/bin/dpkg-query", remote_script)
        self.assertIn("${binary:Package}", remote_script)
        self.assertIn("${Version}", remote_script)

    def test_os_release_identity_accepts_only_allowlisted_resolved_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "etc/os-release"
            target = root / "usr/lib/os-release"
            unexpected = root / "unexpected-os-release"
            link.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            payload = b'ID=arch\nVERSION_ID="rolling"\n'
            target.write_bytes(payload)
            unexpected.write_bytes(b"unexpected\n")
            link.symlink_to("../usr/lib/os-release")

            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "missing or unsafe file"
            ):
                envelopes._sha256_file(link)

            digest = envelopes._sha256_resolved_identity_file(
                link,
                allowed_targets=(link, target),
            )
            self.assertEqual(digest, envelopes._sha256_bytes(payload))

            link.unlink()
            link.symlink_to("../unexpected-os-release")
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "identity file target is not allowed"
            ):
                envelopes._sha256_resolved_identity_file(
                    link,
                    allowed_targets=(link, target),
                )

    def test_entrypoints_pin_execution_envelope_interpreters(self):
        hosted = (ROOT / ".github/actions/qualification-envelope/action.yml").read_text(encoding="utf-8")
        physical = (ROOT / "qualification/v010/workstation-acceptance/run-hardware-qualification.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/bin/python3 -I tools/qualification_envelope.py", hosted)
        self.assertNotIn("\n        created=\"$(python3 tools/qualification_envelope.py", hosted)
        self.assertIn("/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/git -C \"$source_root\" rev-parse HEAD", physical)
        self.assertGreaterEqual(physical.count("/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C"), 2)
        self.assertIn("/usr/bin/python3 -I \"$source_root/tools/qualification_envelope.py\"", physical)

    def test_runner_profiles_pin_native_package_manager(self):
        contract = envelopes.load_contract(ROOT)
        self.assertEqual(contract["runner"]["github_hosted"]["package_manager"], "dpkg")
        self.assertEqual(contract["runner"]["physical"]["package_manager"], "pacman")

        completed = subprocess.CompletedProcess(
            args=["/usr/bin/pacman", "-Q"],
            returncode=0,
            stdout="base 1.0\nlinux 6.17\n",
            stderr="",
        )
        with mock.patch.object(
            envelopes,
            "_trusted_executable",
            side_effect=lambda name, required=True: (
                "/usr/bin/pacman"
                if name == "pacman"
                else (_ for _ in ()).throw(
                    AssertionError(f"unexpected executable: {name}")
                )
            ),
        ), mock.patch.object(envelopes.subprocess, "run", return_value=completed):
            identity = envelopes._host_package_identity("pacman")
        self.assertEqual(identity["package_manager"], "pacman")
        self.assertEqual(identity["package_count"], 2)

    def test_physical_runner_rejects_virtualization(self):
        contract = envelopes.load_contract(ROOT)
        lane = envelopes.lane_by_id(contract, "v010-maintained-hardware")
        package_identity = {
            "package_manager": "pacman",
            "package_manifest_sha256": "a" * 64,
            "package_count": 2,
        }
        with (
            mock.patch.object(
                envelopes, "_host_package_identity", return_value=package_identity
            ),
            mock.patch.object(
                envelopes, "_detect_virtualization", return_value="kvm"
            ),
        ):
            with self.assertRaisesRegex(
                envelopes.EnvelopeError, "non-virtualized maintained hardware"
            ):
                envelopes._runner_identity(contract, lane, {})

    def test_execution_authority_boundary_is_fail_closed(self):
        contract = envelopes.load_contract(ROOT)
        self.assertEqual(
            contract["authority_boundary"],
            {
                "role": "execution-context-only",
                "accepts_qualification_evidence": False,
                "writes_pass_receipts": False,
                "binds_verifier_results": False,
                "binds_accepted_artifacts": False,
            },
        )
        forbidden = (
            "qualification" + "_evidence.py",
            "from tools import qualification" + "_evidence",
            "import tools.qualification" + "_evidence",
            "evidence-" + "binding.json",
            "verifier-" + "result.json",
            "binding_" + "sha256",
        )
        for relative in contract["implementation_files"]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, source)

    def test_physical_lane_requires_machine_identity_inputs(self):
        contract = envelopes.load_contract(ROOT)
        lane = envelopes.lane_by_id(contract, "v010-maintained-hardware")
        self.assertEqual(lane["kind"], "physical")
        self.assertEqual(
            set(lane["required_digests"]),
            {"machine_fixture_sha256", "os_release_sha256", "provider_manifest_sha256"},
        )
        self.assertEqual(
            set(lane["required_observations"]),
            {"kernel_release", "machine_class", "virtualization"},
        )


if __name__ == "__main__":
    unittest.main()
