from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools import applicable_qualification as aq  # noqa: E402


class ApplicableQualificationTests(unittest.TestCase):
    def setUp(self):
        # Legacy routing tests isolate gate selection from merge-provenance I/O.
        # Dedicated immutable-merge tests below exercise the live commit proof.
        self.enterContext(mock.patch.object(
            aq, "_reviewed_test_merge", return_value="e" * 40,
        ))

    def test_module_is_single_structurally_complete_entrypoint(self):
        import ast

        source = (ROOT / "tools/applicable_qualification.py").read_text(
            encoding="utf-8"
        )
        module = ast.parse(source)
        functions = [
            node.name for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.assertEqual(len(functions), len(set(functions)))
        self.assertIsInstance(module.body[-1], ast.If)
        self.assertEqual(source.count('if __name__ == "__main__":'), 1)
        self.assertTrue(source.rstrip().endswith("raise SystemExit(main())"))

    def test_repository_matrix_is_complete_and_aligned(self):
        result = aq.validate_repository(ROOT)
        self.assertTrue(result["ready"])
        self.assertEqual(
            result["mandatory_gate_ids"],
            ["canonical-ci", "security-rustsec", "codeql"],
        )
        self.assertIn("v010-maintained-hardware", result["execution_lanes"])

    def test_guidance_only_and_mixed_shell_changes_route_safely(self):
        contract = aq.load_contract(ROOT)
        guidance = aq.required_gate_ids(
            contract, ["apps/linura-shell/AGENTS.md"]
        )
        self.assertIn("codex-environment", guidance)
        self.assertNotIn("v010-workstation", guidance)

        mixed = aq.required_gate_ids(
            contract,
            [
                "apps/linura-shell/AGENTS.md",
                "apps/linura-shell/ui/StatusPanel.qml",
            ],
        )
        self.assertIn("v010-workstation", mixed)

    def test_update_recovery_and_migration_paths_require_full_v09(self):
        contract = aq.load_contract(ROOT)
        for path in (
            "apps/linura-update-guard/src/main.rs",
            "packaging/arch/hooks/95-linura-update-guard.hook",
            "migrations/system/0004-authority-sqlite-preservation.json",
        ):
            with self.subTest(path=path):
                self.assertIn(
                    "v09-qualification",
                    aq.required_gate_ids(contract, [path]),
                )

    def test_registered_stability_contracts_are_explicitly_routed(self):
        contract = aq.load_contract(ROOT)
        matrix = {item["path"]: item["gates"] for item in contract["contract"]}
        registry = aq._load_toml(
            ROOT, Path("contracts/stability.toml")
        )["contract"]
        schema_paths = {
            item["path"]
            for item in registry
            if item.get("kind") == "json-schema"
        }
        self.assertTrue(schema_paths)
        for path in schema_paths:
            with self.subTest(path=path):
                self.assertIn(path, matrix)
                self.assertTrue(matrix[path])

        expected = {
            "schemas/migration.v1.schema.json": {"v09-qualification"},
            "schemas/intent.v1.schema.json": {
                "v07-library", "v08-agent", "v09-qualification",
                "v010-workstation",
            },
            "schemas/desired-state.v1.schema.json": {
                "control1-plan-preview", "v09-qualification",
                "v010-workstation",
            },
            "schemas/bootstrap.v1.schema.json": {
                "vm-acceptance", "v09-qualification",
            },
            "schemas/update-plan.v1.schema.json": {
                "v09-qualification", "v010-workstation",
            },
            "schemas/acceptance-scenario.v1.schema.json": {
                "vm-acceptance", "control1-plan-preview",
                "v09-qualification",
            },
            "schemas/workflow.v1.schema.json": {
                "v06-managed-lifecycle", "v09-qualification",
                "v010-workstation",
            },
        }
        for path, gates in expected.items():
            with self.subTest(path=path):
                self.assertTrue(gates.issubset(set(matrix[path])))
                self.assertTrue(
                    gates.issubset(
                        set(aq.required_gate_ids(contract, [path]))
                    )
                )

    def test_every_specialized_gate_binds_required_job_identity(self):
        contract = aq.load_contract(ROOT)
        for gate in contract["gate"]:
            if gate["mandatory"]:
                continue
            with self.subTest(gate=gate["id"]):
                self.assertTrue(gate["required_jobs"])
        v09 = next(
            gate for gate in contract["gate"]
            if gate["id"] == "v09-qualification"
        )
        self.assertEqual(v09["job_policy"], "v09-full-vs-regression")
        self.assertTrue(v09["full_required_jobs"])
        self.assertTrue(v09["regression_required_jobs"])

    def test_v09_full_route_cannot_be_satisfied_by_regression_job(self):
        contract = aq.load_contract(ROOT)
        gate = next(
            item for item in contract["gate"]
            if item["id"] == "v09-qualification"
        )
        jobs = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in (
                gate["required_jobs"] + gate["regression_required_jobs"]
            )
        ]
        with mock.patch.object(aq, "_paged", return_value=jobs):
            with self.assertRaisesRegex(
                aq.QualificationError, "required v0.9 full job absent"
            ):
                aq._verify_required_jobs(
                    "linura-org/linura",
                    gate,
                    {"id": 1},
                    "token",
                    root=ROOT,
                    changed_paths=["schemas/migration.v1.schema.json"],
                )

    def test_v09_regression_route_requires_regression_job(self):
        contract = aq.load_contract(ROOT)
        gate = next(
            item for item in contract["gate"]
            if item["id"] == "v09-qualification"
        )
        jobs = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in gate["required_jobs"]
        ]
        with mock.patch.object(aq, "_paged", return_value=jobs):
            with self.assertRaisesRegex(
                aq.QualificationError,
                "required v0.9 regression job absent",
            ):
                aq._verify_required_jobs(
                    "linura-org/linura",
                    gate,
                    {"id": 1},
                    "token",
                    root=ROOT,
                    changed_paths=["docs/qualification/v0.9.0.md"],
                )

    def test_specialized_successful_workflow_cannot_hide_skipped_job(self):
        contract = aq.load_contract(ROOT)
        gate = next(
            item for item in contract["gate"]
            if item["id"] == "v07-library"
        )
        jobs = [
            {
                "name": gate["required_jobs"][0],
                "status": "completed",
                "conclusion": "skipped",
            }
        ]
        with mock.patch.object(aq, "_paged", return_value=jobs):
            with self.assertRaisesRegex(
                aq.QualificationError, "is completed/skipped"
            ):
                aq._verify_required_jobs(
                    "linura-org/linura",
                    gate,
                    {"id": 1},
                    "token",
                    root=ROOT,
                    changed_paths=["crates/linura-library/src/lib.rs"],
                )

    def test_routing_authority_uses_native_static_validation_without_fanout(self):
        contract = aq.load_contract(ROOT)
        mandatory = set(contract["mandatory_gate_ids"])
        for path in contract["routing_authority_paths"]:
            with self.subTest(path=path):
                required = set(aq.required_gate_ids(contract, [path]))
                self.assertEqual(required, mandatory)

    def test_routing_matrix_is_native_only_but_still_routing_authority(self):
        contract = aq.load_contract(ROOT)
        path = "contracts/qualification-gate-matrix.toml"
        self.assertIn(path, contract["routing_authority_paths"])
        self.assertIn(path, contract["native_only_contracts"])
        matrix = {item["path"]: item for item in contract["contract"]}
        self.assertEqual(matrix[path]["gates"], [])

    def test_summary_reconciles_events_without_long_lived_polling(self):
        workflow = (
            ROOT / ".github/workflows/applicable-qualification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("  pull_request_target:", workflow)
        self.assertIn("  workflow_run:", workflow)
        self.assertIn("types: [in_progress, completed]", workflow)
        self.assertIn("statuses: write", workflow)
        self.assertIn("reconcile-head", workflow)
        self.assertIn("event-heads", workflow)
        self.assertIn("ready_for_review, closed", workflow)
        self.assertIn("  push:\n    branches: [main]", workflow)
        self.assertIn("  schedule:\n    - cron: '17 * * * *'", workflow)
        self.assertIn('--retry-only "$RETRY_ONLY"', workflow)
        self.assertIn('--invalidate-only "$INVALIDATE_ONLY"', workflow)
        self.assertIn("fromJSON(needs.affected-heads.outputs.head_groups)", workflow)
        self.assertIn("group: applicable-qualification-shard-${{ matrix.group.shard }}", workflow)
        self.assertIn("      queue: max", workflow)
        self.assertEqual(workflow.count("      queue: max"), 1)
        self.assertIn("reconcile-heads", workflow)
        self.assertIn('--heads-json "$HEAD_SHAS"', workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        prepare, reconcile = workflow.split("  affected-heads:", 1)[1].split("  reconcile:", 1)
        self.assertNotIn("statuses: write", prepare)
        self.assertIn("statuses: write", reconcile)
        self.assertIn(
            "ref: ${{ github.event.repository.default_branch }}",
            workflow,
        )
        self.assertNotIn("verify-pr", workflow)
        self.assertNotIn("--timeout-seconds", workflow)
        self.assertNotIn("--poll-seconds", workflow)


    def test_pinned_linter_does_not_skip_workflows_for_queue_compatibility(self):
        canonical = (
            ROOT / ".github/workflows/ci.yml"
        ).read_text(encoding="utf-8")
        summary = (
            ROOT / ".github/workflows/applicable-qualification.yml"
        ).read_text(encoding="utf-8")
        helper = (ROOT / "scripts/lint_github_workflows.sh").read_text(encoding="utf-8")
        preflight = (ROOT / "scripts/preflight_codex_environment.sh").read_text(encoding="utf-8")
        self.assertIn('bash scripts/lint_github_workflows.sh "$install_dir/actionlint"', canonical)
        self.assertIn('bash scripts/lint_github_workflows.sh "$actionlint_bin"', preflight)
        self.assertIn('python3 tools/applicable_qualification.py validate', helper)
        self.assertIn('"$actionlint_bin" -color "${workflow_files[@]}"', helper)
        self.assertIn("-name '*.yml' -o -name '*.yaml'", helper)
        self.assertIn("sed '/^      queue: max$/d'", helper)
        self.assertIn('"$actionlint_bin" -color -', helper)
        self.assertEqual(summary.count("      queue: max"), 1)

    def test_protected_main_push_discovers_affected_pr_heads(self):
        sha_a, sha_b = "a" * 40, "b" * 40
        candidates = [
            {
                "state": "open", "head": {"sha": sha_a},
                "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}},
            },
            {
                "state": "open", "head": {"sha": sha_b},
                "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}},
            },
            {
                "state": "open", "head": {"sha": sha_a},
                "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}},
            },
            {"state": "closed"},
        ]
        with mock.patch.object(aq, "_paged", return_value=candidates) as query:
            heads = aq.resolve_event_heads(
                repository="linura-org/linura",
                event_name="push",
                event={"ref": "refs/heads/main", "after": "f" * 40},
                token="token",
            )
        self.assertEqual(heads, [sha_a, sha_b])
        self.assertIn("base=main", query.call_args.args[0])
        self.assertIn("state=open", query.call_args.args[0])

    def test_untrusted_feature_push_never_queries_or_writes(self):
        with mock.patch.object(aq, "_paged") as query:
            for event in (
                {"ref": "refs/heads/feature", "after": "a" * 40},
                {"ref": "refs/heads/release", "after": "a" * 40},
                {"ref": "refs/heads/main", "deleted": True},
            ):
                with self.subTest(event=event):
                    with self.assertRaises(aq.QualificationError):
                        aq.resolve_event_heads(
                            repository="linura-org/linura",
                            event_name="push", event=event, token="token"
                        )
            query.assert_not_called()

    def test_closing_shared_head_pr_triggers_reconciliation(self):
        sha = "d" * 40
        for action in ("closed", "edited", "reopened"):
            with self.subTest(action=action):
                heads = aq.resolve_event_heads(
                    repository="linura-org/linura",
                    event_name="pull_request_target",
                    event={"action": action, "pull_request": {"head": {"sha": sha}}},
                    token="token",
                )
                self.assertEqual(heads, [sha])

    def test_synchronize_reconciles_both_previous_and_current_head(self):
        before, after = "1" * 40, "2" * 40
        event = {
            "action": "synchronize", "before": before, "after": after,
            "pull_request": {"head": {"sha": after}},
        }
        self.assertEqual(
            aq.resolve_event_heads(
                repository="linura-org/linura", event_name="pull_request_target",
                event=event, token="token",
            ),
            [before, after],
        )
        # A noop synchronization must not schedule two writers for one head.
        event["before"] = after
        self.assertEqual(
            aq.resolve_event_heads(
                repository="linura-org/linura", event_name="pull_request_target",
                event=event, token="token",
            ),
            [after],
        )

    def test_malformed_synchronize_identity_is_rejected(self):
        before, after = "a" * 40, "b" * 40
        valid = {
            "action": "synchronize", "before": before, "after": after,
            "pull_request": {"head": {"sha": after}},
        }
        for changed in (
            {"before": None}, {"before": "invalid"},
            {"after": "c" * 40}, {"after": None},
        ):
            with self.subTest(change=changed):
                with self.assertRaisesRegex(
                    aq.QualificationError,
                    "synchronize .* SHA",
                ):
                    aq.resolve_event_heads(
                        repository="linura-org/linura",
                        event_name="pull_request_target",
                        event={**valid, **changed}, token="token",
                    )


    def test_workflow_run_discovery_requires_native_event(self):
        sha = "c" * 40
        self.assertEqual(
            aq.resolve_event_heads(
                repository="linura-org/linura", event_name="workflow_run",
                event={"workflow_run": {"event": "pull_request", "head_sha": sha}},
                token="token",
            ), [sha]
        )
        self.assertEqual(
            aq.resolve_event_heads(
                repository="linura-org/linura", event_name="workflow_run",
                event={"workflow_run": {"event": "workflow_dispatch", "head_sha": sha}},
                token="token",
            ), []
        )
        with self.assertRaises(aq.QualificationError):
            aq.resolve_event_heads(
                repository="linura-org/linura", event_name="workflow_run",
                event={"workflow_run": {"event": "pull_request", "head_sha": "invalid"}},
                token="token",
            )

    def test_base_push_discovery_fails_closed_on_unrelated_pr(self):
        foreign = {
            "state": "open", "head": {"sha": "a" * 40},
            "base": {"ref": "main", "repo": {"full_name": "not-linura/other"}},
        }
        with mock.patch.object(aq, "_paged", return_value=[foreign]):
            with self.assertRaisesRegex(aq.QualificationError, "outside protected main"):
                aq.resolve_event_heads(
                    repository="linura-org/linura",
                    event_name="push",
                    event={"ref": "refs/heads/main"}, token="token",
                )

    def test_more_than_256_heads_are_grouped_without_dropping_invalidation(self):
        records = [
            {"state": "open", "head": {"sha": f"{i:040x}"},
             "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}}}
            for i in range(513)
        ]
        with mock.patch.object(aq, "_paged", return_value=records):
            heads = aq.resolve_event_heads(
                repository="linura-org/linura",
                event_name="push", event={"ref": "refs/heads/main"}, token="token",
            )
        self.assertEqual(len(heads), 513)
        groups = aq.group_head_shas(heads)
        self.assertLessEqual(len(groups), 16)
        self.assertEqual(
            sorted(sha for group in groups for sha in group["heads"]), heads,
        )
        self.assertEqual(len(set(group["shard"] for group in groups)), len(groups))
        self.assertEqual(groups[0]["shard"], "0")

    def test_head_grouping_rejects_invalid_sha_and_deduplicates(self):
        head = "a" * 40
        self.assertEqual(
            aq.group_head_shas([head, head]),
            [{"shard": "a", "heads": [head]}],
        )
        for heads in (["invalid"], ["A" * 40], [head, "xyz"]):
            with self.subTest(heads=heads):
                with self.assertRaises(aq.QualificationError):
                    aq.group_head_shas(heads)

    def test_shard_invalidation_precedes_bounded_expensive_work(self):
        first, second = "a" * 39 + "1", "a" * 39 + "2"
        events = []
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(
                aq, "_post_json",
                side_effect=lambda url, token, status:
                    events.append(("pending", url, status["state"])),
            ),
            mock.patch.object(
                aq, "reconcile_head",
                side_effect=lambda **kw:
                    (events.append(("check", kw["head_sha"], "evaluated"))
                     or {"head_sha": kw["head_sha"], "state": "success"}),
            ),
        ):
            result = aq.reconcile_heads(
                root=ROOT, repository="linura-org/linura",
                head_shas=[first, second], shard="a", token="token",
                hour_slot=0,
            )
        self.assertEqual(result["head_count"], 2)
        self.assertEqual(result["invalidated_count"], 2)
        self.assertEqual(result["reconciled_count"], 1)
        self.assertEqual(result["deferred_count"], 1)
        self.assertEqual(result["failures"], [])
        self.assertEqual([item[0] for item in events],
                         ["pending", "pending", "check"])
        self.assertEqual(events[-1][1], first)

    def test_shard_reconciliation_isolates_discovery_and_publish_failures(self):
        first, second, third = ("b" * 39 + value for value in "123")
        writes, checked = [], []
        def fake_write(url, token, status):
            writes.append(url.rsplit("/", 1)[-1])
            if url.endswith(second):
                raise aq.QualificationError("GitHub status API failure")
        def fake_check(**kw):
            checked.append(kw["head_sha"])
            raise aq.QualificationError("PR identity temporarily incomplete")
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_post_json", side_effect=fake_write),
            mock.patch.object(aq, "reconcile_head", side_effect=fake_check),
        ):
            result = aq.reconcile_heads(
                root=ROOT, repository="linura-org/linura",
                head_shas=[third, second, first], shard="b", token="token",
                hour_slot=0,
            )
        self.assertEqual(writes, [first, second, third])
        self.assertEqual(checked, [first])
        self.assertEqual(result["invalidated_count"], 2)
        self.assertEqual(len(result["failures"]), 2)

    def test_hourly_retry_rotates_without_revoking_unrelated_success(self):
        first, second, third = ("c" * 39 + suffix for suffix in "123")
        for slot, expected in ((0, first), (1, second), (2, third), (3, first)):
            writes, checks = [], []
            with (
                mock.patch.object(aq, "load_contract", return_value={
                    "repository": "linura-org/linura",
                    "branch_required_check": "applicable-qualification",
                }),
                mock.patch.object(aq, "_post_json",
                                  side_effect=lambda url, token, payload:
                                      writes.append(url.rsplit("/", 1)[-1])),
                mock.patch.object(aq, "reconcile_head",
                                  side_effect=lambda **kw:
                                      checks.append(kw["head_sha"]) or
                                      {"head_sha": kw["head_sha"], "state": "success"}),
            ):
                result = aq.reconcile_heads(
                    root=ROOT, repository="linura-org/linura",
                    head_shas=[first, second, third], shard="c", token="token",
                    retry_only=True, hour_slot=slot,
                )
            self.assertEqual(writes, [expected])
            self.assertEqual(checks, [expected])
            self.assertEqual(result["reconciled_count"], 1)
            self.assertEqual(result["invalidated_count"], 1)
            self.assertEqual(result["deferred_count"], 2)

    def test_workflow_run_start_only_revokes_stale_status_without_rest_reads(self):
        heads = ["d" * 39 + str(i) for i in range(1, 4)]
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_post_json") as post,
            mock.patch.object(aq, "reconcile_head") as check,
        ):
            result = aq.reconcile_heads(
                root=ROOT, repository="linura-org/linura",
                head_shas=heads, shard="d", token="token",
                invalidate_only=True, hour_slot=0,
            )
        self.assertEqual(post.call_count, 3)
        self.assertEqual(result["invalidated_count"], 3)
        self.assertEqual(result["deferred_count"], 3)
        self.assertEqual(result["reconciled_count"], 0)
        check.assert_not_called()

    def test_retry_and_invalidate_only_modes_must_not_mix(self):
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_post_json") as post,
        ):
            with self.assertRaisesRegex(aq.QualificationError, "conflict"):
                aq.reconcile_heads(
                    root=ROOT, repository="linura-org/linura",
                    head_shas=["e" * 40], shard="e", token="token",
                    retry_only=True, invalidate_only=True,
                )
        post.assert_not_called()

    def test_schedule_recovers_open_main_prs_and_rejects_unknown_cron(self):
        head = "f" * 40
        records = [{
            "state": "open", "head": {"sha": head},
            "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}},
        }]
        with mock.patch.object(aq, "_paged", return_value=records):
            self.assertEqual(aq.resolve_event_heads(
                repository="linura-org/linura", event_name="schedule",
                event={"schedule": "17 * * * *"}, token="token",
            ), [head])
        with mock.patch.object(aq, "_paged") as query:
            with self.assertRaisesRegex(aq.QualificationError, "unknown .*schedule"):
                aq.resolve_event_heads(
                    repository="linura-org/linura", event_name="schedule",
                    event={"schedule": "0 * * * *"}, token="token",
                )
            query.assert_not_called()

    def test_shared_head_api_budget_fails_closed_without_any_pr_evaluation(self):
        head = "e" * 40
        identities = {n: ("main", "1" * 40, 1350812666,
                          "shared", 1350812666, "2" * 40)
                      for n in range(1, 10)}
        writes = []
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs", return_value=identities),
            mock.patch.object(aq, "_post_json",
                              side_effect=lambda url, token, payload:
                                  writes.append(payload)),
            mock.patch.object(aq, "evaluate_pr") as evaluate,
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura",
                head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertEqual(result["pr_count"], 9)
        self.assertEqual([v["state"] for v in writes], ["pending", "failure"])
        self.assertIn("maximum supported is 8", result["failures"][0])
        evaluate.assert_not_called()

    def test_transient_status_write_retries_are_bounded_and_idempotent(self):
        import io
        from urllib.error import HTTPError
        url = "https://api.github.com/repos/linura-org/linura/statuses/" + "a" * 40
        error = HTTPError(url, 503, "temporary", {}, io.BytesIO(b"temporary"))
        with (
            mock.patch.object(aq, "urlopen",
                              side_effect=[error, io.BytesIO(b'{"ok":true}')]) as call,
            mock.patch.object(aq.time, "sleep") as sleep,
        ):
            result = aq._post_json(url, "token", {"state": "pending"})
        self.assertEqual(result, {"ok": True})
        self.assertEqual(call.call_count, 2)
        sleep.assert_called_once()
        self.assertEqual(sleep.call_args.args, (1.0,))

    def test_exhausted_github_token_cannot_spin_or_claim_status(self):
        import io
        from urllib.error import HTTPError
        url = "https://api.github.com/repos/linura-org/linura/statuses/" + "b" * 40
        error = HTTPError(
            url, 403, "rate limit",
            {"X-RateLimit-Remaining": "0", "Retry-After": "60"},
            io.BytesIO(b"rate limited"),
        )
        with (
            mock.patch.object(aq, "urlopen", side_effect=error) as call,
            mock.patch.object(aq.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(aq.QualificationError, "GitHub API 403"):
                aq._post_json(url, "token", {"state": "pending"})
        call.assert_called_once()
        sleep.assert_not_called()

    def test_wrong_shard_never_publishes_statuses(self):
        with mock.patch.object(aq, "_post_json") as post:
            with self.assertRaisesRegex(aq.QualificationError,
                                        "match writer shard"):
                aq.reconcile_heads(
                    root=ROOT, repository="linura-org/linura",
                    head_shas=["a" * 40, "b" * 40],
                    shard="a", token="token",
                )
            post.assert_not_called()

    def test_all_specialized_push_routes_mirror_reviewed_pr_routes(self):
        contract = aq.load_contract(ROOT)
        mirrored = set()
        for gate in contract["gate"]:
            if gate["mandatory"]:
                continue
            workflow = (ROOT / gate["workflow"]).read_text(encoding="utf-8")
            push = aq._push_paths(workflow)
            if push is not None and push:
                mirrored.add(gate["id"])
                self.assertEqual(
                    push, aq._pull_request_paths(workflow),
                    f"push/PR route drift for {gate['id']}",
                )
        self.assertIn("evidence-publication", mirrored)
        self.assertIn("codex-environment", mirrored)

    def test_push_routing_shadow_keys_and_aliases_fail_closed(self):
        source = (
            'name: example\n'
            'on:\n'
            '  pull_request:\n'
            '    paths:\n'
            '      - "schemas/release-evidence.v1.schema.json"\n'
            '  push:\n'
            '    branches: [main]\n'
            '    paths:\n'
            '      - "schemas/release-evidence.v1.schema.json"\n'
            'jobs:\n'
            '  verify:\n'
            '    runs-on: ubuntu-24.04\n'
        )
        self.assertEqual(
            aq._push_paths(source), ["schemas/release-evidence.v1.schema.json"]
        )
        for mutant in (
            source.replace('jobs:\n', '  push:\n    paths:\n      - "docs/**"\njobs:\n'),
            source.replace('  push:\n', '  "push":\n'),
            source.replace(
                '      - "schemas/release-evidence.v1.schema.json"\njobs:\n',
                '      - "schemas/release-evidence.v1.schema.json"\n'
                '    "paths":\n      - "docs/**"\njobs:\n',
            ),
            source.replace('    paths:\n', '    <<: *routes\n    paths:\n'),
        ):
            with self.subTest(mutant=mutant):
                with self.assertRaises(aq.QualificationError):
                    aq._push_paths(mutant)

    def test_changed_file_count_must_prove_exact_complete_inventory(self):
        head = "a" * 40
        basic = {"head": {"sha": head},
                 "base": {"ref": "main", "sha": "b" * 40,
                          "repo": {"id": 1350812666}}}
        cases = [
            (None, [], "unavailable or malformed"),
            (True, ["docs/README.md"], "unavailable or malformed"),
            ("1", ["docs/README.md"], "unavailable or malformed"),
            (-1, [], "unavailable or malformed"),
            (0, ["docs/README.md"], "incomplete or duplicated"),
            (2, ["docs/README.md"], "incomplete or duplicated"),
            (1, [], "incomplete or duplicated"),
            (2, ["docs/a.md", "docs/a.md"], "incomplete or duplicated"),
        ]
        for count, files, message in cases:
            with self.subTest(count=count, files=files):
                pr = dict(basic)
                if count is not None:
                    pr["changed_files"] = count
                with (
                    mock.patch.object(aq, "_api_json", return_value=pr),
                    mock.patch.object(aq, "_pr_changed_paths", return_value=files),
                    mock.patch.object(aq, "_head_runs") as runs,
                    mock.patch.object(aq, "_post_json") as writes,
                ):
                    with self.assertRaisesRegex(aq.QualificationError, message):
                        aq.evaluate_pr(
                            root=ROOT, repository="linura-org/linura",
                            pr_number=9, head_sha=head, token="token",
                        )
                    runs.assert_not_called()
                    writes.assert_not_called()

    def test_large_pr_files_fail_explicitly_before_a_truncated_gate_map(self):
        sha = "a" * 40
        pr = {"head": {"sha": sha}, "changed_files": 3001}
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths") as paths,
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=12, head_sha=sha, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertEqual(result["waiting"], [])
        self.assertEqual(result["accepted"], [])
        self.assertIn("3,000", result["failures"][0])
        self.assertIn("Split the PR", result["failures"][0])
        self.assertEqual(
            result["required_gate_ids"],
            aq.load_contract(ROOT)["mandatory_gate_ids"],
        )
        paths.assert_not_called()
        runs.assert_not_called()

    def test_exactly_3000_changed_files_pages_without_truncation(self):
        entries = [{"filename": f"docs/item-{i}.md", "status": "modified"}
                   for i in range(3000)]
        pages: list[int] = []
        def page_api(url, token):
            from urllib.parse import urlparse, parse_qs
            query = parse_qs(urlparse(url).query)
            page = int(query["page"][0])
            pages.append(page)
            return entries[(page - 1) * 100:page * 100]
        with mock.patch.object(aq, "_api_json", side_effect=page_api):
            paths = aq._pr_changed_paths("linura-org/linura", 12, "token")
        self.assertEqual(len(paths), 3000)
        self.assertEqual(pages, list(range(1, 31)))

    def test_non_file_pagination_continues_beyond_3000_records(self):
        page = [{"id": number} for number in range(100)]
        pages = []
        def fetch(url, token):
            from urllib.parse import parse_qs, urlparse
            index = int(parse_qs(urlparse(url).query)["page"][0])
            pages.append(index)
            return page if index <= 30 else []
        with mock.patch.object(aq, "_api_json", side_effect=fetch):
            items = aq._paged(
                "https://api.github.com/repos/linura-org/linura/pulls",
                "token",
            )
        self.assertEqual(len(items), 3000)
        self.assertEqual(pages, list(range(1, 32)))

    def test_path_routing_rejects_yaml_shadowed_event_keys(self):
        safe = (
            'name: probe\n'
            'on:\n'
            '  pull_request:\n'
            '    paths:\n'
            '      - "apps/**"\n'
            'jobs:\n'
            '  probe:\n'
            '    runs-on: ubuntu-24.04\n'
        )
        self.assertEqual(aq._pull_request_paths(safe), ["apps/**"])
        for source in (
            safe.replace(
                'jobs:\n',
                'on:\n  pull_request:\n    paths:\n      - "docs/**"\njobs:\n',
            ),
            safe.replace(
                'jobs:\n',
                '  "pull_request":\n    paths:\n      - "docs/**"\njobs:\n',
            ),
            safe.replace(
                '      - "apps/**"\n',
                '      - "apps/**"\n    paths:\n      - "docs/**"\n',
            ),
            safe.replace(
                '      - "apps/**"\n',
                '      - "apps/**"\n    "paths":\n      - "docs/**"\n',
            ),
            safe.replace('    paths:\n', '    <<: *routes\n    paths:\n'),
            safe.replace('jobs:\n', '"on":\n  pull_request: []\njobs:\n'),
            safe.replace('  pull_request:\n', '  <<: *events\n  pull_request:\n'),
        ):
            with self.subTest(source=source):
                with self.assertRaises(aq.QualificationError):
                    aq._pull_request_paths(source)

    def test_ordered_negative_path_rules_keep_functional_changes_visible(self):
        patterns = [
            "apps/linura-shell/**",
            "!apps/linura-shell/AGENTS.md",
            "!apps/linura-shell/README.md",
        ]
        self.assertFalse(
            aq.path_selected("apps/linura-shell/AGENTS.md", patterns)
        )
        self.assertTrue(
            aq.path_selected(
                "apps/linura-shell/ui/StatusPanel.qml", patterns
            )
        )

    def test_rename_routing_matches_changed_filename_not_previous_filename(self):
        contract = aq.load_contract(ROOT)
        source = "apps/linura-shell/ui/StatusPanel.qml"
        destination = "docs/renamed-panel.md"
        payload = [{
            "filename": destination,
            "previous_filename": source,
            "status": "renamed",
        }]
        with mock.patch.object(aq, "_paged", return_value=payload):
            paths = aq._pr_changed_paths("linura-org/linura", 1, "token")
        self.assertEqual(paths, [destination])
        self.assertEqual(aq.required_gate_ids(contract, paths),
                         contract["mandatory_gate_ids"])
        self.assertIn("v010-workstation",
                      aq.required_gate_ids(contract, [source]))

    def test_untrusted_workflow_action_and_verifier_edits_fail_closed(self):
        contract = aq.load_contract(ROOT)
        sensitive = [
            ".github/workflows/ci.yml",
            ".github/workflows/security.yml",
            ".github/workflows/codeql.yml",
            ".github/workflows/v010-qualification.yml",
            ".github/workflows/applicable-qualification.yml",
            ".github/actions/qualification-evidence/action.yml",
            "tools/qualification_evidence.py",
            "tools/qualification_evidence_verifiers.py",
            "tools/qualification_envelope.py",
            "contracts/qualification-evidence-binding.toml",
            "tools/check_validation_gates.py",
            "scripts/check_repository.py",
            "tools/applicable_qualification.py",
            "tools/check_ci_cache_policy.py",
            "tools/xtask/Cargo.toml",
            "tools/xtask/src/main.rs",
            ".cargo/config", ".cargo/config.toml", "Cargo.toml",
            "Cargo.lock", "rust-toolchain.toml", "tools/codex/versions.env",
        ]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, sensitive),
            sorted(sensitive),
        )
        self.assertEqual(aq._untrusted_gate_definition_edits(
            contract, ["crates/linura-control/src/lib.rs", "docs/README.md"]
        ), [])

    def test_local_reusable_workflows_and_qualification_harnesses_are_protected(self):
        contract = aq.load_contract(ROOT)
        executable_harnesses = [
            "qualification/v010/shell-runtime/provision-shell-runtime.sh",
            "qualification/v010/shell-runtime/run-shell-runtime.sh",
            "qualification/v010/shell-runtime/verify-substrate.py",
            "qualification/v010/shell-runtime/prepare-substrate.sh",
            "qualification/v010/workstation-acceptance/record-session.sh",
            "qualification/v010/workstation-acceptance/run-hardware-qualification.sh",
            "qualification/v010/shell-runtime/native-keyboard.c",
            "qualification/v010/shell-runtime/virtual-keyboard-unstable-v1.xml",
            "qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service",
            "qualification/v011/future-new-runner.sh",
            ".github/workflows/v010-shell-runtime-qualification.yml",
        ]
        for path in executable_harnesses[:-2]:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, executable_harnesses),
            sorted(executable_harnesses),
        )
        trusted = aq._trusted_gate_script_paths(ROOT, contract)
        self.assertIn(
            ".github/workflows/v010-shell-runtime-qualification.yml",
            trusted,
        )
        self.assertIn(
            "qualification/v010/shell-runtime/verify-substrate.py",
            trusted,
        )

    def test_modified_vm_harness_cannot_self_certify_from_successful_run(self):
        head = "a" * 40
        harness_path = "qualification/v010/shell-runtime/run-shell-runtime.sh"
        pr = {
            "head": {"sha": head}, "changed_files": 2,
            "base": {"ref": "main", "sha": "1" * 40,
                     "repo": {"id": 1350812666}},
        }
        changed = [
            "apps/linura-shell/ui/StatusPanel.qml",
            harness_path,
        ]
        with (
            mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=changed),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=99, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn(harness_path, result["failures"][0])
        runs.assert_not_called()

    def test_implicit_python_startup_and_acceptance_fixtures_require_approval(self):
        contract = aq.load_contract(ROOT)
        protected = [
            "sitecustomize.py", "usercustomize.py",
            "tools/__init__.py", "tools/sitecustomize.py",
            "tools/json.py", "tools/json.pyc",
            "tools/json.cpython-312-x86_64-linux-gnu.so",
            "tools/new_package/__init__.py",
            "tools/new_package/__init__.abi3.so",
            "scripts/__init__.py", "scripts/urllib.py",
            "scripts/urllib.pyc",
            "json.cpython-312-x86_64-linux-gnu.so", "json.pyc",
            "json/__init__.py", "urllib/__init__.pyc",
            "email/__init__.abi3.so",
            "tests/__init__.py", "tests/integration/__init__.py",
            "tests/integration/__init__.abi3.so",
            "tests/integration/__init__.pyc",
            "qualification/v011/sitecustomize.py",
            "bindings/python/tests/new_package/__init__.py",
            "tests/acceptance/007-authoritative-observation.json",
            "tests/acceptance/009-future-scenario.json",
            "tests/acceptance/v05/49-linura-v05-qualification.rules",
            "tests/acceptance/v05/linura-v05-qualification-restart.service",
            "tests/acceptance/v06/linura-managed-v06-qualification.service",
            "tests/acceptance/v07/new-gate-fixture.conf",
        ]
        for path in protected:
            with self.subTest(path=path):
                self.assertEqual(
                    aq._untrusted_gate_definition_edits(contract, [path]),
                    [path],
                )
        unprotected = [
            "docs/README.md", "xtask/src/main.rs",
            "crates/linura-core/src/lib.rs",
            "apps/linura-shell/AGENTS.md",
        ]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, unprotected), [],
        )

    def test_acceptance_fixture_cannot_self_certify_a_green_vm_run(self):
        contract = aq.load_contract(ROOT)
        fixture = "tests/acceptance/007-authoritative-observation.json"
        head = "a" * 40
        pr = {
            "head": {"sha": head}, "changed_files": 1,
            "base": {"ref": "main", "sha": "1" * 40,
                     "repo": {"id": 1350812666}},
        }
        with (
            mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=[fixture]),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=99, head_sha=head, token="token",
                validated_contract=contract,
            )
        self.assertEqual(result["state"], "failure")
        self.assertTrue(
            any(fixture in item for item in result["failures"]),
            result["failures"],
        )
        self.assertEqual(result["accepted"], [])
        runs.assert_not_called()

    def test_unittest_module_references_are_executable_gate_authority(self):
        contract = aq.load_contract(ROOT)
        protected = [
            "tests/tooling/test_evidence_publication.py",
            "tests/tooling/test_roadmap.py",
            "tests/tooling/test_native_keyboard.py",
            "tests/tooling/test_validation_gates.py",
            "tests/tooling/new_qualification_helper.py",
            "bindings/python/tests/test_new_contract.py",
        ]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, protected),
            sorted(protected),
        )
        head = "a" * 40
        pr = {
            "head": {"sha": head},
            "changed_files": 2,
            "base": {
                "ref": "main", "sha": "1" * 40,
                "repo": {"id": 1350812666},
            },
        }
        with (
            mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(
                aq, "_pr_changed_paths",
                return_value=[
                    "contracts/evidence-publication.toml",
                    "tests/tooling/test_evidence_publication.py",
                ],
            ),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=99, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn(
            "tests/tooling/test_evidence_publication.py",
            result["failures"][0],
        )
        self.assertEqual(result["accepted"], [])
        runs.assert_not_called()

    def test_dotted_test_invocations_and_imports_follow_reviewed_sources(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/example.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "name: Gate\nrun: python3 -m unittest -v "
                "tests.integration.test_publish.TestPublish.test_contract\n",
                encoding="utf-8",
            )
            direct = root / "tests/integration/test_publish.py"
            direct.parent.mkdir(parents=True)
            direct.write_text(
                "from tests.integration import publish_helper\n",
                encoding="utf-8",
            )
            helper = root / "tests/integration/publish_helper.py"
            helper.write_text("def verify(): pass\n", encoding="utf-8")
            contract = {
                "gate": [{"workflow": ".github/workflows/example.yml"}],
                "summary_workflow": ".github/workflows/example.yml",
            }
            identified = aq._trusted_gate_script_paths(root, contract)
            self.assertIn("tests/integration/test_publish.py", identified)
            self.assertIn("tests/integration/publish_helper.py", identified)
            self.assertNotIn("tests/integration/unrelated.py", identified)

    def test_transitive_gate_sources_cannot_forge_a_green_check(self):
        contract = aq.load_contract(ROOT)
        protected = [
            "tools/check_ci_cache_policy.py",
            "tools/v09_qualification_scope.py",
            "scripts/lint_github_workflows.sh",
            "tools/xtask/Cargo.toml",
            "tools/xtask/src/main.rs",
            ".cargo/config", ".cargo/config.toml", "Cargo.toml",
            "Cargo.lock",
        ]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, protected),
            sorted(protected),
        )
        self.assertNotIn(
            "crates/linura-core/src/lib.rs",
            aq._untrusted_gate_definition_edits(
                contract, ["crates/linura-core/src/lib.rs"]
            ),
        )

    def test_xtask_authority_paths_match_real_workspace_membership(self):
        # The canonical gate invokes `cargo xtask check`; its crate is rooted
        # in tools/xtask/, not in a top-level xtask/ directory. Regressions in
        # this path silently turn authoritative CI jobs into no-op successes.
        import tomllib

        with (ROOT / "Cargo.toml").open("rb") as source:
            members = tomllib.load(source)["workspace"]["members"]
        self.assertIn("tools/xtask", members)
        self.assertTrue((ROOT / "tools/xtask/Cargo.toml").is_file())
        self.assertTrue((ROOT / "tools/xtask/src/main.rs").is_file())

        contract = aq.load_contract(ROOT)
        dangerous = [
            "tools/xtask/Cargo.toml",
            "tools/xtask/src/main.rs",
            "tools/xtask/src/commands/validation.rs",
        ]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, dangerous),
            sorted(dangerous),
        )
        harmless = ["xtask/src/main.rs", "tools/xtask-shadow/src/main.rs"]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, harmless),
            [],
        )

    def test_cargo_alias_and_workspace_authority_cannot_self_authorize(self):
        contract = aq.load_contract(ROOT)
        inputs = [
            ".cargo/config", ".cargo/config.toml", ".cargo/local.toml",
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
            "tools/codex/versions.env",
        ]
        self.assertEqual(
            aq._untrusted_gate_definition_edits(contract, inputs),
            sorted(inputs),
        )
        for path in inputs:
            with self.subTest(path=path):
                head = "a" * 40
                pr = {
                    "head": {"sha": head},
                    "changed_files": 1,
                    "base": {"ref": "main", "sha": "1" * 40,
                             "repo": {"id": 1350812666}},
                }
                with (
                    mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
                    mock.patch.object(aq, "_api_json", return_value=pr),
                    mock.patch.object(aq, "_pr_changed_paths", return_value=[path]),
                    mock.patch.object(aq, "_head_runs") as runs,
                ):
                    result = aq.evaluate_pr(
                        root=ROOT, repository="linura-org/linura",
                        pr_number=99, head_sha=head, token="token",
                    )
                self.assertEqual(result["state"], "failure")
                self.assertIn(path, result["failures"][0])
                runs.assert_not_called()

    def test_xtask_edit_cannot_accept_self_reported_native_success(self):
        head = "a" * 40
        pr = {
            "head": {"sha": head},
            "changed_files": 1,
            "base": {"ref": "main", "sha": "1" * 40, "repo": {"id": 1350812666}},
        }
        path = "tools/xtask/src/main.rs"
        with (
            mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=[path]),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=99, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn(path, result["failures"][0])
        self.assertIn("executable qualification authority", result["failures"][0])
        runs.assert_not_called()

    def test_unrelated_protected_approval_cannot_authorize_changed_gate(self):
        head = "a" * 40
        path = "tools/xtask/src/main.rs"
        pr = {
            "head": {"sha": head},
            "changed_files": 1,
            "base": {"ref": "main", "sha": "1" * 40,
                     "repo": {"id": 1350812666}},
        }
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=[path]),
            mock.patch.object(
                aq, "_approved_gate_bundles",
                return_value={"sha256:" + "d" * 64: (213, "solo-operator")},
            ),
            mock.patch.object(
                aq, "_authority_bundle_digest",
                return_value="sha256:" + "e" * 64,
            ) as digest,
            mock.patch.object(
                aq, "_independently_reviewed_authority_upgrade",
            ) as approve,
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=99, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn("executable qualification authority", result["failures"][0])
        digest.assert_called_once()
        approve.assert_not_called()
        runs.assert_not_called()

    def test_authority_upgrade_requires_protected_independent_bundle(self):
        import tempfile

        path = "tools/check_ci_cache_policy.py"
        files = [{"filename": path, "status": "modified", "sha": "b" * 40}]
        identity = {
            "number": 99,
            "head": {"sha": "a" * 40},
            "base": {
                "ref": "main", "sha": "c" * 40,
                "repo": {"full_name": "linura-org/linura", "id": 1350812666},
            },
        }
        original = {
            "path": path, "type": "blob",
            "mode": "100644", "sha": "1" * 40,
        }
        tree = {
            "sha": "d" * 40, "truncated": False, "tree": [original],
        }

        def digest_for(changed=files, pr=identity, base_tree=tree, number=99):
            with (
                mock.patch.object(aq, "_paged", return_value=changed),
                mock.patch.object(aq, "_api_json", side_effect=[
                    {"sha": pr["base"]["sha"], "tree": {"sha": base_tree["sha"]}},
                    base_tree,
                ]) as api,
            ):
                digest = aq._authority_bundle_digest(
                    "linura-org/linura", number, "token", [path], pr=pr,
                )
                self.assertEqual(api.call_args_list, [
                    mock.call(
                        "https://api.github.com/repos/linura-org/linura/git/commits/"
                        + pr["base"]["sha"], "token",
                    ),
                    mock.call(
                        "https://api.github.com/repos/linura-org/linura/git/trees/"
                        + base_tree["sha"] + "?recursive=1", "token",
                    ),
                ])
                return digest

        digest = digest_for()
        self.assertTrue(digest.startswith("sha256:"))
        # Approval-state fixtures must not depend on the live repository
        # ledger: valid entries are expected to accumulate on protected main.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / ".github/qualification-authority-approvals.toml"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(
                "schema_version = 1\n"
                'solo_operator = "Ehsan-Azari"\n',
                encoding="utf-8",
            )
            self.assertEqual(aq._approved_gate_bundles(root), {})
            ledger.write_text(
                "schema_version = 1\n"
                'solo_operator = "Ehsan-Azari"\n'
                "[[approval]]\n"
                f'bundle_sha256 = "{digest}"\n'
                "review_pr = 100\n"
                'approval_mode = "independent-review"\n'
                'rationale = "Separately reviewed trust upgrade"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                aq._approved_gate_bundles(root),
                {digest: (100, "independent-review")},
            )
            ledger.write_text(
                "schema_version = 1\n"
                'solo_operator = "Ehsan-Azari"\n'
                "[[approval]]\n"
                f'bundle_sha256 = "{digest}"\n'
                "review_pr = 100\n"
                'approval_mode = "independent-review"\n'
                'rationale = "Reviewed"\n'
                "[[approval]]\n"
                f'bundle_sha256 = "{digest}"\n'
                "review_pr = 101\n"
                'approval_mode = "independent-review"\n'
                'rationale = "Duplicate"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                aq.QualificationError, "duplicate or malformed",
            ):
                aq._approved_gate_bundles(root)

        self.assertNotEqual(
            digest, digest_for([{**files[0], "sha": "d" * 40}]),
        )
        self.assertNotEqual(
            digest, digest_for([
                *files,
                {"filename": "tools/new-indirect-dependency.py",
                 "status": "added", "sha": "d" * 40},
            ]),
        )
        with (
            mock.patch.object(aq, "_paged", return_value=[]),
            mock.patch.object(aq, "_api_json", side_effect=[
                {"sha": identity["base"]["sha"], "tree": {"sha": tree["sha"]}},
                tree,
            ]),
        ):
            with self.assertRaisesRegex(aq.QualificationError, "does not cover"):
                aq._authority_bundle_digest(
                    "linura-org/linura", 99, "token", [path], pr=identity,
                )

        # Approvals must be stable across unrelated main commits but cannot
        # authorize a reversion of a subsequently security-fixed source.
        advanced = {
            **identity, "base": {**identity["base"], "sha": "e" * 40},
            "head": {"sha": "f" * 40},
        }
        advanced_tree = {**tree, "sha": "e" * 40}
        self.assertEqual(digest, digest_for(pr=advanced, base_tree=advanced_tree))
        repaired_tree = {
            **advanced_tree,
            "tree": [{**original, "sha": "2" * 40}],
        }
        self.assertNotEqual(
            digest, digest_for(pr=advanced, base_tree=repaired_tree),
        )
        # An up-to-date-branch merge/rebase after the ledger PR merges
        # changes the code head even if the reviewed diff stays the same.
        # Requiring a new ledger approval here would deadlock forever.
        self.assertEqual(
            digest, digest_for(pr={**identity, "head": {"sha": "f" * 40}}),
        )
        different_pr = {**identity, "number": 100}
        self.assertNotEqual(
            digest, digest_for(pr=different_pr, number=100),
        )

        # A new/removed/renamed authority file is bound to both absence and
        # the exact historical source entry, not merely the destination SHA.
        addition = [{"filename": "tools/new.py", "status": "added", "sha": "3" * 40}]
        with (
            mock.patch.object(aq, "_paged", return_value=addition),
            mock.patch.object(aq, "_api_json", side_effect=[
                {"sha": identity["base"]["sha"], "tree": {"sha": tree["sha"]}},
                tree,
            ]),
        ):
            added = aq._authority_bundle_digest(
                "linura-org/linura", 99, "token", ["tools/new.py"], pr=identity,
            )
        self.assertTrue(added.startswith("sha256:"))
        renamed = [{
            "filename": "tools/renamed.py",
            "previous_filename": path,
            "status": "renamed", "sha": "b" * 40,
        }]
        with (
            mock.patch.object(aq, "_paged", return_value=renamed),
            mock.patch.object(aq, "_api_json", side_effect=[
                {"sha": identity["base"]["sha"], "tree": {"sha": tree["sha"]}},
                tree,
            ]),
        ):
            rename_digest = aq._authority_bundle_digest(
                "linura-org/linura", 99, "token", [path], pr=identity,
            )
        self.assertNotEqual(added, rename_digest)

        copied = [{
            "filename": "tools/copied.py",
            "previous_filename": path,
            "status": "copied", "sha": "b" * 40,
        }]
        with (
            mock.patch.object(aq, "_paged", return_value=copied),
            mock.patch.object(aq, "_api_json", side_effect=[
                {"sha": identity["base"]["sha"], "tree": {"sha": tree["sha"]}},
                tree,
            ]),
        ):
            copy_digest = aq._authority_bundle_digest(
                "linura-org/linura", 99, "token", ["tools/copied.py"],
                pr=identity,
            )
        fixed = {**tree, "tree": [{**original, "sha": "2" * 40}]}
        with (
            mock.patch.object(aq, "_paged", return_value=copied),
            mock.patch.object(aq, "_api_json", side_effect=[
                {"sha": identity["base"]["sha"], "tree": {"sha": fixed["sha"]}},
                fixed,
            ]),
        ):
            self.assertNotEqual(
                copy_digest,
                aq._authority_bundle_digest(
                    "linura-org/linura", 99, "token", ["tools/copied.py"],
                    pr=identity,
                ),
            )
        with (
            mock.patch.object(aq, "_paged",
                              return_value=[{**copied[0], "previous_filename": None}]),
            mock.patch.object(aq, "_api_json", side_effect=[
                {"sha": identity["base"]["sha"], "tree": {"sha": tree["sha"]}},
                tree,
            ]),
        ):
            with self.assertRaisesRegex(
                aq.QualificationError, "rename/copy source identity",
            ):
                aq._authority_bundle_digest(
                    "linura-org/linura", 99, "token", ["tools/copied.py"],
                    pr=identity,
                )

    def test_authority_bundle_denies_incomplete_or_ambiguous_old_source(self):
        path = "tools/check_ci_cache_policy.py"
        identity = {
            "number": 99, "head": {"sha": "a" * 40},
            "base": {"ref": "main", "sha": "c" * 40,
                     "repo": {"full_name": "linura-org/linura"}},
        }
        changed = [{"filename": path, "status": "modified", "sha": "b" * 40}]
        base_tree = {
            "sha": "d" * 40, "truncated": False,
            "tree": [{"path": path, "sha": "1" * 40,
                      "mode": "100644", "type": "blob"}],
        }
        for invalid, reason in (
            ({**base_tree, "truncated": True}, "incomplete"),
            ({**base_tree, "sha": "f" * 40}, "incomplete"),
            ({**base_tree, "tree": base_tree["tree"] * 2}, "ambiguous"),
            ({**base_tree, "tree": []}, "previous file"),
        ):
            with (
                self.subTest(reason=reason),
                mock.patch.object(aq, "_paged", return_value=changed),
                mock.patch.object(aq, "_api_json", side_effect=[
                    {"sha": identity["base"]["sha"],
                     "tree": {"sha": base_tree["sha"]}},
                    invalid,
                ]),
            ):
                with self.assertRaisesRegex(aq.QualificationError, reason):
                    aq._authority_bundle_digest(
                        "linura-org/linura", 99, "token", [path], pr=identity,
                    )
        with (
            mock.patch.object(aq, "_paged", return_value=changed),
            mock.patch.object(aq, "_api_json") as api,
        ):
            with self.assertRaisesRegex(
                aq.QualificationError, "exact code PR/head identity",
            ):
                aq._authority_bundle_digest(
                    "linura-org/linura", 99, "token", [path],
                    pr={**identity, "head": {"sha": "invalid"}},
                )
            api.assert_not_called()

    def test_authority_bundle_denies_unbound_commit_or_tree_identity(self):
        path = "tools/check_ci_cache_policy.py"
        base_sha, tree_sha = "c" * 40, "d" * 40
        identity = {
            "number": 99, "head": {"sha": "a" * 40},
            "base": {"ref": "main", "sha": base_sha,
                     "repo": {"full_name": "linura-org/linura"}},
        }
        changed = [{"filename": path, "status": "modified", "sha": "b" * 40}]
        for invalid_commit in (
            None,
            {"sha": "e" * 40, "tree": {"sha": tree_sha}},
            {"sha": base_sha, "tree": {"sha": "not-a-sha"}},
            {"sha": base_sha, "tree": {}},
            {"sha": base_sha, "tree": tree_sha},
        ):
            with (
                self.subTest(commit=invalid_commit),
                mock.patch.object(aq, "_paged", return_value=changed),
                mock.patch.object(aq, "_api_json", return_value=invalid_commit) as api,
            ):
                with self.assertRaisesRegex(
                    aq.QualificationError, "base commit/tree identity unavailable",
                ):
                    aq._authority_bundle_digest(
                        "linura-org/linura", 99, "token", [path], pr=identity,
                    )
                api.assert_called_once_with(
                    "https://api.github.com/repos/linura-org/linura/git/commits/"
                    + base_sha, "token",
                )

    def test_authority_approval_requires_distinct_merged_review(self):
        digest = "sha256:" + "f" * 64
        self.assertFalse(aq._independently_reviewed_authority_upgrade(
            "linura-org/linura", 7, 7, digest, "token",
            code_author="code-author", approval_mode="independent-review",
            solo_operator="Ehsan-Azari",
        ))
        with mock.patch.object(aq, "_api_json", return_value={"merged": False}):
            self.assertFalse(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 8, 7, digest, "token",
                code_author="code-author", approval_mode="independent-review",
                solo_operator="Ehsan-Azari",
            ))

    def test_authority_approval_binds_reviewed_ledger_snapshot(self):
        import base64

        digest = "sha256:" + "e" * 64
        ledger = (
            "schema_version = 1\n"
            'solo_operator = "Ehsan-Azari"\n'
            "[[approval]]\n"
            f'bundle_sha256 = "{digest}"\n'
            "review_pr = 101\n"
            'approval_mode = "independent-review"\n'
            'rationale = "Reviewed separately"\n'
        )
        approved_pr = {
            "merged": True, "merged_at": "2026-10-08T10:00:00Z",
            "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}},
            "head": {"sha": "a" * 40}, "user": {"login": "author"},
        }
        recorded_source = {
            "encoding": "base64",
            "content": base64.b64encode(ledger.encode()).decode(),
        }
        changed = [{
            "filename": ".github/qualification-authority-approvals.toml",
            "status": "modified",
        }]
        independent = [{
            "user": {"login": "reviewer"},
            "state": "APPROVED", "commit_id": "a" * 40,
            "author_association": "COLLABORATOR",
        }]
        with (
            mock.patch.object(aq, "_api_json", side_effect=[approved_pr, recorded_source]),
            mock.patch.object(aq, "_paged", side_effect=[changed, independent]),
        ):
            self.assertTrue(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 101, 99, digest, "token",
                code_author="code-author", approval_mode="independent-review",
                solo_operator="Ehsan-Azari",
            ))
        with (
            mock.patch.object(aq, "_api_json", side_effect=[approved_pr, recorded_source]),
            mock.patch.object(aq, "_paged", side_effect=[
                changed,
                independent + [{
                    "user": {"login": "reviewer"},
                    "state": "DISMISSED", "commit_id": "a" * 40,
                    "author_association": "COLLABORATOR",
                }],
            ]),
        ):
            self.assertFalse(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 101, 99, digest, "token",
                code_author="code-author", approval_mode="independent-review",
                solo_operator="Ehsan-Azari",
            ))

    def test_executable_author_cannot_approve_independent_ledger(self):
        import base64
        digest = "sha256:" + "c" * 64
        source = (
            "schema_version = 1\n"
            'solo_operator = "Ehsan-Azari"\n'
            "[[approval]]\n"
            f'bundle_sha256 = "{digest}"\n'
            "review_pr = 100\n"
            'approval_mode = "independent-review"\n'
            'rationale = "Separate human review required"\n'
        )
        reviewed = {
            "merged": True, "merged_at": "2026-10-09T00:00:00Z",
            "base": {"ref": "main", "repo": {"full_name": "linura-org/linura"}},
            "head": {"sha": "a" * 40}, "user": {"login": "ledger-author"},
        }
        encoded = {
            "encoding": "base64",
            "content": base64.b64encode(source.encode()).decode(),
        }
        files = [{
            "filename": ".github/qualification-authority-approvals.toml",
            "status": "modified",
        }]
        reviews = [{
            "user": {"login": "code-author"}, "state": "APPROVED",
            "commit_id": "a" * 40, "author_association": "COLLABORATOR",
        }]
        with (
            mock.patch.object(aq, "_api_json", side_effect=[reviewed, encoded]),
            mock.patch.object(aq, "_paged", side_effect=[files, reviews]),
        ):
            self.assertFalse(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 100, 99, digest, "token",
                code_author="code-author", approval_mode="independent-review",
                solo_operator="Ehsan-Azari",
            ))

    def test_solo_operator_requires_distinct_ledger_and_all_native_gate_proofs(self):
        import base64
        digest = "sha256:" + "d" * 64
        source = (
            "schema_version = 1\n"
            'solo_operator = "Ehsan-Azari"\n'
            "[[approval]]\n"
            f'bundle_sha256 = "{digest}"\n'
            "review_pr = 100\n"
            'approval_mode = "solo-operator"\n'
            'rationale = "Operator-approved after adversarial review"\n'
        )
        meta = {
            "merged": True, "merged_at": "2026-10-09T00:00:00Z",
            "author_association": "MEMBER",
            "base": {"ref": "main", "sha": "1" * 40,
                     "repo": {"full_name": "linura-org/linura", "id": 1350812666}},
            "head": {"sha": "a" * 40}, "user": {"login": "Ehsan-Azari"},
            "merge_commit_sha": "d" * 40,
        }
        contents = {
            "encoding": "base64",
            "content": base64.b64encode(source.encode()).decode(),
        }
        changed = [{
            "filename": ".github/qualification-authority-approvals.toml",
            "status": "modified",
        }]
        contract = aq.load_contract(ROOT)
        runs = [
            self._run(gate=g, head="a" * 40, pr=100, run_id=500 + i)
            for i, g in enumerate(contract["gate"]) if g["mandatory"]
        ]
        merged_commit = {"sha": "d" * 40, "parents": [{"sha": "1" * 40}]}
        tested_merge = {"sha": "e" * 40, "parents": [
            {"sha": "1" * 40}, {"sha": "a" * 40}]}

        with (
            mock.patch.object(aq, "_api_json", side_effect=[meta, contents, merged_commit, tested_merge]),
            mock.patch.object(aq, "_paged", return_value=changed),
            mock.patch.object(aq, "_head_runs", return_value=runs),
            mock.patch.object(aq, "_verify_required_jobs",
                              return_value="verified") as verify,
        ):
            self.assertTrue(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 100, 99, digest, "token",
                code_author="Ehsan-Azari", approval_mode="solo-operator",
                solo_operator="Ehsan-Azari", root=ROOT, contract=contract,
            ))
            self.assertEqual(verify.call_count, 3)
        with (
            mock.patch.object(aq, "_api_json", side_effect=[meta, contents, merged_commit]),
            mock.patch.object(aq, "_paged", return_value=changed),
            mock.patch.object(aq, "_head_runs", return_value=[]),
        ):
            self.assertFalse(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 100, 99, digest, "token",
                code_author="Ehsan-Azari", approval_mode="solo-operator",
                solo_operator="Ehsan-Azari", root=ROOT, contract=contract,
            ))
        with (
            mock.patch.object(aq, "_api_json", side_effect=[meta, contents]),
            mock.patch.object(aq, "_paged", return_value=changed),
            mock.patch.object(aq, "_head_runs") as runs_called,
        ):
            self.assertFalse(aq._independently_reviewed_authority_upgrade(
                "linura-org/linura", 100, 99, digest, "token",
                code_author="someone-else", approval_mode="solo-operator",
                solo_operator="Ehsan-Azari", root=ROOT, contract=contract,
            ))
            runs_called.assert_not_called()

    def test_renaming_gate_helper_to_docs_cannot_hide_authority_change(self):
        head = "a" * 40
        original = "tools/check_ci_cache_policy.py"
        destination = "docs/renamed-cache-checker.md"
        pr = {"head": {"sha": head}, "changed_files": 1,
              "base": {"ref": "main", "sha": "1" * 40,
                       "repo": {"id": 1350812666}}}

        def path_inventory(repository, number, token, *,
                           include_rename_sources=False):
            return [destination, original] if include_rename_sources else [destination]

        with (
            mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", side_effect=path_inventory),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=99, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn("executable qualification authority", result["failures"][0])
        runs.assert_not_called()

    def test_fake_successful_native_jobs_cannot_self_certify_changed_workflow(self):
        head = "a" * 40
        gate = next(g for g in aq.load_contract(ROOT)["gate"] if g["id"] == "canonical-ci")
        pr = {"head": {"sha": head}, "changed_files": 1,
              "base": {"ref": "main", "sha": "1" * 40,
                       "repo": {"id": 1350812666}}}
        with (
            mock.patch.object(aq, "_approved_gate_bundles", return_value={}),
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths",
                              return_value=[".github/workflows/ci.yml"]),
            mock.patch.object(aq, "_head_runs", return_value=[
                self._run(gate=gate, head=head)
            ]) as runs,
            mock.patch.object(aq, "_verify_required_jobs") as verify,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn("executable qualification authority", result["failures"][0])
        self.assertEqual(result["accepted"], [])
        runs.assert_not_called()
        verify.assert_not_called()

    def test_renamed_away_critical_code_cannot_bypass_qualified_gate(self):
        old = "apps/linura-shell/ui/StatusPanel.qml"
        new = "docs/renamed-panel.md"
        head = "a" * 40
        pr = {"head": {"sha": head}, "changed_files": 1,
              "base": {"ref": "main", "sha": "1" * 40,
                       "repo": {"id": 1350812666}}}
        def paths(repo, number, token, *, include_rename_sources=False):
            return sorted([old, new]) if include_rename_sources else [new]
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", side_effect=paths),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "failure")
        self.assertIn("Rename removes protected source paths", result["failures"][0])
        self.assertIn("v010-workstation", result["failures"][0])
        runs.assert_not_called()

    def test_v09_rename_out_of_full_scope_remains_full_mode(self):
        from_path = "crates/linura-update/src/lib.rs"
        to_path = "docs/qualification/v0.9.0.md"
        payload = [{
            "filename": to_path,
            "previous_filename": from_path,
            "status": "renamed",
        }]
        with mock.patch.object(aq, "_paged", return_value=payload):
            gate_paths = aq._pr_changed_paths("linura-org/linura", 9, "token")
            scope_paths = aq._pr_changed_paths(
                "linura-org/linura", 9, "token",
                include_rename_sources=True,
            )
        self.assertEqual(gate_paths, [to_path])
        self.assertEqual(scope_paths, sorted([from_path, to_path]))
        self.assertEqual(aq._v09_job_mode(ROOT, gate_paths), "regression")
        self.assertEqual(aq._v09_job_mode(ROOT, scope_paths), "full")
        self.assertIn(
            "v09-qualification",
            aq.required_gate_ids(aq.load_contract(ROOT), gate_paths),
        )

    def test_v09_run_uses_rename_aware_scope_without_expanding_gate_set(self):
        head = "d" * 40
        from_path = "crates/linura-update/src/lib.rs"
        to_path = "docs/qualification/v0.9.0.md"
        other = "apps/linura-shell/ui/Other.qml"
        payload = [{
            "filename": to_path,
            "previous_filename": from_path,
            "status": "renamed",
        }, {"filename": other, "status": "modified"}]
        contract = aq.load_contract(ROOT)
        required = aq.required_gate_ids(contract, [to_path, other])
        gates = {g["id"]: g for g in contract["gate"]}
        runs = [
            self._run(gate=gates[gate_id], head=head, run_id=1000 + i)
            for i, gate_id in enumerate(required)
        ]
        pr = {
            "head": {"sha": head}, "changed_files": 2,
            "base": {
                "ref": "main", "sha": "1" * 40,
                "repo": {"id": 1350812666},
            },
        }
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_paged", return_value=payload),
            mock.patch.object(aq, "_head_runs", return_value=runs),
            mock.patch.object(aq, "_verify_required_jobs",
                              return_value="all-success") as verify,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=head, token="token",
            )
        self.assertEqual(result["state"], "success")
        self.assertEqual(result["required_gate_ids"], required)
        by_gate = {
            call.args[1]["id"]: call.kwargs["changed_paths"]
            for call in verify.call_args_list
        }
        self.assertEqual(by_gate["v09-qualification"],
                         sorted([from_path, to_path, other]))
        self.assertEqual(by_gate["canonical-ci"], sorted([to_path, other]))

    def test_missing_rename_source_denies_v09_scope_admission(self):
        payload = [{"filename": "docs/qualification/v0.9.0.md",
                    "status": "renamed"}]
        with mock.patch.object(aq, "_paged", return_value=payload):
            self.assertEqual(
                aq._pr_changed_paths("linura-org/linura", 9, "token"),
                ["docs/qualification/v0.9.0.md"],
            )
            with self.assertRaisesRegex(
                aq.QualificationError,
                "renamed PR file lacks previous_filename",
            ):
                aq._pr_changed_paths(
                    "linura-org/linura", 9, "token",
                    include_rename_sources=True,
                )

    def test_rename_into_specialized_scope_and_deletion_still_route(self):
        contract = aq.load_contract(ROOT)
        source = "docs/renamed-panel.md"
        destination = "apps/linura-shell/ui/StatusPanel.qml"
        for payload in (
            [{"filename": destination, "previous_filename": source,
              "status": "renamed"}],
            [{"filename": destination, "status": "removed"}],
        ):
            with self.subTest(payload=payload):
                with mock.patch.object(aq, "_paged", return_value=payload):
                    paths = aq._pr_changed_paths("linura-org/linura", 1, "token")
                self.assertEqual(paths, [destination])
                self.assertIn("v010-workstation",
                              aq.required_gate_ids(contract, paths))

    @staticmethod
    def _base():
        return ("main", "1" * 40, 1350812666)

    @staticmethod
    def _identity(number):
        return ("main", "1" * 40, 1350812666, "feature", 1350812666, str(number) * 40)

    def _run(
        self,
        *,
        gate,
        head,
        pr=9,
        event="pull_request",
        status="completed",
        conclusion="success",
        run_number=5,
        attempt=1,
        run_id=100,
    ):
        return {
            "id": run_id,
            "run_number": run_number,
            "run_attempt": attempt,
            "path": gate["workflow"],
            "event": event,
            "head_sha": head,
            "display_title": gate["workflow_name"] + " :: PR" + str(pr) + " :: " + "e" * 40,
            "status": status,
            "conclusion": conclusion,
            "pull_requests": [{
                "number": pr,
                "head": {"sha": head, "ref": "feature", "repo": {"id": 1350812666}},
                "base": {"ref": "main", "sha": "1" * 40, "repo": {"id": 1350812666}},
            }],
        }

    def test_zero_diff_release_pr_selects_only_mandatory_native_gates(self):
        contract = aq.load_contract(ROOT)
        mandatory = contract["mandatory_gate_ids"]
        self.assertEqual(aq.required_gate_ids(contract, []), mandatory)
        with mock.patch.object(aq, "_paged", return_value=[]) as files:
            paths = aq._pr_changed_paths("linura-org/linura", 9, "token")
        self.assertEqual(paths, [])
        self.assertIn("/pulls/9/files", files.call_args.args[0])
        self.assertEqual(aq.required_gate_ids(contract, paths), mandatory)

    def test_zero_diff_release_pr_can_pass_with_exact_native_gate_proofs(self):
        contract = aq.load_contract(ROOT)
        gates = [gate for gate in contract["gate"] if gate["mandatory"]]
        self.assertEqual(len(gates), 3)
        sha = "b" * 40
        runs = [
            self._run(
                gate=gate, head=sha, pr=9,
                run_number=100 + index, run_id=500 + index
            )
            for index, gate in enumerate(gates)
        ]
        pr = {
            "head": {"sha": sha},
            "changed_files": 0,
            "base": {
                "ref": "main", "sha": "1" * 40,
                "repo": {"id": 1350812666},
            },
        }
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=[]),
            mock.patch.object(aq, "_head_runs", return_value=runs),
            mock.patch.object(aq, "_verify_required_jobs", return_value="all-success") as verify,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=sha, token="token"
            )
        self.assertEqual(result["state"], "success")
        self.assertEqual(result["required_gate_ids"], contract["mandatory_gate_ids"])
        self.assertEqual(result["changed_paths"], [])
        self.assertEqual(verify.call_count, 3)

    def test_zero_diff_release_pr_does_not_bypass_native_failures(self):
        contract = aq.load_contract(ROOT)
        gate = next(g for g in contract["gate"] if g["id"] == "canonical-ci")
        sha = "c" * 40
        failed = self._run(gate=gate, head=sha, conclusion="failure")
        pr = {
            "head": {"sha": sha},
            "changed_files": 0,
            "base": {
                "ref": "main", "sha": "1" * 40,
                "repo": {"id": 1350812666},
            },
        }
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=[]),
            mock.patch.object(aq, "_head_runs", return_value=[failed]),
            mock.patch.object(aq, "_verify_required_jobs") as verify,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=sha, token="token"
            )
        self.assertEqual(result["state"], "failure")
        self.assertEqual(len(result["accepted"]), 0)
        self.assertEqual(len(result["waiting"]), 2)
        self.assertIn("canonical-ci: exact-head PR run concluded failure", result["failures"])
        verify.assert_not_called()

    def test_declared_nonzero_diff_cannot_be_downgraded_to_native_only(self):
        sha = "d" * 40
        pr = {
            "head": {"sha": sha}, "changed_files": 3,
            "base": {"ref": "main", "sha": "1" * 40, "repo": {"id": 1350812666}},
        }
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_pr_changed_paths", return_value=[]),
            mock.patch.object(aq, "_head_runs") as runs,
        ):
            with self.assertRaisesRegex(
                aq.QualificationError, "file inventory incomplete"
            ):
                aq.evaluate_pr(
                    root=ROOT, repository="linura-org/linura",
                    pr_number=9, head_sha=sha, token="token",
                )
            runs.assert_not_called()

    def test_malformed_files_api_entries_do_not_become_zero_diff(self):
        with mock.patch.object(aq, "_api_json", return_value=[None]):
            with self.assertRaisesRegex(
                aq.QualificationError, "malformed GitHub list entry"
            ):
                aq._pr_changed_paths("linura-org/linura", 9, "token")

    def test_zero_diff_invalid_path_inventory_is_not_accepted(self):
        contract = aq.load_contract(ROOT)
        for paths in (None, "README.md", ["README.md", None], [""]):
            with self.subTest(paths=paths):
                with self.assertRaises(aq.QualificationError):
                    aq.required_gate_ids(contract, paths)

    def test_run_matching_rejects_dispatch_stale_sha_and_wrong_pr(self):
        contract = aq.load_contract(ROOT)
        gate = next(
            item
            for item in contract["gate"]
            if item["id"] == "v07-library"
        )
        head = "a" * 40
        self.assertTrue(
            aq._run_matches(
                self._run(gate=gate, head=head),
                gate=gate,
                head_sha=head,
                pr_number=9,
                pr_base=self._base(), merge_sha="e" * 40,
            )
        )
        for change in (
            {"event": "workflow_dispatch"},
            {"head": "b" * 40},
            {"pr": 10},
        ):
            with self.subTest(change=change):
                args = {"gate": gate, "head": head}
                args.update(change)
                self.assertFalse(
                    aq._run_matches(
                        self._run(**args),
                        gate=gate,
                        head_sha=head,
                        pr_number=9,
                        pr_base=self._base(), merge_sha="e" * 40,
                    )
                )

    def test_ref_qualified_workflow_paths_match_exact_file_only(self):
        contract = aq.load_contract(ROOT)
        gate = next(item for item in contract["gate"] if item["id"] == "canonical-ci")
        head = "a" * 40
        for suffix in ("", "@main", "@refs/heads/main", "@refs/pull/9/merge", "@release/v0.9"):
            with self.subTest(valid_suffix=suffix):
                run = self._run(gate=gate, head=head)
                run["path"] = gate["workflow"] + suffix
                self.assertTrue(
                    aq._run_matches(
                        run, gate=gate, head_sha=head, pr_number=9,
                        pr_base=self._base(), merge_sha="e" * 40,
                    )
                )
        for value in (
            None,
            42,
            "other/ci.yml@main",
            gate["workflow"] + ".backup@main",
            gate["workflow"] + "@",
            gate["workflow"] + "@/feature",
            gate["workflow"] + "@feature/",
            gate["workflow"] + "@refs//heads/main",
            gate["workflow"] + "@../main",
            gate["workflow"] + "@refs/heads/.hidden",
            gate["workflow"] + "@main\nother",
            gate["workflow"] + "@main@{0}",
        ):
            with self.subTest(invalid_path=value):
                run = self._run(gate=gate, head=head)
                run["path"] = value
                self.assertFalse(
                    aq._run_matches(
                        run, gate=gate, head_sha=head, pr_number=9,
                        pr_base=self._base(), merge_sha="e" * 40,
                    )
                )

    def test_ref_qualified_run_cannot_override_wrong_pr_or_sha(self):
        contract = aq.load_contract(ROOT)
        gate = next(item for item in contract["gate"] if item["id"] == "canonical-ci")
        head = "b" * 40
        for change in ({"pr": 10}, {"head": "c" * 40}, {"event": "workflow_dispatch"}):
            with self.subTest(change=change):
                run_args = {"gate": gate, "head": head, **change}
                run = self._run(**run_args)
                run["path"] = gate["workflow"] + "@main"
                self.assertFalse(
                    aq._run_matches(
                        run, gate=gate, head_sha=head, pr_number=9,
                        pr_base=self._base(), merge_sha="e" * 40,
                    )
                )


    def test_head_reconciliation_recovers_empty_workflow_run_pr_list(self):
        head = "a" * 40
        identities = {17: self._identity(1), 19: self._identity(2)}
        def evaluation(**kwargs):
            return {
                "pr_number": kwargs["pr_number"], "state": "pending",
                "waiting": ["canonical-ci: absent"], "failures": [],
                "required_gate_ids": ["canonical-ci"],
            }
        writes = []
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs", return_value=identities),
            mock.patch.object(aq, "evaluate_pr", side_effect=evaluation) as evaluate,
            mock.patch.object(aq, "_post_json",
                side_effect=lambda url, token, payload: writes.append((url, payload))),
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura", head_sha=head, token="token"
            )
        self.assertEqual(result["pr_count"], 2)
        self.assertEqual(evaluate.call_count, 2)
        self.assertEqual([payload["state"] for _, payload in writes], ["pending", "pending"])
        self.assertEqual([url.rsplit("/", 1)[1] for url, _ in writes], [head, head])
        self.assertIn("#17:", writes[-1][1]["description"])

    def test_head_reconciliation_refuses_duplicate_or_untrusted_identity(self):
        head = "c" * 40
        item = {"number": 17, "state": "open", "head": {"sha": head}}
        with (
            mock.patch.object(aq, "_paged", return_value=[item, item]),
            mock.patch.object(aq, "_api_json", return_value={
                "number": 17, "state": "open",
                "head": {"sha": head, "ref": "feature", "repo": {"id": 1350812666}},
                "base": {"ref": "main", "sha": "1" * 40, "repo": {"id": 1350812666}},
                "merge_commit_sha": "9" * 40,
            }),
        ):
            with self.assertRaisesRegex(aq.QualificationError, "invalid/duplicate"):
                aq._open_head_prs("linura-org/linura", head, "token")
        with mock.patch.object(
            aq, "load_contract", return_value={"repository": "linura-org/linura"}
        ):
            with self.assertRaisesRegex(aq.QualificationError, "repository mismatch"):
                aq.reconcile_head(
                    root=ROOT, repository="other/repo", head_sha=head, token="token"
                )

    def test_head_reconciliation_ignores_absent_pr_associations(self):
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs", return_value={}),
            mock.patch.object(aq, "_post_json") as post,
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura",
                head_sha="e" * 40, token="token"
            )
        self.assertEqual(result["state"], "ignored-no-open-pr")
        self.assertEqual(result["published_status"]["state"], "pending")
        post.assert_called_once()
        self.assertTrue(post.call_args.args[0].endswith("/statuses/" + "e" * 40))
        self.assertEqual(post.call_args.args[2]["state"], "pending")

    def test_reconcile_revokes_stale_success_before_discovery_raises(self):
        head = "d" * 40
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs",
                side_effect=aq.QualificationError("test-merge SHA unavailable")),
            mock.patch.object(aq, "_post_json") as publish,
            mock.patch.object(aq, "evaluate_pr") as evaluate,
        ):
            with self.assertRaisesRegex(
                aq.QualificationError, "test-merge SHA unavailable"
            ):
                aq.reconcile_head(
                    root=ROOT, repository="linura-org/linura",
                    head_sha=head, token="token"
                )
        publish.assert_called_once()
        self.assertEqual(publish.call_args.args[2]["state"], "pending")
        self.assertTrue(publish.call_args.args[0].endswith("/statuses/" + head))
        evaluate.assert_not_called()

    def test_incomplete_second_shared_pr_cannot_retain_prior_success(self):
        head = "3" * 40
        associated = [
            {"number": 9, "state": "open", "head": {"sha": head}},
            {"number": 10, "state": "open", "head": {"sha": head}},
        ]
        def live_pr(url, token):
            number = int(url.split("/pulls/")[-1])
            return {
                "state": "open",
                "head": {"sha": head, "ref": "feature", "repo": {"id": 42}},
                "base": {"ref": "main", "sha": "1" * 40, "repo": {"id": 42}},
                "merge_commit_sha": "e" * 40 if number == 9 else None,
            }
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_paged", return_value=associated),
            mock.patch.object(aq, "_api_json", side_effect=live_pr),
            mock.patch.object(aq, "_post_json") as publish,
            mock.patch.object(aq, "evaluate_pr") as evaluate,
        ):
            with self.assertRaisesRegex(aq.QualificationError,
                                        "synthetic merge SHA unavailable"):
                aq.reconcile_head(
                    root=ROOT, repository="linura-org/linura",
                    head_sha=head, token="token"
                )
        publish.assert_called_once()
        self.assertEqual(publish.call_args.args[2]["state"], "pending")
        evaluate.assert_not_called()

    def test_untrusted_reconciliation_input_never_publishes(self):
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_post_json") as publish,
            mock.patch.object(aq, "_open_head_prs") as resolve,
        ):
            for changed in (
                {"repository": "wrong-org/repo", "head_sha": "f" * 40},
                {"repository": "linura-org/linura", "head_sha": "invalid"},
            ):
                with self.subTest(changed=changed):
                    with self.assertRaises(aq.QualificationError):
                        aq.reconcile_head(root=ROOT, token="token", **changed)
        publish.assert_not_called()
        resolve.assert_not_called()

    def test_missing_mutable_association_cannot_override_immutable_event_proof(self):
        gate = next(g for g in aq.load_contract(ROOT)["gate"]
                    if g["id"] == "canonical-ci")
        head = "f" * 40
        run = self._run(gate=gate, head=head)
        args = {"gate": gate, "head_sha": head, "pr_number": 9,
                "pr_base": self._base(), "merge_sha": "e" * 40}
        run["pull_requests"] = []
        self.assertTrue(aq._run_matches(run, **args))
        run["pull_requests"] = [{"number": 10, "base": {"sha": "0" * 40}}]
        self.assertTrue(aq._run_matches(run, **args))
        self.assertFalse(aq._run_matches(run, **{**args, "merge_sha": "d" * 40}))
        run["event"] = "workflow_dispatch"
        self.assertFalse(aq._run_matches(run, **args))


    def test_mutable_association_base_does_not_replace_merge_parent_evidence(self):
        gate = next(g for g in aq.load_contract(ROOT)["gate"]
                    if g["id"] == "canonical-ci")
        head = "f" * 40
        run = self._run(gate=gate, head=head)
        expected = {"gate": gate, "head_sha": head, "pr_number": 9,
                    "pr_base": self._base(), "merge_sha": "e" * 40}
        self.assertTrue(aq._run_matches(run, **expected))
        duplicate = self._run(gate=gate, head=head)
        duplicate["pull_requests"].append(duplicate["pull_requests"][0].copy())
        self.assertTrue(aq._run_matches(duplicate, **expected))
        for field, replacement in (
            ("ref", "other-branch"), ("sha", "2" * 40),
        ):
            changed = self._run(gate=gate, head=head)
            changed["pull_requests"][0]["base"][field] = replacement
            with self.subTest(field=field):
                self.assertTrue(aq._run_matches(changed, **expected))
        altered = self._run(gate=gate, head=head)
        altered["pull_requests"][0]["base"]["repo"]["id"] = 100
        self.assertTrue(aq._run_matches(altered, **expected))
        altered["display_title"] = gate["workflow_name"] + " :: PR9 :: " + "d" * 40
        self.assertFalse(aq._run_matches(altered, **expected))


    def test_pr_retarget_and_base_advancement_invalidate_old_runs(self):
        head = "c" * 40
        gate = next(
            item for item in aq.load_contract(ROOT)["gate"]
            if item["id"] == "canonical-ci"
        )
        old_run = self._run(gate=gate, head=head)
        for changed in (
            {"ref": "release", "sha": "1" * 40, "repo": {"id": 1350812666}},
            {"ref": "main", "sha": "2" * 40, "repo": {"id": 1350812666}},
            {"ref": "main", "sha": "1" * 40, "repo": {"id": 99}},
        ):
            with self.subTest(changed=changed):
                pr = {"head": {"sha": head}, "changed_files": 1, "base": changed}
                with (
                    mock.patch.object(aq, "_api_json", return_value=pr),
                    mock.patch.object(aq, "_reviewed_test_merge", return_value="f" * 40),
                    mock.patch.object(aq, "_pr_changed_paths", return_value=["docs/README.md"]),
                    mock.patch.object(aq, "_head_runs", return_value=[old_run]),
                    mock.patch.object(aq, "_verify_required_jobs") as verify,
                ):
                    result = aq.evaluate_pr(
                        root=ROOT, repository="linura-org/linura",
                        pr_number=9, head_sha=head, token="token"
                    )
                self.assertEqual(result["state"], "failure")
                self.assertEqual(result["waiting"], ["security-rustsec: absent", "codeql: absent"])
                self.assertIn("canonical-ci: PR base changed", result["failures"][0])
                self.assertIn("new native checks", result["failures"][0])
                verify.assert_not_called()

    def test_fresh_native_pr_run_on_advanced_base_recovers_qualification(self):
        head = "c" * 40
        contract = aq.load_contract(ROOT)
        mandatory = [gate for gate in contract["gate"] if gate["mandatory"]]
        previous = self._run(gate=mandatory[0], head=head, run_id=100)
        current_base = "2" * 40
        current = []
        for index, gate in enumerate(mandatory):
            run = self._run(gate=gate, head=head, run_id=200 + index,
                            run_number=10 + index)
            run["pull_requests"][0]["base"]["sha"] = current_base
            run["display_title"] = gate["workflow_name"] + " :: PR9 :: " + "f" * 40
            current.append(run)
        pr = {"head": {"sha": head}, "changed_files": 1, "base": {
            "ref": "main", "sha": current_base, "repo": {"id": 1350812666},
        }}
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(aq, "_reviewed_test_merge", return_value="f" * 40),
            mock.patch.object(aq, "_pr_changed_paths", return_value=["docs/README.md"]),
            mock.patch.object(aq, "_head_runs", return_value=[previous, *current]),
            mock.patch.object(aq, "_verify_required_jobs", return_value="all-success") as verify,
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=head, token="token"
            )
        self.assertEqual(result["state"], "success")
        self.assertEqual(result["failures"], [])
        self.assertEqual(verify.call_count, 3)

    def test_dispatch_or_foreign_pr_never_counts_as_refresh_required(self):
        head = "c" * 40
        gate = next(
            gate for gate in aq.load_contract(ROOT)["gate"]
            if gate["id"] == "canonical-ci"
        )
        old = self._run(gate=gate, head=head)
        candidates = [
            {**old, "event": "workflow_dispatch"},
            {**old, "head_sha": "e" * 40},
            {**old, "display_title": gate["workflow_name"] + " :: PR10 :: " + "e" * 40},
            {**old, "path": ".github/workflows/not-ci.yml"},
        ]
        for payload in candidates:
            with self.subTest(payload=payload):
                self.assertFalse(aq._has_stale_pr_base_run(
                    [payload], gate=gate, head_sha=head,
                    pr_number=9, pr_base=("main", "2" * 40, 1350812666), merge_sha="f" * 40,
                ))
        self.assertTrue(aq._has_stale_pr_base_run(
            [old], gate=gate, head_sha=head, pr_number=9,
            pr_base=("main", "2" * 40, 1350812666), merge_sha="f" * 40,
        ))

    def test_immutable_event_title_survives_mutable_pr_association_loss(self):
        head = "a" * 40
        gate = next(
            item for item in aq.load_contract(ROOT)["gate"]
            if item["id"] == "canonical-ci"
        )
        run = self._run(gate=gate, head=head)
        run.update({
            "pull_requests": [],
            "head_branch": "feature",
            "head_repository": {"id": 1234},
        })
        pr = {"head": {"sha": head, "ref": "feature", "repo": {"id": 1234}},
              "changed_files": 1,
              "base": {"ref": "main", "sha": "1" * 40,
                       "repo": {"id": 1350812666}}}
        shared = [
            {"state": "open", "number": 9, "head": {"sha": head}},
            {"state": "open", "number": 10, "head": {"sha": head}},
        ]
        with (
            mock.patch.object(aq, "_api_json", return_value=pr),
            mock.patch.object(
                aq, "_pr_changed_paths", return_value=["docs/README.md"]
            ),
            mock.patch.object(aq, "_head_runs", return_value=[run]),
            mock.patch.object(aq, "_verify_required_jobs", return_value="all-success"),
            mock.patch.object(aq, "_paged", return_value=shared),
        ):
            result = aq.evaluate_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=head, token="token"
            )
        self.assertEqual(result["state"], "pending")
        self.assertEqual([g["gate_id"] for g in result["accepted"]], ["canonical-ci"])
        self.assertNotIn("canonical-ci: absent", result["waiting"])

    def test_in_progress_rerun_supersedes_prior_success(self):
        contract = aq.load_contract(ROOT)
        gate = next(
            item
            for item in contract["gate"]
            if item["id"] == "v07-library"
        )
        head = "6" * 40
        completed = self._run(
            gate=gate,
            head=head,
            status="completed",
            conclusion="success",
            run_number=8,
            attempt=1,
            run_id=80,
        )
        rerun = self._run(
            gate=gate,
            head=head,
            status="in_progress",
            conclusion=None,
            run_number=8,
            attempt=2,
            run_id=81,
        )
        selected = aq._newest_matching_run(
            [completed, rerun],
            gate=gate,
            head_sha=head,
            pr_number=9,
        pr_base=self._base(), merge_sha="e" * 40,
        )
        self.assertEqual(selected["id"], 81)
        self.assertEqual(selected["status"], "in_progress")

    def test_newest_matching_run_wins_over_old_success(self):
        contract = aq.load_contract(ROOT)
        gate = next(
            item
            for item in contract["gate"]
            if item["id"] == "v07-library"
        )
        head = "c" * 40
        old = self._run(
            gate=gate,
            head=head,
            conclusion="success",
            run_number=4,
            run_id=1,
        )
        newer = self._run(
            gate=gate,
            head=head,
            conclusion="failure",
            run_number=5,
            run_id=2,
        )
        selected = aq._newest_matching_run(
            [old, newer], gate=gate, head_sha=head, pr_number=9,
        pr_base=self._base(), merge_sha="e" * 40,
        )
        self.assertEqual(selected["id"], 2)
        self.assertEqual(selected["conclusion"], "failure")

    def test_direct_reconcile_entrypoint_uses_headwide_invalidation(self):
        head = "f" * 40
        result = {"state": "pending", "head_sha": head}
        with (
            mock.patch.object(aq, "reconcile_head", return_value=result) as reconcile,
            mock.patch.object(aq, "_api_json") as fetch_pr,
        ):
            actual = aq.reconcile_pr(
                root=ROOT, repository="linura-org/linura",
                pr_number=9, head_sha=head, token="token"
            )
        self.assertEqual(actual, result)
        self.assertEqual(reconcile.call_args.kwargs["head_sha"], head)
        fetch_pr.assert_not_called()

    def test_direct_reconcile_refuses_invalid_pr_number(self):
        with mock.patch.object(aq, "reconcile_head") as reconcile:
            with self.assertRaisesRegex(aq.QualificationError, "invalid PR number"):
                aq.reconcile_pr(
                    root=ROOT, repository="linura-org/linura",
                    pr_number=0, head_sha="f" * 40, token="token"
                )
            reconcile.assert_not_called()

    def test_shared_head_requires_all_prs_and_never_mints_independent_pass(self):
        head = "8" * 40
        identities = {9: self._identity(1), 10: self._identity(2)}
        def inspect(**kwargs):
            number = kwargs["pr_number"]
            return {
                "pr_number": number,
                "state": "success" if number == 9 else "pending",
                "required_gate_ids": ["canonical-ci"],
                "waiting": [] if number == 9 else ["canonical-ci: in_progress"],
                "failures": [],
            }
        writes = []
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs", return_value=identities),
            mock.patch.object(aq, "evaluate_pr", side_effect=inspect) as evaluate,
            mock.patch.object(aq, "_post_json",
                side_effect=lambda url, token, status: writes.append((url, status))),
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura",
                head_sha=head, token="token"
            )
        self.assertEqual(evaluate.call_count, 2)
        self.assertEqual(result["state"], "pending")
        self.assertEqual(len(writes), 2)
        self.assertTrue(all(url.endswith("/statuses/" + head) for url, _ in writes))
        self.assertNotEqual(writes[-1][1]["state"], "success")

    def test_rerun_start_between_evaluations_revokes_stale_success(self):
        head = "7" * 40
        identities = {9: self._identity(1)}
        observations = iter(("success", "pending"))
        writes = []
        def inspect(**kwargs):
            state = next(observations)
            return {
                "pr_number": 9, "state": state,
                "required_gate_ids": ["canonical-ci"],
                "waiting": [] if state == "success" else ["canonical-ci: in_progress"],
                "failures": [],
            }
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs", return_value=identities),
            mock.patch.object(aq, "evaluate_pr", side_effect=inspect) as evaluate,
            mock.patch.object(aq, "_post_json",
                side_effect=lambda url, token, status: writes.append(status)),
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura",
                head_sha=head, token="token"
            )
        self.assertEqual(evaluate.call_count, 2)
        self.assertEqual(result["state"], "pending")
        self.assertEqual([s["state"] for s in writes], ["pending", "pending"])

    def test_shared_head_all_valid_prs_publish_one_head_success(self):
        head = "6" * 40
        identities = {9: self._identity(1), 10: self._identity(2)}
        statuses = []
        def inspect(**kwargs):
            return {
                "pr_number": kwargs["pr_number"], "state": "success",
                "required_gate_ids": ["canonical-ci"],
                "waiting": [], "failures": [],
            }
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs", return_value=identities),
            mock.patch.object(aq, "evaluate_pr", side_effect=inspect) as evaluate,
            mock.patch.object(aq, "_post_json",
                side_effect=lambda url, token, status: statuses.append((url, status))),
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura",
                head_sha=head, token="token"
            )
        self.assertEqual(evaluate.call_count, 4)
        self.assertEqual(result["state"], "success")
        self.assertEqual([s["state"] for _, s in statuses], ["pending", "success"])
        self.assertTrue(all(url.endswith("/statuses/" + head) for url, _ in statuses))

    def test_base_change_during_aggregation_cannot_publish_success(self):
        head = "5" * 40
        original = {9: self._identity(1)}
        changed = {9: ("other", "9" * 40, 1350812666,
                       "feature", 1350812666, "1" * 40)}
        statuses = []
        def inspect(**kwargs):
            return {
                "pr_number": 9, "state": "success", "waiting": [],
                "failures": [], "required_gate_ids": ["canonical-ci"],
            }
        with (
            mock.patch.object(aq, "load_contract", return_value={
                "repository": "linura-org/linura",
                "branch_required_check": "applicable-qualification",
            }),
            mock.patch.object(aq, "_open_head_prs",
                side_effect=[original, changed]) as resolve,
            mock.patch.object(aq, "evaluate_pr", side_effect=inspect),
            mock.patch.object(aq, "_post_json",
                side_effect=lambda url, token, status: statuses.append(status)),
        ):
            result = aq.reconcile_head(
                root=ROOT, repository="linura-org/linura",
                head_sha=head, token="token"
            )
        self.assertEqual(resolve.call_count, 2)
        self.assertEqual(result["state"], "ignored-stale-pr-identity")
        self.assertEqual([s["state"] for s in statuses], ["pending"])

    def test_terminal_non_success_conclusions_fail_closed(self):
        head = "d" * 40
        contract = aq.load_contract(ROOT)
        mandatory = [
            gate for gate in contract["gate"] if gate["mandatory"]
        ]
        changed = ["docs/README.md"]
        required_ids = aq.required_gate_ids(contract, changed)
        self.assertEqual(
            required_ids, [gate["id"] for gate in mandatory]
        )

        pr_payload = {"head": {"sha": head}, "changed_files": 1,
                      "base": {"ref": "main", "sha": "1" * 40,
                               "repo": {"id": 1350812666}}}
        files_payload = [
            {"filename": changed[0], "status": "modified"}
        ]

        for conclusion in (
            "failure",
            "cancelled",
            "skipped",
            "timed_out",
            "action_required",
        ):
            with self.subTest(conclusion=conclusion):
                runs = [
                    self._run(
                        gate=gate,
                        head=head,
                        conclusion=(
                            conclusion if index == 0 else "success"
                        ),
                        run_number=10 + index,
                        run_id=1000 + index,
                    )
                    for index, gate in enumerate(mandatory)
                ]

                def fake_api(url, token):
                    if "/pulls/9" in url and "/files" not in url:
                        return pr_payload
                    raise AssertionError(url)

                def fake_paged(
                    url, token, collection_key=None
                ):
                    if "/pulls/9/files" in url:
                        return files_payload
                    if "/actions/runs?" in url:
                        return runs
                    if "/jobs?" in url:
                        run_id = int(
                            url.split("/actions/runs/", 1)[1]
                            .split("/", 1)[0]
                        )
                        matching_run = next(
                            run for run in runs if run["id"] == run_id
                        )
                        gate = next(
                            item
                            for item in mandatory
                            if item["workflow"]
                            == matching_run["path"]
                        )
                        return [
                            {
                                "name": gate["required_jobs"][0],
                                "status": "completed",
                                "conclusion": "success",
                            }
                        ]
                    raise AssertionError(url)

                with (
                    mock.patch.object(
                        aq,
                        "validate_repository",
                        return_value={"ready": True},
                    ),
                    mock.patch.object(
                        aq, "_api_json", side_effect=fake_api
                    ),
                    mock.patch.object(
                        aq, "_paged", side_effect=fake_paged
                    ),
                ):
                    with self.assertRaisesRegex(
                        aq.QualificationError,
                        f"concluded {conclusion}",
                    ):
                        aq.verify_pr(
                            root=ROOT,
                            repository="linura-org/linura",
                            pr_number=9,
                            head_sha=head,
                            token="token",
                            timeout_seconds=0,
                            poll_seconds=0,
                        )


    @staticmethod
    def _app_decision_result(pr, head, state="success", accepted=None):
        required = ["canonical-ci", "security-rustsec", "codeql"]
        if accepted is None:
            accepted = required if state == "success" else required[:1]
        return {
            "schema_version": 1, "repository": "linura-org/linura",
            "pr_number": pr, "head_sha": head, "state": state,
            "required_gate_ids": required,
            "accepted": [{"gate_id": name} for name in accepted],
        }

    def test_independent_app_decision_is_read_only_complete_and_pr_specific(self):
        head = "a" * 40
        identities = {9: self._identity(1), 10: self._identity(2)}
        source = {
            number: self._app_decision_result(number, head)
            for number in identities
        }
        contract = {
            "repository": "linura-org/linura",
            "mandatory_gate_ids": ["canonical-ci", "security-rustsec", "codeql"],
        }
        with (
            mock.patch.object(aq, "load_contract", return_value=contract),
            mock.patch.object(aq, "validate_repository") as validate,
            mock.patch.object(aq, "_open_head_prs", return_value=identities) as listing,
            mock.patch.object(aq, "_head_runs", return_value=[]) as runs,
            mock.patch.object(aq, "evaluate_pr",
                              side_effect=lambda **kw: source[kw["pr_number"]]) as evaluate,
            mock.patch.object(aq, "_post_json") as status_write,
        ):
            receipt = aq.decision_head(
                root=ROOT, repository="linura-org/linura",
                head_sha=head, token="read-only-token",
            )
        self.assertEqual(receipt["state"], "success")
        self.assertEqual([p["number"] for p in receipt["prs"]], [9, 10])
        self.assertTrue(all(p["head_sha"] == head and p["base_ref"] == "main"
                            and p["accepted_gate_ids"] == p["required_gate_ids"]
                            for p in receipt["prs"]))
        self.assertEqual(evaluate.call_count, 4)  # Two independent successful reads.
        self.assertEqual(listing.call_count, 2)
        self.assertEqual(runs.call_count, 2)
        runs.assert_has_calls([
            mock.call("linura-org/linura", head, "read-only-token"),
            mock.call("linura-org/linura", head, "read-only-token"),
        ])
        validate.assert_called_once()
        status_write.assert_not_called()

    def test_independent_app_decision_never_promotes_pending_or_failure(self):
        head = "a" * 40
        identities = {9: self._identity(1), 10: self._identity(2)}
        contract = {
            "repository": "linura-org/linura",
            "mandatory_gate_ids": ["canonical-ci", "security-rustsec", "codeql"],
        }
        for second_state, expected in (("pending", "pending"), ("failure", "failure")):
            with self.subTest(state=second_state):
                def inspect(**kwargs):
                    number = kwargs["pr_number"]
                    return self._app_decision_result(
                        number, head, second_state if number == 10 else "success")
                with (
                    mock.patch.object(aq, "load_contract", return_value=contract),
                    mock.patch.object(aq, "validate_repository"),
                    mock.patch.object(aq, "_open_head_prs", return_value=identities),
                    mock.patch.object(aq, "_head_runs", return_value=[]) as runs,
                    mock.patch.object(aq, "evaluate_pr", side_effect=inspect) as evaluate,
                    mock.patch.object(aq, "_post_json") as write,
                ):
                    receipt = aq.decision_head(
                        root=ROOT, repository="linura-org/linura",
                        head_sha=head, token="read-only-token",
                    )
                self.assertEqual(receipt["state"], expected)
                self.assertEqual(evaluate.call_count, 2)
                runs.assert_called_once_with(
                    "linura-org/linura", head, "read-only-token")
                self.assertEqual(len(receipt["prs"]), 2)
                write.assert_not_called()

    def test_independent_app_decision_rejects_changed_identity_and_overcapacity(self):
        head = "b" * 40
        contract = {
            "repository": "linura-org/linura",
            "mandatory_gate_ids": ["canonical-ci", "security-rustsec", "codeql"],
        }
        original = {9: self._identity(1)}
        updated = {9: ("main", "f" * 40, 1350812666,
                       "feature", 1350812666, "1" * 40)}
        with (
            mock.patch.object(aq, "load_contract", return_value=contract),
            mock.patch.object(aq, "validate_repository"),
            mock.patch.object(aq, "_open_head_prs",
                              side_effect=[original, updated]),
            mock.patch.object(aq, "_head_runs", return_value=[]) as runs,
            mock.patch.object(aq, "evaluate_pr",
                              return_value=self._app_decision_result(9, head)),
            mock.patch.object(aq, "_post_json") as write,
        ):
            with self.assertRaisesRegex(aq.QualificationError, "identity changed"):
                aq.decision_head(
                    root=ROOT, repository="linura-org/linura",
                    head_sha=head, token="read-only-token")
            write.assert_not_called()
            self.assertEqual(runs.call_count, 2)
            runs.assert_has_calls([
                mock.call("linura-org/linura", head, "read-only-token"),
                mock.call("linura-org/linura", head, "read-only-token"),
            ])
        for identities, reason in (
            ({}, "no open main-targeting"),
            ({i: self._identity(1) for i in range(1, 10)}, "exceeds eight"),
        ):
            with (
                self.subTest(reason=reason),
                mock.patch.object(aq, "load_contract", return_value=contract),
                mock.patch.object(aq, "validate_repository"),
                mock.patch.object(aq, "_open_head_prs", return_value=identities),
                mock.patch.object(aq, "_head_runs") as runs,
                mock.patch.object(aq, "evaluate_pr") as evaluate,
            ):
                with self.assertRaisesRegex(aq.QualificationError, reason):
                    aq.decision_head(
                        root=ROOT, repository="linura-org/linura",
                        head_sha=head, token="read-only-token")
                evaluate.assert_not_called()
                runs.assert_not_called()

    def test_independent_app_decision_rejects_malformed_and_incomplete_receipts(self):
        head = "c" * 40
        contract = {
            "repository": "linura-org/linura",
            "mandatory_gate_ids": ["canonical-ci", "security-rustsec", "codeql"],
        }
        valid = self._app_decision_result(9, head)
        malformed = [
            {**valid, "repository": "attacker/repo"},
            {**valid, "head_sha": "d" * 40},
            {**valid, "pr_number": 10},
            {**valid, "required_gate_ids": ["canonical-ci"]},
            {**valid, "accepted": [{"gate_id": "canonical-ci"}]},
            {**valid, "accepted": valid["accepted"] + valid["accepted"][:1]},
            {**valid, "accepted": valid["accepted"] + [{"gate_id": "forged"}]},
        ]
        for payload in malformed:
            with (
                self.subTest(payload=payload),
                mock.patch.object(aq, "load_contract", return_value=contract),
                mock.patch.object(aq, "validate_repository"),
                mock.patch.object(aq, "_open_head_prs",
                                  return_value={9: self._identity(1)}),
                mock.patch.object(aq, "_head_runs", return_value=[]) as runs,
                mock.patch.object(aq, "evaluate_pr",
                                  return_value=payload) as evaluate,
                mock.patch.object(aq, "_post_json") as write,
            ):
                with self.assertRaisesRegex(
                    aq.QualificationError,
                    "malformed per-PR independent decision"
                    "|invalid independent gate receipt"
                    "|incomplete or ambiguous accepted gate receipt",
                ):
                    aq.decision_head(
                        root=ROOT, repository="linura-org/linura",
                        head_sha=head, token="read-only-token")
                self.assertEqual(runs.call_count, 2)
                self.assertEqual(evaluate.call_count, 2)
                runs.assert_has_calls([
                    mock.call("linura-org/linura", head, "read-only-token"),
                    mock.call("linura-org/linura", head, "read-only-token"),
                ])
                write.assert_not_called()


    def test_independent_app_decision_rejects_github_read_outage(self):
        head = "a" * 40
        contract = {
            "repository": "linura-org/linura",
            "mandatory_gate_ids": ["canonical-ci", "security-rustsec", "codeql"],
        }
        with (
            mock.patch.object(aq, "load_contract", return_value=contract),
            mock.patch.object(aq, "validate_repository"),
            mock.patch.object(aq, "_open_head_prs",
                              return_value={9: self._identity(1)}),
            mock.patch.object(
                aq, "_head_runs",
                side_effect=aq.QualificationError("GitHub read unavailable"),
            ) as runs,
            mock.patch.object(aq, "evaluate_pr") as evaluate,
            mock.patch.object(aq, "_post_json") as writer,
        ):
            with self.assertRaisesRegex(
                aq.QualificationError, "GitHub read unavailable",
            ):
                aq.decision_head(
                    root=ROOT, repository="linura-org/linura",
                    head_sha=head, token="read-only-token",
                )
            runs.assert_called_once_with(
                "linura-org/linura", head, "read-only-token")
            evaluate.assert_not_called()
            writer.assert_not_called()

    def test_independent_app_cli_emits_only_versioned_receipt(self):
        import io
        head = "e" * 40
        receipt = {
            "schema_version": 1, "repository": "linura-org/linura",
            "head_sha": head, "state": "pending", "prs": [],
        }
        with (
            mock.patch.object(sys, "argv", [
                "applicable_qualification.py", "decision-head",
                "--repository", "linura-org/linura", "--head-sha", head,
                "--token-env", "LINURA_READ_TEST_TOKEN",
            ]),
            mock.patch.dict(aq.os.environ, {"LINURA_READ_TEST_TOKEN": "token"}),
            mock.patch.object(aq, "decision_head", return_value=receipt) as decision,
            mock.patch.object(sys, "stdout", new_callable=io.StringIO) as out,
        ):
            self.assertEqual(aq.main(), 0)
        self.assertEqual(__import__("json").loads(out.getvalue()), receipt)
        decision.assert_called_once()

    def test_publisher_service_source_is_protected_gate_authority(self):
        contract = aq.load_contract(ROOT)
        changed = [
            "services/qualification-publisher/publisher.mjs",
            "services/qualification-publisher/server.mjs",
            "services/qualification-publisher/test/new-bypass.test.mjs",
        ]
        detected = aq._untrusted_gate_definition_edits(contract, changed, root=ROOT)
        self.assertEqual(detected, changed)




class ImmutableRunBaseProofTests(unittest.TestCase):
    """Exercise immutable event SHA independently from legacy routing mocks."""

    @staticmethod
    def _source_pr():
        return {
            "state": "open", "merge_commit_sha": "c" * 40,
            "head": {"sha": "a" * 40},
            "base": {"ref": "main", "sha": "b" * 40,
                     "repo": {"id": 1350812666}},
        }

    @staticmethod
    def _merge_response(base="b", head="a"):
        return {
            "sha": "c" * 40,
            "parents": [{"sha": base * 40}, {"sha": head * 40}],
        }

    def test_pr_event_merge_sha_immutably_binds_exact_base_and_head(self):
        pr = self._source_pr()
        with mock.patch.object(aq, "_api_json",
                               return_value=self._merge_response()) as api:
            sha = aq._reviewed_test_merge(
                "linura-org/linura", pr, "a" * 40, "read-only")
        self.assertEqual(sha, "c" * 40)
        self.assertIn("/commits/" + "c" * 40, api.call_args.args[0])
        for payload in (
            self._merge_response(base="d"),
            self._merge_response(head="e"),
            {"sha": "c" * 40, "parents": [{"sha": "b" * 40}]},
            {"sha": "d" * 40, "parents": [{"sha": "b" * 40},
                                         {"sha": "a" * 40}]},
        ):
            with self.subTest(payload=payload):
                with mock.patch.object(aq, "_api_json", return_value=payload):
                    with self.assertRaisesRegex(
                        aq.QualificationError, "synthetic merge parents"
                    ):
                        aq._reviewed_test_merge(
                            "linura-org/linura", pr, "a" * 40, "read-only")

    def test_unknown_merge_identity_fails_closed_even_with_native_success(self):
        pr = self._source_pr()
        for field in ("merge_commit_sha", "base"):
            mutant = dict(pr)
            if field == "merge_commit_sha":
                mutant.pop(field)
                message = "synthetic test-merge"
            else:
                mutant["base"] = {"ref": "feature", "sha": "b" * 40,
                                  "repo": {"id": 1350812666}}
                message = "protected main"
            with self.subTest(field=field):
                with self.assertRaisesRegex(aq.QualificationError, message):
                    aq._reviewed_test_merge(
                        "linura-org/linura", mutant, "a" * 40, "read-only")

    def test_mutable_pr_association_cannot_reauthorize_old_base_run(self):
        gate = next(g for g in aq.load_contract(ROOT)["gate"]
                    if g["id"] == "canonical-ci")
        run = {
            "path": gate["workflow"], "event": "pull_request",
            "head_sha": "a" * 40,
            "display_title": gate["workflow_name"] + " :: PR9 :: " + "c" * 40,
            "pull_requests": [{"number": 9, "head": {"sha": "z" * 40},
                               "base": {"ref": "main", "sha": "f" * 40}}],
        }
        expected = {
            "gate": gate, "head_sha": "a" * 40, "pr_number": 9,
            "pr_base": ("main", "b" * 40, 1350812666),
        }
        self.assertTrue(aq._run_matches(run, **expected, merge_sha="c" * 40))
        self.assertFalse(aq._run_matches(run, **expected, merge_sha="d" * 40))
        self.assertFalse(aq._run_matches(run, **expected))
        self.assertTrue(aq._has_stale_pr_base_run(
            [run], **expected, merge_sha="d" * 40))
        for alternate in (
            {"display_title": gate["workflow_name"] + " :: PR9 :: forged"},
            {"event": "workflow_dispatch"},
            {"head_sha": "d" * 40},
            {"display_title": gate["workflow_name"] + " :: PR10 :: " + "c" * 40},
        ):
            with self.subTest(alternate=alternate):
                self.assertFalse(aq._run_matches(
                    {**run, **alternate}, **expected, merge_sha="c" * 40))

    def test_merged_ledger_uses_actual_pre_merge_main_parent(self):
        contract = aq.load_contract(ROOT)
        head, base, synthetic, merged = "a" * 40, "b" * 40, "c" * 40, "d" * 40
        approval = {"head": {"sha": head}, "merge_commit_sha": merged}
        runs = [
            {
                "id": i+1, "run_number": i+1, "run_attempt": 1,
                "event": "pull_request", "head_sha": head,
                "path": gate["workflow"], "status": "completed",
                "conclusion": "success",
                "display_title": gate["workflow_name"] + " :: PR100 :: " + synthetic,
                "pull_requests": [{"number": 100}],
            }
            for i, gate in enumerate(contract["gate"][:3])
        ]
        def fetched(url, token):
            if url.endswith("/commits/" + merged):
                return {"sha": merged, "parents": [{"sha": base}]}
            if url.endswith("/commits/" + synthetic):
                return {"sha": synthetic, "parents": [
                    {"sha": base}, {"sha": head}]}
            raise AssertionError(url)
        with (
            mock.patch.object(aq, "_api_json", side_effect=fetched),
            mock.patch.object(aq, "_head_runs", return_value=runs),
            mock.patch.object(aq, "_verify_required_jobs", return_value="all-success") as jobs,
        ):
            self.assertTrue(aq._verify_ledger_native_checks(
                root=ROOT, contract=contract, repository="linura-org/linura",
                approval_pr=100, approval=approval, token="read-only"))
        self.assertEqual(jobs.call_count, 3)
        def stale(url, token):
            payload = fetched(url, token)
            if url.endswith("/commits/" + synthetic):
                payload["parents"][0]["sha"] = "e" * 40
            return payload
        with (
            mock.patch.object(aq, "_api_json", side_effect=stale),
            mock.patch.object(aq, "_head_runs", return_value=runs),
            mock.patch.object(aq, "_verify_required_jobs") as jobs,
        ):
            self.assertFalse(aq._verify_ledger_native_checks(
                root=ROOT, contract=contract, repository="linura-org/linura",
                approval_pr=100, approval=approval, token="read-only"))
            jobs.assert_not_called()

    def test_pr_file_cache_is_scoped_to_each_independent_snapshot(self):
        entries = [{"filename": "docs/README.md", "status": "modified"}]
        with mock.patch.object(aq, "_paged", return_value=entries) as paged:
            token = aq._PR_FILE_BATCH.set({})
            try:
                self.assertEqual(aq._pr_changed_paths(
                    "linura-org/linura", 9, "read-only"), ["docs/README.md"])
                self.assertEqual(aq._pr_changed_paths(
                    "linura-org/linura", 9, "read-only",
                    include_rename_sources=True), ["docs/README.md"])
                self.assertEqual(paged.call_count, 1)
            finally:
                aq._PR_FILE_BATCH.reset(token)
            token = aq._PR_FILE_BATCH.set({})
            try:
                aq._pr_changed_paths("linura-org/linura", 9, "read-only")
            finally:
                aq._PR_FILE_BATCH.reset(token)
            self.assertEqual(paged.call_count, 2)

    def test_required_job_cache_is_snapshot_scoped_and_attempt_bound(self):
        gate = next(g for g in aq.load_contract(ROOT)["gate"]
                    if g["id"] == "canonical-ci")
        jobs = [{"name": "canonical-check", "status": "completed",
                 "conclusion": "success"}]
        run = {"id": 999, "run_attempt": 1}
        with mock.patch.object(aq, "_paged", return_value=jobs) as paged:
            batch = aq._RUN_JOBS_BATCH.set({})
            try:
                for _ in range(2):
                    self.assertEqual(aq._verify_required_jobs(
                        "linura-org/linura", gate, run, "read-only",
                        root=ROOT, changed_paths=["docs/README.md"]),
                        "all-success")
                self.assertEqual(paged.call_count, 1)
                aq._verify_required_jobs(
                    "linura-org/linura", gate,
                    {"id": 999, "run_attempt": 2}, "read-only",
                    root=ROOT, changed_paths=["docs/README.md"])
                self.assertEqual(paged.call_count, 2)
            finally:
                aq._RUN_JOBS_BATCH.reset(batch)
            batch = aq._RUN_JOBS_BATCH.set({})
            try:
                aq._verify_required_jobs(
                    "linura-org/linura", gate, run, "read-only",
                    root=ROOT, changed_paths=["docs/README.md"])
            finally:
                aq._RUN_JOBS_BATCH.reset(batch)
            self.assertEqual(paged.call_count, 3)

    def test_read_only_api_budget_denies_before_120_second_hard_timeout(self):
        token = aq._READ_DEADLINE.set(aq.time.monotonic() - 2.0)
        try:
            with mock.patch.object(aq, "urlopen") as network:
                with self.assertRaisesRegex(aq.QualificationError,
                                             "115-second API budget"):
                    aq._api_json(
                        "https://api.github.com/repos/linura-org/linura/pulls/9",
                        "read-only")
                network.assert_not_called()
        finally:
            aq._READ_DEADLINE.reset(token)

    def test_unreviewed_workflow_run_name_cannot_override_provenance(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        actual = next(line for line in source.splitlines()
                      if line.startswith("run-name:"))
        mutants = [
            source.replace(actual, "run-name: 'forged'", 1),
            source.replace(actual, "# " + actual + "\nrun-name: 'forged'", 1),
        ]
        original_read = aq._read
        for mutant in mutants:
            with self.subTest(mutant=mutant[:70]):
                def fake_read(root, path):
                    return mutant if str(path) == ".github/workflows/ci.yml" else original_read(root, path)
                with mock.patch.object(aq, "_read", side_effect=fake_read):
                    with self.assertRaisesRegex(
                        aq.QualificationError, "merge-SHA run-name drift"):
                        aq.validate_repository(ROOT)

    def test_shared_head_evaluates_on_two_fresh_bounded_run_snapshots(self):
        head = "a" * 40
        base = "b" * 40
        identities = {
            n: ("main", base, 1350812666, "feature",
                1350812666, f"{n:040x}") for n in range(1, 9)
        }
        required = ["canonical-ci", "security-rustsec", "codeql"]
        contract = {"repository": "linura-org/linura",
                    "mandatory_gate_ids": required}
        def evaluate(**kwargs):
            return {
                "schema_version": 1, "repository": "linura-org/linura",
                "pr_number": kwargs["pr_number"], "head_sha": head,
                "state": "success", "required_gate_ids": required,
                "accepted": [{"gate_id": g} for g in required],
            }
        with (
            mock.patch.object(aq, "load_contract", return_value=contract),
            mock.patch.object(aq, "validate_repository") as validate,
            mock.patch.object(aq, "_open_head_prs", return_value=identities),
            mock.patch.object(aq, "_head_runs", return_value=[]) as runs,
            mock.patch.object(aq, "evaluate_pr", side_effect=evaluate) as evaluator,
            mock.patch.object(aq, "_post_json") as writer,
        ):
            result = aq.decision_head(
                root=ROOT, repository="linura-org/linura", head_sha=head,
                token="read-only")
        self.assertEqual(result["state"], "success")
        self.assertEqual(len(result["prs"]), 8)
        self.assertEqual(runs.call_count, 2)
        self.assertEqual(evaluator.call_count, 16)
        validate.assert_called_once()
        writer.assert_not_called()
        self.assertTrue(all("validated_contract" in call.kwargs and
                            "head_runs_snapshot" in call.kwargs
                            for call in evaluator.call_args_list))



if __name__ == "__main__":
    unittest.main()
