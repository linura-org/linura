from __future__ import annotations

from pathlib import Path
import shutil
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import check_validation_gates as gates  # noqa: E402


class ValidationGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        paths = set(gates.MANDATORY.values())
        paths.update(("tools/xtask/src/main.rs", "tools/codex/versions.env",
                      ".github/workflows/trusted-release-proof.yml"))
        for workflow, critical in gates.SPECIALIZED.values():
            paths.add(workflow)
            paths.update(critical)
        for path in paths:
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, dest)

    def change(self, path, before, after):
        file = self.root / path
        source = file.read_text()
        self.assertIn(before, source)
        file.write_text(source.replace(before, after, 1))

    def test_checked_in_contract(self):
        self.assertEqual(gates.check(ROOT), [])

    def test_fixture_contract(self):
        self.assertEqual(gates.check(self.root), [])

    def test_quoted_control_keys_cannot_disable_required_jobs(self):
        for job, workflow in (*gates.MANDATORY.items(),
                              ("fresh-environment", gates.SPECIALIZED["codex"][0])):
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            marker = "  " + job + ":\n"
            self.assertIn(marker, original)
            for directive in ('"if": false', "'if': false",
                              '"continue-on-error": true',
                              "'needs': impossible-prerequisite"):
                with self.subTest(job=job, directive=directive):
                    target.write_text(original.replace(
                        marker, marker + "    " + directive + "\n", 1
                    ), encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        ("mandatory job must be unconditional" if job in gates.MANDATORY
                         else "required qualification job cannot be skipped"
                              if "needs" not in directive else
                              "required qualification job has unapproved dependencies")
                        in error for error in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_encoded_job_controls_cannot_skip_native_or_codex_gates(self):
        jobs = [*gates.MANDATORY.items(),
                ("fresh-environment", gates.SPECIALIZED["codex"][0])]
        for job, workflow in jobs:
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            marker = "  " + job + ":\n"
            self.assertIn(marker, original)
            for key in ('"\\u0069f"', '"\\x69f"', '"\\U00000069f"',
                        '"\\u0063ontinue-on-error"'):
                with self.subTest(job=job, key=key):
                    value = ("true" if "ontinue" in key else "false")
                    target.write_text(original.replace(
                        marker, marker + "    " + key + ": " + value + "\n", 1
                    ), encoding="utf-8")
                    errors = gates.check(self.root)
                    if "\\x" in key or "\\U" in key:
                        self.assertTrue(any("unsafe workflow mapping syntax" in e
                                            for e in errors), errors)
                    else:
                        expected = ("mandatory job must be unconditional"
                                    if job in gates.MANDATORY
                                    else "required qualification job cannot be skipped")
                        self.assertTrue(any(expected in e for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_unicode_escaped_step_condition_cannot_skip_canonical_checks(self):
        self.change(".github/workflows/ci.yml",
                    "      - name: Run canonical Linura checks\n",
                    '      - name: Run canonical Linura checks\n'
                    '        "\\u0069f": false\n')
        errors = gates.check(self.root)
        self.assertTrue(any("missing unconditional executable step: "
                            "Run canonical Linura checks" in e for e in errors), errors)

    def test_unicode_escaped_dependencies_and_event_filters_are_audited(self):
        workflow = ".github/workflows/ci.yml"
        target = self.root / workflow
        original = target.read_text(encoding="utf-8")
        cases = (
            ("  canonical-check:\n",
             '  canonical-check:\n    "\\u006eeeds": missing-job\n',
             "mandatory job must be unconditional"),
            ("permissions:\n",
             '"\\u0064efaults": {run: {shell: "bash -c \'exit 0\' {0}"}}\n'
             "permissions:\n",
             "run defaults may bypass mandatory"),
            ("  pull_request:\n",
             '  pull_request:\n    "\\u0062ranches": [never]\n',
             "must run on every PR"),
        )
        for before, after, expected in cases:
            with self.subTest(control=expected):
                self.assertIn(before, original)
                target.write_text(original.replace(before, after, 1),
                                  encoding="utf-8")
                self.assertTrue(any(expected in e for e in gates.check(self.root)),
                                gates.check(self.root))
        target.write_text(original, encoding="utf-8")

    def test_encoded_quoted_mapping_and_yaml_merges_fail_closed(self):
        path = ".github/workflows/codex-environment.yml"
        target = self.root / path
        original = target.read_text(encoding="utf-8")
        cases = (
            ('  fresh-environment:\n',
             '  fresh-environment:\n    "\\x69f": false\n'),
            ('  fresh-environment:\n',
             '  fresh-environment:\n    <<: *inherited-skip\n'),
            ('  fresh-environment:\n',
             '  fresh-environment:\n    &gate if: false\n'),
            ('  fresh-environment:\n',
             '  fresh-environment:\n    *gate: false\n'),
            ('  fresh-environment:\n',
             '  fresh-environment:\n    !!str if: false\n'),
            ('  fresh-environment:\n',
             '  fresh-environment:\n    ? "\\u0069f"\n    : false\n'),
        )
        for before, after in cases:
            with self.subTest(injected=after):
                self.assertIn(before, original)
                target.write_text(original.replace(before, after, 1),
                                  encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any("unsafe workflow mapping syntax" in e
                                    for e in errors), errors)
        target.write_text(original, encoding="utf-8")

    def test_encoded_uses_key_cannot_replace_triggering_checkout(self):
        path = ".github/workflows/codex-environment.yml"
        target = self.root / path
        original = target.read_text(encoding="utf-8")
        marker = "      - name: Prepare isolated environment\n"
        self.assertIn(marker, original)
        injected = ('      - "\\u0075ses": actions/checkout@main\n'
                    + marker)
        target.write_text(original.replace(marker, injected, 1),
                          encoding="utf-8")
        # An escaped key is valid YAML. It must decode to a real "uses" key,
        # then the exact-source guard must reject the second checkout.
        errors = gates.check(self.root)
        self.assertTrue(any(
            "codex: must checkout triggering revision without a ref override" in e
            for e in errors
        ), errors)

    def test_block_scalar_actions_cannot_hide_a_second_checkout(self):
        workflows = (*gates.MANDATORY.values(),
                     gates.SPECIALIZED["codex"][0],
                     gates.SPECIALIZED["vm"][0],
                     ".github/workflows/v010-shell-runtime-qualification.yml")
        checkout = ("      - uses: actions/checkout@"
                    "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n")
        for workflow in workflows:
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            self.assertIn(checkout, original)
            # Insert *after* the original checkout and its with: block: this
            # is valid YAML and could otherwise replace the verified source.
            start = original.index(checkout) + len(checkout)
            insertion = original.index("\n      - ", start) + 1
            for directive in ("uses: >-", "uses: |-", "uses : >2-",
                              '"uses": |+', '"\\u0075ses": >-'):
                with self.subTest(workflow=workflow, directive=directive):
                    extra = (
                        "      - " + directive + "\n"
                        "          actions/checkout@"
                        "3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                        "        with: { ref: main }\n"
                    )
                    target.write_text(original[:insertion] + extra +
                                      original[insertion:], encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any("unsafe workflow mapping syntax" in e
                                        for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_noncanonical_action_value_headers_fail_closed(self):
        for directive in ("uses: !!str >-", "uses: &checkout >-",
                          "uses: *checkout", "uses:", '"\\u0075ses": &checkout >-'):
            with self.subTest(directive=directive):
                source = (
                    "jobs:\n  probe:\n    steps:\n      - " + directive + "\n"
                    "          actions/checkout@"
                    "3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                )
                with self.assertRaisesRegex(
                        ValueError, "noncanonical action references"):
                    gates.normalize_workflow_keys(source)

    def test_workflow_literal_block_is_not_interpreted_as_yaml_mapping(self):
        source = ('jobs:\n  probe:\n    run: |\n'
                  '      "\\u0069f": false\n'
                  '      "<<": "\\x69f"\n')
        self.assertEqual(gates.normalize_workflow_keys(source), source)

    def test_spaced_yaml_controls_cannot_skip_required_jobs(self):
        required = [*gates.MANDATORY.items()]
        required.extend((required_job, workflow)
                        for name, (workflow, _) in gates.SPECIALIZED.items()
                        for required_job in gates.SPECIALIZED_REQUIRED_JOBS[name])
        for job, workflow in required:
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            marker = "  " + job + ":\n"
            self.assertIn(marker, original)
            for directive in ("if : false", "continue-on-error : true"):
                with self.subTest(job=job, directive=directive):
                    target.write_text(original.replace(
                        marker, marker + "    " + directive + "\n", 1
                    ), encoding="utf-8")
                    errors = gates.check(self.root)
                    expected = ("mandatory job must be unconditional"
                                if job in gates.MANDATORY else
                                "required qualification job cannot be skipped")
                    self.assertTrue(any(expected in e for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_spaced_yaml_step_controls_cannot_skip_canonical_checks(self):
        workflow = ".github/workflows/ci.yml"
        target = self.root / workflow
        original = target.read_text(encoding="utf-8")
        marker = "      - name: Run canonical Linura checks\n"
        self.assertIn(marker, original)
        for directive in ("if : false", "continue-on-error : true"):
            with self.subTest(directive=directive):
                target.write_text(original.replace(
                    marker, marker + "        " + directive + "\n", 1
                ), encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any(
                    "missing unconditional executable step: Run canonical Linura checks"
                    in e for e in errors), errors)
        target.write_text(original, encoding="utf-8")

    def test_spaced_checkout_and_shell_keys_cannot_bypass_guards(self):
        path = self.root / ".github/workflows/ci.yml"
        original = path.read_text(encoding="utf-8")
        checkout = ("      - uses: actions/checkout@"
                    "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n")
        self.assertIn(checkout, original)
        for replacement in (
            checkout + "      - uses : actions/checkout@main\n",
            checkout + "        with : { ref: main }\n",
        ):
            with self.subTest(checkout=replacement):
                path.write_text(original.replace(checkout, replacement, 1),
                                encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any("must checkout triggering revision" in e
                                    for e in errors), errors)
        marker = "      - name: Run canonical Linura checks\n"
        self.assertIn(marker, original)
        path.write_text(original.replace(
            marker, marker + "        shell : bash -c 'exit 0' {0}\n", 1),
            encoding="utf-8")
        errors = gates.check(self.root)
        self.assertTrue(any(
            "missing unconditional executable step: Run canonical Linura checks" in e
            for e in errors), errors)
        path.write_text(original, encoding="utf-8")

    def test_normalization_preserves_literal_shell_and_comment_text(self):
        source = ("jobs:\n  safe:\n    if   : false # comment\n"
                  "    run: |\n      if : shell text\n      uses : not an action\n"
                  "      # needs : preserved\n")
        expected = source.replace("    if   : false", "    if: false")
        self.assertEqual(gates.normalize_workflow_keys(source), expected)

    def test_weekly_security_scans_cannot_be_removed_or_silently_rescheduled(self):
        for job, workflow, cron in (
            ("dependency-audit", ".github/workflows/security.yml", "17 4 * * 1"),
            ("analyze", ".github/workflows/codeql.yml", "41 3 * * 3"),
        ):
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            marker = '  schedule:\n    - cron: "' + cron + '"\n'
            self.assertIn(marker, original)
            for replacement in ('', '  schedule:\n',
                                '  schedule:\n    - cron: "0 0 * * 0"\n'):
                with self.subTest(job=job, replacement=replacement):
                    target.write_text(original.replace(marker, replacement, 1),
                                      encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        job + ": must retain reviewed independent weekly scheduled scan"
                        in e for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_quoted_step_condition_cannot_skip_canonical_checks(self):
        self.change(".github/workflows/ci.yml",
                    "      - name: Run canonical Linura checks\n",
                    '      - name: Run canonical Linura checks\n        "if": false\n')
        self.assertTrue(any("missing unconditional executable step: Run canonical Linura checks"
                            in error for error in gates.check(self.root)))

    def test_quoted_inherited_defaults_cannot_hide_noop_shell(self):
        for job, workflow in (*gates.MANDATORY.items(),
                              ("codex", gates.SPECIALIZED["codex"][0])):
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            target.write_text(
                '"defaults": {run: {shell: "bash -c \'exit 0\' {0}"}}\n' +
                original, encoding="utf-8",
            )
            with self.subTest(job=job):
                errors = gates.check(self.root)
                self.assertTrue(any("run defaults may bypass mandatory" in e
                                    if job in gates.MANDATORY else
                                    "inherited run defaults may bypass required steps" in e
                                    for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_codex_main_push_branch_cannot_be_disabled(self):
        self.change(".github/workflows/codex-environment.yml",
                    "  push:\n    branches: [main]\n",
                    "  push:\n    branches: [never]\n")
        errors = gates.check(self.root)
        self.assertTrue(any("main-push trigger must target main" in e
                            for e in errors), errors)

    def test_codex_main_push_must_include_critical_sources(self):
        path = self.root / ".github/workflows/codex-environment.yml"
        source = path.read_text(encoding="utf-8")
        prefix, suffix = source.split("  push:\n", 1)
        push, rest = suffix.split("  workflow_dispatch:\n", 1)
        target = '      - "tools/check_validation_gates.py"\n'
        self.assertIn(target, push)
        path.write_text(prefix + "  push:\n" + push.replace(target, "", 1) +
                        "  workflow_dispatch:\n" + rest, encoding="utf-8")
        errors = gates.check(self.root)
        self.assertTrue(any("main-push routing must cover critical sources" in e
                            for e in errors), errors)

    def test_codex_required_steps_cannot_be_skipped_or_fail_open(self):
        path = ".github/workflows/codex-environment.yml"
        target = self.root / path
        original = target.read_text(encoding="utf-8")
        for label, _ in gates.CODEX_REQUIRED_STEPS:
            marker = "      - name: " + label + "\n"
            self.assertIn(marker, original)
            for directive in ("if: false", "continue-on-error: true",
                              "shell: bash -c 'exit 0' {0}"):
                with self.subTest(step=label, directive=directive):
                    target.write_text(original.replace(
                        marker, marker + "        " + directive + "\n", 1
                    ), encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        "Codex required step must execute: " + label in e for e in errors
                    ), errors)
        target.write_text(original, encoding="utf-8")

    def test_codex_inherited_shell_defaults_cannot_bypass_verification(self):
        path = self.root / ".github/workflows/codex-environment.yml"
        original = path.read_text(encoding="utf-8")
        cases = (
            ("workflow mapping", "permissions:\n",
             "defaults:\n  run:\n    shell: bash -c 'exit 0' {0}\n\npermissions:\n"),
            ("workflow inline", "permissions:\n",
             'defaults: {run: {shell: "bash -c \'exit 0\' {0}"}}\n\npermissions:\n'),
            ("job mapping", "    runs-on: ubuntu-24.04\n",
             "    defaults:\n      run:\n        shell: bash -c 'exit 0' {0}\n"
             "    runs-on: ubuntu-24.04\n"),
            ("job inline", "    runs-on: ubuntu-24.04\n",
             '    defaults: {run: {shell: "bash -c \'exit 0\' {0}"}}\n'
             "    runs-on: ubuntu-24.04\n"),
        )
        for case, before, after in cases:
            with self.subTest(case=case):
                self.assertIn(before, original)
                path.write_text(original.replace(before, after, 1), encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any(
                    "codex: inherited run defaults may bypass required steps" in e
                    for e in errors
                ), errors)
        path.write_text(original, encoding="utf-8")

    def test_codex_verification_cannot_exit_before_full_gate(self):
        self.change(".github/workflows/codex-environment.yml",
                    "          PATH=/usr/bin:/bin bash scripts/preflight_codex_environment.sh --full",
                    "          exit 0\n"
                    "          PATH=/usr/bin:/bin bash scripts/preflight_codex_environment.sh --full")
        self.assertTrue(any("Codex verification must execute the complete reviewed task-time gate"
                            in e for e in gates.check(self.root)))


    def test_codex_checkout_must_use_triggering_revision(self):
        path = self.root / ".github/workflows/codex-environment.yml"
        original = path.read_text(encoding="utf-8")
        checkout = ("      - uses: actions/checkout@"
                    "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n")
        self.assertIn(checkout, original)
        cases = (
            ("inline ref override", checkout + "        with: { ref: main }\n"),
            ("nested ref override", checkout + "        with:\n          ref: main\n"),
            ("second checkout", checkout + checkout),
            ("skipped checkout", checkout + "        if: false\n"),
            ("mutable checkout", checkout.replace(
                "3d3c42e5aac5ba805825da76410c181273ba90b1", "main")),
        )
        for scenario, replacement in cases:
            with self.subTest(scenario=scenario):
                path.write_text(original.replace(checkout, replacement, 1),
                                encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(
                    any("codex: must checkout triggering revision" in e for e in errors),
                    errors,
                )
        path.write_text(original, encoding="utf-8")

    def test_quoted_or_named_second_checkout_cannot_replace_revision(self):
        workflows = dict(gates.MANDATORY)
        workflows["codex"] = ".github/workflows/codex-environment.yml"
        sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        bare_checkout = "      - uses: actions/checkout@" + sha + " # v7.0.1\n"
        replacements = (
            ("double-quoted", '      - uses: "actions/checkout@' + sha +
             '"\n        with:\n          ref: main\n'),
            ("single-quoted", "      - uses: 'actions/checkout@" + sha +
             "'\n        with:\n          ref: main\n"),
            ("named checkout", '      - name: Replace triggering source\n'
             '        uses: "actions/checkout@' + sha +
             '"\n        with:\n          ref: main\n'),
        )
        for job, workflow in workflows.items():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            # Keep the canonical checkout's existing with: block attached
            # to the first checkout before inserting the second step.
            insertion = ("          fetch-depth: 0\n"
                         if job == "canonical-check" else bare_checkout)
            self.assertIn(insertion, original)
            for scenario, second in replacements:
                with self.subTest(job=job, scenario=scenario):
                    target.write_text(
                        original.replace(insertion, insertion + second, 1),
                        encoding="utf-8",
                    )
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        job + ": must checkout triggering revision" in e
                        for e in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_escaped_checkout_action_cannot_replace_triggering_revision(self):
        workflows = dict(gates.MANDATORY)
        workflows["codex"] = ".github/workflows/codex-environment.yml"
        workflows["vm"] = ".github/workflows/vm-acceptance.yml"
        workflows["v010"] = ".github/workflows/v010-qualification.yml"
        workflows["reusable-v010"] = ".github/workflows/v010-shell-runtime-qualification.yml"
        sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        for job, workflow in workflows.items():
            target = self.root / workflow
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / workflow, target)
            original = target.read_text(encoding="utf-8")
            checkout = "actions/checkout@" + sha
            self.assertIn(checkout, original)
            for encoded in ('"actions/check\\u006fut@' + sha + '"',
                            '"actions\\/checkout@' + sha + '"',
                            "'actions/checkout@" + sha + "'"):
                with self.subTest(job=job, action=encoded):
                    # Place the overriding checkout *after* the existing one.
                    marker = re.search(
                        r"(?m)^([ ]+)- uses: actions/checkout@" + sha +
                        r"[^\n]*\n", original)
                    self.assertIsNotNone(marker)
                    indent = marker.group(1)
                    injected = (indent + "- name: Replace checked-out source\n" +
                                indent + "  uses: " + encoded + "\n" +
                                indent + "  with:\n" +
                                indent + "    ref: main\n")
                    # Insert before the next step, keeping the first
                    # checkout's with: block attached to its own action.
                    following = re.search(
                        r"(?m)^" + re.escape(indent) + r"- ",
                        original[marker.end():],
                    )
                    self.assertIsNotNone(following)
                    pos = marker.end() + following.start()
                    target.write_text(
                        original[:pos] + injected + original[pos:],
                        encoding="utf-8",
                    )
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        "checkout triggering revision" in e or
                        "exact-source executable binding" in e for e in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_malformed_quoted_action_is_rejected_without_guessing(self):
        source = ('jobs:\n  sample:\n    steps:\n'
                  '      - uses: "actions/check\\x6fut@main"\n')
        with self.assertRaisesRegex(ValueError, "action reference escape"):
            gates.normalize_workflow_keys(source)

    def test_decoded_action_scalar_is_canonical_for_checkout_audit(self):
        source = ('jobs:\n  sample:\n    steps:\n'
                  '      - uses: "actions/check\\u006fut@abc" # a checkout\n'
                  "      - uses: 'actions/checkout@def'\n")
        output = gates.normalize_workflow_keys(source)
        self.assertIn("      - uses: actions/checkout@abc # a checkout\n", output)
        self.assertIn("      - uses: actions/checkout@def\n", output)

    def test_flow_style_steps_cannot_hide_second_checkout(self):
        # Flow-style mappings are legal GitHub YAML, but all protected
        # qualification jobs use audited block-style steps exclusively.
        workflows = dict(gates.MANDATORY)
        workflows["codex"] = ".github/workflows/codex-environment.yml"
        sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        bare_checkout = "      - uses: actions/checkout@" + sha + " # v7.0.1\n"
        cases = (
            ("flow checkout with ref",
             '      - {uses: "actions/checkout@' + sha +
             '", with: {ref: main}}\n'),
            ("flow checkout with name",
             '      - {name: "Replace source", uses: "actions/checkout@' +
             sha + '", with: {ref: main}}\n'),
            ("flow checkout without ref",
             '      - {uses: "actions/checkout@' + sha + '"}\n'),
        )
        for job, workflow in workflows.items():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            insertion = ("          fetch-depth: 0\n"
                         if job == "canonical-check" else bare_checkout)
            self.assertIn(insertion, original)
            for scenario, injected in cases:
                with self.subTest(job=job, scenario=scenario):
                    target.write_text(
                        original.replace(insertion, insertion + injected, 1),
                        encoding="utf-8",
                    )
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        job + ": must checkout triggering revision" in error
                        for error in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_codeql_actions_must_use_immutable_shas(self):
        path = self.root / ".github/workflows/codeql.yml"
        original = path.read_text(encoding="utf-8")
        for action in ("github/codeql-action/init@",
                       "github/codeql-action/analyze@"):
            with self.subTest(action=action):
                pin = re.search(
                    r"(?m)^      - uses: " + re.escape(action) +
                    r"([0-9a-f]{40})(?:\s+#.*)?$", original,
                )
                self.assertIsNotNone(pin, action)
                old = action + pin.group(1)
                path.write_text(original.replace(old, action + "main", 1),
                                encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(
                    any("CodeQL missing unconditional SHA-pinned action: " +
                        action in e for e in errors), errors,
                )
        path.write_text(original, encoding="utf-8")

    def test_codeql_init_analyze_must_share_one_pinned_revision(self):
        path = self.root / ".github/workflows/codeql.yml"
        original = path.read_text(encoding="utf-8")
        actions = ("github/codeql-action/init@", "github/codeql-action/analyze@")
        pins = {}
        for action in actions:
            match = re.search(
                r"(?m)^      - uses: " + re.escape(action) +
                r"([0-9a-f]{40})(?:\s+#.*)?$", original,
            )
            self.assertIsNotNone(match, action)
            pins[action] = match.group(1)
        self.assertEqual(pins[actions[0]], pins[actions[1]])

        # Exercise a subsequent grouped Dependabot upgrade without modifying
        # this test: any common immutable revision is valid for this invariant.
        upgraded_pin = "f" * 40 if pins[actions[0]] != "f" * 40 else "e" * 40
        upgraded = original
        for action in actions:
            upgraded = upgraded.replace(
                action + pins[action], action + upgraded_pin, 1,
            )
        path.write_text(upgraded, encoding="utf-8")
        self.assertEqual(gates.check(self.root), [])

        mismatched_pin = "0" * 40 if upgraded_pin != "0" * 40 else "1" * 40
        for action in actions:
            with self.subTest(action=action):
                path.write_text(upgraded.replace(
                    action + upgraded_pin, action + mismatched_pin, 1,
                ), encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any(
                    "CodeQL init/analyze actions must share the same immutable revision"
                    in err for err in errors
                ), errors)
        path.write_text(original, encoding="utf-8")

    def test_codex_contamination_injection_cannot_exit_early(self):
        path = self.root / ".github/workflows/codex-environment.yml"
        original = path.read_text(encoding="utf-8")
        label = "      - name: Inject stale bindings distribution before maintenance\n"
        block = label + "        run: |\n          set -euo pipefail\n"
        self.assertIn(block, original)
        for scenario, replacement in (
            ("early exit", block + "          exit 0\n"),
            ("no-op guard", block + "          true\n"),
            ("dead-code injection", block + "          if false; then\n"),
        ):
            with self.subTest(scenario=scenario):
                path.write_text(original.replace(block, replacement, 1),
                                encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(
                    any("Codex contamination injection must execute the complete"
                        " reviewed shell block" in e for e in errors), errors,
                )
        path.write_text(original, encoding="utf-8")

    def test_every_codex_step_rejects_shell_early_exit_or_noop(self):
        path = self.root / ".github/workflows/codex-environment.yml"
        original = path.read_text(encoding="utf-8")
        changes = (
            ("Prepare isolated environment",
             "          set -euo pipefail\n",
             "          set -euo pipefail\n          exit 0\n"),
            ("Bootstrap from host primitives",
             "        run: PATH=/usr/bin:/bin bash scripts/setup_codex_environment.sh --bindings\n",
             "        run: exit 0 # run: PATH=/usr/bin:/bin bash scripts/setup_codex_environment.sh --bindings\n"),
            ("Resume cached environment at selected checkout",
             "        run: PATH=/usr/bin:/bin bash scripts/maintain_codex_environment.sh --bindings\n",
             "        run: exit 0 # run: PATH=/usr/bin:/bin bash scripts/maintain_codex_environment.sh --bindings\n"),
            ("Verify maintenance removed contaminated distributions",
             "          set -euo pipefail\n",
             "          set -euo pipefail\n          exit 0\n"),
        )
        for label, before, after in changes:
            with self.subTest(step=label):
                start = original.index("      - name: " + label + "\n")
                end = original.find("      - name: ", start + 8)
                if end < 0:
                    end = len(original)
                block = original[start:end]
                self.assertIn(before, block)
                modified = original[:start] + block.replace(before, after, 1) + original[end:]
                (self.root / path).write_text(modified, encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any(
                    "Codex required step must match reviewed executable content: " +
                    label in e for e in errors
                ), errors)
        (self.root / path).write_text(original, encoding="utf-8")

    def test_cargo_audit_cannot_be_removed(self):
        self.change(".github/workflows/security.yml",
                    '"$HOME/.cargo/bin/cargo-audit" audit', "echo disabled")
        self.assertTrue(any("security audit missing" in x for x in gates.check(self.root)))

    def test_cargo_audit_cannot_be_suppressed(self):
        self.change(".github/workflows/security.yml",
                    '"$HOME/.cargo/bin/cargo-audit" audit',
                    '"$HOME/.cargo/bin/cargo-audit" audit || true')
        self.assertTrue(any("audit may be bypassed" in x for x in gates.check(self.root)))

    def test_cargo_audit_cannot_be_hidden_in_dead_shell_branch(self):
        self.change(".github/workflows/security.yml",
                    '          "$HOME/.cargo/bin/cargo-audit" audit\n',
                    '          if false; then\n'
                    '            "$HOME/.cargo/bin/cargo-audit" audit\n'
                    '          fi\n')
        self.assertTrue(any("security audit must run unconditionally" in x
                            for x in gates.check(self.root)))

    def test_cargo_audit_cannot_be_preceded_by_successful_exit(self):
        self.change(".github/workflows/security.yml",
                    '          "$HOME/.cargo/bin/cargo-audit" audit\n',
                    '          exit 0\n          "$HOME/.cargo/bin/cargo-audit" audit\n')
        self.assertTrue(any("security audit must run unconditionally" in x
                            for x in gates.check(self.root)))

    def test_cargo_audit_cannot_be_conditional(self):
        self.change(".github/workflows/security.yml",
                    "      - name: Audit Rust dependencies\n        run: |",
                    "      - name: Audit Rust dependencies\n        if: false\n        run: |")
        self.assertTrue(any("must run unconditionally" in x for x in gates.check(self.root)))

    def test_mandatory_checkout_cannot_override_triggering_revision(self):
        checkout_line = ("      - uses: actions/checkout@"
                         "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1")
        for job, workflow in gates.MANDATORY.items():
            file = self.root / workflow
            original = file.read_text(encoding="utf-8")
            self.assertIn(checkout_line + "\n", original)
            if job == "canonical-check":
                mutated = original.replace(
                    "          fetch-depth: 0\n",
                    "          fetch-depth: 0\n          ref: main\n", 1
                )
            else:
                mutated = original.replace(
                    checkout_line + "\n",
                    checkout_line + "\n        with: { ref: main }\n", 1
                )
            for scenario, source in (
                ("ref override", mutated),
                ("second checkout", original.replace(
                    checkout_line + "\n",
                    checkout_line + "\n" + checkout_line + "\n", 1
                )),
                ("skipped checkout", original.replace(
                    checkout_line + "\n",
                    checkout_line + "\n        if: false\n", 1
                )),
            ):
                with self.subTest(job=job, scenario=scenario):
                    file.write_text(source, encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        job + ": must checkout triggering revision" in e for e in errors
                    ), errors)
            file.write_text(original, encoding="utf-8")

    def test_mandatory_inherited_shell_defaults_cannot_bypass_gates(self):
        for job, workflow in gates.MANDATORY.items():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            for case, before, after in (
                ("workflow mapping", "permissions:\n",
                 "defaults:\n  run:\n    shell: bash -c 'exit 0' {0}\n\npermissions:\n"),
                ("workflow inline", "permissions:\n",
                 'defaults: {run: {shell: "bash -c \'exit 0\' {0}"}}\n\npermissions:\n'),
                ("job mapping", "    runs-on:",
                 "    defaults:\n      run:\n        shell: bash -c 'exit 0' {0}\n"
                 "    runs-on:"),
                ("job inline", "    runs-on:",
                 '    defaults: {run: {shell: "bash -c \'exit 0\' {0}"}}\n'
                 "    runs-on:"),
            ):
                with self.subTest(job=job, case=case):
                    self.assertIn(before, original)
                    target.write_text(original.replace(before, after, 1),
                                      encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        job + ": run defaults may bypass mandatory executable steps" in e
                        for e in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_mandatory_pr_gate_cannot_filter_target_branches(self):
        for workflow in gates.MANDATORY.values():
            with self.subTest(workflow=workflow):
                self.change(workflow, "  pull_request:\n",
                            "  pull_request:\n    branches: [never]\n")
                self.assertTrue(any("every PR" in x for x in gates.check(self.root)))
                self.change(workflow, "  pull_request:\n    branches: [never]\n",
                            "  pull_request:\n")

    def test_mandatory_pr_gate_cannot_filter_event_types(self):
        self.change(".github/workflows/ci.yml", "  pull_request:\n",
                    "  pull_request:\n    types: [opened]\n")
        self.assertTrue(any("every PR" in x for x in gates.check(self.root)))

    def test_mandatory_pr_filters_at_any_valid_indentation_are_rejected(self):
        for workflow in gates.MANDATORY.values():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            for spaces in (4, 6, 8):
                with self.subTest(workflow=workflow, indent=spaces):
                    target.write_text(original.replace(
                        "  pull_request:\n",
                        "  pull_request:\n" + " " * spaces + "branches: [never]\n",
                        1), encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any("every PR" in e for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_mandatory_job_cannot_have_if_condition(self):
        for job, workflow in gates.MANDATORY.items():
            with self.subTest(job=job):
                self.change(workflow, "  " + job + ":\n",
                            "  " + job + ":\n    if: false\n")
                self.assertTrue(
                    any("mandatory job must be unconditional" in x
                        for x in gates.check(self.root))
                )
                self.change(workflow, "  " + job + ":\n    if: false\n",
                            "  " + job + ":\n")

    def test_mandatory_job_rejects_alternative_valid_indentation(self):
        for job, workflow in gates.MANDATORY.items():
            with self.subTest(job=job):
                file = self.root / workflow
                source = file.read_text(encoding="utf-8")
                before, after = source.split("  " + job + ":\n", 1)
                # Shift every nonempty direct/descendant job line by two spaces.
                import re
                next_job = re.search(r"(?m)^  [a-z][a-z0-9-]*:\s*$", after)
                job_body = after[:next_job.start()] if next_job else after
                rest = after[next_job.start():] if next_job else ""
                shifted = "".join("  " + line if line.strip() else line
                                  for line in job_body.splitlines(keepends=True))
                file.write_text(before + "  " + job + ":\n" +
                                shifted.replace("      runs-on:", "      if: false\n      runs-on:", 1)
                                + rest)
                errors = gates.check(self.root)
                self.assertTrue(any("mandatory job must be unconditional" in e
                                    for e in errors), errors)
                file.write_text(source)

    def test_canonical_steps_reject_conditional_execution(self):
        for label in ("Run canonical Linura checks",
                      "Verify canonical crates.io package",
                      "Verify canonical PyPI package"):
            with self.subTest(step=label):
                path = ".github/workflows/ci.yml"
                before = "      - name: " + label + "\n        run:"
                self.change(path, before,
                            "      - name: " + label + "\n        if: false\n        run:")
                errors = gates.check(self.root)
                self.assertTrue(any("missing unconditional executable step: " + label in e
                                    for e in errors), errors)
                self.change(path, "      - name: " + label + "\n        if: false\n        run:", before)

    def test_canonical_checks_cannot_report_success_after_ignored_errors(self):
        self.change(".github/workflows/ci.yml",
                    "run: cargo xtask check", "run: cargo xtask check || true")
        self.assertTrue(any("missing unconditional executable step: Run canonical Linura checks"
                            in e for e in gates.check(self.root)))

    def test_pypi_verification_cannot_exit_before_package_checks(self):
        workflow = ".github/workflows/ci.yml"
        self.change(workflow,
                    "          set -euo pipefail\n"
                    "          PYTHONPATH=bindings/python/src python3 -m unittest discover",
                    "          set -euo pipefail\n"
                    "          exit 0\n"
                    "          PYTHONPATH=bindings/python/src python3 -m unittest discover")
        errors = gates.check(self.root)
        self.assertTrue(
            any("missing unconditional executable step: Verify canonical PyPI package" in e
                for e in errors), errors,
        )

    def test_pypi_verification_cannot_skip_wheel_installation(self):
        workflow = ".github/workflows/ci.yml"
        self.change(workflow,
                    "          python3 -m pip install ",
                    "          true # pip installation removed")
        errors = gates.check(self.root)
        self.assertTrue(
            any("missing unconditional executable step: Verify canonical PyPI package" in e
                for e in errors), errors,
        )

    def test_codeql_must_analyze_the_configured_rust_language(self):
        path = ".github/workflows/codeql.yml"
        target = self.root / path
        original = target.read_text(encoding="utf-8")
        for replacement in (
            "          languages: python # languages: rust\n",
            "          languages: python\n          languages: rust\n",
            "          languages: rust, python\n",
        ):
            with self.subTest(setting=replacement.strip()):
                target.write_text(
                    original.replace("          languages: rust\n", replacement, 1),
                    encoding="utf-8",
                )
                errors = gates.check(self.root)
                self.assertTrue(
                    any("CodeQL initialization must configure exactly Rust" in e
                        for e in errors), errors,
                )
        target.write_text(original, encoding="utf-8")

    def test_codeql_actions_cannot_be_conditional(self):
        path = ".github/workflows/codeql.yml"
        self.change(path, "          languages: rust\n",
                    "          languages: rust\n        if: false\n")
        self.assertTrue(any("CodeQL missing unconditional SHA-pinned action: "
                            "github/codeql-action/init@" in e
                            for e in gates.check(self.root)))

    def test_required_job_cannot_be_skipped_by_failed_dependency(self):
        self.change(".github/workflows/ci.yml", "  canonical-check:\n",
                    "  canonical-check:\n    needs: optional-job\n")
        self.assertTrue(
            any("mandatory job must be unconditional" in x
                for x in gates.check(self.root))
        )

    def test_unfiltered_ci_cannot_be_path_filtered(self):
        self.change(".github/workflows/ci.yml", "  pull_request:\n",
                    "  pull_request:\n    paths: [\"docs/**\"]\n")
        self.assertTrue(any("every PR" in x for x in gates.check(self.root)))

    def test_all_codex_entry_points_must_trigger_environment_validation(self):
        path = ".github/workflows/codex-environment.yml"
        source = (self.root / path).read_text(encoding="utf-8")
        self.assertIn('      - "scripts/*codex*.sh"\n', source)
        (self.root / path).write_text(
            source.replace('      - "scripts/*codex*.sh"\n',
                           '      - "scripts/setup_codex_environment.sh"\n')
        )
        errors = gates.check(self.root)
        for script in ("scripts/preflight_codex_environment.sh",
                       "scripts/maintain_codex_environment.sh",
                       "scripts/run_codex.sh"):
            with self.subTest(script=script):
                self.assertTrue(any(script in error and "missing critical PR trigger" in error
                                    for error in errors), errors)

    def test_codex_version_and_bindings_lock_changes_must_trigger_fresh_environment(self):
        path = ".github/workflows/codex-environment.yml"
        source = (self.root / path).read_text(encoding="utf-8")
        self.assertIn('      - "tools/codex/**"\n', source)
        self.assertIn('      - "bindings/python/build-requirements.lock"\n', source)
        (self.root / path).write_text(
            source.replace('      - "tools/codex/**"\n',
                           '      - "tools/codex/doctor.py"\n', 1)
                  .replace('      - "bindings/python/build-requirements.lock"\n',
                           "", 1)
        )
        errors = gates.check(self.root)
        for contract in ("tools/codex/versions.env",
                         "bindings/python/build-requirements.lock"):
            with self.subTest(contract=contract):
                self.assertTrue(
                    any(contract in e and "missing critical PR trigger" in e
                        for e in errors), errors
                )

    def test_rustup_bootstrap_helper_must_trigger_fresh_environment(self):
        workflow = ".github/workflows/codex-environment.yml"
        source = (self.root / workflow).read_text(encoding="utf-8")
        self.assertIn('      - "scripts/lib/*.sh"\n', source)
        (self.root / workflow).write_text(
            source.replace('      - "scripts/lib/*.sh"\n',
                           '      - "scripts/lib/codex_source_state.sh"\n')
        )
        errors = gates.check(self.root)
        self.assertTrue(
            any("codex: missing critical PR trigger: scripts/lib/bootstrap_rustup.sh" in e
                for e in errors), errors,
        )

    def test_mandatory_workflow_and_job_cannot_override_run_shell(self):
        unsafe_shell = "bash -c 'exit 0' {0}"
        for job, workflow in gates.MANDATORY.items():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            with self.subTest(job=job, scope="workflow"):
                target.write_text("defaults:\n  run:\n    shell: " + unsafe_shell +
                                  "\n" + original, encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any("run defaults may bypass mandatory" in e
                                    for e in errors), errors)
                target.write_text(original, encoding="utf-8")
            with self.subTest(job=job, scope="job"):
                marker = "  " + job + ":\n"
                self.assertIn(marker, original)
                target.write_text(original.replace(
                    marker, marker + "    defaults:\n      run:\n        shell: " +
                    unsafe_shell + "\n", 1,
                ), encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any("run defaults may bypass mandatory" in e
                                    for e in errors), errors)
                target.write_text(original, encoding="utf-8")

    def test_mandatory_step_cannot_override_run_shell(self):
        for workflow, label, expected in (
            (".github/workflows/ci.yml", "Run canonical Linura checks",
             "missing unconditional executable step: Run canonical Linura checks"),
            (".github/workflows/security.yml", "Audit Rust dependencies",
             "security audit must run unconditionally"),
        ):
            with self.subTest(step=label):
                target = self.root / workflow
                original = target.read_text(encoding="utf-8")
                marker = "      - name: " + label + "\n"
                self.assertIn(marker, original)
                target.write_text(original.replace(
                    marker, marker + "        shell: bash -c 'exit 0' {0}\n", 1,
                ), encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any(expected in e for e in errors), errors)
                target.write_text(original, encoding="utf-8")

    def test_every_specialized_lane_rejects_inherited_noop_shell(self):
        for name, (workflow, _) in gates.SPECIALIZED.items():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            for scope in ("workflow", "job"):
                if scope == "workflow":
                    modified = ("defaults:\n  run:\n"
                                "    shell: bash -c 'exit 0' {0}\n" + original)
                else:
                    job = gates.SPECIALIZED_REQUIRED_JOBS[name][0]
                    marker = "  " + job + ":\n"
                    self.assertIn(marker, original)
                    modified = original.replace(
                        marker,
                        marker + "    defaults:\n      run:\n"
                        "        shell: bash -c 'exit 0' {0}\n",
                        1,
                    )
                with self.subTest(lane=name, scope=scope):
                    target.write_text(modified, encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        name + ": inherited run defaults may bypass qualification" in e
                        for e in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_specialized_required_jobs_reject_noop_step_shells(self):
        for name, (workflow, _) in gates.SPECIALIZED.items():
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            job = gates.SPECIALIZED_REQUIRED_JOBS[name][0]
            marker = "  " + job + ":\n"
            self.assertIn(marker, original)
            before, rest = original.split(marker, 1)
            # Insert an explicit replacement shell at the first block step.
            step = re.search(r"(?m)^      - (?:name|uses):[^\n]*\n", rest)
            if step is None:
                continue  # Caller-only reusable jobs contain no executable steps.
            injected = rest[:step.end()] + (
                "        shell: bash -c 'exit 0' {0}\n") + rest[step.end():]
            with self.subTest(lane=name, job=job):
                target.write_text(before + marker + injected, encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(any(
                    name + ": unapproved step shell may bypass qualification" in e
                    for e in errors
                ), errors)
            target.write_text(original, encoding="utf-8")

    def test_required_qualification_steps_reject_unreviewed_guards(self):
        lanes = [(name, workflow, job)
                 for name, (workflow, _) in gates.SPECIALIZED.items()
                 for job in gates.SPECIALIZED_REQUIRED_JOBS[name]]
        lanes.extend(("v010-reusable",
                      ".github/workflows/v010-shell-runtime-qualification.yml",
                      job) for job in ("substrate", "runtime"))
        for name, workflow, job in lanes:
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            body = gates.section(gates.section(original, "jobs") or "", job, 2)
            if gates.section(body or "", "steps", 4) is None:
                continue  # Reusable-workflow caller has no executable steps.
            first = re.search(r"(?m)^      - name: ([^\r\n]+)$", body or "")
            self.assertIsNotNone(first, (name, job))
            marker = first.group(0) + "\n"
            self.assertIn(marker, original)
            for directive in ("if: false", "if: always()",
                              '"\\u0069f": false',
                              "continue-on-error: true"):
                with self.subTest(lane=name, job=job, directive=directive):
                    target.write_text(
                        original.replace(
                            marker, marker + "        " + directive + "\n", 1),
                        encoding="utf-8",
                    )
                    errors = gates.check(self.root)
                    expected = (
                        name + ": required qualification step guard may bypass execution: " +
                        job if name != "v010-reusable" else
                        "v0.10 shell-runtime " + job +
                        ": required qualification step guard may bypass execution")
                    self.assertTrue(any(expected in e for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_reviewed_conditional_cleanup_cannot_be_changed_to_skip(self):
        for (name, job), steps in gates.REVIEWED_STEP_CONDITIONS.items():
            workflow = (".github/workflows/v010-shell-runtime-qualification.yml"
                        if name == "v010-reusable" else gates.SPECIALIZED[name][0])
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            label, condition = next(iter(steps.items()))
            marker = "      - name: " + label + "\n        if: " + condition + "\n"
            self.assertIn(marker, original, (name, job))
            with self.subTest(lane=name, job=job, step=label):
                target.write_text(
                    original.replace(
                        marker, marker.replace("if: " + condition, "if: false"), 1),
                    encoding="utf-8",
                )
                errors = gates.check(self.root)
                expected = (
                    name + ": required qualification step guard may bypass execution: " +
                    job if name != "v010-reusable" else
                    "v0.10 shell-runtime " + job +
                    ": required qualification step guard may bypass execution")
                self.assertTrue(any(expected in e for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_step_guard_reader_preserves_literal_shell_source(self):
        body = ("    steps:\n"
                "      - name: Qualify real step\n"
                "        run: |\n"
                "          echo 'if: false'\n"
                "          echo 'continue-on-error: true'\n")
        self.assertTrue(gates.protected_step_guards(body, 4, {}))

    def test_unknown_step_mapping_cannot_hide_conditional_action(self):
        body = ("    steps:\n"
                "      - name: Qualify real step\n"
                "        run: echo test\n"
                "      - {name: Replace qualification, if: false, run: true}\n")
        self.assertFalse(gates.protected_step_guards(body, 4, {}))

    def test_specialized_required_job_cannot_be_skipped(self):
        for name, (workflow, _) in gates.SPECIALIZED.items():
            for required_job in gates.SPECIALIZED_REQUIRED_JOBS[name]:
                with self.subTest(lane=name, job=required_job):
                    target = self.root / workflow
                    original = target.read_text(encoding="utf-8")
                    marker = "  " + required_job + ":\n"
                    self.assertIn(marker, original)
                    target.write_text(original.replace(
                        marker, marker + "    if: false\n", 1,
                    ), encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        name + ": required qualification job cannot be skipped: " +
                        required_job in e for e in errors
                    ), errors)
                    target.write_text(original, encoding="utf-8")

    def test_specialized_entry_jobs_reject_skip_causing_dependencies(self):
        for name, (workflow, _) in gates.SPECIALIZED.items():
            for required_job in gates.SPECIALIZED_REQUIRED_JOBS[name]:
                with self.subTest(lane=name, job=required_job):
                    target = self.root / workflow
                    original = target.read_text(encoding="utf-8")
                    if name == "v09" and required_job == "contract":
                        self.assertIn("    needs: scope\n", original)
                        modified = original.replace(
                            "    needs: scope\n",
                            "    needs: [scope, conditional-helper]\n", 1,
                        )
                    else:
                        marker = "  " + required_job + ":\n"
                        self.assertIn(marker, original)
                        modified = original.replace(
                            marker, marker + "    needs: conditional-helper\n", 1,
                        )
                    target.write_text(modified, encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(
                        any(name + ": required qualification job has unapproved dependencies: "
                            + required_job in e for e in errors), errors,
                    )
                    target.write_text(original, encoding="utf-8")

    def test_v09_contract_dependency_is_required(self):
        self.change(".github/workflows/v09-qualification.yml",
                    "    needs: scope\n", "")
        errors = gates.check(self.root)
        self.assertTrue(
            any("v09: required qualification job has unapproved dependencies: contract" in e
                for e in errors), errors,
        )

    def test_specialized_required_job_cannot_ignore_failure(self):
        target = self.root / ".github/workflows/codex-environment.yml"
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace(
            "  fresh-environment:\n",
            "  fresh-environment:\n    continue-on-error: true\n", 1,
        ), encoding="utf-8")
        errors = gates.check(self.root)
        self.assertTrue(any("codex: required qualification job cannot be skipped:"
                            " fresh-environment" in e for e in errors), errors)

    def test_specialized_pr_branch_restrictions_are_rejected(self):
        for name, (workflow, _) in gates.SPECIALIZED.items():
            with self.subTest(name=name):
                self.change(workflow, "  pull_request:\n",
                            "  pull_request:\n    branches: [never]\n")
                self.assertTrue(any(name + ": specialized PR event may contain only paths" in x
                                    for x in gates.check(self.root)))
                self.change(workflow, "  pull_request:\n    branches: [never]\n",
                            "  pull_request:\n")

    def test_specialized_pr_event_type_restrictions_are_rejected(self):
        self.change(".github/workflows/codex-environment.yml",
                    "  pull_request:\n", "  pull_request:\n    types: [opened]\n")
        self.assertTrue(any("codex: specialized PR event may contain only paths" in x
                            for x in gates.check(self.root)))

    def test_v09_routing_guard_must_trigger_v09_regression(self):
        self.change(".github/workflows/v09-qualification.yml",
                    '      - "tools/check_validation_gates.py"\n', "")
        self.assertTrue(any("v09: missing critical PR trigger: tools/check_validation_gates.py" in x
                            for x in gates.check(self.root)))

    def test_every_specialized_lane_must_trigger_on_its_own_workflow(self):
        # Includes the two independent v0.4 fault-qualification lanes.
        for name, (workflow, _) in gates.SPECIALIZED.items():
            with self.subTest(lane=name):
                own_path = '      - "' + workflow + '"\n'
                self.change(workflow, own_path, "")
                errors = gates.check(self.root)
                self.assertTrue(
                    any(name + ": missing critical PR trigger: " + workflow in error
                        for error in errors), errors
                )
                self.change(workflow, '  pull_request:\n    paths:\n',
                            '  pull_request:\n    paths:\n' + own_path)

    def test_guidance_only_does_not_trigger_expensive_v010_runtime(self):
        workflow = ".github/workflows/v010-qualification.yml"
        source = (self.root / workflow).read_text()
        events = gates.section(source, "on")
        pr = gates.section(events, "pull_request", 2)
        paths = gates.section(pr, "paths", 4)
        import re
        patterns = re.findall(r'(?m)^      - "([^"]+)"\s*$', paths)
        for guidance in gates.GUIDANCE_EXCLUSIONS["v010"]:
            with self.subTest(path=guidance):
                self.assertFalse(gates.path_selected(guidance, patterns))
        actual_change = "apps/linura-shell/panel/WorkstationPanel.qml"
        self.assertTrue(gates.path_selected(actual_change, patterns))
        # A mixed documentation+code PR must still qualify the real code.
        self.assertTrue(any(gates.path_selected(p, patterns)
                            for p in (*gates.GUIDANCE_EXCLUSIONS["v010"], actual_change)))
        self.assertTrue(gates.path_selected(workflow, patterns))

    def test_guidance_only_exclusion_cannot_be_removed(self):
        workflow = ".github/workflows/v010-qualification.yml"
        self.change(workflow, '      - "!apps/linura-shell/AGENTS.md"\n', "")
        errors = gates.check(self.root)
        self.assertTrue(
            any("guidance-only change triggers machine qualification" in e for e in errors),
            errors,
        )

    def test_negative_filter_cannot_hide_a_critical_source(self):
        workflow = ".github/workflows/v010-qualification.yml"
        self.change(workflow,
                    '      - "!apps/linura-shell/README.md"\n',
                    '      - "!apps/linura-shell/README.md"\n'
                    '      - "!apps/linura-shell/bridge/CMakeLists.txt"\n')
        errors = gates.check(self.root)
        self.assertTrue(
            any("v010: missing critical PR trigger: apps/linura-shell/bridge/CMakeLists.txt"
                in e for e in errors), errors,
        )

    def test_later_positive_filter_reincludes_matching_source(self):
        patterns = ["apps/linura-shell/**", "!apps/linura-shell/**",
                    "apps/linura-shell/panel/**"]
        self.assertTrue(gates.path_selected("apps/linura-shell/panel/WorkstationPanel.qml",
                                            patterns))
        self.assertFalse(gates.path_selected("apps/linura-shell/AGENTS.md", patterns))
        self.assertFalse(gates.path_selected("apps/linura-shell/tray/SystemTrayView.qml",
                                             patterns))

    def test_v09_release_always_uses_full_qualification(self):
        workflow = ".github/workflows/v09-qualification.yml"
        self.change(workflow, "full_qualification=true", "full_qualification=false")
        self.assertTrue(any("v0.9 must retain full release qualification" in e
                            for e in gates.check(self.root)))

    def test_specialized_shell_change_cannot_lose_qualifier(self):
        self.change(".github/workflows/v010-qualification.yml",
                    '      - "apps/linura-shell/**"\n', "")
        self.assertTrue(any("missing critical PR trigger" in x for x in gates.check(self.root)))

    def test_inherited_release_qualification_cannot_be_disconnected(self):
        proof = ".github/workflows/trusted-release-proof.yml"
        target = self.root / proof
        for job, workflow in gates.RELEASE_INHERITED.items():
            with self.subTest(job=job):
                source = target.read_text()
                marker = "  " + job + ":\n"
                before, after = source.split(marker, 1)
                expected = "    uses: ./" + workflow + "\n"
                self.assertIn(expected, after)
                target.write_text(before + marker + after.replace(
                    expected, "    uses: ./missing-workflow.yml\n", 1
                ))
                self.assertTrue(
                    any("release proof missing unconditional inherited qualification: " + job
                        in x for x in gates.check(self.root))
                )
                target.write_text(source)

    def test_release_build_cannot_drop_inherited_dependency(self):
        proof = ".github/workflows/trusted-release-proof.yml"
        source = (self.root / proof).read_text()
        marker = "  build:"
        prefix, build = source.split(marker, 1)
        self.assertIn("executor-verifier-qualification,", build)
        altered = build.replace("executor-verifier-qualification,", "", 1)
        (self.root / proof).write_text(prefix + marker + altered)
        self.assertTrue(
            any("release proof build missing inherited dependency: "
                "executor-verifier-qualification" in x for x in gates.check(self.root))
        )

    def test_release_promotion_cannot_drop_inherited_dependency(self):
        proof = ".github/workflows/trusted-release-proof.yml"
        source = (self.root / proof).read_text()
        marker = "  dispatch-promotion:"
        prefix, dispatch = source.split(marker, 1)
        self.assertIn("executor-verifier-qualification,", dispatch)
        altered = dispatch.replace("executor-verifier-qualification,", "", 1)
        (self.root / proof).write_text(prefix + marker + altered)
        self.assertTrue(
            any("release proof dispatch-promotion missing inherited dependency: "
                "executor-verifier-qualification" in x for x in gates.check(self.root))
        )

    def test_release_promotion_cannot_ignore_failed_inherited_qualification(self):
        proof = ".github/workflows/trusted-release-proof.yml"
        self.change(
            proof,
            "needs.durability-qualification.result == 'success'",
            "needs.durability-qualification.result == 'failure'",
        )
        self.assertTrue(
            any("release promotion missing inherited success guard: durability-qualification"
                in x for x in gates.check(self.root))
        )

    def test_release_promotion_requires_all_successes_not_an_or(self):
        proof = ".github/workflows/trusted-release-proof.yml"
        target = self.root / proof
        source = target.read_text(encoding="utf-8")
        good = ("needs.observation-acceptance.result == 'success' && "
                "needs.plan-preview-acceptance.result == 'success'")
        self.assertIn(good, source)
        for replacement in (
            good.replace(" && ", " || "),
            good.replace(" && ", " && always() || "),
        ):
            with self.subTest(replacement=replacement):
                target.write_text(source.replace(good, replacement, 1),
                                  encoding="utf-8")
                errors = gates.check(self.root)
                self.assertTrue(
                    any("release promotion success guard must be a reviewed conjunction" in e
                        for e in errors), errors,
                )
        target.write_text(source, encoding="utf-8")

    def test_quoted_event_filters_cannot_skip_required_pr_gates(self):
        workflows = [*gates.MANDATORY.values(),
                     *(workflow for workflow, _ in gates.SPECIALIZED.values())]
        for workflow in workflows:
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            for filter_key in ('"branches"', "'types'", '"paths-ignore"'):
                with self.subTest(workflow=workflow, key=filter_key):
                    mutation = original.replace(
                        "  pull_request:\n",
                        "  pull_request:\n    " + filter_key + ": [never]\n", 1,
                    )
                    self.assertNotEqual(mutation, original)
                    target.write_text(mutation, encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        "every PR" in e if workflow in gates.MANDATORY.values()
                        else "specialized PR event may contain only paths" in e
                        for e in errors
                    ), errors)
            target.write_text(original, encoding="utf-8")

    def test_specialized_source_binding_is_executable_and_immutable(self):
        for workflow in (".github/workflows/vm-acceptance.yml",
                         ".github/workflows/v010-qualification.yml"):
            target = self.root / workflow
            original = target.read_text(encoding="utf-8")
            source_ref = "          ref: ${{ inputs.source_sha || github.event.pull_request.head.sha || github.sha }}\n"
            assert_line = '          test "$(git rev-parse HEAD)" = "$SOURCE_SHA"\n'
            self.assertIn(source_ref, original)
            self.assertIn(assert_line, original)
            for scenario, before, after in (
                ("different checkout", source_ref, "          ref: main\n"),
                ("commented-out assertion", assert_line,
                 '          # test "$(git rev-parse HEAD)" = "$SOURCE_SHA"\n'),
                ("early exit", assert_line, "          exit 0\n" + assert_line),
            ):
                with self.subTest(workflow=workflow, scenario=scenario):
                    target.write_text(original.replace(before, after, 1),
                                      encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any("missing exact-source executable binding" in e
                                        for e in errors), errors)
            target.write_text(original, encoding="utf-8")

    def test_reusable_shell_runtime_jobs_require_exact_source(self):
        workflow = ".github/workflows/v010-shell-runtime-qualification.yml"
        target = self.root / workflow
        original = target.read_text(encoding="utf-8")
        source_ref = "          ref: ${{ inputs.source_sha || github.sha }}\n"
        assert_line = '          test "$(git rev-parse HEAD)" = "$SOURCE_SHA"\n'
        self.assertEqual(original.count(source_ref), 2)
        self.assertEqual(original.count(assert_line), 2)
        for job in ("substrate", "runtime"):
            prefix, body = original.split("  " + job + ":\n", 1)
            for scenario, before, after in (
                    ("changed ref", source_ref, "          ref: main\n"),
                    ("missing assertion", assert_line,
                     '          # test "$(git rev-parse HEAD)" = "$SOURCE_SHA"\n'),
                    ("early success", assert_line, "          exit 0\n" + assert_line),
                    ("conditional assertion",
                     "      - name: Assert exact source and " +
                     ("substrate" if job == "substrate" else "runtime") +
                     " contract\n",
                     "      - name: Assert exact source and " +
                     ("substrate" if job == "substrate" else "runtime") +
                     " contract\n        if: false\n"),
            ):
                with self.subTest(job=job, scenario=scenario):
                    self.assertIn(before, body)
                    target.write_text(prefix + "  " + job + ":\n" +
                                      body.replace(before, after, 1),
                                      encoding="utf-8")
                    errors = gates.check(self.root)
                    self.assertTrue(any(
                        "v0.10 shell-runtime " + job +
                        ": missing exact-source executable binding" in e
                        for e in errors), errors)
        target.write_text(original, encoding="utf-8")

    def test_reusable_shell_runtime_environment_cannot_be_overridden(self):
        workflow = ".github/workflows/v010-shell-runtime-qualification.yml"
        target = self.root / workflow
        original = target.read_text(encoding="utf-8")
        self.assertIn("  SOURCE_SHA: ${{ inputs.source_sha || github.sha }}\n", original)
        target.write_text(original.replace(
            "  SOURCE_SHA: ${{ inputs.source_sha || github.sha }}\n",
            "  SOURCE_SHA: ${{ github.sha }}\n", 1),
            encoding="utf-8")
        self.assertTrue(any("exact-source environment" in e
                            for e in gates.check(self.root)))

    def test_xtask_tests_cannot_be_replaced_with_a_comment(self):
        self.change("tools/xtask/src/main.rs",
                    '    run(\n        "cargo",\n'
                    '        &["test", "--workspace", "--all-features", "--locked"],\n'
                    '    )?;\n',
                    '    // run("cargo", &["test", "--workspace", '
                    '"--all-features", "--locked"])?;\n')
        errors = gates.check(self.root)
        self.assertTrue(any("canonical xtask execution sequence changed" in e
                            for e in errors), errors)

    def test_exact_source_assertion_cannot_be_removed(self):
        self.change(".github/workflows/vm-acceptance.yml",
                    'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"', "true")
        self.assertTrue(any("missing exact-source executable binding" in x for x in gates.check(self.root)))

    def test_glob_does_not_cross_directories_without_double_star(self):
        self.assertTrue(gates.path_matches("crates/linura-control/src/lib.rs", "crates/linura-control/**"))
        self.assertFalse(gates.path_matches("crates/linura-control/src/lib.rs", "crates/linura-control/*"))


if __name__ == "__main__":
    unittest.main()
