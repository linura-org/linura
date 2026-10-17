from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from tools import check_ci_cache_policy as policy


ROOT = Path(__file__).resolve().parents[2]
FILES = (
    ".github/actions/dependency-input-cache-policy.toml",
    ".github/actions/cargo-input-cache/action.yml",
    ".github/actions/ubuntu-apt-input-cache/action.yml",
    ".github/workflows/ci.yml",
)


class CiCachePolicyTests(unittest.TestCase):
    def copy_root(self) -> Path:
        temp = Path(tempfile.mkdtemp(prefix="linura-ci-cache-policy-"))
        self.addCleanup(shutil.rmtree, temp, True)
        for relative in FILES:
            source = ROOT / relative
            target = temp / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return temp

    def test_repository_policy_passes(self) -> None:
        self.assertEqual(policy.check(ROOT), [])

    def test_pinned_apt_package_selector_preflight(self) -> None:
        action = (ROOT / ".github/actions/ubuntu-apt-input-cache/action.yml").read_text(
            encoding="utf-8"
        )
        resolver = action.split("    - id: resolve\n", 1)[1]
        preflight = resolver.split("      run: |\n", 1)[1].split(
            "        sudo apt-get update\n", 1
        )[0]
        script = "\n".join(
            line.removeprefix("        ") for line in preflight.splitlines()
        )
        for selector, valid in (
            ("qt6-base-dev", True),
            ("qml6-module-qtqml=6.4.2+dfsg-4build3", True),
            ("libexample:amd64=1:2.0~stable-1", True),
            ("qml6-module-qtqml=", False),
            ("qml6-module-qtqml=../bad", False),
            ("qml6-module-qtqml=1;printf", False),
            ("qml6-module-qtqml=1=2", False),
        ):
            with self.subTest(selector=selector):
                result = subprocess.run(
                    ["bash", "-c", script],
                    env={
                        **os.environ,
                        "LINURA_APT_NAMESPACE": "canonical-ci-shell",
                        "LINURA_APT_PACKAGES": selector,
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, valid, result.stderr)

    def test_exact_apt_selectors_reject_candidate_and_installed_drift(self) -> None:
        action = (ROOT / policy.APT_ACTION).read_text(encoding="utf-8")
        steps = policy._canonical_composite_steps(action, "APT")

        def literal_body(index: int) -> str:
            raw = steps[index]["run_lines"]
            assert isinstance(raw, list)
            lines: list[str] = []
            for line in raw:
                assert isinstance(line, str)
                lines.append(line)
            return "\n".join(lines)

        resolver = literal_body(0)
        requested = resolver.split('requested="$(\n', 1)[1].split('\n)"', 1)[0]
        installed = (
            literal_body(2)
            .split('for spec in "${packages[@]}"; do', 1)[1]
            .split("\ndone", 1)[0]
        )
        mocks = """set -euo pipefail
apt-cache() { printf '  Candidate: %s\\n' "$LINURA_TEST_CANDIDATE"; return "${LINURA_TEST_QUERY_EXIT:-0}"; }
dpkg-query() {
    if [[ "$2" == '-f=${Status}' ]]; then
        printf '%s' "$LINURA_TEST_STATUS"
    else
        printf '%s' "$LINURA_TEST_INSTALLED"
    fi
}
packages=('qml6-module-qtqml=6.4.2+dfsg-4build3')
"""
        pinned = "6.4.2+dfsg-4build3"
        for candidate, version, status, valid in (
            (pinned, pinned, "install ok installed", True),
            ("6.4.2+dfsg-4build4", pinned, "install ok installed", False),
            ("6.4.2+dfsg-4build4", "6.4.2+dfsg-4build4", "install ok installed", False),
            ("(none)", pinned, "install ok installed", False),
            ("", pinned, "install ok installed", False),
            (pinned, "6.4.2+dfsg-4build4", "install ok installed", False),
            (pinned, "", "install ok installed", False),
            (pinned, pinned, "deinstall ok config-files", False),
            (pinned, pinned, "install ok unpacked", False),
        ):
            with self.subTest(candidate=candidate, installed=version, status=status):
                for phase, body, allowed in (
                    (
                        "resolve",
                        'requested="$(\n' + requested + '\n)"\n',
                        candidate == pinned,
                    ),
                    (
                        "installed",
                        'for spec in "${packages[@]}"; do\n' + installed + "\ndone\n",
                        valid,
                    ),
                ):
                    with self.subTest(phase=phase):
                        result = subprocess.run(
                            ["bash", "-c", mocks + body],
                            env={
                                **os.environ,
                                "LINURA_TEST_CANDIDATE": candidate,
                                "LINURA_TEST_INSTALLED": version,
                                "LINURA_TEST_STATUS": status,
                            },
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=5,
                        )
                        self.assertEqual(result.returncode == 0, allowed, result.stderr)
        # Even plausible output from a failed query cannot authorize identity
        # resolution. Exercise the actual command-substitution error behavior.
        result = subprocess.run(
            ["bash", "-c", mocks + 'requested="$(\n' + requested + '\n)"\n'],
            env={
                **os.environ,
                "LINURA_TEST_CANDIDATE": pinned,
                "LINURA_TEST_QUERY_EXIT": "1",
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_exact_pin_checks_cannot_be_inert_or_weakened(self) -> None:
        for old, new in (
            ('test "${spec#*=}" = "$candidate"', "true"),
            ('test "$installed" = "$candidate"', "true"),
            (
                "test \"$(dpkg-query -W -f='${Status}' \"$package\")\" = 'install ok installed'",
                "true",
            ),
            ('test "${spec#*=}" = "$candidate"', '# test "${spec#*=}" = "$candidate"'),
            (
                'test "${spec#*=}" = "$candidate"',
                'if false; then\n              test "${spec#*=}" = "$candidate"\n            fi',
            ),
        ):
            with self.subTest(old=old, new=new):
                root = self.copy_root()
                action = root / policy.APT_ACTION
                source = action.read_text(encoding="utf-8")
                self.assertIn(old, source)
                action.write_text(source.replace(old, new, 1), encoding="utf-8")
                self.assertTrue(
                    any("reviewed SHA-256" in failure for failure in policy.check(root))
                )

    def test_contract_cannot_authorize_build_output_caching(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/dependency-input-cache-policy.toml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "linura_build_outputs = false", "linura_build_outputs = true", 1
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("contract drifted" in failure for failure in failures), failures
        )

    def test_contract_cannot_treat_cache_hit_as_evidence(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/dependency-input-cache-policy.toml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "cache_hit_is_qualification_evidence = false",
                "cache_hit_is_qualification_evidence = true",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("contract drifted" in failure for failure in failures), failures
        )

    def test_cargo_cache_cannot_include_build_outputs(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace("~/.cargo/git/db", "~/.cargo/git/db\n          target/", 1),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any(
                "dependency-input-only" in failure
                or "forbidden cached output" in failure
                for failure in failures
            ),
            failures,
        )

    def test_cache_action_pin_cannot_become_mutable(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(source.replace(policy.CACHE_SHA, "main", 1), encoding="utf-8")
        failures = policy.check(root)
        self.assertTrue(
            any("pinned actions/cache" in failure for failure in failures), failures
        )

    def test_mutable_cache_ref_cannot_hide_behind_pinned_comment(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        source = source.replace(
            f"uses: actions/cache@{policy.CACHE_SHA} # v6.1.0",
            f"uses: actions/cache@main\n      # uses: actions/cache@{policy.CACHE_SHA}",
            1,
        )
        path.write_text(source, encoding="utf-8")
        failures = policy.check(root)
        self.assertTrue(
            any("canonical pinned actions/cache" in failure for failure in failures),
            failures,
        )

    def test_folded_mutable_cache_ref_cannot_hide_behind_block_scalar_decoy(
        self,
    ) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        source = source.replace(
            f"      uses: actions/cache@{policy.CACHE_SHA} # v6.1.0",
            "      uses: >-\n"
            "        actions/cache@main\n"
            "      description: |\n"
            f"        uses: actions/cache@{policy.CACHE_SHA}",
            1,
        )
        path.write_text(source, encoding="utf-8")
        failures = policy.check(root)
        self.assertTrue(
            any("canonical pinned actions/cache" in failure for failure in failures),
            failures,
        )

    def test_quoted_uses_key_cannot_add_mutable_cache_action(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        pinned = f"      uses: actions/cache@{policy.CACHE_SHA} # v6.1.0"
        self.assertIn(pinned, source)
        path.write_text(
            source.replace(pinned, pinned + '\n      "uses": actions/cache@main', 1),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("noncanonical step key" in failure for failure in failures),
            failures,
        )

    def test_quoted_uses_key_cannot_replace_pinned_cache_action(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        pinned = f"uses: actions/cache@{policy.CACHE_SHA} # v6.1.0"
        self.assertIn(pinned, source)
        path.write_text(
            source.replace(pinned, '"uses": actions/cache@main', 1),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("noncanonical step key" in failure for failure in failures),
            failures,
        )

    def test_commented_apt_refresh_is_not_executable(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "        sudo apt-get update\n",
                "        # sudo apt-get update\n",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("sudo apt-get update" in failure for failure in failures),
            failures,
        )

    def test_commented_apt_candidate_assertion_is_not_executable(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                '          test "$installed" = "$candidate"\n',
                '          # test "$installed" = "$candidate"\n',
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any('test "$installed" = "$candidate"' in failure for failure in failures),
            failures,
        )

    def test_quoted_shadow_runs_mapping_is_rejected(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source + '\n"runs" :\n  using: composite\n  steps:\n'
            "    - uses: actions/cache@main\n",
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("noncanonical root key" in failure for failure in failures),
            failures,
        )

    def test_duplicate_runs_mapping_cannot_shadow_canonical_steps(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source
            + "\nruns:\n  using: composite\n  steps:\n    - uses: actions/cache@main\n",
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("canonical" in failure for failure in failures),
            failures,
        )

    def test_apt_refresh_hidden_in_heredoc_cannot_pass(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        self.assertIn("        sudo apt-get update\n", source)
        path.write_text(
            source.replace(
                "        sudo apt-get update\n",
                "        cat <<'INVARIANT'\n"
                "        sudo apt-get update\n"
                "        INVARIANT\n",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("reviewed SHA-256 fingerprint" in failure for failure in failures),
            failures,
        )

    def test_apt_candidate_assertion_hidden_in_heredoc_cannot_pass(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        assertion = '          test "$installed" = "$candidate"\n'
        self.assertIn(assertion, source)
        path.write_text(
            source.replace(
                assertion,
                "          cat <<'INVARIANT'\n" + assertion + "          INVARIANT\n",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("reviewed SHA-256 fingerprint" in failure for failure in failures),
            failures,
        )

    def test_apt_refresh_in_unreachable_branch_cannot_pass(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        self.assertIn("        sudo apt-get update\n", source)
        path.write_text(
            source.replace(
                "        sudo apt-get update\n",
                "        if false; then\n          sudo apt-get update\n        fi\n",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("reviewed SHA-256 fingerprint" in failure for failure in failures),
            failures,
        )

    def test_unreviewed_cargo_action_shell_mutation_is_rejected(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        self.assertIn("        test -f Cargo.lock\n", source)
        path.write_text(
            source.replace(
                "        test -f Cargo.lock\n",
                "        test -f Cargo.lock\n        echo unexpected-command\n",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("reviewed SHA-256 fingerprint" in failure for failure in failures),
            failures,
        )

    def test_apt_cache_cannot_move_into_home(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "$RUNNER_TEMP/linura-apt-inputs",
                "$HOME/.cache/linura/apt",
                1,
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(any("runner.temp" in failure for failure in failures), failures)

    def test_apt_identity_must_bind_runner_package_universe(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace("installed_universe_sha256=", "ignored_universe_sha256=", 1),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any("installed_universe_sha256" in failure for failure in failures),
            failures,
        )

    def test_apt_install_must_verify_exact_candidate_versions(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/ubuntu-apt-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace('          test "$installed" = "$candidate"\n', "", 1),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any('test "$installed" = "$candidate"' in failure for failure in failures),
            failures,
        )

    def test_broad_restore_keys_are_forbidden(self) -> None:
        root = self.copy_root()
        path = root / ".github/actions/cargo-input-cache/action.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(source + "\n# restore-keys: linura-cargo-\n", encoding="utf-8")
        failures = policy.check(root)
        self.assertTrue(
            any("broad restore keys" in failure for failure in failures), failures
        )

    def mutate_ci(self, before: str, after: str) -> list[str]:
        root = self.copy_root()
        path = root / ".github/workflows/ci.yml"
        source = path.read_text(encoding="utf-8")
        self.assertIn(before, source)
        path.write_text(source.replace(before, after, 1), encoding="utf-8")
        return policy.check(root)

    def test_qml_step_if_false_cannot_bypass_exact_source(self) -> None:
        failures = self.mutate_ci(
            "      - name: Build and install Linura Shell QML modules\n",
            "      - name: Build and install Linura Shell QML modules\n"
            "        if: false\n",
        )
        self.assertTrue(any("unsafe step key" in x for x in failures), failures)

    def test_xtask_if_false_cannot_bypass_canonical_gate(self) -> None:
        failures = self.mutate_ci(
            "      - name: Run canonical Linura checks\n",
            "      - name: Run canonical Linura checks\n        if: false\n",
        )
        self.assertTrue(any("unsafe step key" in x for x in failures), failures)

    def test_build_continue_on_error_cannot_mask_failure(self) -> None:
        failures = self.mutate_ci(
            "      - name: Build and install Linura Shell QML modules\n",
            "      - name: Build and install Linura Shell QML modules\n"
            "        continue-on-error: true\n",
        )
        self.assertTrue(any("unsafe step key" in x for x in failures), failures)

    def test_job_level_if_false_is_rejected(self) -> None:
        failures = self.mutate_ci(
            "    runs-on: ubuntu-24.04\n",
            "    if: false\n    runs-on: ubuntu-24.04\n",
        )
        self.assertTrue(
            any("job must run unconditionally" in x for x in failures), failures
        )

    def test_quoted_step_if_false_is_rejected(self) -> None:
        failures = self.mutate_ci(
            "      - name: Run canonical Linura checks\n",
            '      - name: Run canonical Linura checks\n        "if": false\n',
        )
        self.assertTrue(any("noncanonical step key" in x for x in failures), failures)

    def test_disabled_qml_commands_cannot_hide_as_heredoc(self) -> None:
        failures = self.mutate_ci(
            "          cmake -S apps/linura-shell/bridge",
            "          cat <<'FAKE_BUILD'\n          cmake -S apps/linura-shell/bridge",
        )
        self.assertTrue(any("QML build differs" in x for x in failures), failures)

    def test_xtask_scalar_cannot_be_an_inert_echo(self) -> None:
        failures = self.mutate_ci(
            "        run: cargo xtask check\n",
            '        run: echo "cargo xtask check"\n',
        )
        self.assertTrue(any("must execute the full" in x for x in failures), failures)

    def test_cache_step_must_keep_exact_namespace(self) -> None:
        failures = self.mutate_ci(
            "          namespace: canonical-ci-shell\n",
            "          namespace: alternate\n",
        )
        self.assertTrue(
            any("APT cache input step drifted" in x for x in failures), failures
        )

    def test_component_test_qml_inputs_remain_pinned(self) -> None:
        for package in (
            "qtqml",
            "qtqml-models",
            "qtqml-workerscript",
            "qtquick",
            "qtquick-controls",
            "qtquick-layouts",
            "qtquick-templates",
            "qtquick-window",
        ):
            with self.subTest(package=package):
                failures = self.mutate_ci(
                    f"qml6-module-{package}=6.4.2+dfsg-4build3",
                    f"qml6-module-{package}",
                )
                self.assertTrue(
                    any("APT cache input step drifted" in x for x in failures), failures
                )

    def test_component_tests_cannot_be_disabled_or_use_ambient_modules(self) -> None:
        for old, new in (
            ('ctest --test-dir "$build_dir" --output-on-failure', "true"),
            ('QML_IMPORT_PATH="$install_dir/lib/qt6/qml"', "QML_IMPORT_PATH=/tmp"),
        ):
            with self.subTest(command=old):
                failures = self.mutate_ci(old, new)
                self.assertTrue(
                    any("QML build differs" in x for x in failures), failures
                )

    def test_shadow_jobs_mapping_cannot_bypass_ci(self) -> None:
        failures = self.mutate_ci(
            "jobs:\n  canonical-check:\n",
            '"jobs":\n  canonical-check:\n',
        )
        self.assertTrue(
            any("noncanonical root mappings" in x for x in failures), failures
        )

    def test_extra_cargo_cache_step_cannot_shadow_reviewed_step(self) -> None:
        failures = self.mutate_ci(
            "      - name: Restore Cargo dependency inputs\n",
            "      - name: Restore Cargo dependency inputs\n        if: false\n",
        )
        self.assertTrue(any("unsafe step key" in x for x in failures), failures)

    def test_early_policy_step_must_remain_unconditional(self) -> None:
        failures = self.mutate_ci(
            "      - name: Validate CI dependency cache policy before builds\n",
            "      - name: Validate CI dependency cache policy before builds\n"
            "        if: false\n",
        )
        self.assertTrue(any("unsafe step key" in x for x in failures), failures)

    def test_qml_step_cannot_gain_arbitrary_environment(self) -> None:
        failures = self.mutate_ci(
            "      - name: Build and install Linura Shell QML modules\n",
            "      - name: Build and install Linura Shell QML modules\n"
            "        env:\n"
            "          BASH_ENV: /tmp/bypass\n",
        )
        self.assertTrue(
            any("critical step structure drifted" in x for x in failures), failures
        )

    def test_missing_early_policy_check_is_rejected(self) -> None:
        failures = self.mutate_ci(
            "        run: python3 tools/check_ci_cache_policy.py\n",
            "        run: echo skip-policy\n",
        )
        self.assertTrue(
            any("must validate cache policy before builds" in x for x in failures),
            failures,
        )

    def test_exact_source_qml_builds_cannot_be_replaced_by_cache(self) -> None:
        root = self.copy_root()
        path = root / ".github/workflows/ci.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "cmake -S apps/linura-shell/bridge", "echo cached-bridge", 1
            ),
            encoding="utf-8",
        )
        failures = policy.check(root)
        self.assertTrue(
            any(
                "cache integration missing invariant" in failure for failure in failures
            ),
            failures,
        )


if __name__ == "__main__":
    unittest.main()
