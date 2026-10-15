"""Security regressions for non-executable repository toolchain pins."""

from __future__ import annotations

from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest

from tools.check_toolchain_env import EXPECTED_KEYS, validate, validate_bytes

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "tools/codex/versions.env"


class ToolchainEnvironmentTests(unittest.TestCase):
    def test_validation_only_steps_execute_with_their_declared_environments(
        self,
    ) -> None:
        from tools.check_validation_gates import (
            executable_run_block,
            section,
            workflow_step,
        )

        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertRegex(head, r"^[0-9a-f]{40}$")
        checked = []
        main_guards = []
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            source = path.read_text(encoding="utf-8")
            jobs = section(source, "jobs") or ""
            for name in re.findall(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):$", jobs):
                body = section(jobs, name, 2) or ""
                step = workflow_step(
                    body, 4, "name", "Validate repository toolchain data"
                )
                if step is None:
                    continue
                with self.subTest(workflow=path.name, job=name):
                    commands = executable_run_block(step, 4)
                    self.assertTrue(commands)
                    script = "\n".join(commands)
                    environment = {
                        "PATH": str(Path(sys.executable).resolve().parent)
                        + os.pathsep
                        + os.defpath,
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_SHA": head,
                    }
                    binding = re.findall(
                        r"(?m)^      SOURCE_SHA: (.+)$", section(body, "env", 4) or ""
                    )
                    if binding == ["${{ inputs.source_sha }}"]:
                        environment["SOURCE_SHA"] = head
                    result = subprocess.run(
                        ["bash", "--noprofile", "--norc", "-c", script],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    checked.append((path.name, name))
                    if 'test "$GITHUB_SHA" = "$SOURCE_SHA"' not in commands:
                        continue
                    main_guards.append((path.name, name))
                    for overrides in (
                        {"GITHUB_REF": "refs/tags/v0.10.0"},
                        {"GITHUB_SHA": "0" * 40},
                        {"GITHUB_SHA": "0" * 40, "SOURCE_SHA": "0" * 40},
                        {"SOURCE_SHA": None},
                    ):
                        with self.subTest(overrides=overrides):
                            rejected = environment.copy()
                            for key, value in overrides.items():
                                if value is None:
                                    rejected.pop(key, None)
                                else:
                                    rejected[key] = value
                            result = subprocess.run(
                                ["bash", "--noprofile", "--norc", "-c", script],
                                cwd=ROOT,
                                env=rejected,
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(result.stdout, "")
        self.assertEqual(len(checked), 29)
        self.assertEqual(len(main_guards), 6)

    def test_main_source_validation_requires_its_job_input_binding(self) -> None:
        from tools.check_validation_gates import section, toolchain_data_loads_guarded

        for relative in (
            ".github/workflows/release.yml",
            ".github/workflows/release-promotion.yml",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            jobs = section(source, "jobs") or ""
            headers = list(re.finditer(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):$", jobs))
            for index, header in enumerate(headers):
                end = (
                    headers[index + 1].start()
                    if index + 1 < len(headers)
                    else len(jobs)
                )
                body = jobs[header.start() : end]
                if 'test "$GITHUB_SHA" = "$SOURCE_SHA"' not in body:
                    continue
                marker = "      SOURCE_SHA: ${{ inputs.source_sha }}\n"
                with self.subTest(workflow=relative, job=header[1]):
                    self.assertEqual(body.count(marker), 1)
                    for replacement in (
                        "",
                        "      SOURCE_SHA: deadbeef\n",
                        "      SOURCE_SHA: ${{ github.sha }}\n",
                    ):
                        with self.subTest(binding=replacement):
                            changed = source.replace(
                                body, body.replace(marker, replacement, 1), 1
                            )
                            self.assertFalse(
                                toolchain_data_loads_guarded(
                                    changed,
                                    require_load=True,
                                    workflow_name=relative,
                                )
                            )

    def test_existing_contract_has_every_reviewed_key(self) -> None:
        self.assertEqual(set(validate(CONTRACT)), EXPECTED_KEYS)

    def test_shell_metacharacters_and_commands_are_rejected(self) -> None:
        original = CONTRACT.read_bytes()
        for payload in (
            b"RUST_VERSION=1.98.0;id>/tmp/proof",
            b"RUST_VERSION=$(id)",
            b"RUST_VERSION=" + bytes([96]) + b"id" + bytes([96]),
            b"RUST_VERSION=1.98.0&&id",
            b"RUST_VERSION=1.98.0|id",
            b"RUST_VERSION=1.98.0>proof",
            b"RUST_VERSION=1.98.0 # comment",
            b"RUST_VERSION=1.98.0\nexport INJECTED=1",
            b"RUST_VERSION=1.98.0\nRUST_VERSION=1.98.0",
            b"RUST_VERSION=1.98.0\nBASH_ENV=proof",
        ):
            with self.subTest(payload=payload):
                self.assertRaises(
                    ValueError,
                    validate_bytes,
                    original.replace(b"RUST_VERSION=1.98.0", payload),
                )

    def test_wrong_pin_and_missing_key_are_rejected(self) -> None:
        original = CONTRACT.read_bytes()
        self.assertRaises(
            ValueError,
            validate_bytes,
            original.replace(b"HOST_OS=Linux", b"HOST_OS=Windows"),
        )
        self.assertRaises(
            ValueError,
            validate_bytes,
            original.replace(b"RUST_VERSION=1.98.0\n", b""),
        )
        self.assertRaises(
            ValueError,
            validate_bytes,
            original.replace(b"ACTIONLINT_SHA256=", b"ACTIONLINT_SHA256=xx"),
        )

    def test_symlinked_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "real.env"
            source.write_bytes(CONTRACT.read_bytes())
            alias = root / "alias.env"
            alias.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "symlinked"):
                validate(alias)

    def test_executable_toolchain_contract_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "versions.env"
            contract.write_bytes(CONTRACT.read_bytes())
            contract.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "executable"):
                validate(contract)

    def test_entrypoint_denies_tampering_before_shell_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "versions.env"
            marker = Path(directory) / "executed"
            payload = f"RUST_VERSION=1.98.0;touch {marker}".encode("utf-8")
            source.write_bytes(
                CONTRACT.read_bytes().replace(b"RUST_VERSION=1.98.0", payload)
            )
            command = (
                "set -e; "
                f'{sys.executable} -I -S tools/check_toolchain_env.py "{source}"; '
                f'source "{source}"'
            )
            result = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_isolated_script_skips_mutable_tools_package_initializer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools_dir = root / "tools"
            tools_dir.mkdir()
            (tools_dir / "check_toolchain_env.py").write_bytes(
                (ROOT / "tools/check_toolchain_env.py").read_bytes()
            )
            (tools_dir / "__init__.py").write_text(
                "from pathlib import Path\nPath('executed').write_text('unsafe')\n",
                encoding="utf-8",
            )
            source = root / "versions.env"
            source.write_bytes(CONTRACT.read_bytes())
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "tools/check_toolchain_env.py",
                    str(source),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "executed").exists())

    def test_readonly_release_rust_version_is_strictly_validated(self) -> None:
        command = [
            sys.executable,
            "-I",
            "-S",
            str(ROOT / "tools/check_toolchain_env.py"),
            "--rust-version",
        ]
        good = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(good.stdout, validate(CONTRACT)["RUST_VERSION"] + "\n")

        with tempfile.TemporaryDirectory() as directory:
            contract = Path(directory) / "tools/codex/versions.env"
            contract.parent.mkdir(parents=True)
            original = CONTRACT.read_bytes()
            self.assertIn(b"RUST_VERSION=1.98.0", original)
            for payload in (
                b"RUST_VERSION=1.98.0;id",
                b"RUST_VERSION=$(id)",
                b"RUST_VERSION=1.98.0\nRUST_VERSION=1.98.0",
            ):
                with self.subTest(payload=payload):
                    contract.write_bytes(
                        original.replace(b"RUST_VERSION=1.98.0", payload)
                    )
                    denied = subprocess.run(
                        command,
                        cwd=directory,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=20,
                    )
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertEqual(denied.stdout, "")
                    self.assertIn("unsafe toolchain contract", denied.stderr)

    def test_ruff_reader_and_diagnostic_use_shared_strict_validator(self) -> None:
        command = [
            sys.executable,
            "-I",
            "-S",
            str(ROOT / "tools/check_toolchain_env.py"),
            "--ruff-version",
        ]
        good = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=20
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(good.stdout, validate(CONTRACT)["RUFF_VERSION"] + "\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tools/codex/versions.env"
            source.parent.mkdir(parents=True)
            source.write_bytes(
                CONTRACT.read_bytes().replace(
                    b"RUST_VERSION=1.98.0", b"RUST_VERSION=1.98.0;id"
                )
            )
            denied = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(denied.stdout, "")

        from tools.codex.doctor import versions

        self.assertEqual(versions(), validate(CONTRACT))

    def test_toolchain_readers_do_not_reimplement_schema(self) -> None:
        self.assertIn(
            "from tools.check_toolchain_env import validate",
            (ROOT / "tools/codex/doctor.py").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "pinned_ruff_version()",
            (ROOT / "tools/xtask/src/main.rs").read_text(encoding="utf-8"),
        )
        self.assertNotIn(
            'strip_prefix("RUFF_VERSION=")',
            (ROOT / "tools/xtask/src/main.rs").read_text(encoding="utf-8"),
        )

    def test_release_toolchain_reader_never_sources_contract(self) -> None:
        from tools.check_validation_gates import toolchain_data_loads_guarded

        workflow = (ROOT / ".github/workflows/crates-io-publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            workflow.count(
                'rust_version="$(/usr/bin/python3 -I -S '
                'tools/check_toolchain_env.py --rust-version)"'
            ),
            1,
        )
        self.assertNotIn("source tools/codex/versions.env", workflow)
        self.assertNotIn(". tools/codex/versions.env", workflow)
        self.assertEqual(
            workflow.count(
                "python3 -I -S tools/check_toolchain_env.py tools/codex/versions.env"
            ),
            3,
        )
        # Only the three new data-validation commands may name the contract;
        # preserve the original ban on all other release-path references.
        self.assertNotIn(
            "tools/codex/versions.env",
            workflow.replace(
                "python3 -I -S tools/check_toolchain_env.py tools/codex/versions.env",
                "",
            ),
        )
        self.assertTrue(
            toolchain_data_loads_guarded(
                workflow,
                require_load=True,
                workflow_name=".github/workflows/crates-io-publish.yml",
            )
        )

    def test_release_preparation_markdown_is_literal_data(self) -> None:
        workflow = (ROOT / ".github/workflows/release-preparation.yml").read_text(
            encoding="utf-8"
        )
        commands = [
            line.strip()
            for line in workflow.splitlines()
            if line.strip().startswith("printf '%s %s\\n'")
        ]
        self.assertEqual(len(commands), 1)
        description = "Review data $(printf unexpected) `printf unexpected`"
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", commands[0]],
            env={"preparation_description": description},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            description + " Product claims, qualification narratives, authority "
            "boundaries and roadmap release state were already reviewed on the "
            "preceding `release: ready` source.\n",
        )

    def test_workflow_guard_requires_validated_data_load(self) -> None:
        from tools.check_validation_gates import (
            TOOLCHAIN_VALUES_NONEMPTY,
            TOOLCHAIN_VALUES_READ,
            TOOLCHAIN_WORKFLOW_LOAD,
            toolchain_data_loads_guarded,
        )

        guard = "python3 -I -S tools/check_toolchain_env.py tools/codex/versions.env"
        source = "source tools/codex/versions.env"

        def block(*commands: str) -> str:
            return (
                "jobs:\n  verify:\n    steps:\n"
                "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
                "      - name: Load contract\n"
                "        id: toolchain_data\n"
                "        run: |\n"
                + "".join(f"          {command}\n" for command in commands)
            )

        valid = block(
            "set -euo pipefail",
            TOOLCHAIN_WORKFLOW_LOAD,
            TOOLCHAIN_VALUES_READ,
            TOOLCHAIN_VALUES_NONEMPTY,
        )
        self.assertTrue(toolchain_data_loads_guarded(valid, require_load=True))
        for invalid in (
            block("set -euo pipefail", guard, source),
            block("set -euo pipefail", TOOLCHAIN_WORKFLOW_LOAD, TOOLCHAIN_VALUES_READ),
            block(
                "set -euo pipefail",
                TOOLCHAIN_WORKFLOW_LOAD + " || true",
                TOOLCHAIN_VALUES_READ,
                TOOLCHAIN_VALUES_NONEMPTY,
            ),
            block(
                "set -euo pipefail",
                TOOLCHAIN_WORKFLOW_LOAD,
                TOOLCHAIN_VALUES_READ,
                "echo pre-check",
                TOOLCHAIN_VALUES_NONEMPTY,
            ),
            block("set -euo pipefail", guard, "echo skipped", source),
            block("set -euo pipefail", "echo " + guard, source),
            block("set -euo pipefail", guard + " || true", source),
            block("set -euo pipefail", "false &&", guard, source),
            block("set -euo pipefail", "if false; then", guard, "fi", source),
            block("set -euo pipefail", "true ||", guard, source),
            block("set -euo pipefail", "set +e", guard, source),
            block("set -euo pipefail", "false; true", guard, source),
            block("set -euo pipefail", "function fake() {", guard, "}", source),
            block("set -euo pipefail", "eval 'true'", guard, source),
            block("set -euo pipefail", guard, "false &&", source),
            block("set -euo pipefail", guard, "\\source tools/codex/versions.env"),
            block("set -euo pipefail", guard, "source${IFS}tools/codex/versions.env"),
            block("set -euo pipefail", guard, 'source "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, "source\\"),
            block("set -euo pipefail", guard, 'source\\\\ "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, '. "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'eval "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'bash -c "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'bash -lc "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'run: source "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'run: . "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'true; source "$TOOLCHAIN"'),
            block("set -euo pipefail", guard, 'if true; then source "$TOOLCHAIN"; fi'),
            (
                block("set -euo pipefail", guard, source)
                + "      - name: Early indirect toolchain load\n"
                + "        run: |\n"
                + '          load_contract() { source "$1"; }\n'
                + "          load_contract tools/codex/versions.env\n"
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - name: Early indirect toolchain load\n"
                "        run: |\n"
                '          load_contract() { source "$1"; }\n'
                "          load_contract tools/codex/versions.env\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            block("set -euo pipefail", guard, source)
            + "      - name: Function alias bypass\n"
            "        run: |\n"
            '          load_contract() { . "$1"; }\n'
            "          load_contract tools/codex/versions.env\n",
            block("set -euo pipefail", guard, source) + "      - name: Builtin bypass\n"
            "        run: |\n"
            '          load_contract() { builtin source "$1"; }\n'
            "          load_contract tools/codex/versions.env\n",
            block("set -euo pipefail", guard, source) + "      - name: Alias bypass\n"
            "        run: |\n"
            "          alias load_contract='source tools/codex/versions.env'\n"
            "          shopt -s expand_aliases\n"
            "          load_contract\n",
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - name: Early opaque execution\n"
                "        run: |\n"
                "          cat tools/codex/versions.env > /tmp/staged-toolchain\n"
                "          bash /tmp/staged-toolchain\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - run: bash tools/codex/versions.env\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - run: |\n"
                "          bash tools/codex/versions.env\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - run: >-\n"
                "          bash tools/codex/versions.env\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                '      - run: source "$TOOLCHAIN"\n'
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - name: Inline toolchain execution\n"
                "        run: bash tools/codex/versions.env\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            block(
                "set -euo pipefail", guard, 'load_contract() { source "$1"; }', source
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - name: Folded shell execution\n"
                "        run: >-\n"
                "          cat tools/codex/versions.env | bash\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            (
                "jobs:\n  verify:\n    steps:\n"
                "      - name: Chomped literal shell execution\n"
                "        run: |-\n"
                "          bash tools/codex/versions.env\n"
                + block("set -euo pipefail", guard, source).split(
                    "jobs:\n  verify:\n    steps:\n", 1
                )[1]
            ),
            block("set -euo pipefail", guard, 'load_contract() { . "$1"; }', source),
            block(
                "set -euo pipefail",
                guard,
                'load_contract() { builtin source "$1"; }',
                source,
            ),
            block(
                "set -euo pipefail",
                guard,
                "alias load_contract='source tools/codex/versions.env'",
                source,
            ),
            block("set -euo pipefail", guard, "\\. tools/codex/versions.env"),
            block("set -euo pipefail", guard, source).replace(
                "      - name: Load contract\n",
                "      - name: Load contract\n        if: false\n",
            ),
            block("set -euo pipefail", guard, source).replace(
                "      - name: Load contract\n",
                "      - name: Load contract\n        continue-on-error: true\n",
            ),
            block("set -euo pipefail", guard, source).replace(
                "      - name: Load contract\n",
                "      - name: Load contract\n        shell: sh\n",
            ),
            block("set -euo pipefail", guard, source).replace(
                "        run: |\n",
                "        if: false\n        run: |\n",
            ),
            block("set -euo pipefail", guard, source).replace(
                "        run: |\n",
                "        env:\n          BASH_ENV: /tmp/skipper\n        run: |\n",
            ),
            block("set -euo pipefail", guard, source).replace(
                "        run: |\n",
                "        shell: bash -c 'true'\n        run: |\n",
            ),
            block("set -euo pipefail", guard, source).replace(
                "          source tools/codex/versions.env\n",
                "          source tools/codex/versions.env\n        if: false\n",
            ),
            block("set -euo pipefail", guard, source, source),
            block("set -euo pipefail", guard, ". tools/codex/versions.env"),
            block(
                "set -euo pipefail",
                guard,
                "bash -c 'source tools/codex/versions.env'",
            ),
            block("set -euo pipefail", "cat <<'EOT'", guard, source, "EOT"),
            block("set -euo pipefail", guard, "cat <<'EOT'", source, "EOT"),
            block("set -euo pipefail", guard)
            + "      - name: Later step\n        run: |\n          "
            + source,
            "      - name: Text only\n        env:\n          SOURCE: |\n"
            "            " + guard + "\n            " + source + "\n",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(
                    toolchain_data_loads_guarded(invalid, require_load=True)
                )
        for startup in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            with self.subTest(startup=startup):
                valid_workflow = valid
                malicious_workflows = (
                    f"env:\n  {startup}: ./inject.sh\n" + valid_workflow,
                    valid_workflow.replace(
                        "  verify:\n",
                        f"  verify:\n    env:\n      {startup}: ./inject.sh\n",
                    ),
                    valid_workflow.replace(
                        "      - name: Load contract\n",
                        "      - name: prior\n"
                        f'        run: echo "{startup}=./inject.sh" >> "$GITHUB_ENV"\n'
                        "      - name: Load contract\n",
                    ),
                )
                for malicious in malicious_workflows:
                    self.assertFalse(
                        toolchain_data_loads_guarded(malicious, require_load=True)
                    )
        self.assertTrue(
            toolchain_data_loads_guarded(
                "env:\n  BASH_ENV: ''\n  ENV: ''\n" + valid,
                require_load=True,
            )
        )
        self.assertFalse(
            toolchain_data_loads_guarded(block("set -euo pipefail", guard, source))
        )
        self.assertTrue(toolchain_data_loads_guarded(block("echo no contract")))
        self.assertFalse(
            toolchain_data_loads_guarded(block("echo no contract"), require_load=True)
        )
        self.assertFalse(
            toolchain_data_loads_guarded(block("cat tools/codex/versions.env | bash"))
        )
        self.assertFalse(
            toolchain_data_loads_guarded(
                "jobs:\n  verify:\n    steps:\n"
                "      - name: Unrecognized folded execution\n"
                "        run: >-\n"
                "          cat tools/codex/versions.env | bash\n"
            )
        )

    def test_every_workflow_consumer_is_guarded_and_routed(self) -> None:
        from tools.check_validation_gates import (
            TOOLCHAIN_DATA_WORKFLOWS,
            toolchain_data_loads_guarded,
        )

        matrix = tomllib.loads(
            (ROOT / "contracts/qualification-gate-matrix.toml").read_text(
                encoding="utf-8"
            )
        )
        gates = {entry["workflow"]: entry for entry in matrix["gate"]}
        validator_paths = {
            "tools/check_toolchain_env.py",
            "tests/tooling/test_toolchain_env.py",
        }
        self.assertTrue(TOOLCHAIN_DATA_WORKFLOWS)
        for path in TOOLCHAIN_DATA_WORKFLOWS:
            with self.subTest(path=path):
                source = (ROOT / path).read_text(encoding="utf-8")
                self.assertTrue(
                    toolchain_data_loads_guarded(
                        source, require_load=True, workflow_name=path
                    )
                )
                if path in gates and not gates[path]["mandatory"]:
                    self.assertTrue(validator_paths.issubset(set(gates[path]["paths"])))
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            with self.subTest(extra=path.name):
                self.assertTrue(
                    toolchain_data_loads_guarded(
                        path.read_text(encoding="utf-8"),
                        require_load=True,
                        workflow_name=path.relative_to(ROOT).as_posix(),
                    )
                )

    def test_reusable_vm_caller_routes_guard_dependencies(self) -> None:
        wrapper = (ROOT / ".github/workflows/control1-plan-preview-vm.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "uses: ./.github/workflows/vm-acceptance.yml",
            wrapper,
        )
        for path in (
            "tools/check_toolchain_env.py",
            "tests/tooling/test_toolchain_env.py",
        ):
            self.assertEqual(wrapper.count(f'      - "{path}"'), 1)

    def test_all_consumers_load_validated_data_without_source(self) -> None:
        from tools.check_validation_gates import (
            TOOLCHAIN_LOCAL_LOAD,
            TOOLCHAIN_DATA_WORKFLOWS,
            TOOLCHAIN_VALUES_NONEMPTY,
            TOOLCHAIN_VALUES_READ,
            TOOLCHAIN_WORKFLOW_LOAD,
            TOOLCHAIN_WORKSTATION_LOAD,
        )

        for name in TOOLCHAIN_DATA_WORKFLOWS:
            with self.subTest(workflow=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertNotIn("source tools/codex/versions.env", source)
                self.assertGreater(source.count(TOOLCHAIN_WORKFLOW_LOAD), 0)
                self.assertEqual(
                    source.count(TOOLCHAIN_WORKFLOW_LOAD),
                    source.count(TOOLCHAIN_VALUES_READ),
                )
                self.assertEqual(
                    source.count(TOOLCHAIN_VALUES_READ),
                    source.count(TOOLCHAIN_VALUES_NONEMPTY),
                )
        for name in (
            "scripts/setup_codex_environment.sh",
            "scripts/preflight_codex_environment.sh",
        ):
            with self.subTest(script=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertNotIn('source "$VERSION_CONTRACT"', source)
                self.assertEqual(source.count(TOOLCHAIN_LOCAL_LOAD), 1)
                self.assertEqual(source.count(TOOLCHAIN_VALUES_READ), 1)
                self.assertEqual(source.count(TOOLCHAIN_VALUES_NONEMPTY), 1)
        workstation = (
            ROOT / "qualification/v010/workstation-acceptance/launch-interactive.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn('source "$build_root/tools/codex/versions.env"', workstation)
        self.assertIn(TOOLCHAIN_WORKSTATION_LOAD, workstation)
        self.assertEqual(workstation.count(TOOLCHAIN_VALUES_READ), 1)
        self.assertEqual(workstation.count(TOOLCHAIN_VALUES_NONEMPTY), 1)

    def test_cli_emits_exactly_validated_fixed_order_values(self) -> None:
        command = [
            sys.executable,
            "-I",
            "-S",
            str(ROOT / "tools/check_toolchain_env.py"),
            "--values",
            str(CONTRACT),
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            " ".join(validate(CONTRACT)[key] for key in sorted(EXPECTED_KEYS)) + "\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            unsafe = Path(directory) / "versions.env"
            unsafe.write_bytes(CONTRACT.read_bytes() + b"EVIL=1\n")
            command[-1] = str(unsafe)
            denied = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(denied.stdout, "")


if __name__ == "__main__":
    unittest.main()
