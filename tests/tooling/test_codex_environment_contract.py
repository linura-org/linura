from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CodexEnvironmentContractTests(unittest.TestCase):
    def _exercise_rustup_bootstrap(
        self,
        *,
        curl_fail: bool = False,
        installer_fail: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], str | None, bool | None]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            installer = temp / "fake-installer"
            observed_basename = temp / "observed-basename"
            observed_dir = temp / "observed-dir"

            installer.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    printf '%s\\n' "${0##*/}" > "$OBSERVED_BASENAME"
                    printf '%s\\n' "${0%/*}" > "$OBSERVED_DIR"
                    if [[ "${FAKE_INSTALLER_FAIL:-0}" == "1" ]]; then
                      exit 43
                    fi
                    """
                ),
                encoding="utf-8",
            )
            curl = fake_bin / "curl"
            curl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    output=''
                    while [[ $# -gt 0 ]]; do
                      case "$1" in
                        --output)
                          output="$2"
                          shift 2
                          ;;
                        *)
                          shift
                          ;;
                      esac
                    done
                    test -n "$output"
                    printf '%s\\n' "${output%/*}" > "$OBSERVED_DIR"
                    if [[ "${FAKE_CURL_FAIL:-0}" == "1" ]]; then
                      exit 42
                    fi
                    cp "$FAKE_INSTALLER" "$output"
                    """
                ),
                encoding="utf-8",
            )
            curl.chmod(0o755)

            digest = hashlib.sha256(installer.read_bytes()).hexdigest()
            env = os.environ.copy()
            env.update(
                {
                    "BOOTSTRAP_LIB": str(ROOT / "scripts/lib/bootstrap_rustup.sh"),
                    "EXPECTED_SHA": digest,
                    "FAKE_CURL_FAIL": "1" if curl_fail else "0",
                    "FAKE_INSTALLER": str(installer),
                    "FAKE_INSTALLER_FAIL": "1" if installer_fail else "0",
                    "OBSERVED_BASENAME": str(observed_basename),
                    "OBSERVED_DIR": str(observed_dir),
                    "PATH": f"{fake_bin}:{env['PATH']}",
                }
            )
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$BOOTSTRAP_LIB"; bootstrap_rustup '
                    '"https://example.invalid/rustup-init" "$EXPECTED_SHA" '
                    '"x86_64-unknown-linux-gnu"',
                ],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            basename = (
                observed_basename.read_text(encoding="utf-8").strip()
                if observed_basename.exists()
                else None
            )
            bootstrap_dir_exists: bool | None = None
            if observed_dir.exists():
                bootstrap_dir = Path(observed_dir.read_text(encoding="utf-8").strip())
                bootstrap_dir_exists = bootstrap_dir.exists()
            return completed, basename, bootstrap_dir_exists

    def test_rustup_bootstrap_is_pinned_and_digest_verified(self) -> None:
        versions = (ROOT / "tools/codex/versions.env").read_text(encoding="utf-8")
        setup = (ROOT / "scripts/setup_codex_environment.sh").read_text(encoding="utf-8")
        bootstrap = (ROOT / "scripts/lib/bootstrap_rustup.sh").read_text(encoding="utf-8")

        self.assertRegex(versions, r"(?m)^RUSTUP_VERSION=\d+\.\d+\.\d+$")
        self.assertRegex(versions, r"(?m)^RUSTUP_INIT_SHA256=[0-9a-f]{64}$")
        self.assertIn(
            'https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TARGET}/rustup-init',
            setup,
        )
        self.assertIn(
            'bootstrap_rustup "$RUSTUP_INIT_URL" "$RUSTUP_INIT_SHA256" "$RUSTUP_TARGET"',
            setup,
        )
        self.assertIn("sha256sum --check --strict", bootstrap)
        self.assertIn("--default-toolchain none", bootstrap)

    def test_rustup_bootstrap_executes_canonical_basename_and_cleans_success(self) -> None:
        completed, basename, bootstrap_dir_exists = self._exercise_rustup_bootstrap()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(basename, "rustup-init")
        self.assertFalse(bootstrap_dir_exists)

    def test_rustup_bootstrap_cleans_tempdir_on_installer_failure(self) -> None:
        completed, basename, bootstrap_dir_exists = self._exercise_rustup_bootstrap(
            installer_fail=True
        )

        self.assertEqual(completed.returncode, 43, completed.stderr)
        self.assertEqual(basename, "rustup-init")
        self.assertFalse(bootstrap_dir_exists)

    def test_rustup_bootstrap_cleans_tempdir_on_download_failure(self) -> None:
        completed, basename, bootstrap_dir_exists = self._exercise_rustup_bootstrap(
            curl_fail=True
        )

        self.assertEqual(completed.returncode, 42, completed.stderr)
        self.assertIsNone(basename)
        self.assertFalse(bootstrap_dir_exists)

    def test_bindings_recreation_drops_contaminated_cache(self) -> None:
        setup = (ROOT / "scripts/setup_codex_environment.sh").read_text(encoding="utf-8")
        self.assertIn('python3 -m venv --clear "$python_root"', setup)
        self.assertIn('[[ -L "$TOOL_ROOT" || -L "$python_root" ]]', setup)
        self.assertIn("--no-cache-dir --require-hashes --only-binary=:all: --no-deps", setup)
        self.assertIn('.linura-bindings-lock-sha256', setup)
        with tempfile.TemporaryDirectory() as temp:
            environment = Path(temp) / "python"
            subprocess.run([sys.executable, "-m", "venv", str(environment)],
                           check=True, capture_output=True, text=True)
            stale = environment / "lib/python-stale-contamination"
            stale.parent.mkdir(exist_ok=True)
            stale.write_text("undeclared package survives\n", encoding="utf-8")
            subprocess.run([sys.executable, "-m", "venv", "--clear", str(environment)],
                           check=True, capture_output=True, text=True)
            self.assertFalse(stale.exists())

    def test_fresh_host_does_not_require_preinstalled_rustup(self) -> None:
        setup = (ROOT / "scripts/setup_codex_environment.sh").read_text(encoding="utf-8")
        host_loop = re.search(
            r"for command_name in (?P<commands>[^;]+); do\n\s+require_command",
            setup,
        )
        self.assertIsNotNone(host_loop)
        assert host_loop is not None
        self.assertNotIn("rustup", host_loop.group("commands").split())
        self.assertIn("if ! command -v rustup", setup)

    def test_fresh_host_contract_requires_supported_glibc_and_linker(self) -> None:
        for script_name in (
            "scripts/setup_codex_environment.sh",
            "scripts/preflight_codex_environment.sh",
        ):
            script = (ROOT / script_name).read_text(encoding="utf-8")
            host_loop = re.search(
                r"for command_name in (?P<commands>[^;]+); do\n\s+require_command",
                script,
            )
            self.assertIsNotNone(host_loop, script_name)
            assert host_loop is not None
            commands = set(host_loop.group("commands").split())
            self.assertIn("cc", commands, script_name)
            self.assertIn("getconf", commands, script_name)
            self.assertIn("getconf GNU_LIBC_VERSION", script, script_name)
            self.assertIn("MIN_GLIBC_MAJOR=2", script, script_name)
            self.assertIn("MIN_GLIBC_MINOR=17", script, script_name)
            self.assertIn("unsupported glibc version", script, script_name)

    def test_custom_cargo_home_is_the_rust_tool_bin_root(self) -> None:
        for script_name in (
            "scripts/setup_codex_environment.sh",
            "scripts/preflight_codex_environment.sh",
        ):
            script = (ROOT / script_name).read_text(encoding="utf-8")
            self.assertIn(
                'readonly CARGO_ROOT="${CARGO_HOME:-${HOME}/.cargo}"',
                script,
                script_name,
            )
            self.assertIn('export CARGO_HOME="$CARGO_ROOT"', script, script_name)
            self.assertIn('${CARGO_ROOT}/bin:', script, script_name)

    def test_rustup_cannot_self_update_during_pinned_toolchain_install(self) -> None:
        setup = (ROOT / "scripts/setup_codex_environment.sh").read_text(encoding="utf-8")
        disable = "rustup set auto-self-update disable"
        install = (
            'rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal '
            '--component clippy --component rustfmt --no-self-update'
        )
        self.assertIn(disable, setup)
        self.assertIn(install, setup)
        self.assertLess(setup.index(disable), setup.index(install))
        self.assertGreaterEqual(
            setup.count('reports_exact_version "$RUSTUP_VERSION" rustup --version'),
            2,
        )
        self.assertIn("rustup self-updated during toolchain setup", setup)

    def test_rust_toolchain_host_is_fully_qualified_and_verified(self) -> None:
        setup = (ROOT / "scripts/setup_codex_environment.sh").read_text(encoding="utf-8")
        preflight = (ROOT / "scripts/preflight_codex_environment.sh").read_text(encoding="utf-8")
        for script in (setup, preflight):
            self.assertIn(
                'readonly RUST_TOOLCHAIN="${RUST_VERSION}-${RUSTUP_TARGET}"',
                script,
            )
        self.assertIn('rustup set default-host "$RUSTUP_TARGET"', setup)
        self.assertIn('rustup toolchain install "$RUST_TOOLCHAIN"', setup)
        self.assertIn('rustup default "$RUST_TOOLCHAIN"', setup)
        self.assertIn('active_toolchain="$(rustup show active-toolchain', setup)
        self.assertIn('active_toolchain="$(rustup show active-toolchain', preflight)
        self.assertIn('$1 == toolchain', preflight)
        self.assertIn('rustup which --toolchain "$RUST_TOOLCHAIN" rustc', preflight)
        self.assertIn('rustup which --toolchain "$RUST_TOOLCHAIN" cargo', preflight)

    def test_task_preflight_requires_exact_rustup_version(self) -> None:
        preflight = (ROOT / "scripts/preflight_codex_environment.sh").read_text(encoding="utf-8")
        self.assertIn(': "${RUSTUP_VERSION:?}"', preflight)
        self.assertIn('reports_exact_version "$RUSTUP_VERSION" rustup --version', preflight)


if __name__ == "__main__":
    unittest.main()
