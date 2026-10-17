"""Codex native-build infrastructure is deterministic and non-authorizing."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "tools/codex/native-auth"
spec = importlib.util.spec_from_file_location("native_auth_check", BUILDER / "check.py")
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class NativeAuthBuilderTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((BUILDER / "contract.json").read_text())

    def test_base_and_archive_inputs_are_immutable_and_match(self):
        self.assertRegex(
            self.contract["base_image"],
            r"^docker.io/library/buildpack-deps@sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(self.contract["platform"], "linux/amd64")
        dockerfile = (BUILDER / "Dockerfile").read_text()
        self.assertEqual(
            re.findall(r"(?m)^FROM (.+)$", dockerfile),
            [
                self.contract["base_image"] + " AS native-auth-dependencies",
                "native-auth-dependencies",
            ],
        )
        for file, scheme in (("ubuntu-snapshot.list", "https"),):
            lines = (BUILDER / file).read_text().splitlines()
            self.assertEqual(len(lines), 3)
            for line, suite in zip(lines, ("noble", "noble-updates", "noble-security")):
                self.assertEqual(
                    line,
                    "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                    f"{scheme}://snapshot.ubuntu.com/ubuntu/{self.contract['snapshot']} {suite} main universe",
                )
        self.assertIn("Dir::Etc::sourceparts=-", dockerfile)
        self.assertIn("APT::Update::Error-Mode=any", dockerfile)
        for forbidden in (
            "trusted=yes",
            "AllowUnauthenticated",
            "--allow-unauthenticated",
            "Verify-Peer=false",
            "Check-Valid-Until=false",
            "latest",
            "ADD https:",
        ):
            self.assertNotIn(forbidden, dockerfile)

    def test_context_is_minimal_and_declares_no_qualification(self):
        self.assertEqual(
            (BUILDER / ".dockerignore").read_text().splitlines(),
            [
                "**",
                "!Dockerfile",
                "!ubuntu-snapshot.list",
                "!packages.txt",
                "!contract.json",
                "!check.py",
            ],
        )
        self.assertIs(self.contract["qualification_evidence"], False)
        self.assertEqual(self.contract["purpose"], "development-build-only")
        self.assertIn("USER 1000:1000", (BUILDER / "Dockerfile").read_text())
        self.assertIn(
            "USER 1000:1000\nRUN --network=none python3 /opt/linura-native-auth/check.py --json",
            (BUILDER / "Dockerfile").read_text(),
        )
        self.assertIn("libpolkit-agent-1-dev", (BUILDER / "packages.txt").read_text())
        self.assertIn("<polkitagent/polkitagent.h>", checker.API_PROBE.decode())
        self.assertIn("<gio/gio.h>", checker.API_PROBE.decode())
        packages = (BUILDER / "packages.txt").read_text().splitlines()
        for package in checker.QML_PACKAGES:
            self.assertIn(f"{package}={self.contract['qml_runtime_version']}", packages)

    def test_version_mismatch_missing_headers_and_tools_fail(self):
        inventory = "synthetic-build-package\t1"
        self.contract["installed_packages_sha256"] = hashlib.sha256(
            (inventory + "\n").encode()
        ).hexdigest()

        def native(argv, input_bytes=None, *, merge_stderr=False):
            if argv[:2] == ["/usr/bin/pkg-config", "--modversion"]:
                return self.contract["modules"][argv[2]]
            if argv[0] == "/usr/bin/dpkg-query":
                if tuple(argv[-len(checker.QML_PACKAGES) :]) == checker.QML_PACKAGES:
                    return "\n".join(
                        ["ii \t" + self.contract["qml_runtime_version"]]
                        * len(checker.QML_PACKAGES)
                    )
                return inventory
            tool = Path(argv[0]).name
            if tool in self.contract["tools"]:
                value = self.contract["tools"][tool]
                return f"cmake version {value}" if tool == "cmake" else value
            return ""

        with (
            patch.object(checker.platform, "system", return_value="Linux"),
            patch.object(checker.platform, "machine", return_value="x86_64"),
            patch.object(
                checker.platform,
                "python_version",
                return_value=self.contract["python_version"],
            ),
            patch.object(checker.os, "getuid", return_value=1000),
            patch.object(checker.os, "geteuid", return_value=1000),
            patch.object(
                checker.Path,
                "read_text",
                return_value='ID=ubuntu\nVERSION_ID="24.04"\n',
            ),
            patch.object(checker, "probe", side_effect=native),
        ):
            self.assertTrue(all(checker.checks(self.contract).values()))

            def missing(argv, input_bytes=None, *, merge_stderr=False):
                if argv[0] in (
                    "/usr/bin/c++",
                    "/usr/bin/cmake",
                    "/usr/bin/ninja",
                    "/usr/bin/wayland-scanner",
                ):
                    return None
                if argv[-1] == "polkit-agent-1" and "--modversion" in argv:
                    return "124.0"  # Substrings/aliases do not match an exact pin.
                if tuple(argv[-len(checker.QML_PACKAGES) :]) == checker.QML_PACKAGES:
                    return None
                return native(argv, input_bytes)

            with patch.object(checker, "probe", side_effect=missing):
                status = checker.checks(self.contract)
                self.assertFalse(status["module:polkit-agent-1"])
                self.assertFalse(status["official-authentication-headers"])
                self.assertFalse(status["tool:cmake"])
                self.assertFalse(status["tool:ninja"])
                self.assertFalse(status["tool:wayland-scanner"])
                self.assertFalse(status["official-qml-runtime-packages"])

    def test_incomplete_alias_duplicate_and_authorizing_contracts_fail(self):
        checker.validate_contract(self.contract)
        for name in (
            "installed_packages_sha256",
            "qml_runtime_version",
            "modules",
            "tools",
            "purpose",
            "qualification_evidence",
        ):
            invalid = dict(self.contract)
            del invalid[name]
            with self.assertRaises((ValueError, KeyError)):
                checker.validate_contract(invalid)
        invalid = dict(self.contract, qualification_evidence=True)
        with self.assertRaises(ValueError):
            checker.validate_contract(invalid)
        invalid = dict(self.contract, modules={"polkit-agent-1": "124"})
        with self.assertRaises(ValueError):
            checker.validate_contract(invalid)
        for alias in (True, 1.0, "1"):
            with self.assertRaises(ValueError):
                checker.validate_contract(dict(self.contract, schema_version=alias))
        with self.assertRaises(ValueError):
            json.loads(
                '{"qualification_evidence":false,"qualification_evidence":true}',
                object_pairs_hook=checker.unique_object,
            )

    def test_probe_fails_closed_and_bounds_output(self):
        self.assertIsNone(checker.probe(["/missing/linura-native-build-tool"]))
        self.assertIsNone(
            checker.probe(["/usr/bin/python3", "-c", "raise SystemExit(1)"])
        )
        self.assertIsNone(
            checker.probe(["/usr/bin/python3", "-c", "print('x' * 70000)"])
        )
        self.assertIsNone(
            checker.probe(
                ["/usr/bin/python3", "-c", "import os; os.write(1, bytes([255]))"]
            )
        )
        self.assertIsNone(
            checker.probe(["/usr/bin/python3", "-c", "pass"], b"x" * 4097)
        )

    def test_probe_timeout_and_inherited_stdout_are_bounded(self):
        with patch.object(checker, "TIMEOUT_SECONDS", 0.15):
            self.assertIsNone(
                checker.probe(["/usr/bin/python3", "-c", "import time; time.sleep(10)"])
            )
            # Parent exits successfully but its child retains stdout. This must
            # not keep a readiness probe alive beyond its overall deadline.
            self.assertIsNone(
                checker.probe(
                    [
                        "/usr/bin/python3",
                        "-c",
                        "import os,time; pid=os.fork(); time.sleep(10) if pid == 0 else os._exit(0)",
                    ]
                )
            )

    def test_stderr_version_probe_retains_failure_and_output_bounds(self):
        version = [
            "/usr/bin/python3",
            "-c",
            "import sys; sys.stderr.write('wayland-scanner 1.22.0\\n')",
        ]
        self.assertEqual(checker.probe(version), "")
        self.assertEqual(
            checker.probe(version, merge_stderr=True), "wayland-scanner 1.22.0"
        )
        self.assertIsNone(
            checker.probe(
                ["/usr/bin/python3", "-c", "import sys; sys.stderr.write('x' * 70000)"],
                merge_stderr=True,
            )
        )
        self.assertIsNone(
            checker.probe(
                [
                    "/usr/bin/python3",
                    "-c",
                    "import sys; sys.stderr.write('wayland-scanner 1.22.0'); sys.exit(1)",
                ],
                merge_stderr=True,
            )
        )

    def test_canonical_ci_builds_authentication_without_qualification_shortcuts(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        start = workflow.index(
            "      - name: Build and test native authentication components in pinned builder"
        )
        end = workflow.index("      - name: Run canonical Linura checks", start)
        step = workflow[start:end]
        for required in (
            "tools/codex/native-auth",
            "--platform linux/amd64",
            "--network none",
            "--read-only",
            "--user 1000:1000",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--ulimit core=0",
            "security-owner,target=/source/security-owner,readonly",
            "ui,target=/source/ui,readonly",
            "packaging,target=/source/packaging,readonly",
            "-DLINURA_SECURITY_OWNER_PACKAGING_DIR=/source/packaging",
            "org.linura.SecurityOwner1.xml,target=/source/contracts/org.linura.SecurityOwner1.xml,readonly",
            "-DLINURA_SECURITY_OWNER_CONTRACT=/source/contracts/org.linura.SecurityOwner1.xml",
            "--tmpfs /build:rw,exec,nosuid,nodev",
            "--tmpfs /tmp:rw,nosuid,nodev,noexec",
            "python3 /opt/linura-native-auth/check.py --json",
            "-DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON",
            "ctest --test-dir",
            "cmake --install /build/security-owner --prefix /build/install/usr",
        ):
            self.assertIn(required, step)
        for forbidden in (
            "continue-on-error",
            "|| true",
            "NATIVE_AUTH=OFF",
            "--privileged",
            "docker.sock",
            "qualification_evidence=true",
        ):
            self.assertNotIn(forbidden, step)


if __name__ == "__main__":
    unittest.main()
