from __future__ import annotations

from contextlib import ExitStack
import copy
import datetime as dt
import fcntl
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.codex import doctor, native, native_install as install  # noqa: E402

# Capture the real native guard before any fake package-manager test patch.
REAL_DEVELOPER_GUARD = install.require_developer


class PackageHost(native.Commands):
    """Stateful native package-manager fixture; never executes an OS mutation."""

    def __init__(self, home: Path) -> None:
        super().__init__(ROOT, home)
        self.installed = {"bash": "1.0", "existing-auto": "1.0"}
        self.manual = {"bash"}
        self.calls: list[list[str]] = []
        self.effects: list[list[str]] = []
        self.source = b"source"
        self.repository = b"authenticated-index"
        self.broken = False
        self.pending_upgrade = False
        self.extra_simulation = ""
        self.fail_effect = False
        self.mutate_source = False
        self.comparison_error = False

    def run(self, args, **kwargs):
        self.calls.append(args)
        binary = Path(args[0]).name
        if binary == "vercmp":
            return native.Completed(
                0, str((args[1] > args[2]) - (args[1] < args[2])).encode()
            )
        if binary == "git":
            return native.Completed(0, self.source)
        if binary == "dpkg":
            if "--audit" in args:
                return native.Completed(0, b"broken" if self.broken else b"")
            if "--compare-versions" in args:
                return native.Completed(
                    2 if self.comparison_error else int(not args[-3] > args[-1]), b""
                )
        if binary == "dpkg-query":
            if args[-1] in self.installed:
                return native.Completed(0, self.installed[args[-1]].encode())
            if args[-1].startswith("-f=${binary:Package}"):
                return native.Completed(
                    0,
                    "".join(
                        f"{name}\t{version}\tii \n"
                        for name, version in sorted(self.installed.items())
                    ).encode(),
                )
            return native.Completed(1, b"")
        if binary == "apt-mark":
            return native.Completed(0, "\n".join(sorted(self.manual)).encode())
        if binary == "apt-cache":
            if len(args) == 2:
                return native.Completed(0, self.repository)
            return native.Completed(
                0, "".join(f"{name}:\n  Candidate: 1.0\n" for name in args[2:]).encode()
            )
        if binary == "apt-get" and "--simulate" in args:
            changes = []
            for target in args[args.index("install") + 1 :]:
                name, version = target.split("=")
                if self.installed.get(name) != version or "--reinstall" in args:
                    changes.append(f"Inst {name} ({version} Ubuntu [amd64])")
            if changes:
                changes.extend(
                    [
                        "Inst new-shared (1.0 Ubuntu [amd64])",
                        "Inst existing-auto [1.0] (1.0 Ubuntu [amd64])",
                    ]
                )
            return native.Completed(
                0, ("\n".join(changes) + self.extra_simulation).encode()
            )
        if binary == "pacman":
            if "-Q" in args:
                return native.Completed(
                    0,
                    "".join(
                        f"{n} {v}\n" for n, v in sorted(self.installed.items())
                    ).encode(),
                )
            if "-Qqe" in args:
                return native.Completed(0, "\n".join(sorted(self.manual)).encode())
            if "-Qu" in args:
                return native.Completed(
                    0 if self.pending_upgrade else 1,
                    b"bash 2.0" if self.pending_upgrade else b"",
                )
            if "-Sp" in args:
                names = args[args.index("--print-format") + 2 :]
                return native.Completed(
                    0,
                    "".join(
                        f"{n}\t1.0\t{'a' * 64}\n"
                        for n in names
                        if self.installed.get(n) != "1.0" or "--needed" not in args
                    ).encode(),
                )
            if "-Si" in args:
                return native.Completed(0, b"Version : 1.0\n")
        if binary == "node":
            pins = native.tool_pins(ROOT / "tools/codex/versions.env")
            return native.Completed(
                0,
                (
                    "v" + pins["NATIVE_NODE_VERSION"]
                    if len(args) == 2
                    else "pyright 1.1.408"
                ).encode(),
            )
        if binary == "python3.12":
            return native.Completed(0, b"")
        raise AssertionError(f"unexpected query: {args}")

    def effect(self, args, **kwargs):
        self.effects.append(args)
        if self.fail_effect:
            raise native.PreparationError(
                "preparation_command_failed_reobserve_required"
            )
        if self.mutate_source:
            self.source = b"changed"
        if "install" in args or "-S" in args:
            for target in args:
                if "=" in target and not target.startswith("-") and "::" not in target:
                    name, version = target.split("=", 1)
                    self.installed[name] = version
                    self.manual.add(name)
        if "/usr/bin/apt-mark" in args and "auto" in args:
            self.manual.difference_update(args[args.index("auto") + 1 :])
        if "--asdeps" in args:
            self.manual.difference_update(args[args.index("--asdeps") + 1 :])


def fake_python(commands, generation, pins):
    binary = generation / "python/bin/python3.12"
    binary.parent.mkdir(parents=True)
    binary.write_text("fixture Python")
    binary.chmod(0o700)
    return binary


def fake_typing(commands, generation, pins):
    binary = generation / f"node-v{pins['NATIVE_NODE_VERSION']}-linux-x64/bin/node"
    binary.parent.mkdir(parents=True)
    binary.write_text("fixture Node")
    binary.chmod(0o700)
    program = generation / "typing/node_modules/pyright/index.js"
    program.parent.mkdir(parents=True)
    program.write_text("fixture Pyright")
    program.with_name("langserver.index.js").write_text("fixture language server")
    return binary, program


class NativePreparationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)
        self.commands = PackageHost(self.home)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # These are isolated package-manager fixtures, not native preparation.
        # When the test runner is root, simulate the unprivileged actor only
        # at the developer-entry guard. Preserve real UID/ownership checks,
        # real production denial, and the dedicated root-rejection test.
        if os.geteuid() == 0:
            self.stack.enter_context(patch.object(install, "require_developer"))
        self.stack.enter_context(
            patch.object(
                native,
                "host",
                return_value={
                    "id": "ubuntu",
                    "version": "24.04",
                    "architecture": "x86_64",
                },
            )
        )
        self.stack.enter_context(
            patch.object(
                install.shutil,
                "disk_usage",
                return_value=SimpleNamespace(free=10 * 1024**3),
            )
        )

    def make_plan(self, profiles=None, **kwargs):
        return native.plan(profiles or ["core"], commands=self.commands, **kwargs)

    def fake_preparation(self):
        self.stack.enter_context(patch.object(install, "root_program"))
        build = self.stack.enter_context(
            patch.object(install, "build_python", side_effect=fake_python)
        )
        self.stack.enter_context(
            patch.object(install, "install_typing", side_effect=fake_typing)
        )
        self.stack.enter_context(
            patch.object(
                doctor,
                "inventory",
                return_value=[doctor.Check("core", "fixture", True, "", "ready")],
            )
        )
        return build

    def test_profiles_cover_doctor_and_expand_dependencies(self):
        spec = native.load_spec()
        self.assertEqual(set(spec["profile"]), set(doctor.PROFILES))
        self.assertEqual(
            native.host_preparation_profiles(spec),
            sorted(name for name in doctor.PROFILES if name != "hyprland-build"),
        )
        self.assertEqual(
            native.profiles(["editor", "bindings"], spec),
            ["bindings", "core", "editor", "shell"],
        )
        spec["profile"]["core"]["requires"] = ["editor"]
        with self.assertRaisesRegex(native.PreparationError, "dependency_cycle"):
            native.profiles(["core"], spec)

    def test_plan_is_read_only_binds_dependency_closure_and_source(self):
        result = self.make_plan(["editor"])
        self.assertTrue(result["read_only"])
        self.assertFalse(result["payload"]["qualification_evidence"])
        self.assertEqual(result["payload"]["profiles"], ["core", "editor", "shell"])
        self.assertIn(
            "new-shared",
            {p["name"] for p in result["payload"]["system"]["transaction"]},
        )
        self.assertEqual(self.commands.effects, [])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_ubuntu_image_refuses_before_package_queries(self):
        with self.assertRaisesRegex(native.PreparationError, "native_arch_builder"):
            self.make_plan(list(doctor.PROFILES))
        self.assertEqual(self.commands.calls, [])

    def test_unknown_profile_and_untyped_mode_fail_before_effects(self):
        for profiles, mode in [
            (["unknown"], False),
            (["core"], "false"),
            (None, False),
        ]:
            with (
                self.subTest(profiles=profiles, mode=mode),
                self.assertRaises(native.PreparationError),
            ):
                native.plan(profiles, repair=mode, commands=self.commands)
        self.assertEqual(self.commands.effects, [])

    def test_broken_package_database_refuses(self):
        self.commands.broken = True
        with self.assertRaisesRegex(native.PreparationError, "database_recovery"):
            self.make_plan()

    def test_removal_dependency_downgrade_and_bad_comparison_refuse(self):
        self.commands.installed["existing-auto"] = "9.0"
        with self.assertRaisesRegex(native.PreparationError, "downgrade"):
            self.make_plan()
        self.commands.installed["existing-auto"] = "1.0"
        self.commands.extra_simulation = "\nRemv bash [1.0]\n"
        with self.assertRaisesRegex(native.PreparationError, "removal"):
            self.make_plan()
        self.commands.extra_simulation = ""
        self.commands.comparison_error = True
        with self.assertRaisesRegex(native.PreparationError, "comparison_failed"):
            self.make_plan()

    def test_direct_newer_installed_version_is_preserved(self):
        self.commands.installed["curl"] = "9.0"
        result = self.make_plan()
        self.assertIn(
            {"name": "curl", "version": "9.0"}, result["payload"]["system"]["requested"]
        )

    def test_multiarch_requested_target_uses_only_native_installed_version(self):
        # dpkg may list both architecture-qualified instances of a requested
        # package. Never concatenate their versions or adopt the foreign one.
        self.commands.installed.update(
            {"zlib1g-dev:amd64": "3.0", "zlib1g-dev:i386": "9.0"}
        )
        planned = self.make_plan()
        requested = {
            item["name"]: item["version"]
            for item in planned["payload"]["system"]["requested"]
        }
        self.assertEqual(requested["zlib1g-dev"], "3.0")
        self.assertFalse(
            any(
                args[0] == "/usr/bin/dpkg-query" and "-f=${Version}" in args
                for args in self.commands.calls
            )
        )

        # A foreign-only installation is not evidence of a native version.
        del self.commands.installed["zlib1g-dev:amd64"]
        self.commands.calls.clear()
        planned = self.make_plan()
        requested = {
            item["name"]: item["version"]
            for item in planned["payload"]["system"]["requested"]
        }
        self.assertEqual(requested["zlib1g-dev"], "1.0")
        self.assertFalse(
            any(
                args[0] == "/usr/bin/dpkg-query" and "-f=${Version}" in args
                for args in self.commands.calls
            )
        )

    def test_requested_multiarch_target_preparation_preserves_foreign_package(self):
        self.commands.installed.update({"zlib1g-dev": "3.0", "zlib1g-dev:i386": "9.0"})
        self.commands.manual.add("zlib1g-dev:i386")
        plan = self.make_plan()
        self.fake_preparation()
        receipt = install.prepare(plan, self.commands)
        self.assertEqual(receipt["status"], "ready")
        self.assertEqual(self.commands.installed["zlib1g-dev"], "3.0")
        self.assertEqual(self.commands.installed["zlib1g-dev:i386"], "9.0")
        self.assertIn("zlib1g-dev:i386", self.commands.manual)
        self.assertFalse(
            any(
                "zlib1g-dev:i386" in arg
                for effect in self.commands.effects
                for arg in effect
            )
        )

    def test_metadata_parser_rejects_unsafe_or_ambiguous_candidates(self):
        for data in (
            b"curl:\n Candidate: (none)\n",
            b"curl:\n Candidate: 1\n Candidate: 2\n",
            b"curl:\n Candidate: --evil\n",
            b"other:\n Candidate: 1\n",
        ):
            with self.subTest(data=data), self.assertRaises(native.PreparationError):
                native.apt_candidates(data, ["curl"])

    def test_transaction_parser_rejects_duplicate_and_malformed_records(self):
        for data in (
            b"Inst curl ???",
            b"Inst curl (1 source)\nInst curl (2 source)",
            b"Inst --evil (1 source)",
        ):
            with self.subTest(data=data), self.assertRaises(native.PreparationError):
                native.apt_transaction(data)

    def test_apt_intermediate_dependency_notes_are_metadata_not_commands(self):
        data = b"Inst libheif-plugin-aomdec (1.21.2-3ubuntu0.6 Ubuntu:26.04/resolute-updates [amd64]) []\nInst curl [1.0] (2.0 Ubuntu [amd64]) [libcurl]\n"
        self.assertEqual(
            native.apt_transaction(data),
            [
                {"name": "curl", "version": "2.0"},
                {"name": "libheif-plugin-aomdec", "version": "1.21.2-3ubuntu0.6"},
            ],
        )

    def test_saved_plan_rejects_tampering_staleness_expiry_and_future(self):
        current = self.make_plan()
        for change in ("tampered", "stale", "old", "future", "extra", "naive"):
            saved = copy.deepcopy(current)
            if change == "tampered":
                saved["payload"]["command"] = "untrusted"
            elif change == "stale":
                saved["payload"]["uid"] = -1
                saved["plan_digest"] = native.digest(saved["payload"])
            elif change == "extra":
                saved["commands"] = []
            elif change == "naive":
                saved["created_utc"] = "2026-10-25T01:00:00"
            else:
                seconds = -901 if change == "old" else 60
                saved["created_utc"] = (
                    dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
                ).isoformat()
            with (
                self.subTest(change=change),
                self.assertRaises(native.PreparationError),
            ):
                native.validate_saved_plan(saved, current)

    def test_package_state_change_during_planning_refuses(self):
        real = self.commands.run
        queries = 0

        def changing(args, **kwargs):
            nonlocal queries
            result = real(args, **kwargs)
            if Path(args[0]).name == "apt-cache" and len(args) == 2:
                queries += 1
                if queries == 2:
                    return native.Completed(0, b"changed repository")
            return result

        with patch.object(self.commands, "run", side_effect=changing):
            with self.assertRaisesRegex(native.PreparationError, "state_changed"):
                self.make_plan()

    def test_arch_all_profiles_plan_and_maintenance_never_refresh_or_upgrade(self):
        with (
            patch.object(
                native,
                "host",
                return_value={
                    "id": "arch",
                    "version": "rolling",
                    "architecture": "x86_64",
                },
            ),
            patch.object(native, "repository_state", return_value="a" * 64),
        ):
            host_profiles = [
                name for name in doctor.PROFILES if name != "hyprland-build"
            ]
            current = self.make_plan(host_profiles)
            self.assertEqual(current["payload"]["profiles"], sorted(host_profiles))
            self.fake_preparation()
            receipt = install.prepare(current, self.commands)
            self.assertEqual(receipt["status"], "ready")
            self.assertTrue(any("-S" in args for args in self.commands.effects))
            self.assertFalse(
                any(
                    "-Sy" in args or "-Syu" in args
                    for args in self.commands.calls + self.commands.effects
                )
            )
            with self.assertRaisesRegex(
                native.PreparationError, "full_system_maintenance"
            ):
                install.refresh_metadata(["core"], self.commands)

    def test_compositor_sdk_uses_pinned_substrate_without_host_package_effects(self):
        with patch.object(
            native,
            "host",
            return_value={"id": "arch", "version": "rolling", "architecture": "x86_64"},
        ):
            with self.assertRaisesRegex(
                native.PreparationError, "s21_pinned_substrate"
            ):
                self.make_plan(["hyprland-build"])
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(self.commands.effects, [])
        spec = native.load_spec()
        self.assertIn("libglvnd", spec["profile"]["hyprland-build"]["arch"])
        self.assertIn("systemd-libs", spec["profile"]["hyprland-build"]["arch"])
        self.assertNotIn("editor", native.profiles(["hyprland-build"], spec))
        broken = (
            native.read_regular(ROOT / native.SPEC)
            .decode()
            .replace('  "libglvnd",\n', "")
        )
        with patch.object(native, "read_regular", return_value=broken.encode()):
            with self.assertRaisesRegex(
                native.PreparationError, "dependency_inventory_drift"
            ):
                native.load_spec()

    def test_arch_pending_upgrade_fails_before_effects(self):
        self.commands.pending_upgrade = True
        with (
            patch.object(native, "host", return_value={"id": "arch"}),
            patch.object(native, "repository_state", return_value="a" * 64),
        ):
            with self.assertRaisesRegex(native.PreparationError, "full_system_upgrade"):
                self.make_plan()
        self.assertEqual(self.commands.effects, [])

    def test_arch_local_newer_package_is_never_downgraded(self):
        self.commands.installed["curl"] = "9.0"
        with (
            patch.object(native, "host", return_value={"id": "arch"}),
            patch.object(native, "repository_state", return_value="a" * 64),
        ):
            with self.assertRaisesRegex(native.PreparationError, "downgrade_refused"):
                self.make_plan()
        self.assertEqual(self.commands.effects, [])

    def test_interrupted_package_state_requires_review_preserves_receipt_and_history(
        self,
    ):
        self.fake_preparation()
        original = self.make_plan()
        base = install.safe_directory(
            self.home / ".local/linura-tools/native", create=True, private=True
        )
        interrupted = {
            "kind": "native-development-preparation",
            "schema_version": 1,
            "phase": "system_packages",
            "status": "in_progress",
            "system": original["payload"]["system"],
        }
        install.atomic_json(base / "last-run.json", interrupted)
        # Simulate termination after installing a shared dependency but before
        # the native automatic-dependency marker could be restored.
        self.commands.installed["new-shared"] = "1.0"
        self.commands.manual.add("new-shared")
        current = self.make_plan()
        with self.assertRaisesRegex(
            native.PreparationError, "requires_operator_review"
        ):
            install.prepare(current, self.commands)
        self.assertEqual(json.loads((base / "last-run.json").read_text()), interrupted)
        self.assertEqual(self.commands.effects, [])
        # Operator has reviewed/accepted this newly observed ownership state.
        result = install.prepare(current, self.commands, accept_current_packages=True)
        self.assertEqual(result["status"], "ready")
        self.assertIn("new-shared", self.commands.manual)
        history = list((base / "history").glob("*.json"))
        self.assertEqual(len(history), 1)
        self.assertEqual(json.loads(history[0].read_text()), interrupted)

    def test_package_postcondition_failure_is_not_a_success_receipt(self):
        self.fake_preparation()
        real_effect = self.commands.effect

        def missing_package(args, **kwargs):
            real_effect(args, **kwargs)
            self.commands.installed.pop("curl", None)

        with patch.object(self.commands, "effect", side_effect=missing_package):
            with self.assertRaisesRegex(
                native.PreparationError, "postcondition_failed"
            ):
                install.prepare(self.make_plan(), self.commands)

    def test_unplanned_package_change_fails_postcondition(self):
        self.fake_preparation()
        real_effect = self.commands.effect

        def unexpected_package(args, **kwargs):
            real_effect(args, **kwargs)
            self.commands.installed["unplanned"] = "1.0"

        with patch.object(self.commands, "effect", side_effect=unexpected_package):
            with self.assertRaisesRegex(
                native.PreparationError, "unexpected_package_changes"
            ):
                install.prepare(self.make_plan(), self.commands)

    def test_npm_uses_distinct_private_configuration_and_locked_flags(self):
        generation = self.home / "typing-generation"
        generation.mkdir(mode=0o700)
        node, program = fake_typing(
            self.commands,
            generation,
            native.tool_pins(ROOT / "tools/codex/versions.env"),
        )
        (program.parent / "package.json").write_text('{"version":"1.1.408"}')
        # The real implementation creates typing and copies the repository lock.
        import shutil

        shutil.rmtree(generation / "typing")

        def npm_ci(args, **kwargs):
            self.commands.effects.append(args)
            program.parent.mkdir(parents=True)
            program.write_text("fixture")
            program.with_name("langserver.index.js").write_text("fixture")
            (program.parent / "package.json").write_text('{"version":"1.1.408"}')

        with (
            patch.object(install, "download"),
            patch.object(install, "extract_archive", return_value=node.parent.parent),
            patch.object(self.commands, "effect", side_effect=npm_ci),
        ):
            actual = install.install_typing(
                self.commands,
                generation,
                native.tool_pins(ROOT / "tools/codex/versions.env"),
            )
        self.assertEqual(actual, (node, program))
        command = self.commands.effects[-1]
        user = Path(command[command.index("--userconfig") + 1])
        global_config = Path(command[command.index("--globalconfig") + 1])
        self.assertNotEqual(user, global_config)
        self.assertEqual(user.read_bytes(), b"")
        self.assertEqual(global_config.read_bytes(), b"")
        for flag in (
            "ci",
            "--ignore-scripts",
            "--omit=optional",
            "--no-audit",
            "--no-fund",
        ):
            self.assertIn(flag, command)

    def test_multiarch_aliases_preserve_existing_manual_owner(self):
        self.commands.manual.add("existing-auto:amd64")
        self.fake_preparation()
        result = install.prepare(self.make_plan(), self.commands)
        self.assertEqual(result["status"], "ready")
        self.assertIn("existing-auto:amd64", self.commands.manual)
        self.assertFalse(
            any(
                "auto" in args and "existing-auto" in args
                for args in self.commands.effects
            )
        )

    def test_foreign_architecture_packages_are_observed_not_requested(self):
        self.commands.installed.update(
            {
                "libcompat:amd64": "1.0",
                "libcompat:i386": "2.0",
                "other:arm64": "3.0",
            }
        )
        self.commands.manual.update({"libcompat:i386", "other:arm64"})
        observed = native.installed_versions(
            native.package_inventory(self.commands, "ubuntu"), "ubuntu"
        )
        self.assertEqual(observed["libcompat"], "1.0")
        self.assertEqual(observed["libcompat:i386"], "2.0")
        self.assertEqual(observed["other:arm64"], "3.0")
        manual = native.manual_packages(self.commands, "ubuntu")
        self.assertIn("libcompat:i386", manual)
        self.assertIn("other:arm64", manual)
        plan = self.make_plan()
        self.assertNotIn(
            "libcompat:i386",
            {p["name"] for p in plan["payload"]["system"]["requested"]},
        )
        self.fake_preparation()
        result = install.prepare(plan, self.commands)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(self.commands.installed["libcompat:i386"], "2.0")
        self.assertEqual(self.commands.installed["other:arm64"], "3.0")
        self.assertTrue({"libcompat:i386", "other:arm64"} <= self.commands.manual)
        self.assertFalse(
            any(
                "libcompat:i386" in arg or "other:arm64" in arg
                for effect in self.commands.effects
                for arg in effect
            )
        )

    def test_cli_maintenance_plan_and_saved_mode_agreement(self):
        output = io.StringIO()
        with (
            patch.object(native, "Commands", return_value=self.commands),
            patch.object(
                sys,
                "argv",
                ["native.py", "plan", "--maintenance", "--profile", "bindings"],
            ),
            patch("sys.stdout", output),
        ):
            self.assertEqual(native.main(), 0)
        saved = json.loads(output.getvalue())
        self.assertTrue(saved["payload"]["repair"])
        path = self.home / "plan.json"
        path.write_text(json.dumps(saved))
        for args in (
            ["prepare", "--plan-file", str(path)],
            ["maintain", "--profile", "editor", "--plan-file", str(path)],
            ["maintain", "--refresh", "--plan-file", str(path)],
        ):
            with (
                self.subTest(args=args),
                patch.object(native, "Commands", return_value=self.commands),
                patch.object(sys, "argv", ["native.py", *args]),
                patch("sys.stdout", io.StringIO()),
            ):
                self.assertEqual(native.main(), 2)
        self.assertEqual(self.commands.effects, [])

    def test_corrupt_cache_record_rebuilds_without_adopting_stale_marker(self):
        build = self.fake_preparation()
        first = install.prepare(self.make_plan(), self.commands)
        record = self.home / ".local/linura-tools/native/user-tools.json"
        record.write_text("{interrupted write")
        second = install.prepare(self.make_plan(), self.commands)
        self.assertNotEqual(first["tools"], second["tools"])
        self.assertEqual(build.call_count, 2)

    def test_cache_cannot_select_executable_from_another_generation(self):
        self.fake_preparation()
        first = install.prepare(self.make_plan(), self.commands)
        record = self.home / ".local/linura-tools/native/user-tools.json"
        data = json.loads(record.read_text())
        data["python"] = str(self.home / "outside/python3.12")
        record.write_text(json.dumps(data))
        self.commands.calls.clear()
        install.prepare(self.make_plan(), self.commands)
        self.assertFalse(any(args[0] == data["python"] for args in self.commands.calls))
        self.assertTrue(Path(first["tools"]["python"]).exists())

    def test_prepare_verifies_and_preserves_shared_dependency_reasons(self):
        self.fake_preparation()
        result = install.prepare(self.make_plan(["bindings"]), self.commands)
        self.assertEqual(result["status"], "ready")
        self.assertFalse(result["qualification_evidence"])
        self.assertIn("bash", self.commands.manual)
        self.assertIn("curl", self.commands.manual)
        self.assertNotIn("existing-auto", self.commands.manual)
        self.assertNotIn("new-shared", self.commands.manual)
        self.assertIn("new-shared", self.commands.installed)
        self.assertTrue(any("--bindings" in args for args in self.commands.effects))
        self.assertFalse(any("remove" in args for args in self.commands.effects))
        self.assertTrue((self.home / ".local/bin/pyright").is_symlink())

    def test_repeated_prepare_reuses_verified_generation_and_restores_launcher(self):
        build = self.fake_preparation()
        first = install.prepare(self.make_plan(), self.commands)
        (self.home / ".local/bin/pyright").unlink()
        second = install.prepare(self.make_plan(), self.commands)
        self.assertEqual(first["tools"], second["tools"])
        self.assertEqual(build.call_count, 1)
        self.assertTrue((self.home / ".local/bin/pyright").is_symlink())

    def test_cache_corruption_is_never_executed_and_rebuilds_generation(self):
        build = self.fake_preparation()
        first = install.prepare(self.make_plan(), self.commands)
        python = Path(first["tools"]["python"])
        python.write_text("corrupted fixture")
        self.commands.calls.clear()
        second = install.prepare(self.make_plan(), self.commands)
        self.assertNotEqual(first["tools"], second["tools"])
        self.assertEqual(build.call_count, 2)
        self.assertFalse(any(args[0] == str(python) for args in self.commands.calls))
        self.assertTrue(python.exists())

    def test_maintain_rebuilds_tools_and_reinstalls_exact_packages(self):
        build = self.fake_preparation()
        first = install.prepare(self.make_plan(), self.commands)
        second = install.prepare(self.make_plan(repair=True), self.commands)
        self.assertEqual(build.call_count, 2)
        self.assertNotEqual(first["tools"], second["tools"])
        self.assertTrue(any("--reinstall" in args for args in self.commands.effects))

    def test_denied_package_effect_retains_failure_and_replan_can_recover(self):
        self.fake_preparation()
        self.commands.fail_effect = True
        with self.assertRaisesRegex(native.PreparationError, "reobserve_required"):
            install.prepare(self.make_plan(), self.commands)
        path = self.home / ".local/linura-tools/native/last-run.json"
        receipt = json.loads(path.read_text())
        self.assertEqual(receipt["status"], "failed_reobserve_required")
        self.assertEqual(receipt["phase"], "system_packages")
        self.commands.fail_effect = False
        self.assertEqual(
            install.prepare(self.make_plan(), self.commands)["status"], "ready"
        )

    def test_readiness_failure_never_publishes_success(self):
        self.fake_preparation()
        with patch.object(
            doctor,
            "inventory",
            return_value=[doctor.Check("shell", "Qt", False, "install SDK")],
        ):
            with self.assertRaisesRegex(
                native.PreparationError, "profile_verification_failed"
            ):
                install.prepare(self.make_plan(), self.commands)
        receipt = json.loads(
            (self.home / ".local/linura-tools/native/last-run.json").read_text()
        )
        self.assertEqual(receipt["status"], "failed_reobserve_required")

    def test_source_mutation_stops_before_bootstrap(self):
        self.fake_preparation()
        self.commands.mutate_source = True
        with self.assertRaisesRegex(native.PreparationError, "changed_source"):
            install.prepare(self.make_plan(), self.commands)
        self.assertFalse(
            any(
                "scripts/setup_codex_environment.sh" in args
                for args in self.commands.effects
            )
        )

    def test_unmanaged_launcher_conflict_stops_before_system_mutation(self):
        self.fake_preparation()
        directory = self.home / ".local/bin"
        directory.mkdir(parents=True, mode=0o700)
        directory.parent.chmod(0o700)
        launcher = directory / "pyright"
        launcher.write_text("user tool")
        with self.assertRaisesRegex(
            native.PreparationError, "unmanaged_tool_path_conflict"
        ):
            install.prepare(self.make_plan(), self.commands)
        self.assertEqual(launcher.read_text(), "user tool")
        self.assertEqual(self.commands.effects, [])

    def test_unmanaged_python_alias_refuses_before_system_mutation(self):
        alias = self.home / ".local/linura-tools/python312/bin/python3"
        alias.parent.mkdir(parents=True, mode=0o700)
        outside = self.home / "unmanaged-python"
        outside.write_text("keep existing user alias")
        alias.symlink_to(outside)
        with self.assertRaisesRegex(
            native.PreparationError, "unmanaged_tool_path_conflict"
        ):
            install.prepare(self.make_plan(), self.commands)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve(), outside)
        self.assertEqual(outside.read_text(), "keep existing user alias")
        self.assertEqual(self.commands.effects, [])

    def test_competing_preparation_cannot_overwrite_active_receipt(self):
        self.fake_preparation()
        base = install.safe_directory(
            self.home / ".local/linura-tools/native", create=True, private=True
        )
        record = base / "last-run.json"
        install.atomic_json(record, {"active": True})
        with (base / "preparation.lock").open("w") as lock:
            (base / "preparation.lock").chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(native.PreparationError, "already_running"):
                install.prepare(self.make_plan(), self.commands)
        self.assertEqual(json.loads(record.read_text()), {"active": True})
        self.assertEqual(self.commands.effects, [])

    def test_root_preparation_refuses_before_files_or_effects(self):
        current = self.make_plan()
        with (
            patch.object(install, "require_developer", wraps=REAL_DEVELOPER_GUARD),
            patch.object(install.os, "geteuid", return_value=0),
        ):
            with self.assertRaisesRegex(native.PreparationError, "as_developer"):
                install.prepare(current, self.commands)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_insufficient_disk_refuses_before_package_mutation(self):
        with patch.object(
            install.shutil, "disk_usage", return_value=SimpleNamespace(free=0)
        ):
            with self.assertRaisesRegex(
                native.PreparationError, "insufficient_preparation_disk_space"
            ):
                install.prepare(self.make_plan(), self.commands)
        self.assertEqual(self.commands.effects, [])

    def test_symlinked_install_root_is_not_followed(self):
        (self.home / ".local").symlink_to(self.home / "outside")
        with self.assertRaises(native.PreparationError):
            install.prepare(self.make_plan(), self.commands)
        self.assertFalse((self.home / "outside").exists())

    def test_json_record_refuses_symlinks_and_hardlinks(self):
        base = self.home / "private"
        base.mkdir(mode=0o700)
        target = base / "record"
        outside = self.home / "original"
        outside.write_text("original")
        target.symlink_to(outside)
        with self.assertRaises(native.PreparationError):
            install.atomic_json(target, {})
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(native.PreparationError):
            install.atomic_json(target, {})
        self.assertEqual(outside.read_text(), "original")


class NativeHostTests(unittest.TestCase):
    def test_refresh_metadata_refuses_root_before_query_or_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            commands = PackageHost(Path(directory))
            with patch.object(install.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(
                    native.PreparationError, "run_preparation_as_developer"
                ):
                    install.refresh_metadata(["core"], commands)
            self.assertEqual(commands.calls, [])
            self.assertEqual(commands.effects, [])

    def test_installed_inventory_includes_held_packages_and_rejects_ambiguity(self):
        self.assertEqual(
            native.installed_versions(
                b"curl:amd64\t1.0\thi \nold\t0.5\trc \n", "ubuntu"
            ),
            {"curl": "1.0"},
        )
        for data in (
            b"bad record",
            b"curl\t1\tii \ncurl:amd64\t2\tii \n",
            b"curl\t1\tunknown\n",
        ):
            with self.subTest(data=data), self.assertRaises(native.PreparationError):
                native.installed_versions(data, "ubuntu")

    def test_foreign_architecture_inventory_is_distinct_and_bounded(self):
        self.assertEqual(
            native.installed_versions(
                b"libc6:amd64\t2.1\tii \nlibc6:i386\t2.0\thi \nlibc6:arm64\t3.0\tii \n",
                "ubuntu",
            ),
            {"libc6": "2.1", "libc6:i386": "2.0", "libc6:arm64": "3.0"},
        )
        self.assertEqual(
            native.package_pair("libc6:i386", "2.0", observed=True),
            {"name": "libc6:i386", "version": "2.0"},
        )
        for name in ("libc6:i386", "libc6:arm64", "libc6:armhf"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    native.PreparationError, "invalid_package_metadata"
                ),
            ):
                native.package_pair(name, "2.0")
        for name in (
            "libc6:",
            "libc6:../../tmp",
            "libc6:i386=1",
            "libc6:ARCH",
            "libc6:i386 extra",
        ):
            with self.subTest(name=name), self.assertRaises(native.PreparationError):
                native.package_pair(name, "2.0", observed=True)

    def test_arch_stale_or_missing_databases_require_system_maintenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = native.Commands()
            with patch.object(native, "Path", return_value=root):
                with self.assertRaisesRegex(
                    native.PreparationError, "synchronized_host"
                ):
                    native.repository_state(commands, "arch")
                database = root / "core.db"
                database.write_bytes(b"fixture database")
                self.assertEqual(len(native.repository_state(commands, "arch")), 64)
                os.utime(database, (1, 1))
                with self.assertRaisesRegex(
                    native.PreparationError, "synchronized_host"
                ):
                    native.repository_state(commands, "arch")

    def test_manifest_supports_internal_links_and_refuses_external_links(self):
        with tempfile.TemporaryDirectory() as directory:
            generation = Path(directory)
            with patch.object(install.os, "umask", wraps=os.umask):
                previous = os.umask(0o077)
                try:
                    fake_python(None, generation, {})
                    fake_typing(None, generation, {"NATIVE_NODE_VERSION": "22.23.3"})
                    (generation / "bin").mkdir(mode=0o700)
                    link = generation / "bin/internal"
                    link.symlink_to("../python/bin/python3.12")
                    self.assertIn("bin/internal", install.tree_manifest(generation))
                    link.unlink()
                    link.symlink_to("/usr/bin/python3")
                    with self.assertRaisesRegex(native.PreparationError, "tool_link"):
                        install.tree_manifest(generation)
                finally:
                    os.umask(previous)

    def test_exact_supported_platforms(self):
        spec = native.load_spec()
        for identity, version, supported in [
            ("ubuntu", "24.04", True),
            ("ubuntu", "26.04", True),
            ("arch", "", True),
            ("ubuntu", "22.04", False),
            ("debian", "13", False),
            ("manjaro", "", False),
        ]:
            with (
                self.subTest(identity=identity, version=version),
                patch.object(native.platform, "system", return_value="Linux"),
                patch.object(native.platform, "machine", return_value="x86_64"),
                patch.object(
                    native.platform,
                    "freedesktop_os_release",
                    return_value={"ID": identity, "VERSION_ID": version},
                ),
            ):
                if supported:
                    self.assertEqual(native.host(spec)["id"], identity)
                else:
                    with self.assertRaises(native.PreparationError):
                        native.host(spec)
        with patch.object(native.platform, "machine", return_value="aarch64"):
            with self.assertRaises(native.PreparationError):
                native.host(spec)

    def test_native_commands_drop_environment_overrides(self):
        with patch.dict(
            os.environ,
            {
                "LD_PRELOAD": "secret",
                "PYTHONPATH": "secret",
                "APT_CONFIG": "secret",
                "NPM_CONFIG_USERCONFIG": "secret",
                "GIT_CONFIG_COUNT": "4",
            },
        ):
            env = native.Commands().env
        self.assertFalse(any("secret" in value for value in env.values()))
        self.assertNotIn("GIT_CONFIG_COUNT", env)

    def test_commands_bound_time_output_and_hide_stderr(self):
        commands = native.Commands()
        result = commands.run(
            [
                sys.executable,
                "-c",
                "import sys; print('ok'); print('credential',file=sys.stderr)",
            ]
        )
        self.assertEqual(result.output, b"ok\n")
        with self.assertRaisesRegex(native.PreparationError, "timeout"):
            commands.run(
                [sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05
            )
        with patch.object(native, "MAX_BYTES", 8):
            with self.assertRaisesRegex(native.PreparationError, "output_limit"):
                commands.run([sys.executable, "-c", "print('x'*100)"])

    def test_commands_preserve_terminal_session_and_isolate_process_group(self):
        commands = native.Commands()
        result = commands.run(
            [
                sys.executable,
                "-c",
                "import os; print(os.getsid(0), os.getpgrp(), os.getpid())",
            ]
        )
        self.assertEqual(result.code, 0)
        child_session, child_group, child_pid = map(int, result.output.split())
        self.assertEqual(child_session, os.getsid(0))
        self.assertEqual(child_group, child_pid)
        self.assertNotEqual(child_group, os.getpgrp())

    def test_privileged_helper_rejects_shell_and_preserves_native_auth(self):
        with (
            patch.object(install, "root_program") as trusted,
            patch.object(native.Commands, "effect") as effect,
        ):
            with self.assertRaises(native.PreparationError):
                install.privileged(
                    native.Commands(), ["/usr/bin/bash", "-c", "arbitrary"]
                )
            effect.assert_not_called()
            install.privileged(
                native.Commands(),
                ["/usr/bin/apt-get", "--no-remove", "install", "curl=1"],
            )
            self.assertEqual(
                effect.call_args.args[0][:4],
                ["/usr/bin/sudo", "-n", "--", "/usr/bin/apt-get"],
            )
            self.assertEqual(trusted.call_count, 2)

    def test_download_digest_checked_before_archive_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "source.tar.xz"
            target.write_bytes(b"wrong digest")
            with patch.object(native.Commands, "effect") as effect:
                with self.assertRaisesRegex(native.PreparationError, "digest_mismatch"):
                    install.download(
                        native.Commands(),
                        "https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz",
                        "0" * 64,
                        target,
                    )
                self.assertEqual(
                    effect.call_args.args[0][:2], ["/usr/bin/curl", "--disable"]
                )
            with patch.object(native.Commands, "effect") as effect:
                with self.assertRaises(native.PreparationError):
                    install.download(
                        native.Commands(),
                        "https://evil.invalid/payload",
                        "0" * 64,
                        target,
                    )
                effect.assert_not_called()


class NativeArchiveTests(unittest.TestCase):
    def archive(self, directory, members):
        path = Path(directory) / "test.tar.xz"
        with tarfile.open(path, "w:xz") as archive:
            for name, kind, link in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = link
                info.mode = 0o755
                content = b"fixture" if kind == tarfile.REGTYPE else b""
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content) if content else None)
        return path

    def test_archive_rejects_traversal_external_links_and_special_entries(self):
        for member in [
            ("../escape", tarfile.REGTYPE, ""),
            ("/absolute", tarfile.REGTYPE, ""),
            ("sdk/link", tarfile.SYMTYPE, "../../escape"),
            ("sdk/link", tarfile.SYMTYPE, "/tmp/escape"),
            ("sdk/fifo", tarfile.FIFOTYPE, ""),
            ("sdk/hard", tarfile.LNKTYPE, "sdk/file"),
        ]:
            with (
                self.subTest(member=member),
                tempfile.TemporaryDirectory() as directory,
            ):
                archive = self.archive(directory, [member])
                with self.assertRaises(native.PreparationError):
                    install.extract_archive(archive, Path(directory), "sdk")
                self.assertFalse((Path(directory) / "sdk").exists())

    def test_archive_allows_internal_node_links_after_regular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(
                directory,
                [
                    ("sdk/bin/npm", tarfile.SYMTYPE, "../lib/npm.js"),
                    ("sdk/lib/npm.js", tarfile.REGTYPE, ""),
                ],
            )
            sdk = install.extract_archive(archive, Path(directory), "sdk")
            self.assertEqual((sdk / "bin/npm").read_bytes(), b"fixture")

    def test_archive_link_composition_cannot_escape_through_a_shorter_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(
                directory,
                [
                    ("sdk/z/file", tarfile.REGTYPE, ""),
                    ("sdk/x/y", tarfile.SYMTYPE, "../z"),
                    ("sdk/x/y/escape", tarfile.SYMTYPE, "../../outside"),
                    ("sdk/x/y/escape/write", tarfile.SYMTYPE, "../../sdk/z/file"),
                ],
            )
            with self.assertRaisesRegex(native.PreparationError, "archive_link"):
                install.extract_archive(archive, Path(directory), "sdk")
            self.assertFalse((Path(directory) / "outside").exists())


if __name__ == "__main__":
    unittest.main()
