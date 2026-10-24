"""S17 installation/component contracts, never native qualification evidence."""

from __future__ import annotations

import configparser
import fnmatch
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools import image

ROOT = Path(__file__).resolve().parents[2]


def unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = lambda optionstr: optionstr
    parser.read(ROOT / "packaging/systemd/system" / name)
    return parser


class S17DeploymentTests(unittest.TestCase):
    def test_native_sleep_gate_is_fixed_fail_closed_and_staged_with_runtime(self):
        relative = "systemd-suspend.service.d/50-linura-protective-lock.conf"
        drop_in = unit(relative)
        self.assertEqual(drop_in.sections(), ["Service"])
        self.assertEqual(
            dict(drop_in["Service"]),
            {
                "ExecStartPre": "/usr/lib/linura/linura-executor-session --protect-before-sleep"
            },
        )
        source = ROOT / "packaging/systemd/system" / relative
        self.assertEqual(
            image.RUNTIME_ASSETS[source], "usr/lib/systemd/system/" + relative
        )
        contract = ROOT / "interfaces/dbus/org.linura.SleepGate1.xml"
        self.assertEqual(
            image.RUNTIME_ASSETS[contract],
            "usr/share/dbus-1/interfaces/" + contract.name,
        )
        interface = ET.parse(contract).getroot().find("interface")
        assert interface is not None
        self.assertEqual(interface.get("name"), "org.linura.SleepGate1")
        methods = interface.findall("method")
        self.assertEqual(
            [method.get("name") for method in methods], ["ProtectBeforeSleep"]
        )
        self.assertEqual(
            [
                (arg.get("type"), arg.get("direction"))
                for arg in methods[0].findall("arg")
            ],
            [("b", "out")],
        )
        policy = ET.parse(
            ROOT / "packaging/dbus-1/system.d/org.linura.Authority1.conf"
        ).getroot()
        default = policy.find("policy[@context='default']")
        helper = policy.find("policy[@user='linura-authority']")
        assert default is not None and helper is not None
        self.assertIsNotNone(
            default.find("deny[@send_interface='org.linura.SleepGate1']")
        )
        self.assertIsNotNone(default.find("deny[@send_path='/org/linura/SleepGate1']"))
        self.assertIsNotNone(
            helper.find(
                "allow[@send_interface='org.linura.SleepGate1'][@send_path='/org/linura/SleepGate1']"
            )
        )
        self.assertIsNone(policy.find("policy[@user='root']"))
        self.assertEqual(
            [
                item.get("user")
                for item in policy.findall("policy")
                if item.find("allow[@send_interface='org.linura.SleepGate1']")
                is not None
            ],
            ["linura-authority"],
        )

    def test_unqualified_hibernation_modes_are_not_alternative_sleep_routes(self):
        source = ROOT / "packaging/systemd/sleep.conf.d/50-linura-qualified-sleep.conf"
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = lambda optionstr: optionstr
        parser.read(source)
        self.assertEqual(parser.sections(), ["Sleep"])
        self.assertEqual(
            dict(parser["Sleep"]),
            {
                "AllowHibernation": "no",
                "AllowHybridSleep": "no",
                "AllowSuspendThenHibernate": "no",
            },
        )
        self.assertEqual(
            image.RUNTIME_ASSETS[source], "usr/lib/systemd/sleep.conf.d/" + source.name
        )

    def test_protective_policy_actions_require_fresh_owner_authentication_not_unlock(
        self,
    ):
        policy = ET.parse(
            ROOT / "packaging/polkit-1/actions/org.linura.authority.policy"
        ).getroot()
        rust = (ROOT / "crates/linura-linux-session/src/owner.rs").read_text()
        native = (
            ROOT / "apps/linura-shell/security-owner/native_scope.cpp"
        ).read_text()
        for suffix in ("enable-protective-lock", "revoke-protective-lock"):
            action_id = f"org.linura.authority.{suffix}"
            actions = [
                action
                for action in policy.findall("action")
                if action.get("id") == action_id
            ]
            self.assertEqual(len(actions), 1)
            action = actions[0]
            self.assertEqual(action.findtext("defaults/allow_any"), "no")
            self.assertEqual(action.findtext("defaults/allow_inactive"), "no")
            self.assertEqual(action.findtext("defaults/allow_active"), "auth_self")
            owners = [
                node.text
                for node in action.findall("annotate")
                if node.get("key") == "org.freedesktop.policykit.owner"
            ]
            self.assertEqual(owners, ["unix-user:linura-authority"])
            self.assertIn(f'"{action_id}"', rust)
            self.assertIn(f'"{action_id}"', native)

    def test_owner_supervision_does_not_assume_group_or_inherit_session_routes(self):
        service = unit("linura-security-owner@.service")["Service"]
        self.assertEqual(service["ExecStart"], "/usr/lib/linura/linura-security-owner")
        self.assertEqual(service["User"], "%i")
        self.assertNotIn("Group", service)
        self.assertEqual(service["AmbientCapabilities"], "")
        self.assertEqual(service["NoNewPrivileges"], "no")
        self.assertEqual(service["LimitCORE"], "0")
        self.assertEqual(service["MemorySwapMax"], "0")
        self.assertEqual(service["LimitMEMLOCK"], service["MemoryMax"])
        self.assertEqual(service["DevicePolicy"], "closed")
        self.assertEqual(service["Restart"], "no")
        self.assertEqual(service["TimeoutStartSec"], "15s")
        # ProtectHome=yes hides /run/user entirely. Keep homes hidden while
        # exposing only the already-existing, logind-owned runtime directory
        # needed for peer-attested Unix socket connections.
        self.assertEqual(service["ProtectHome"], "tmpfs")
        self.assertEqual(service["BindReadOnlyPaths"], "/run/user/%i")
        self.assertNotIn("BindPaths", service)
        for option in (
            "EnvironmentFile",
            "PassEnvironment",
            "PAMName",
            "ExecStartPre",
            "ExecStartPost",
            "CapabilityBoundingSet",
            "SystemCallFilter",
            "SystemCallArchitectures",
            "RestrictAddressFamilies",
            "RestrictNamespaces",
            "PrivateDevices",
            "LockPersonality",
            "MemoryDenyWriteExecute",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectClock",
            "ProtectHostname",
            "RestrictRealtime",
            "RestrictSUIDSGID",
        ):
            self.assertNotIn(option, service, option)
        path_source = (
            ROOT / "packaging/systemd/system/linura-security-owner@.path"
        ).read_text()
        triggers = [
            line.partition("=")[2]
            for line in path_source.splitlines()
            if line.startswith("PathExistsGlob=")
        ]
        self.assertEqual(
            triggers,
            [
                "/run/user/%i/wayland-[0-9]",
                "/run/user/%i/wayland-[0-9]*[0-9]",
            ],
        )
        self.assertTrue(all(not trigger.endswith(".lock") for trigger in triggers))
        for name in ("wayland-0", "wayland-9", "wayland-12", "wayland-1234"):
            self.assertTrue(
                any(
                    fnmatch.fnmatchcase(
                        f"/run/user/1000/{name}", trigger.replace("%i", "1000")
                    )
                    for trigger in triggers
                ),
                name,
            )
        for name in ("wayland-0.lock", "wayland-12.lock", "wayland-a"):
            self.assertFalse(
                any(
                    fnmatch.fnmatchcase(
                        f"/run/user/1000/{name}", trigger.replace("%i", "1000")
                    )
                    for trigger in triggers
                ),
                name,
            )
        # Keep strict duplicate detection for every nonrepeatable unit option.
        ordinary_options = "\n".join(
            line
            for line in path_source.splitlines()
            if not line.startswith("PathExistsGlob=")
        )
        path = configparser.ConfigParser(interpolation=None, strict=True)
        path.optionxform = lambda optionstr: optionstr
        path.read_string(ordinary_options)
        self.assertEqual(
            dict(path["Path"]),
            {
                "Unit": "linura-security-owner@%i.service",
                "TriggerLimitIntervalSec": "120s",
                "TriggerLimitBurst": "5",
            },
        )
        self.assertEqual(path["Install"]["WantedBy"], "user@%i.service")
        # No manually enabled UID instance or unprivileged systemctl escape is
        # required on first login. Root systemd's user-manager dependency starts
        # the availability watcher; Wayland/logind attestation is still required.
        activation = unit("user@.service.d/50-linura-security-owner.conf")
        self.assertEqual(activation["Unit"]["Wants"], "linura-security-owner@%i.path")
        cmake = (ROOT / "apps/linura-shell/security-owner/CMakeLists.txt").read_text()
        self.assertIn(
            "systemd/system/user@.service.d/50-linura-security-owner.conf", cmake
        )
        self.assertIn("DESTINATION lib/systemd/system/user@.service.d", cmake)

        startup = (
            ROOT / "apps/linura-shell/security-owner/native_startup.cpp"
        ).read_text()
        protect = startup.index("protectNativeProcess(getuid())")
        readiness = startup.index("const auto routes = waitForNativeSocketRoutes(")
        sanitize = startup.index("clearenv()")
        self.assertLess(protect, readiness)
        self.assertLess(readiness, sanitize)
        header = (
            ROOT / "apps/linura-shell/security-owner/native_startup.h"
        ).read_text()
        self.assertIn("maximumWait = std::chrono::seconds(5)", header)
        self.assertIn("maximumEvents = 256", header)
        wait_body = startup[
            startup.index("waitForNativeSocketRoutes(const QString") : readiness
        ]
        self.assertIn("discoverNativeSocketRoutes(runtimeDirectory, uid)", wait_body)
        self.assertIn("inotify_init1(IN_CLOEXEC | IN_NONBLOCK)", wait_body)
        self.assertIn("poll(&request", wait_body)
        self.assertIn("IN_Q_OVERFLOW | IN_UNMOUNT", startup)
        self.assertIn("installReadinessWatches", wait_body)
        self.assertIn("readinessNameIsRelevant", startup)
        self.assertIn("if (!topologyChanged)", wait_body)
        self.assertIn(
            "++eventCount > NativeCompositorReadinessContract::maximumEvents", startup
        )
        self.assertIn('QLatin1String(".socket.sock")', startup)
        self.assertIn("startup/socket-routes/event-overflow", startup)
        self.assertIn("startup/socket-routes/event-watch", startup)
        self.assertNotIn("strerror", startup)
        self.assertNotIn("sleep_for", wait_body)

    def test_fonts_never_include_user_or_general_fontconfig_routes(self):
        fonts = ET.parse(ROOT / "packaging/security-owner/fonts.conf").getroot()
        self.assertEqual(fonts.tag, "fontconfig")
        self.assertEqual(
            [node.text for node in fonts.findall("dir")], ["/usr/share/fonts/TTF"]
        )
        self.assertEqual(
            [node.text for node in fonts.findall("cachedir")], ["/var/cache/fontconfig"]
        )
        self.assertEqual(fonts.findall(".//include"), [])
        text = ET.tostring(fonts).decode()
        for route in ("~", "$HOME", "xdg", "http:", "https:", "/tmp", "/home/"):
            self.assertNotIn(route, text)

    def test_image_build_requires_official_native_auth_and_installs_only_into_image(
        self,
    ):
        with (
            patch.object(image.shutil, "which", return_value="/trusted/tool"),
            patch.object(image, "have_qt_modules", return_value=True),
            patch.object(image.subprocess, "run") as run,
        ):
            image.build_security_owner(
                Path("/isolated/profile"), Path("/isolated/security-owner-build")
            )
            commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertIn("-DLINURA_SECURITY_OWNER_NATIVE_AUTH=ON", commands[0])
        self.assertEqual(
            commands[0][commands[0].index("-B") + 1],
            "/isolated/security-owner-build",
        )
        self.assertIn(
            "-DBUILD_TESTING=OFF", commands[0]
        )  # Artifact build, not evidence.
        self.assertEqual(commands[1][-2:], ["--parallel", "1"])
        self.assertEqual(
            commands[2][-2:], ["--prefix", "/isolated/profile/airootfs/usr"]
        )
        with (
            patch.object(image.shutil, "which", return_value=None),
            patch.object(image.subprocess, "run") as run,
        ):
            with self.assertRaises(RuntimeError):
                image.build_security_owner(
                    Path("/isolated/profile"), Path("/isolated/security-owner-build")
                )
            run.assert_not_called()
        with (
            patch.object(image.shutil, "which", return_value="/trusted/tool"),
            patch.object(image, "have_qt_modules", return_value=False),
            patch.object(image.subprocess, "run") as run,
        ):
            with self.assertRaises(RuntimeError):
                image.build_security_owner(
                    Path("/isolated/profile"), Path("/isolated/security-owner-build")
                )
            run.assert_not_called()

    def test_staging_keeps_authority_policy_and_executor_installation_together(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binaries = root / "binaries"
            binaries.mkdir()
            for binary in image.BINARIES:
                (binaries / binary).write_bytes(b"component fixture, not an executable")
            image.install_binaries(root / "profile", binaries)
            staged = root / "profile/airootfs"
            for source, relative in image.RUNTIME_ASSETS.items():
                self.assertEqual((staged / relative).read_bytes(), source.read_bytes())
            helper = staged / "usr/lib/linura/linura-security-owner-install-capability"
            self.assertEqual(helper.stat().st_mode & 0o7777, 0o755)
            authority = (
                staged
                / "usr/lib/systemd/system/multi-user.target.wants/linura-authorityd.service"
            )
            self.assertTrue(authority.is_symlink())
            self.assertEqual(authority.readlink(), Path("../linura-authorityd.service"))
            self.assertTrue(
                (staged / "usr/lib/linura/linura-executor-session").is_file()
            )

    def test_capability_install_is_fixed_root_only_and_not_run_by_build_tools(self):
        guard = (
            ROOT / "apps/linura-shell/security-owner/process_guard.cpp"
        ).read_text()
        secure_exec = guard.index("getauxval(AT_SECURE)")
        force_nondumpable = guard.index("prctl(PR_SET_DUMPABLE, 0)")
        inspect_capabilities = guard.index("syscall(SYS_capget")
        lock_memory = guard.index("mlockall(MCL_CURRENT | MCL_FUTURE)")
        self.assertIn(
            "ProcessGuardDetail::protectedExecDumpability(initialDumpability)",
            guard,
        )
        self.assertLess(secure_exec, force_nondumpable)
        self.assertLess(force_nondumpable, inspect_capabilities)
        self.assertLess(force_nondumpable, lock_memory)
        self.assertGreaterEqual(guard.count("prctl(PR_SET_DUMPABLE, 0)"), 2)
        header = (ROOT / "apps/linura-shell/security-owner/process_guard.h").read_text()
        self.assertIn("return value == 0 || value == 2;", header)

        helper = ROOT / "packaging/security-owner/install-capability.sh"
        syntax = subprocess.run(
            ["bash", "-n", str(helper)], check=False, capture_output=True
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        if os.geteuid() != 0:
            denied = subprocess.run(
                ["bash", str(helper)], check=False, capture_output=True
            )
            self.assertEqual(denied.returncode, 78, denied.stderr)
        text = helper.read_text()
        self.assertIn('[[ "$EUID" = 0 && "$#" = 0 ]]', text)
        self.assertIn('/usr/bin/setcap cap_ipc_lock=ep "$image"', text)
        self.assertIn('"$links" = 1', text)
        self.assertIn('! -L "$image"', text)
        for forbidden in (
            "eval",
            "sudo",
            "pkexec",
            "cap_sys_admin",
            "cap_setuid",
            "setcap -r",
        ):
            self.assertNotIn(forbidden, text)
        hook = (
            ROOT / "packaging/arch/hooks/90-linura-security-owner-capability.hook"
        ).read_text()
        self.assertIn("Target = libcap", hook)
        self.assertIn("When = PostTransaction", hook)
        self.assertIn(
            "Exec = /usr/lib/linura/linura-security-owner-install-capability", hook
        )


if __name__ == "__main__":
    unittest.main()
