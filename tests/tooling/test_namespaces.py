from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NamespaceContractTests(unittest.TestCase):
    def _run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_namespaces.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _copy_fixture(self, destination: Path) -> None:
        paths = (
            "Cargo.toml",
            "contracts/namespaces.toml",
            "interfaces/dbus",
            "packaging/dbus-1/system.d",
            "packaging/polkit-1/actions",
            "packaging/systemd",
            "crates/linura-dbus/src/lib.rs",
            "crates/linura-dbus/src/authority.rs",
            "crates/linura-dbus/src/session.rs",
            "executors/linura-executor-systemd/src/lib.rs",
            "apps/linura-shell/org.linura.ControlCenter.desktop",
            "apps/linura-shell/org.linura.CommandPalette.desktop",
            "apps/linura-control-center/data/org.linura.Linura.desktop",
            "apps/linura-control-center/data/org.linura.Linura.metainfo.xml",
            "apps/linura-shell/bridge/CMakeLists.txt",
            "apps/linura-shell/ui/CMakeLists.txt",
        )
        for rel in paths:
            source = ROOT / rel
            target = destination / rel
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)

    def test_repository_namespace_contract_is_valid(self) -> None:
        result = self._run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_undeclared_dbus_interface_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            interface = root / "interfaces/dbus/org.linura.Future1.xml"
            interface.write_text(
                '<node><interface name="org.linura.Future1"/></node>\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("undeclared repository dbus-interface: org.linura.Future1", result.stderr)

    def test_dbus_policy_uses_deployed_names_not_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            policy = root / "packaging/dbus-1/system.d/org.linura.Authority1.conf"
            policy.write_text(
                policy.read_text(encoding="utf-8").replace(
                    "org.linura.Authority1",
                    "com.example.Authority1",
                ),
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.Authority1",
                result.stderr,
            )

    def test_dbus_send_destination_does_not_claim_service_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            policy = root / "packaging/dbus-1/system.d/org.linura.Authority1.conf"
            text = policy.read_text(encoding="utf-8")
            text = text.replace(
                "<policy context=\"default\">",
                '<policy context="default">\n    <allow send_destination="org.freedesktop.systemd1"/>',
                1,
            )
            policy.write_text(text, encoding="utf-8")
            result = self._run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_systemd_bus_name_is_part_of_dbus_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            unit = root / "packaging/systemd/system/linura-authorityd.service"
            unit.write_text(
                unit.read_text(encoding="utf-8").replace(
                    "BusName=org.linura.Authority1",
                    "BusName=com.example.Authority1",
                ),
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.Authority1",
                result.stderr,
            )

    def test_runtime_dbus_service_name_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_bus_name_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const SERVICE_NAME: &str = "com.example.ControlBus1";\n'
                'pub const INTERFACE_NAME: &str = "org.linura.Control1";\n'
                'pub const OBJECT_PATH: &str = "/org/linura/Control1";\n'
                'fn register(builder: zbus::connection::Builder, service: ()) {\n'
                '    let _ = builder.name(SERVICE_NAME).serve_at(OBJECT_PATH, service);\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.ControlBus1",
                result.stderr,
            )

    def test_runtime_dbus_service_name_is_discovered_without_same_file_serve_at(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_bus_name_only_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const SERVICE_NAME: &str = "com.example.SplitBus1";\n'
                'fn register(builder: zbus::connection::Builder) {\n'
                '    let _ = builder.name(SERVICE_NAME);\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.SplitBus1",
                result.stderr,
            )

    def test_runtime_dbus_service_cannot_swap_primary_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_bus_name_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const SERVICE_NAME: &str = "org.linura.Control1";\n'
                'pub const INTERFACE_NAME: &str = "org.linura.Session1";\n'
                'pub const OBJECT_PATH: &str = "/org/linura/Session1";\n'
                'fn register(builder: zbus::connection::Builder, service: ()) {\n'
                '    let _ = builder.name(SERVICE_NAME).serve_at(OBJECT_PATH, service);\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "D-Bus runtime service/interface mismatch for org.linura.Control1",
                result.stderr,
            )

    def test_dbus_activation_name_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            activation = root / "packaging/dbus-1/system-services/com.example.Future1.service"
            activation.parent.mkdir(parents=True, exist_ok=True)
            activation.write_text(
                "[D-BUS Service]\nName=com.example.Future1\nExec=/usr/bin/true\n",
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.Future1",
                result.stderr,
            )

    def test_systemd_alias_is_part_of_unit_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            unit = root / "packaging/systemd/system/linura-authorityd.service"
            unit.write_text(
                unit.read_text(encoding="utf-8")
                + "\nAlias=com.example.Future.service linura-future.service\n",
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository systemd-unit: com.example.Future.service",
                result.stderr,
            )

    def test_appdata_application_id_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            metadata = root / "apps/future-app/com.example.Future.appdata.xml"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text(
                '<component type="desktop-application"><id>com.example.Future</id></component>\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository application-id: com.example.Future",
                result.stderr,
            )

    def test_packaging_desktop_id_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            desktop = root / "packaging/applications/com.example.Future.desktop"
            desktop.parent.mkdir(parents=True, exist_ok=True)
            desktop.write_text(
                "[Desktop Entry]\nType=Application\nName=Future\nExec=/usr/bin/true\n",
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository desktop-id: com.example.Future",
                result.stderr,
            )

    def test_packaging_appstream_id_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            metadata = root / "packaging/metainfo/com.example.Future.metainfo.xml"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text(
                '<component type="desktop-application"><id>com.example.Future</id></component>\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository application-id: com.example.Future",
                result.stderr,
            )

    def test_dbus_policy_foreign_own_prefix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            policy = root / "packaging/dbus-1/system.d/org.linura.Authority1.conf"
            text = policy.read_text(encoding="utf-8")
            text = text.replace(
                "<policy context=\"default\">",
                '<policy context="default">\n    <allow own_prefix="com.example"/>',
                1,
            )
            policy.write_text(text, encoding="utf-8")
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "uses unsupported own_prefix 'com.example'",
                result.stderr,
            )

    def test_imported_zbus_interface_attribute_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/imported_interface_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'use zbus::interface;\n'
                'pub const INTERFACE_NAME: &str = "org.linura.Control1";\n'
                '#[interface(name = "com.example.Control1")]\n'
                'impl Control1Service {}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "zbus::interface/runtime contract mismatch",
                result.stderr,
            )

    def test_inline_qml_uri_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            cmake = root / "apps/inline-qml/CMakeLists.txt"
            cmake.parent.mkdir(parents=True)
            cmake.write_text(
                "qt_add_qml_module(inline-qml URI com.example.Future VERSION 1.0)\n",
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("undeclared repository qml-uri: com.example.Future", result.stderr)

    def test_slice_and_swap_units_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            systemd = root / "packaging/systemd/system"
            for suffix in (".slice", ".swap"):
                with self.subTest(suffix=suffix):
                    unit = systemd / f"foreign{suffix}"
                    unit.write_text("[Unit]\nDescription=foreign fixture\n", encoding="utf-8")
                    result = self._run_checker(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"undeclared repository systemd-unit: foreign{suffix}",
                        result.stderr,
                    )
                    unit.unlink()

    def test_runtime_dbus_object_path_must_match_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_path_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'use zbus::Connection;\n'
                'pub const INTERFACE_NAME: &str = "org.linura.Control1";\n'
                'pub const OBJECT_PATH: &str = "/org/linura/Control1Wrong";\n'
                'fn register(builder: zbus::connection::Builder, service: ()) {\n'
                '    let _ = builder.serve_at(OBJECT_PATH, service);\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "D-Bus runtime object path mismatch for org.linura.Control1: "
                "declared /org/linura/Control1, registered /org/linura/Control1Wrong",
                result.stderr,
            )

    def test_zbus_interface_attribute_is_part_of_runtime_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_interface_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const INTERFACE_NAME: &str = "org.linura.Control1";\n'
                '#[zbus::interface(name = "com.example.Control1")]\n'
                'impl Control1Service {}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-interface: com.example.Control1",
                result.stderr,
            )

    def test_polkit_action_argument_is_part_of_runtime_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_polkit_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const ACTION_ID: &str = "com.example.manage-system";\n'
                'fn arguments(sender: &str) {\n'
                '    let _ = vec![\n'
                '        "--action-id".to_owned(),\n'
                '        ACTION_ID.to_owned(),\n'
                '        "--system-bus-name".to_owned(),\n'
                '        sender.to_owned(),\n'
                '    ];\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository polkit-action: com.example.manage-system",
                result.stderr,
            )

    def test_authorize_caller_action_is_part_of_runtime_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "executors/linura-executor-systemd/src/runtime_polkit_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const ACTION_ID: &str = "com.example.executor-action";\n'
                'fn run(sender: &str) {\n'
                '    let _ = authorize_caller(sender, ACTION_ID, "fixture");\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository polkit-action: com.example.executor-action",
                result.stderr,
            )

    def test_zbus_attribute_cannot_swap_to_another_declared_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/runtime_interface_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const INTERFACE_NAME: &str = "org.linura.Control1";\n'
                'pub const OBJECT_PATH: &str = "/org/linura/Control1";\n'
                '#[zbus::interface(name = "org.linura.Session1")]\n'
                'impl Control1Service {}\n'
                'fn register(builder: zbus::connection::Builder, service: Control1Service) {\n'
                '    let _ = builder.serve_at(OBJECT_PATH, service);\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "zbus::interface/runtime contract mismatch",
                result.stderr,
            )

    def test_globbed_workspace_members_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "3"\nmembers = ["crates/*", "executors/*"]\n',
                encoding="utf-8",
            )
            runtime = root / "crates/globbed-runtime/src/lib.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const INTERFACE_NAME: &str = "com.example.Globbed1";\n'
                '#[zbus::interface(name = "com.example.Globbed1")]\n'
                'impl GlobbedService {}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-interface: com.example.Globbed1",
                result.stderr,
            )

    def test_verifier_workspace_member_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "verifiers/linura-verifier-systemd/src/namespace_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const INTERFACE_NAME: &str = "com.example.Verifier1";\n'
                '#[zbus::interface(name = "com.example.Verifier1")]\n'
                'impl VerifierService {}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-interface: com.example.Verifier1",
                result.stderr,
            )

    def test_external_client_service_constant_is_not_owned_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/external_client_fixture.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const SERVICE_NAME: &str = "org.freedesktop.NetworkManager";\n'
                'pub const OBJECT_PATH: &str = "/org/freedesktop/NetworkManager";\n'
                'pub const INTERFACE_NAME: &str = "org.freedesktop.NetworkManager";\n'
                'fn client() { let _ = (SERVICE_NAME, OBJECT_PATH, INTERFACE_NAME); }\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_polkit_callsite_cannot_swap_to_another_declared_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            authority = root / "crates/linura-dbus/src/authority.rs"
            authority.write_text(
                authority.read_text(encoding="utf-8").replace(
                    '"org.linura.authority.manage-systemd-active-state"',
                    '"org.linura.executor.systemd.set-active-state"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Polkit runtime binding mismatch for "
                "crates/linura-dbus/src/authority.rs:action-arg:"
                "MANAGE_SYSTEMD_ACTIVE_STATE_ACTION",
                result.stderr,
            )

    def test_serve_at_object_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/lib.rs"
            text = runtime.read_text(encoding="utf-8")
            old = (
                ".serve_at(OBJECT_PATH, control)?\n"
                "        .serve_at(SESSION_OBJECT_PATH, session)?"
            )
            new = (
                ".serve_at(OBJECT_PATH, session)?\n"
                "        .serve_at(SESSION_OBJECT_PATH, control)?"
            )
            self.assertIn(old, text)
            runtime.write_text(text.replace(old, new, 1), encoding="utf-8")
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "missing D-Bus runtime registration crates/linura-dbus/src/lib.rs: "
                "serve_at(OBJECT_PATH, control)",
                result.stderr,
            )
            self.assertIn(
                "undeclared D-Bus runtime registration crates/linura-dbus/src/lib.rs: "
                "serve_at(OBJECT_PATH, session)",
                result.stderr,
            )

    def test_session_bus_policy_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            policy = root / "packaging/dbus-1/session.d/org.linura.Future1.conf"
            policy.parent.mkdir(parents=True, exist_ok=True)
            policy.write_text(
                '<busconfig><policy user="*"><allow own="com.example.Future1"/></policy></busconfig>\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.Future1",
                result.stderr,
            )

    def test_systemd_dropin_bus_name_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            dropin = (
                root
                / "packaging/systemd/system/linura-authorityd.service.d/override.conf"
            )
            dropin.parent.mkdir(parents=True, exist_ok=True)
            dropin.write_text(
                "[Service]\nBusName=com.example.Future1\n",
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "undeclared repository dbus-service: com.example.Future1",
                result.stderr,
            )

    def test_same_root_dbus_own_prefix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            policy = root / "packaging/dbus-1/system.d/org.linura.Authority1.conf"
            text = policy.read_text(encoding="utf-8")
            text = text.replace(
                "<policy context=\"default\">",
                '<policy context="default">\n    <allow own_prefix="org.linura.Unallocated"/>',
                1,
            )
            policy.write_text(text, encoding="utf-8")
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "uses unsupported own_prefix 'org.linura.Unallocated'",
                result.stderr,
            )

    def test_commented_out_runtime_binding_is_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/lib.rs"
            text = runtime.read_text(encoding="utf-8")
            active = ".serve_at(SESSION_OBJECT_PATH, session)?"
            self.assertIn(active, text)
            runtime.write_text(
                text.replace(active, f"// {active}", 1),
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "missing D-Bus runtime registration crates/linura-dbus/src/lib.rs: "
                "serve_at(SESSION_OBJECT_PATH, session)",
                result.stderr,
            )

    def test_cfg_test_rust_namespace_is_not_a_runtime_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/src/test_only_mock.rs"
            runtime.write_text(
                '#[cfg(test)]\n'
                'mod mocks {\n'
                '    pub const INTERFACE_NAME: &str = "com.example.Mock1";\n'
                '    #[zbus::interface(name = "com.example.Mock1")]\n'
                '    impl MockService {}\n'
                '}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rust_integration_test_namespace_is_not_a_runtime_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            runtime = root / "crates/linura-dbus/tests/mock.rs"
            runtime.parent.mkdir(parents=True, exist_ok=True)
            runtime.write_text(
                'pub const INTERFACE_NAME: &str = "com.example.IntegrationMock1";\n'
                '#[zbus::interface(name = "com.example.IntegrationMock1")]\n'
                'impl MockService {}\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_reserved_desktop_and_appstream_identity_may_be_predeclared(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/namespaces.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8")
                + '\n[[identifier]]\n'
                + 'id = "org.linura.FutureApp"\n'
                + 'kind = "application-id"\n'
                + 'status = "reserved"\n'
                + '\n[[identifier]]\n'
                + 'id = "org.linura.FutureApp"\n'
                + 'kind = "desktop-id"\n'
                + 'status = "reserved"\n',
                encoding="utf-8",
            )
            data = root / "apps/future-app/data"
            data.mkdir(parents=True)
            (data / "org.linura.FutureApp.desktop").write_text(
                "[Desktop Entry]\nType=Application\n",
                encoding="utf-8",
            )
            (data / "org.linura.FutureApp.metainfo.xml").write_text(
                '<component type="desktop-application"><id>org.linura.FutureApp</id></component>\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_alternate_reverse_dns_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            interface = root / "interfaces/dbus/com.linura.Future1.xml"
            interface.write_text(
                '<node><interface name="com.linura.Future1"/></node>\n',
                encoding="utf-8",
            )
            contract = root / "contracts/namespaces.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8")
                + '\n[[identifier]]\n'
                + 'id = "com.linura.Future1"\n'
                + 'kind = "dbus-interface"\n'
                + 'status = "active"\n'
                + 'object_path = "/org/linura/Future1"\n',
                encoding="utf-8",
            )
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must use org.linura.*", result.stderr)

    def test_active_identifier_cannot_disappear(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "apps/linura-shell/org.linura.CommandPalette.desktop").unlink()
            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "active desktop-id is not present in repository surfaces: org.linura.CommandPalette",
                result.stderr,
            )


if __name__ == "__main__":
    unittest.main()
