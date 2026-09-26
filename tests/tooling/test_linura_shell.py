from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from tools import check_linura_shell

ROOT = Path(__file__).resolve().parents[2]


class LinuraShellContractTests(unittest.TestCase):
    def test_control1_freshness_wire_value_matches_audio_client(self) -> None:
        observation = (ROOT / "crates/linura-observation/src/lib.rs").read_text(
            encoding="utf-8"
        )
        transport = (ROOT / "crates/linura-dbus/src/lib.rs").read_text(
            encoding="utf-8"
        )
        client = (ROOT / "apps/linura-shell/bridge/audio_session_controller.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('Self::Current => "current"', observation)
        self.assertIn("response.freshness.as_str().into()", transport)
        self.assertIn('if (freshness != QStringLiteral("current"))', client)
        self.assertIn('freshness_ = QStringLiteral("fresh")', client)

    def _copy_fixture(self, destination: Path) -> None:
        for relative in check_linura_shell.REQUIRED:
            source = ROOT / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def test_repository_shell_contract_is_valid(self) -> None:
        self.assertEqual(check_linura_shell.validate(ROOT), [])

    def test_qml_cannot_gain_process_or_provider_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
            panel.write_text(
                panel.read_text(encoding="utf-8")
                + "\n// Process { command: [\"wpctl\"] }\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("forbidden authority/process/provider surface" in item for item in failures))

    def test_manifest_cannot_become_capability_grant(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "apps/linura-shell/plugins/control-center/manifest.json"
            text = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                text.replace(
                    '"authority": "none",',
                    '"authority": "none",\n  "capabilities": ["system.audio.control"],',
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertIn(
                "Control Center shell manifest must not become a capability grant",
                failures,
            )

    def test_standalone_control_center_must_remain_roadmap_scaffold(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/components.toml"
            text = contract.read_text(encoding="utf-8")
            start = text.index('id = "linura-control-center"')
            end = text.find("[[component]]", start)
            if end == -1:
                end = len(text)
            block = text[start:end]
            changed = block.replace(
                'maturity = "roadmap-scaffold"',
                'maturity = "integrated-experimental"',
                1,
            )
            contract.write_text(text[:start] + changed + text[end:], encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("standalone linura-control-center maturity" in item for item in failures))

    def test_pre_dispatch_state_binding_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = "samePrecondition(pending_->displayed, snapshot)"
            self.assertEqual(text.count(marker), 1)
            source.write_text(text.replace(marker, "true", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("pre-dispatch state check" in item for item in failures))

    def test_post_receipt_reobservation_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = "observe(ObservePurpose::PostApply)"
            self.assertEqual(text.count(marker), 1)
            source.write_text(text.replace(marker, "pending_.reset()", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("re-observe after receipt" in item for item in failures))

    def test_shell_bridge_transport_must_remain_timeout_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = "session.setTimeout(kEffectTimeoutMs)"
            self.assertEqual(text.count(marker), 1)
            source.write_text(text.replace(marker, "", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("authority contract missing" in item and marker in item for item in failures))

    def test_control_center_must_have_a_packaged_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "apps/linura-shell/org.linura.ControlCenter.desktop"
            text = launcher.read_text(encoding="utf-8")
            marker = (
                "Exec=/usr/bin/qs -p /usr/share/linura/shell "
                "ipc call -- linura.shell toggleControlCenter"
            )
            self.assertIn(marker, text)
            launcher.write_text(text.replace(marker, "Exec=/bin/false", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("packaged launcher contract missing" in item for item in failures))

    def test_audio_observation_must_be_inactive_without_audio_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("refreshTimer_", text)
            source.write_text(text + "\n// refreshTimer_ regression\n", encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("must not poll while audio controls are inactive" in item for item in failures)
            )

    def test_shell_root_must_own_shared_audio_controller_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = "active: shell.controlCenterOpen || shell.quickSettingsOpen"
            self.assertEqual(text.count(marker), 1)
            shell.write_text(
                text.replace(marker, "active: shell.controlCenterOpen", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("exclusively own shared audio-controller activation" in item for item in failures)
            )

    def test_audio_panels_cannot_own_shared_controller_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml"
            panel.write_text(
                panel.read_text(encoding="utf-8")
                + "\n// forbidden lifecycle ownership\nConnections { target: controller; Component.onCompleted: controller.setActive(opened) }\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("must not own shared audio-controller activation" in item for item in failures)
            )

    def test_missing_control_service_must_be_unavailable_not_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = "isServiceUnavailableError(reply.errorName())"
            self.assertEqual(text.count(marker), 2)
            source.write_text(text.replace(marker, "false", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("classify Control1 and Session1 service disappearance" in item for item in failures))

    def test_ipc_open_must_request_initial_keyboard_focus(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
            text = panel.read_text(encoding="utf-8")
            marker = "closeButton.forceActiveFocus(Qt.TabFocusReason)"
            self.assertEqual(text.count(marker), 1)
            panel.write_text(text.replace(marker, "controller.refresh()", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Control Center shell panel contract missing" in item and marker in item for item in failures))

    def test_keyboard_changes_must_preserve_slider_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
            text = panel.read_text(encoding="utf-8")
            self.assertNotIn("volumeSlider.value =", text)
            panel.write_text(
                text.replace(
                    "root.draftVolume = Math.max(0, root.draftVolume - 1)",
                    "root.draftVolume = Math.max(0, root.draftVolume - 1)\n"
                    "                            volumeSlider.value = root.draftVolume",
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("preserve the slider value binding" in item for item in failures))

    def test_closed_initial_observation_must_reset_to_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = 'QStringLiteral("Audio controls are inactive.")'
            self.assertIn(marker, text)
            source.write_text(text.replace(marker, 'QStringLiteral("still loading")', 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("reset canceled audio observations to inactive" in item for item in failures))

    def test_closing_panel_must_cancel_undispatched_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = "pending_.has_value() && !pending_->dispatched"
            self.assertIn(marker, text)
            source.write_text(text.replace(marker, "false", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("authority contract missing" in item and marker in item for item in failures))

    def test_active_observation_failure_must_recover_with_bounded_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = "retryTimer_.start(delay)"
            self.assertIn(marker, text)
            source.write_text(text.replace(marker, "return", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("bounded observation recovery" in item for item in failures))

    def test_no_reply_must_be_classified_as_service_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            marker = 'QStringLiteral("org.freedesktop.DBus.Error.NoReply")'
            self.assertEqual(text.count(marker), 1)
            source.write_text(text.replace(marker, 'QStringLiteral("org.example.Missing")', 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("NoReply" in item for item in failures))

    def test_control_center_must_consume_linura_ui_primitives(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
            text = panel.read_text(encoding="utf-8")
            self.assertIn("LinuraButton {", text)
            panel.write_text(text.replace("LinuraButton {", "Button {", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("consume Linura UI primitives" in item for item in failures))

    def test_ui_sdk_focus_contract_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            button = root / "apps/linura-shell/ui/LinuraButton.qml"
            text = button.read_text(encoding="utf-8")
            marker = "theme.focusBorderWidth"
            self.assertIn(marker, text)
            button.write_text(
                text.replace(marker, "theme.borderWidth", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Linura UI SDK component" in item for item in failures))

    def test_ui_sdk_runtime_module_is_staged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            image = root / "tools/image.py"
            text = image.read_text(encoding="utf-8")
            marker = "build_ui_sdk(STAGED)"
            self.assertIn(marker, text)
            image.write_text(
                text.replace(marker, "missing_ui_sdk(STAGED)", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Arch image shell integration missing" in item for item in failures)
            )

    def test_shared_theme_token_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            theme = root / "apps/linura-shell/ui/LinuraTheme.qml"
            text = theme.read_text(encoding="utf-8")
            theme.write_text(
                text.replace(
                    "readonly property int spacingLg: 16",
                    "readonly property int spacingLg: 17",
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("spacing.lg" in item for item in failures))

    def test_shell_package_and_service_staging_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            image = root / "tools/image.py"
            text = image.read_text(encoding="utf-8")
            marker = "graphical-session.target.wants/linura-shell.service"
            self.assertIn(marker, text)
            image.write_text(text.replace(marker, "missing-shell.service", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Arch image shell integration missing" in item for item in failures))

    def test_canonical_ci_must_compile_and_install_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/ci.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "cmake -S apps/linura-shell/bridge"
            self.assertIn(marker, text)
            workflow.write_text(text.replace(marker, "cmake -S unrelated", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Linura Shell CI contract missing" in item for item in failures))


    def test_canonical_ci_must_compile_and_install_ui_sdk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/ci.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = "cmake -S apps/linura-shell/ui"
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, "cmake -S unrelated-ui", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Linura Shell CI contract missing" in item for item in failures)
            )


    def test_shell_service_is_bound_to_graphical_session_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            service = root / "packaging/systemd/user/linura-shell.service"
            text = service.read_text(encoding="utf-8")
            marker = "BindsTo=graphical-session.target"
            self.assertIn(marker, text)
            service.write_text(text.replace(marker, "", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Linura Shell user-service contract missing" in item and marker in item for item in failures)
            )

    def test_workstation_qualification_requires_graphical_session_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            qualification = root / "docs/qualification/v0.10.0.md"
            text = qualification.read_text(encoding="utf-8")
            marker = "hyprland-session.target"
            self.assertIn(marker, text)
            qualification.write_text(
                text.replace(marker, "missing-session-target", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("v0.10 workstation session qualification missing" in item and marker in item for item in failures)
            )


    def test_ui_sdk_module_is_required_for_product_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
            text = panel.read_text(encoding="utf-8")
            marker = "import org.linura.UI 1.0"
            self.assertIn(marker, text)
            panel.write_text(
                text.replace(marker, 'import "../../ui"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Control Center shell panel contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_ui_sdk_rejects_authority_surface_in_new_component(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            component = root / "apps/linura-shell/ui/LinuraActionRow.qml"
            component.write_text(
                component.read_text(encoding="utf-8") + "\nProcess { }\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "forbidden authority/process/provider surface" in item
                    for item in failures
                )
            )

    def test_ui_sdk_cmake_module_contract_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            cmake = root / "apps/linura-shell/ui/CMakeLists.txt"
            text = cmake.read_text(encoding="utf-8")
            marker = "URI org.linura.UI"
            self.assertIn(marker, text)
            cmake.write_text(
                text.replace(marker, "URI org.linura.Broken", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK CMake contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_icon_button_requires_explicit_accessible_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            component = root / "apps/linura-shell/ui/LinuraIconButton.qml"
            text = component.read_text(encoding="utf-8")
            marker = "required property string accessibleName"
            self.assertIn(marker, text)
            component.write_text(
                text.replace(marker, 'property string accessibleName: ""', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK component" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_dialog_reopen_resets_decision_before_enter_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            component = root / "apps/linura-shell/ui/LinuraDialog.qml"
            text = component.read_text(encoding="utf-8")
            marker = "onAboutToShow: decisionEmitted = false"
            self.assertIn(marker, text)
            component.write_text(
                text.replace(marker, "onOpened: decisionEmitted = false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK component" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_dialog_nonaccepted_close_must_emit_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            component = root / "apps/linura-shell/ui/LinuraDialog.qml"
            text = component.read_text(encoding="utf-8")
            marker = "onClosed:"
            self.assertIn(marker, text)
            component.write_text(
                text.replace(marker, "onVisibleChanged:", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK component" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_image_doctor_qt_probe_covers_ui_sdk_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            image = root / "tools/image.py"
            text = image.read_text(encoding="utf-8")
            marker = (
                'UI_SDK_QT_MODULES = ("Qt6Core", "Qt6Qml", '
                '"Qt6Quick", "Qt6QuickControls2")'
            )
            self.assertIn(marker, text)
            image.write_text(
                text.replace(
                    marker,
                    'UI_SDK_QT_MODULES = ("Qt6Core", "Qt6Qml")',
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Arch image shell integration missing" in item
                    and "Qt6QuickControls2" in item
                    for item in failures
                )
            )

    def test_command_palette_rejects_process_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            palette.write_text(
                palette.read_text(encoding="utf-8") + "\nProcess { }\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "forbidden authority/process/provider surface" in item
                    for item in failures
                )
            )

    def test_command_palette_manifest_cannot_gain_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "apps/linura-shell/plugins/command-palette/manifest.json"
            text = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                text.replace(
                    '"authority": "none",',
                    '"authority": "none",\n  "capabilities": ["system.audio.control"],',
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Command palette manifest" in item for item in failures)
            )

    def test_command_palette_must_use_linura_ui_primitives(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "LinuraActionRow {"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, "Button {", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette product surface must consume Linura UI primitives" in item
                    or ("Command palette shell contract missing" in item and marker in item)
                    for item in failures
                )
            )

    def test_application_controller_owns_visible_desktop_entry_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "const applications = DesktopEntries.applications.values"
            self.assertEqual(text.count(marker), 2)
            controller.write_text(
                text.replace(marker, "const applications = []", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must read the visible desktop-entry model once for descriptors "
                    "and once immediately before launch" in item
                    for item in failures
                )
            )

    def test_application_controller_launches_only_exact_current_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "if (application.id !== applicationId)"
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, "if (false)", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Application launcher controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_application_controller_rejects_terminal_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = 'return "terminal-unsupported"'
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, 'return "launched"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Application launcher controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_application_controller_rejects_generic_process_material(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            controller.write_text(
                controller.read_text(encoding="utf-8")
                + '\n// forbidden regression\nQuickshell.execDetached({ command: ["sh"] })\n',
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "forbidden authority/process/provider surface: execDetached" in item
                    or "must not bypass the fixed user-systemd broker" in item
                    for item in failures
                )
            )

    def test_application_catalog_filters_no_display_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            self.assertEqual(text.count("application.noDisplay"), 2)
            controller.write_text(
                text.replace("application.noDisplay", "false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must filter NoDisplay entries from discovery" in item
                    for item in failures
                )
            )

    def test_application_controller_preserves_forked_app_cgroup_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = '"--property=ExitType=cgroup"'
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, '"--property=ExitType=main"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must keep transient GUI applications alive until their cgroup is empty"
                    in item
                    for item in failures
                )
            )

    def test_application_controller_uses_user_systemd_app_slice(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            for marker in (
                '"/usr/bin/systemd-run"',
                '"--user"',
                '"--collect"',
                '"--service-type=exec"',
                '"--slice=app.slice"',
                '"--expand-environment=no"',
            ):
                self.assertIn(marker, text)

            marker = '"--slice=app.slice"'
            controller.write_text(
                text.replace(marker, '"--slice=linura-shell.slice"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Application launcher controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_application_controller_never_directly_executes_desktop_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            self.assertNotIn("application.execute()", text)
            controller.write_text(
                text + "\n// forbidden regression\napplication.execute()\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must not bypass the fixed user-systemd broker" in item
                    for item in failures
                )
            )

    def test_application_controller_passes_argv_directly_to_process_exec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "launchBroker.exec(command)"
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, "launchBroker.exec({ command: command })", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must not bypass the fixed user-systemd broker" in item
                    or (
                        "Application launcher controller contract missing" in item
                        and marker in item
                    )
                    for item in failures
                )
            )

    def test_application_controller_has_single_bounded_broker_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            self.assertEqual(text.count("Process {"), 1)
            controller.write_text(
                text + "\nProcess { }\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must own exactly one bounded systemd-run broker process" in item
                    for item in failures
                )
            )

    def test_application_launch_waits_for_broker_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = (
                "onLaunchCompleted: (status, requestGeneration) =>"
            )
            self.assertIn(marker, text)
            shell.write_text(
                text.replace(marker, "onLaunchCompleted: status => {}", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell root contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_application_launch_completion_is_bound_to_palette_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "if (!opened || requestGeneration !== sessionGeneration)"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, "if (!opened)", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_application_launch_request_carries_palette_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "applicationRequested(entry.applicationId, sessionGeneration)"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, "applicationRequested(entry.applicationId, 0)", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_cannot_gain_process_execution_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            palette.write_text(
                palette.read_text(encoding="utf-8")
                + "\nimport Quickshell.Io\nProcess { }\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "command palette must not own process execution surface" in item
                    for item in failures
                )
            )

    def test_command_palette_cannot_retain_desktop_entry_provider_material(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            palette.write_text(
                palette.read_text(encoding="utf-8")
                + "\n// forbidden regression\nDesktopEntries.byId(\"org.example.App\")\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "presentation must not retain desktop-entry launch/provider material"
                    in item
                    for item in failures
                )
            )

    def test_shell_routes_application_id_through_launcher_controller(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = "const status = applicationLauncher.launchApplication("
            self.assertIn(marker, text)
            shell.write_text(
                text.replace(marker, 'const status = "invalid-target" // ', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell root contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_manifest_declares_application_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "apps/linura-shell/plugins/command-palette/manifest.json"
            text = manifest.read_text(encoding="utf-8")
            marker = '"xdg.desktop-entries"'
            self.assertIn(marker, text)
            manifest.write_text(
                text.replace(marker, '"arbitrary.processes"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette manifest must remain exact" in item
                    for item in failures
                )
            )

    def test_application_launcher_requires_systemd_255(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profile = root / "profiles/arch-hyprland-v1.toml"
            text = profile.read_text(encoding="utf-8")
            marker = 'systemd = ">=255"'
            self.assertIn(marker, text)
            profile.write_text(
                text.replace(marker, 'systemd = ">=253"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must require systemd >=255" in item
                    for item in failures
                )
            )

    def test_workspace_navigation_requires_quickshell_031(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profile = root / "profiles/arch-hyprland-v1.toml"
            text = profile.read_text(encoding="utf-8")
            marker = 'quickshell = ">=0.3.1"'
            self.assertIn(marker, text)
            profile.write_text(
                text.replace(marker, 'quickshell = ">=0.3.0"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must require quickshell >=0.3.1" in item
                    for item in failures
                )
            )

    def test_workspace_controller_owns_typed_hyprland_workspace_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "const workspaces = Hyprland.workspaces.values"
            self.assertEqual(text.count(marker), 2)
            controller.write_text(
                text.replace(marker, "const workspaces = []", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "must read the live Hyprland workspace model once for descriptors "
                    "and once immediately before activation" in item
                    for item in failures
                )
            )

    def test_command_palette_cannot_retain_hyprland_provider_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            palette.write_text(
                palette.read_text(encoding="utf-8")
                + "\nimport Quickshell.Hyprland\n",
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "presentation must not retain Hyprland provider control" in item
                    for item in failures
                )
            )

    def test_shell_routes_workspace_intent_through_controller(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = "workspaceNavigation.activateWorkspace(workspaceId)"
            self.assertIn(marker, text)
            shell.write_text(
                text.replace(marker, "false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell root contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_workspace_target_uses_stable_numeric_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = 'targetId: "navigation:workspace:" + workspace.id'
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(
                    marker,
                    'targetId: "navigation:workspace:" + workspace.name',
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_does_not_break_current_index_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            self.assertNotIn("resultList.currentIndex =", text)

    def test_workspace_controller_uses_typed_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "workspace.activate()"
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, "return false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Workspace navigation controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_workspace_controller_matches_exact_numeric_identity_before_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "if (workspace.id !== workspaceId)"
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, "if (false)", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Workspace navigation controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_workspace_focus_uses_supported_workspace_property(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = "focused: workspace.focused"
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, "focused: false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Workspace navigation controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_workspace_controller_rejects_raw_hyprland_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"
            )
            controller.write_text(
                controller.read_text(encoding="utf-8")
                + '\n// forbidden regression\nHyprland.dispatch("workspace 1")\n',
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "forbidden authority/process/provider surface: Hyprland.dispatch("
                    in item
                    for item in failures
                )
            )

    def test_command_palette_refreshes_when_workspace_descriptors_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "onWorkspaceCatalogChanged:"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, "onVisibleChanged:", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_manifest_declares_workspace_navigation_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "apps/linura-shell/plugins/command-palette/manifest.json"
            text = manifest.read_text(encoding="utf-8")
            marker = '"hyprland.workspaces"'
            self.assertIn(marker, text)
            manifest.write_text(
                text.replace(marker, '"arbitrary.commands"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette manifest must remain exact" in item
                    for item in failures
                )
            )

    def test_command_palette_keeps_keyboard_selection_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, "// selection visibility removed", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_list_current_index_tracks_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "currentIndex: root.selectedIndex"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, "currentIndex: -1", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_exposes_keyboard_selection_to_search_accessibility(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = "accessibleDescription: root.selectedAccessibilityDescription()"
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, 'accessibleDescription: ""', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_action_row_exposes_accessible_selected_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            component = root / "apps/linura-shell/ui/LinuraActionRow.qml"
            text = component.read_text(encoding="utf-8")
            marker = "Accessible.selected: control.selected"
            self.assertIn(marker, text)
            component.write_text(
                text.replace(marker, "Accessible.selected: false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK component" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_text_field_preserves_accessible_description_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            component = root / "apps/linura-shell/ui/LinuraTextField.qml"
            text = component.read_text(encoding="utf-8")
            marker = "Accessible.description: invalid ? errorText : accessibleDescription"
            self.assertIn(marker, text)
            component.write_text(
                text.replace(
                    marker,
                    'Accessible.description: invalid ? errorText : ""',
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK component" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_shell_root_owns_navigation_before_ipc_delegation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = "function toggleCommandPalette()"
            ipc_index = text.index("IpcHandler {")
            root_method_index = text.index(marker)
            self.assertLess(root_method_index, ipc_index)

            text = (
                text[:root_method_index]
                + "function brokenToggleCommandPalette()"
                + text[root_method_index + len(marker):]
            )
            shell.write_text(text, encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "root must own navigation method before IPC delegation" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_global_shortcut_registration_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = 'name: "commandPalette"'
            self.assertIn(marker, text)
            shell.write_text(
                text.replace(marker, 'name: "brokenCommandPalette"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell root contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_command_palette_must_have_a_packaged_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "apps/linura-shell/org.linura.CommandPalette.desktop"
            text = launcher.read_text(encoding="utf-8")
            marker = (
                "Exec=/usr/bin/qs -p /usr/share/linura/shell "
                "ipc call -- linura.shell toggleCommandPalette"
            )
            self.assertIn(marker, text)
            launcher.write_text(
                text.replace(marker, "Exec=/bin/false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette packaged launcher contract missing" in item
                    for item in failures
                )
            )

    def test_transient_shell_surfaces_remain_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            shell = root / "apps/linura-shell/shell.qml"
            text = shell.read_text(encoding="utf-8")
            marker = (
                "function showCommandPalette() {\n"
                "        shell.controlCenterOpen = false\n"
                "        shell.quickSettingsOpen = false\n"
                "        shell.commandPaletteOpen = true\n"
                "    }"
            )
            replacement = (
                "function showCommandPalette() {\n"
                "        shell.commandPaletteOpen = true\n"
                "    }"
            )
            self.assertIn(marker, text)
            shell.write_text(
                text.replace(marker, replacement, 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "transient surfaces must remain mutually exclusive" in item
                    for item in failures
                )
            )

    def test_quick_settings_open_focuses_always_enabled_close_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml"
            text = panel.read_text(encoding="utf-8")
            marker = "closeButton.forceActiveFocus(Qt.TabFocusReason)"
            self.assertEqual(text.count(marker), 1)
            self.assertNotIn("volumeSlider.forceActiveFocus(Qt.TabFocusReason)", text)
            panel.write_text(
                text.replace(marker, "volumeSlider.forceActiveFocus(Qt.TabFocusReason)", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Quick Settings shell panel contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_quick_settings_manifest_cannot_gain_capability_grant(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "apps/linura-shell/plugins/quick-settings/manifest.json"
            text = manifest.read_text(encoding="utf-8")
            marker = '"authority": "none",'
            self.assertIn(marker, text)
            manifest.write_text(
                text.replace(
                    marker,
                    marker + '\n  "capabilities": ["system.audio.control"],',
                    1,
                ),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Quick Settings manifest" in item for item in failures)
            )

    def test_quick_settings_cannot_gain_provider_or_process_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml"
            panel.write_text(
                panel.read_text(encoding="utf-8")
                + '\n// forbidden provider bypass: wpctl\n',
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("forbidden authority/process/provider surface" in item for item in failures)
            )

    def test_quick_settings_manifest_must_bind_registered_volume_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "apps/linura-shell/plugins/quick-settings/manifest.json"
            text = manifest.read_text(encoding="utf-8")
            marker = "operation:audio.output.set-session-volume"
            self.assertIn(marker, text)
            manifest.write_text(
                text.replace(marker, "operation:audio.output.unregistered-volume", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("bound to the registered session-volume operation" in item for item in failures)
            )

    def test_quick_settings_must_have_a_packaged_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            launcher = root / "apps/linura-shell/org.linura.QuickSettings.desktop"
            text = launcher.read_text(encoding="utf-8")
            marker = (
                "Exec=/usr/bin/qs -p /usr/share/linura/shell "
                "ipc call -- linura.shell toggleQuickSettings"
            )
            self.assertIn(marker, text)
            launcher.write_text(
                text.replace(marker, "Exec=/bin/false", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Quick Settings packaged launcher contract missing" in item for item in failures)
            )

    def test_command_palette_must_retain_quick_settings_navigation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            palette = root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
            text = palette.read_text(encoding="utf-8")
            marker = 'targetId: "navigation:quick-settings"'
            self.assertIn(marker, text)
            palette.write_text(
                text.replace(marker, 'targetId: "navigation:missing"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Command palette shell contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_application_launcher_must_reserve_quick_settings_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            controller = (
                root
                / "apps/linura-shell/integrations/xdg/ApplicationLauncherController.qml"
            )
            text = controller.read_text(encoding="utf-8")
            marker = '"org.linura.QuickSettings.desktop"'
            self.assertIn(marker, text)
            controller.write_text(
                text.replace(marker, '"org.linura.QuickSettings.unreserved"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Application launcher controller contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_ui_sdk_control_size_token_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            theme = root / "apps/linura-shell/ui/LinuraTheme.qml"
            text = theme.read_text(encoding="utf-8")
            marker = "readonly property int controlMd: 40"
            self.assertIn(marker, text)
            theme.write_text(
                text.replace(marker, "readonly property int controlMd: 41", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("design token control_size.md" in item for item in failures)
            )



    def test_shell_bridge_qml_plugin_must_keep_origin_rpath(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            cmake = root / "apps/linura-shell/bridge/CMakeLists.txt"
            text = cmake.read_text(encoding="utf-8")
            marker = 'INSTALL_RPATH "$ORIGIN"'
            self.assertIn(marker, text)
            cmake.write_text(
                text.replace(marker, 'INSTALL_RPATH ""', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell bridge CMake contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_shell_bridge_qml_install_must_include_backing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            cmake = root / "apps/linura-shell/bridge/CMakeLists.txt"
            text = cmake.read_text(encoding="utf-8")
            marker = "TARGETS linura-shell-bridge linura-shell-bridgeplugin"
            self.assertIn(marker, text)
            cmake.write_text(
                text.replace(marker, "TARGETS linura-shell-bridgeplugin", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell bridge CMake contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_canonical_ci_must_verify_shell_bridge_dependency_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/ci.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'bridge_linkage="$(ldd "$bridge_plugin")"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, 'bridge_linkage="unchecked"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell CI contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_ui_qml_plugin_must_keep_origin_rpath(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            cmake = root / "apps/linura-shell/ui/CMakeLists.txt"
            text = cmake.read_text(encoding="utf-8")
            marker = 'INSTALL_RPATH "$ORIGIN"'
            self.assertIn(marker, text)
            cmake.write_text(
                text.replace(marker, 'INSTALL_RPATH ""', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK CMake contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_ui_qml_install_must_include_backing_library_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            cmake = root / "apps/linura-shell/ui/CMakeLists.txt"
            text = cmake.read_text(encoding="utf-8")
            marker = "TARGETS linura-ui linura-uiplugin"
            self.assertIn(marker, text)
            cmake.write_text(
                text.replace(marker, "TARGETS linura-uiplugin", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura UI SDK CMake contract missing" in item
                    and marker in item
                    for item in failures
                )
            )

    def test_canonical_ci_must_verify_ui_plugin_dependency_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/ci.yml"
            text = workflow.read_text(encoding="utf-8")
            marker = 'ui_linkage="$(ldd "$ui_plugin")"'
            self.assertIn(marker, text)
            workflow.write_text(
                text.replace(marker, 'ui_linkage="unchecked"', 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any(
                    "Linura Shell CI contract missing" in item
                    and marker in item
                    for item in failures
                )
            )


    def test_audio_bridge_dbus_demarshalling_must_use_read_side_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            bridge = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = bridge.read_text(encoding="utf-8")
            marker = "const QDBusArgument argument = qvariant_cast<QDBusArgument>(value);"
            self.assertIn(marker, text)
            bridge.write_text(
                text.replace(marker, "QDBusArgument argument = qvariant_cast<QDBusArgument>(value);", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Linura Shell bridge authority contract missing" in item and marker in item for item in failures)
            )

    def test_audio_receipt_demarshalling_must_use_read_side_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            bridge = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = bridge.read_text(encoding="utf-8")
            marker = "const QDBusArgument wire = arguments.at(0).value<QDBusArgument>();"
            self.assertIn(marker, text)
            bridge.write_text(
                text.replace(marker, "QDBusArgument wire = arguments.at(0).value<QDBusArgument>();", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Linura Shell bridge authority contract missing" in item and marker in item for item in failures)
            )


    def test_audio_receipt_must_validate_dbus_structure_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            bridge = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = bridge.read_text(encoding="utf-8")
            marker = "wire.currentType() != QDBusArgument::StructureType"
            self.assertIn(marker, text)
            bridge.write_text(text.replace(marker, "false", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Linura Shell bridge authority contract missing" in item and marker in item for item in failures)
            )

    def test_session1_client_deadline_covers_bounded_authority_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            bridge = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = bridge.read_text(encoding="utf-8")
            marker = "constexpr int kEffectTimeoutMs = 10'000;"
            self.assertIn(marker, text)
            bridge.write_text(
                text.replace(marker, "constexpr int kEffectTimeoutMs = 5'000;", 1),
                encoding="utf-8",
            )
            failures = check_linura_shell.validate(root)
            self.assertTrue(
                any("Linura Shell bridge authority contract missing" in item and marker in item for item in failures)
            )


    def test_bound_audio_draft_can_enter_fresh_pre_dispatch_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            contract = "(!canApply() && !canCommitDraft())"
            self.assertIn(contract, text)
            source.write_text(text.replace(contract, "!canApply()", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("authority contract missing" in item and contract in item for item in failures))

    def test_quick_settings_apply_uses_bound_draft_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml"
            text = panel.read_text(encoding="utf-8")
            contract = "enabled: controller.canCommitDraft"
            self.assertIn(contract, text)
            panel.write_text(text.replace(contract, "enabled: controller.canApply", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Quick Settings shell panel contract missing" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
