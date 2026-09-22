from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from tools import check_linura_shell

ROOT = Path(__file__).resolve().parents[2]


class LinuraShellContractTests(unittest.TestCase):
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

    def test_audio_observation_must_be_inactive_while_panel_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            source = root / "apps/linura-shell/bridge/audio_session_controller.cpp"
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("refreshTimer_", text)
            source.write_text(text + "\n// refreshTimer_ regression\n", encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("must not poll while Control Center is closed" in item for item in failures))

    def test_panel_lifecycle_must_drive_bridge_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            panel = root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
            text = panel.read_text(encoding="utf-8")
            marker = "controller.setActive(opened)"
            self.assertEqual(text.count(marker), 1)
            panel.write_text(text.replace(marker, "controller.refresh()", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("activate observation only while opened" in item for item in failures))

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
            marker = 'QStringLiteral("Control Center is closed.")'
            self.assertIn(marker, text)
            source.write_text(text.replace(marker, 'QStringLiteral("still loading")', 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("reset canceled panel observations to inactive" in item for item in failures))

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
            marker = "control.activeFocus ? 2 : 1"
            self.assertIn(marker, text)
            button.write_text(text.replace(marker, "1", 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Linura UI SDK component" in item for item in failures))

    def test_ui_sdk_runtime_assets_are_staged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            image = root / "tools/image.py"
            text = image.read_text(encoding="utf-8")
            marker = 'ROOT / "apps/linura-shell/ui/LinuraSlider.qml"'
            self.assertIn(marker, text)
            image.write_text(text.replace(marker, 'ROOT / "missing/LinuraSlider.qml"', 1), encoding="utf-8")
            failures = check_linura_shell.validate(root)
            self.assertTrue(any("Arch image shell integration missing" in item for item in failures))

    def test_shared_theme_token_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            theme = root / "apps/linura-shell/theme/LinuraTheme.qml"
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
            self.assertTrue(any("canonical CI must build/install" in item for item in failures))


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


if __name__ == "__main__":
    unittest.main()
