from __future__ import annotations

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
ACTION_ID = "org.linura.authority.manage-systemd-active-state"
ACTION_OWNER = "unix-user:linura-authority"
EXECUTOR_DESTINATION = "org.linura.Executor.Systemd1"
EXECUTOR_INTERFACE = "org.linura.Executor.Systemd1"
READ_ONLY_INTERFACES = {
    "org.freedesktop.DBus.Introspectable",
    "org.freedesktop.DBus.Peer",
    "org.freedesktop.DBus.Properties",
}


class V06PolkitBoundaryTests(unittest.TestCase):
    def test_authority_action_owner_matches_unprivileged_service_identity(self) -> None:
        policy_path = ROOT / "packaging/polkit-1/actions/org.linura.authority.policy"
        root = ET.fromstring(policy_path.read_text(encoding="utf-8"))
        actions = [action for action in root.findall("action") if action.get("id") == ACTION_ID]
        self.assertEqual(len(actions), 1, "Authority1 must own exactly one canonical Polkit action")

        action = actions[0]
        owners = [
            annotation.text
            for annotation in action.findall("annotate")
            if annotation.get("key") == "org.freedesktop.policykit.owner"
        ]
        self.assertEqual(owners, [ACTION_OWNER])

        defaults = action.find("defaults")
        self.assertIsNotNone(defaults)
        assert defaults is not None
        self.assertEqual(defaults.findtext("allow_any"), "no")
        self.assertEqual(defaults.findtext("allow_inactive"), "auth_admin")
        self.assertEqual(defaults.findtext("allow_active"), "auth_admin")
        self.assertNotIn("auth_admin_keep", policy_path.read_text(encoding="utf-8"))

        service = (ROOT / "packaging/systemd/system/linura-authorityd.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("User=linura-authority\n", service)
        self.assertIn("Group=linura-authority\n", service)
        self.assertIn("NoNewPrivileges=yes\n", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn("AmbientCapabilities=\n", service)

    def test_executor_dbus_transport_is_authority_only_for_mutation(self) -> None:
        config = ET.fromstring(
            (ROOT / "packaging/dbus-1/system.d/org.linura.Executor.Systemd1.conf").read_text(
                encoding="utf-8"
            )
        )
        policies = config.findall("policy")

        default_policy = next(
            policy for policy in policies if policy.get("context") == "default"
        )
        mutation_deny = default_policy.find(
            f"deny[@send_destination='{EXECUTOR_DESTINATION}'][@send_interface='{EXECUTOR_INTERFACE}']"
        )
        self.assertIsNotNone(mutation_deny)

        metadata_allows = {
            element.get("send_interface")
            for element in default_policy.findall("allow")
            if element.get("send_destination") == EXECUTOR_DESTINATION
        }
        self.assertEqual(metadata_allows, READ_ONLY_INTERFACES)
        self.assertNotIn(EXECUTOR_INTERFACE, metadata_allows)

        authority_policy = next(
            policy for policy in policies if policy.get("user") == "linura-authority"
        )
        authority_allow = authority_policy.find(
            f"allow[@send_destination='{EXECUTOR_DESTINATION}']"
        )
        self.assertIsNotNone(authority_allow)
        assert authority_allow is not None
        self.assertIsNone(authority_allow.get("send_interface"))

        root_policy = next(policy for policy in policies if policy.get("user") == "root")
        self.assertIsNotNone(root_policy.find(f"allow[@own='{EXECUTOR_DESTINATION}']"))
        self.assertIsNotNone(
            root_policy.find(
                f"deny[@send_destination='{EXECUTOR_DESTINATION}'][@send_interface='{EXECUTOR_INTERFACE}']"
            )
        )
        self.assertIsNone(
            root_policy.find(f"allow[@send_destination='{EXECUTOR_DESTINATION}']")
        )

        product_text = ET.tostring(config, encoding="unicode")
        self.assertNotIn("linura-v05-qualifier", product_text)
        self.assertNotIn("linura-v06-qualifier", product_text)

        qualification = ET.fromstring(
            (
                ROOT / "tests/acceptance/v05/49-linura-v05-qualification-dbus.conf"
            ).read_text(encoding="utf-8")
        )
        qualification_policy = next(
            policy
            for policy in qualification.findall("policy")
            if policy.get("user") == "linura-v05-qualifier"
        )
        self.assertIsNotNone(
            qualification_policy.find(f"allow[@send_destination='{EXECUTOR_DESTINATION}']")
        )

    def test_qualification_approval_remains_test_only(self) -> None:
        qualification_rule = (
            ROOT / "tests/acceptance/v06/49-linura-v06-qualification.rules"
        ).read_text(encoding="utf-8")
        product_policy = (
            ROOT / "packaging/polkit-1/actions/org.linura.authority.policy"
        ).read_text(encoding="utf-8")

        self.assertIn('subject.user === "linura-v06-qualifier"', qualification_rule)
        self.assertIn("polkit.Result.YES", qualification_rule)
        self.assertNotIn("linura-v06-qualifier", product_policy)
        self.assertNotIn("polkit.Result.YES", product_policy)

    def test_expected_denials_do_not_disable_errexit_or_trip_err_trap(self) -> None:
        guest = (ROOT / "tests/acceptance/v06/qualify-guest.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("trap on_error ERR", guest)
        self.assertIn('if output="$("$@" 2>&1)"; then', guest)
        self.assertNotIn("set +e", guest)
        self.assertIn("expect_failure unapproved-human call_authority_unapproved", guest)
        self.assertIn("expect_failure direct-executor-ordinary call_executor_direct", guest)
        self.assertIn("expect_failure direct-executor-root call_executor_direct_root", guest)


if __name__ == "__main__":
    unittest.main()
