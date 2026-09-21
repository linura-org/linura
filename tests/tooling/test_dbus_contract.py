from __future__ import annotations

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
XML_PATH = ROOT / "interfaces/dbus/org.linura.Control1.xml"
RUNTIME_PATH = ROOT / "crates/linura-dbus/src/lib.rs"
SESSION_XML_PATH = ROOT / "interfaces/dbus/org.linura.Session1.xml"
SESSION_RUNTIME_PATH = ROOT / "crates/linura-dbus/src/session.rs"

PLAN_PREVIEW_OUTPUTS = (
    ("ids", "(ss)", "out"),
    ("actor", "(ssb)", "out"),
    ("route", "(sss)", "out"),
    ("reason", "(sasasas)", "out"),
    ("observed_evidence_id", "s", "out"),
    ("prospective_risk", "s", "out"),
    ("status", "s", "out"),
    ("execution_authorized", "b", "out"),
    ("changes", "a(sbss)", "out"),
    ("findings", "a(sss)", "out"),
)

PLAN_REVIEW_OUTPUTS = (
    ("ids", "(ss)", "out"),
    ("principal", "s", "out"),
    ("actor", "(ssb)", "out"),
    ("route", "(sss)", "out"),
    ("reason", "(sasasas)", "out"),
    ("observed_evidence_id", "s", "out"),
    ("review", "(sssss)", "out"),
    ("decision", "(sbssb)", "out"),
    ("changes", "a(sbss)", "out"),
    ("findings", "a(sss)", "out"),
)

EXPECTED_METHODS = {
    "GetProtocolVersion": (("major", "q", "out"), ("product_version", "s", "out")),
    "WhoAmI": (
        ("actor_id", "s", "out"), ("actor_kind", "s", "out"),
        ("interactive", "b", "out"), ("uid", "u", "out"),
        ("pid", "u", "out"), ("dbus_sender", "s", "out"),
    ),
    "Capabilities": (("providers", "a(sss)", "out"), ("capabilities", "a(ssss)", "out")),
    "Observe": (
        ("provider", "s", "in"), ("resource", "s", "in"), ("capability", "s", "in"),
        ("observed_provider", "s", "out"), ("observed_resource", "s", "out"),
        ("observed_capability", "s", "out"), ("authority", "s", "out"),
        ("freshness", "s", "out"), ("observed_at_unix_ms", "t", "out"),
        ("valid_for_ms", "t", "out"), ("sequence", "t", "out"),
        ("attributes", "a(ss)", "out"),
    ),
    "Graph": (("nodes", "a(sa(ss))", "out"), ("edges", "a(ssss)", "out")),
    "ExplainObservation": (
        ("resource", "s", "in"), ("explained_resource", "s", "out"),
        ("provider", "s", "out"), ("capability", "s", "out"),
        ("freshness", "s", "out"), ("evidence_id", "s", "out"),
        ("authority", "s", "out"),
    ),
    "PlanDesiredState": (
        ("request", "((ssss)(sasasas)a(ss))", "in"),
        *PLAN_PREVIEW_OUTPUTS,
    ),
    "GetPlanPreview": (("plan_id", "s", "in"), *PLAN_PREVIEW_OUTPUTS),
    "ExplainPlanPreview": (("plan_id", "s", "in"), *PLAN_PREVIEW_OUTPUTS),
    "ReviewPlan": (("plan_id", "s", "in"), *PLAN_REVIEW_OUTPUTS),
    "ExplainPlanReview": (("plan_id", "s", "in"), *PLAN_REVIEW_OUTPUTS),
}

RUNTIME_METHODS = {
    "GetProtocolVersion": "async fn get_protocol_version(",
    "WhoAmI": "async fn who_am_i(",
    "Capabilities": "async fn capabilities(",
    "Observe": "async fn observe(",
    "Graph": "async fn graph(",
    "ExplainObservation": "async fn explain_observation(",
    "PlanDesiredState": "async fn plan_desired_state(",
    "GetPlanPreview": "async fn get_plan_preview(",
    "ExplainPlanPreview": "async fn explain_plan_preview(",
    "ReviewPlan": "async fn review_plan(",
    "ExplainPlanReview": "async fn explain_plan_review(",
}

REMOVED_EXPERIMENTAL_METHODS = {
    "GetCapabilitySnapshot": "async fn get_capability_snapshot(",
    "GetSystemGraph": "async fn get_system_graph(",
    "ProposeIntent": "async fn propose_intent(",
    "Plan": "async fn plan(",
    "Explain": "async fn explain(",
    "ExportProfile": "async fn export_profile(",
}


class Control1ContractTests(unittest.TestCase):
    def test_control1_is_exact_canonical_experimental_surface(self) -> None:
        root = ET.parse(XML_PATH).getroot()
        interface = root.find("./interface[@name='org.linura.Control1']")
        self.assertIsNotNone(interface)
        assert interface is not None
        annotations = {
            annotation.attrib["name"]: annotation.attrib["value"]
            for annotation in interface.findall("annotation")
        }
        self.assertEqual(annotations["org.linura.ContractId"], "dbus.org.linura.Control1")
        self.assertEqual(annotations["org.linura.ContractVersion"], "1")
        self.assertEqual(annotations["org.linura.Stability"], "experimental")
        actual = {}
        for method in interface.findall("method"):
            actual[method.attrib["name"]] = tuple(
                (arg.attrib["name"], arg.attrib["type"], arg.attrib.get("direction", "in"))
                for arg in method.findall("arg")
            )
        self.assertEqual(actual, EXPECTED_METHODS)

    def test_runtime_matches_current_contract_without_obsolete_shims(self) -> None:
        source = RUNTIME_PATH.read_text(encoding="utf-8")
        for marker in RUNTIME_METHODS.values():
            self.assertIn(marker, source)
        for name, marker in REMOVED_EXPERIMENTAL_METHODS.items():
            with self.subTest(name=name):
                self.assertNotIn(marker, source)
        self.assertIn('CONTRACT_STABILITY: &str = "experimental"', source)

    def test_plan_preview_surface_stays_explicitly_non_executable(self) -> None:
        root = ET.parse(XML_PATH).getroot()
        interface = root.find("./interface[@name='org.linura.Control1']")
        assert interface is not None
        method_names = {method.attrib["name"] for method in interface.findall("method")}
        self.assertTrue(
            {
                "PlanDesiredState",
                "GetPlanPreview",
                "ExplainPlanPreview",
                "ReviewPlan",
                "ExplainPlanReview",
            }
            <= method_names
        )
        for forbidden in {"Apply", "Execute", "CommitPlan", "AuthorizePlan", "PreparePlan"}:
            self.assertNotIn(forbidden, method_names)


class Session1ContractTests(unittest.TestCase):
    def test_session1_is_one_exact_bounded_mutation_surface(self) -> None:
        root = ET.parse(SESSION_XML_PATH).getroot()
        interface = root.find("./interface[@name='org.linura.Session1']")
        self.assertIsNotNone(interface)
        assert interface is not None
        annotations = {
            annotation.attrib["name"]: annotation.attrib["value"]
            for annotation in interface.findall("annotation")
        }
        self.assertEqual(annotations["org.linura.ContractId"], "dbus.org.linura.Session1")
        self.assertEqual(annotations["org.linura.ContractVersion"], "1")
        self.assertEqual(annotations["org.linura.Stability"], "experimental")
        methods = interface.findall("method")
        self.assertEqual([method.attrib["name"] for method in methods], ["SetAudioOutputVolume"])
        args = tuple(
            (arg.attrib["name"], arg.attrib["type"], arg.attrib.get("direction", "in"))
            for arg in methods[0].findall("arg")
        )
        self.assertEqual(
            args,
            (
                ("request_id", "s", "in"),
                ("node_id", "u", "in"),
                ("volume_percent", "q", "in"),
                ("reason", "s", "in"),
                ("receipt", "(sssssss)", "out"),
            ),
        )

    def test_session1_runtime_delegates_authority_inward(self) -> None:
        source = SESSION_RUNTIME_PATH.read_text(encoding="utf-8")
        self.assertIn("trait Session1Handler", source)
        self.assertIn(".set_audio_output_volume(context, request)", source)
        for forbidden in ("Command::new", "wpctl", "PolicyDecision", "OperationClass"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
