"""Static S26 WIP boundary regressions; not a substitute for native qualification."""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class S26WorkstationWipBoundaries(unittest.TestCase):
    def test_reuses_released_library_and_sdk(self) -> None:
        library = source("crates/linura-library/src/lib.rs")
        sdk = source("crates/linura-sdk/src/lib.rs")
        self.assertIn("mod catalog;", library)
        self.assertIn("mod workflows;", library)
        self.assertIn("pub use workflows::{", library)
        self.assertIn("MachineAdoptionReadiness", sdk)
        self.assertIn("RevisionInspection", sdk)

    def test_read_only_cli_is_offline_and_bounded(self) -> None:
        store = source("crates/linura-library/src/store.rs")
        command = source("apps/linuractl/src/main.rs")
        self.assertIn("pub fn open_existing_read_only(", store)
        self.assertIn("OpenFlags::SQLITE_OPEN_READ_ONLY", store)
        self.assertIn('name: "library-list"', command)
        self.assertIn('Some("library-list") => library_list(&args)?', command)
        self.assertIn("LocalLibrary::open_existing_read_only(&args[1])", command)
        self.assertIn("MAX_CATALOG_PAGE_SIZE", command)

    def test_import_review_does_not_mutate_or_execute(self) -> None:
        workflows = source("crates/linura-library/src/workflows.rs")
        self.assertIn("decode_setup_bundle(untrusted)?", workflows)
        self.assertIn("preflight_setup_adoption(&bundle, context)?", workflows)
        self.assertIn("MachineAdoptionDecision::RequiresFreshControlPlan", workflows)
        self.assertIn("machine_verified: false", workflows)
        self.assertNotIn("restore_backup(", workflows)
        self.assertNotIn("std::process::Command", workflows)

    def test_qml_is_presentation_only_and_fails_closed(self) -> None:
        paths = [
            "apps/linura-shell/plugins/library/LibraryPanel.qml",
            "apps/linura-shell/plugins/library/ImportReview.qml",
            "apps/linura-shell/plugins/setups/SetupEditor.qml",
            "apps/linura-shell/plugins/machine-profiles/MachineProfileEditor.qml",
        ]
        for path in paths:
            with self.subTest(path=path):
                value = source(path)
                self.assertIn("import org.linura.UI 1.0", value)
                for forbidden in ("Qt.openUrlExternally", "Process {", "exec(", "eval(", "XMLHttpRequest"):
                    self.assertNotIn(forbidden, value)
        for path in paths[2:]:
            self.assertIn("property bool authenticatedWriteAvailable: false", source(path))
        review = source(paths[1])
        self.assertNotIn("saveRequested(", review)
        self.assertNotIn("applyRequested(", review)

    def test_wip_does_not_promote_unsupported_machine_operations(self) -> None:
        contract = source("contracts/v010-s26-design.toml")
        self.assertIn("register_runtime_operations = false", contract)
        self.assertIn("runtime_support_promotion = false", contract)
        self.assertIn("generic_apply_setup_executor = false", contract)
        self.assertIn("interactive_evidence_ready = false", contract)


if __name__ == "__main__":
    unittest.main()
