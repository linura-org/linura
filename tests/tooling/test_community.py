from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/check_community.py"

COMMUNITY_FILES = [
    "README.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "SUPPORT.md",
    "CITATION.cff",
    "contracts/community.toml",
    ".github/FUNDING.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/compatibility.yml",
    ".github/ISSUE_TEMPLATE/rfc.yml",
    "docs/community/labels.md",
    "docs/community/repository-settings.md",
    "docs/community/sponsorship.md",
    "docs/rfcs/README.md",
    "docs/rfcs/0000-template.md",
]


class CommunityContractTests(unittest.TestCase):
    def run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def copy_fixture(self, target: Path) -> None:
        for rel in COMMUNITY_FILES:
            source = ROOT / rel
            destination = target / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def test_repository_community_contract_passes(self) -> None:
        result = self.run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_rejects_stale_hosted_state_language(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            support = root / "SUPPORT.md"
            support.write_text(
                support.read_text(encoding="utf-8") + "\nUse Issues once hosted.\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stale hosted-state language", result.stderr)

    def test_rejects_commented_blank_issue_setting_masking_true_effective_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            config = root / ".github/ISSUE_TEMPLATE/config.yml"
            text = config.read_text(encoding="utf-8")
            config.write_text(
                text.replace("blank_issues_enabled: false", "blank_issues_enabled: true", 1)
                + "\n# blank_issues_enabled: false\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("effective YAML setting", result.stderr)

    def test_rejects_malformed_or_unrecognized_issue_routing_yaml(self) -> None:
        for extra, expected in (
            ("this is invalid yaml\n", "is malformed"),
            ("unexpected_setting: true\n", "unsupported top-level key"),
        ):
            with self.subTest(extra=extra):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_fixture(root)
                    config = root / ".github/ISSUE_TEMPLATE/config.yml"
                    config.write_text(
                        config.read_text(encoding="utf-8") + "\n" + extra,
                        encoding="utf-8",
                    )

                    result = self.run_checker(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)

    def test_active_funding_requires_explicit_canonical_active_status(self) -> None:
        for replacement in (
            "Status: pending a verified funding destination.",
            "",
        ):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_fixture(root)
                    contract = root / "contracts/community.toml"
                    contract.write_text(
                        contract.read_text(encoding="utf-8").replace(
                            "active = false", "active = true", 1
                        ),
                        encoding="utf-8",
                    )
                    sponsorship = root / "docs/community/sponsorship.md"
                    sponsorship.write_text(
                        sponsorship.read_text(encoding="utf-8").replace(
                            "Status: inactive pending a verified funding destination.",
                            replacement,
                            1,
                        ),
                        encoding="utf-8",
                    )
                    (root / ".github/FUNDING.yml").write_text(
                        'custom: ["https://github.com/sponsors/linura-org"]\n',
                        encoding="utf-8",
                    )

                    result = self.run_checker(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        "requires exactly the canonical active sponsorship status",
                        result.stderr,
                    )

    def test_rejects_empty_or_unsupported_active_funding_destination(self) -> None:
        for funding_text, expected in (
            ("github:\n", "requires a nonempty destination"),
            ("placeholder: value\n", "unsupported funding key"),
        ):
            with self.subTest(funding_text=funding_text):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_fixture(root)
                    contract = root / "contracts/community.toml"
                    contract.write_text(
                        contract.read_text(encoding="utf-8").replace(
                            "active = false", "active = true", 1
                        ),
                        encoding="utf-8",
                    )
                    sponsorship = root / "docs/community/sponsorship.md"
                    sponsorship.write_text(
                        sponsorship.read_text(encoding="utf-8").replace(
                            "Status: inactive pending a verified funding destination.",
                            "Status: active with a verified funding destination.",
                            1,
                        ),
                        encoding="utf-8",
                    )
                    (root / ".github/FUNDING.yml").write_text(
                        funding_text,
                        encoding="utf-8",
                    )

                    result = self.run_checker(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)

    def test_accepts_supported_usable_funding_destination_when_activated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            contract = root / "contracts/community.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(
                    "active = false", "active = true", 1
                ),
                encoding="utf-8",
            )
            sponsorship = root / "docs/community/sponsorship.md"
            sponsorship.write_text(
                sponsorship.read_text(encoding="utf-8").replace(
                    "Status: inactive pending a verified funding destination.",
                    "Status: active with a verified funding destination.",
                    1,
                ),
                encoding="utf-8",
            )
            (root / ".github/FUNDING.yml").write_text(
                'custom: ["https://github.com/sponsors/linura-org"]\n',
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_rejects_unreviewed_funding_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            funding = root / ".github/FUNDING.yml"
            funding.write_text('custom: ["https://example.com/fund"]\n', encoding="utf-8")

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("funding.active=false", result.stderr)


    def test_rejects_indented_funding_activation_when_contract_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            funding = root / ".github/FUNDING.yml"
            funding.write_text("  github: real-sponsor\n", encoding="utf-8")

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("funding.active=false", result.stderr)

    def test_rejects_unterminated_quoted_issue_routing_scalar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            config = root / ".github/ISSUE_TEMPLATE/config.yml"
            config.write_text(
                config.read_text(encoding="utf-8").replace(
                    "url: https://github.com/linura-org/linura/discussions",
                    'url: "https://github.com/linura-org/linura/discussions',
                    1,
                ),
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unterminated quoted YAML scalar", result.stderr)

    def test_rejects_malformed_required_issue_forms(self) -> None:
        for rel in (
            ".github/ISSUE_TEMPLATE/bug.yml",
            ".github/ISSUE_TEMPLATE/feature.yml",
            ".github/ISSUE_TEMPLATE/compatibility.yml",
            ".github/ISSUE_TEMPLATE/rfc.yml",
        ):
            with self.subTest(rel=rel):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_fixture(root)
                    (root / rel).write_text("not_yaml: [\n", encoding="utf-8")

                    result = self.run_checker(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unterminated inline YAML sequence", result.stderr)


    def test_rejects_unterminated_flow_mapping_in_issue_form_scalar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            form = root / ".github/ISSUE_TEMPLATE/bug.yml"
            form.write_text(
                form.read_text(encoding="utf-8").replace(
                    "label: Summary",
                    "label: {bad",
                    1,
                ),
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unterminated inline YAML mapping", result.stderr)

    def test_rejects_unquoted_mapping_delimiter_in_issue_form_scalar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            form = root / ".github/ISSUE_TEMPLATE/bug.yml"
            form.write_text(
                form.read_text(encoding="utf-8").replace(
                    "label: Summary",
                    "label: Summary: details",
                    1,
                ),
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unquoted YAML mapping delimiter", result.stderr)

    def test_rejects_provider_invalid_funding_identifiers_and_cardinality(self) -> None:
        cases = (
            ("github: not/a/github-user\n", "contains an invalid destination"),
            (
                "github: [one, two, three, four, five]\n",
                "supports between one and four destinations",
            ),
            (
                "patreon: [first, second]\n",
                "requires exactly one destination",
            ),
            (
                "tidelift: unknown/package\n",
                "contains an invalid destination",
            ),
            (
                "thanks_dev: github-user\n",
                "contains an invalid destination",
            ),
        )
        for funding_text, expected in cases:
            with self.subTest(funding_text=funding_text):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_fixture(root)
                    contract = root / "contracts/community.toml"
                    contract.write_text(
                        contract.read_text(encoding="utf-8").replace(
                            "active = false", "active = true", 1
                        ),
                        encoding="utf-8",
                    )
                    sponsorship = root / "docs/community/sponsorship.md"
                    sponsorship.write_text(
                        sponsorship.read_text(encoding="utf-8").replace(
                            "Status: inactive pending a verified funding destination.",
                            "Status: active with a verified funding destination.",
                            1,
                        ),
                        encoding="utf-8",
                    )
                    (root / ".github/FUNDING.yml").write_text(
                        funding_text,
                        encoding="utf-8",
                    )

                    result = self.run_checker(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)


    def test_rejects_canonical_contact_url_hidden_outside_parsed_url_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            config = root / ".github/ISSUE_TEMPLATE/config.yml"
            text = config.read_text(encoding="utf-8")
            canonical = "https://github.com/linura-org/linura/security/policy"
            config.write_text(
                text.replace(
                    f"url: {canonical}",
                    "url: https://example.invalid/report",
                    1,
                )
                + f"\n# canonical security route: {canonical}\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "parsed contact links missing canonical security_policy URL",
                result.stderr,
            )

    def test_rejects_empty_items_in_inline_funding_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            contract = root / "contracts/community.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(
                    "active = false", "active = true", 1
                ),
                encoding="utf-8",
            )
            sponsorship = root / "docs/community/sponsorship.md"
            sponsorship.write_text(
                sponsorship.read_text(encoding="utf-8").replace(
                    "Status: inactive pending a verified funding destination.",
                    "Status: active with a verified funding destination.",
                    1,
                ),
                encoding="utf-8",
            )
            (root / ".github/FUNDING.yml").write_text(
                "github: [valid-user,,]\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains an invalid destination", result.stderr)


    def test_rejects_invalid_double_quoted_yaml_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            form = root / ".github/ISSUE_TEMPLATE/bug.yml"
            form.write_text(
                form.read_text(encoding="utf-8").replace(
                    "label: Summary",
                    'label: "Bad\\q"',
                    1,
                ),
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid double-quoted YAML escape", result.stderr)

    def test_rejects_malformed_funding_block_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            contract = root / "contracts/community.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(
                    "active = false", "active = true", 1
                ),
                encoding="utf-8",
            )
            sponsorship = root / "docs/community/sponsorship.md"
            sponsorship.write_text(
                sponsorship.read_text(encoding="utf-8").replace(
                    "Status: inactive pending a verified funding destination.",
                    "Status: active with a verified funding destination.",
                    1,
                ),
                encoding="utf-8",
            )
            (root / ".github/FUNDING.yml").write_text(
                "github:\n  - valid-user\n  garbage\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("malformed funding list child", result.stderr)

    def test_rejects_commented_cff_license_masking_effective_license(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_fixture(root)
            citation = root / "CITATION.cff"
            citation.write_text(
                citation.read_text(encoding="utf-8").replace(
                    'license: "Apache-2.0"',
                    'license: "GPL-3.0"',
                    1,
                )
                + '\n# license: "Apache-2.0"\n',
                encoding="utf-8",
            )

            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "CITATION.cff effective license must be 'Apache-2.0'",
                result.stderr,
            )


if __name__ == "__main__":
    unittest.main()
