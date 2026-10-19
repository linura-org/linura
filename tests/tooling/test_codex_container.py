"""Anti-drift checks for the isolated development prerequisite recipe.

These inspect development infrastructure, never qualify a native workstation.
Actual bootstrap and preflight must still execute in the prepared instance.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "tools/codex/container"


class CodexContainerTests(unittest.TestCase):
    def test_restricted_context_excludes_source_and_credentials(self):
        self.assertEqual(
            (RECIPE / ".dockerignore").read_text().splitlines(),
            ["*", "!Dockerfile", "!ubuntu-snapshot.list"],
        )
        dockerfile = (RECIPE / "Dockerfile").read_text()
        self.assertEqual(
            re.findall(r"^COPY (.+)$", dockerfile, re.MULTILINE),
            ["ubuntu-snapshot.list /etc/apt/linura-snapshot.list"],
        )
        self.assertNotRegex(dockerfile, r"(?m)^(?:ADD|ARG|EXPOSE|VOLUME)\b")

    def test_base_snapshot_and_complete_graph_are_pinned(self):
        dockerfile = (RECIPE / "Dockerfile").read_text()
        self.assertRegex(
            dockerfile,
            r"(?m)^FROM mcr\.microsoft\.com/playwright@sha256:[0-9a-f]{64}$",
        )
        self.assertIn("APT::Update::Error-Mode=any", dockerfile)
        self.assertIn("Dir::Etc::sourceparts=-", dockerfile)
        self.assertIn(
            "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'", dockerfile
        )
        self.assertIn("sha256sum --check --strict", dockerfile)
        self.assertIn(
            "4eb4d71ec34b49a3dd94e19a831376feb40d1a7311af305f354e4da9ebee85a5",
            dockerfile,
        )
        entries = (RECIPE / "ubuntu-snapshot.list").read_text().splitlines()
        self.assertEqual(len(entries), 3)
        for entry, suite in zip(
            entries, ("noble", "noble-updates", "noble-security"), strict=True
        ):
            self.assertEqual(
                entry,
                "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                "https://snapshot.ubuntu.com/ubuntu/20261006T000000Z "
                f"{suite} main universe",
            )
        self.assertNotRegex(dockerfile, r"(?i)allow-unauthenticated|trusted=yes|latest")

    def test_language_tools_remain_owned_by_canonical_setup(self):
        dockerfile = (RECIPE / "Dockerfile").read_text()
        self.assertNotRegex(dockerfile, r"cargo install|pip install|rustup.*install")
        guide = (RECIPE / "README.md").read_text()
        for contract in (
            "tools/codex/versions.env",
            "tools/python/ruff-requirements.lock",
            "Cargo.lock",
            "bash scripts/setup_codex_environment.sh --bindings",
            "bash scripts/preflight_codex_environment.sh",
        ):
            self.assertIn(contract, guide)
        self.assertLess(
            guide.index("bash scripts/setup_codex_environment.sh --bindings"),
            guide.index("docker network disconnect bridge"),
        )
        self.assertLess(
            guide.index("docker network disconnect bridge"),
            guide.index("bash scripts/preflight_codex_environment.sh"),
        )

    def test_instance_is_nonprivileged_and_not_qualification(self):
        dockerfile = (RECIPE / "Dockerfile").read_text()
        self.assertIn("USER 1000:1000", dockerfile)
        self.assertIn('org.linura.qualification-evidence="false"', dockerfile)
        guide = (RECIPE / "README.md").read_text()
        for boundary in (
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--memory 2g",
            "--pids-limit 512",
            "target=/source,readonly",
            "outside\nbuild/artifact cleanup directories",
            "never replace Security",
            "physical-workstation evidence",
        ):
            self.assertIn(boundary, guide)
        self.assertNotRegex(guide, r"--privileged|docker\.sock|--network host")

    def test_source_checks_use_main_locks_and_a_fresh_isolated_instance(self):
        guide = (RECIPE / "README.md").read_text()
        profile = guide.split("## Optional source-analysis creation profile", 1)[1]
        for contract in (
            "mkdir /workspace/source-checks",
            "node-v22.23.3-linux-x64.tar.xz",
            "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de",
            "sha256sum --check --strict",
            "/source/tools/python-typecheck/package-lock.json",
            "/source/tools/source-format/package-lock.json",
            "/source/tools/source-format/clang-requirements.lock",
            "--ignore-scripts --omit=optional --no-audit --no-fund",
            "--require-hashes --only-binary=:all: --no-deps",
            "docker network disconnect bridge linura-source-checks",
            "does **not** supply the pinned shfmt or Qt QML formatter",
        ):
            self.assertIn(contract, profile)
        self.assertIn(
            "node-version: '22.23.3'", (ROOT / ".github/workflows/ci.yml").read_text()
        )
        self.assertNotRegex(profile, r"npm install|pip install (?!.*--disable)")


if __name__ == "__main__":
    unittest.main()
