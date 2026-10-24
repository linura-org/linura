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
        # Worktree-local Cargo outputs must not be overridden by the image.
        # The documented "development_workspace.py outputs" readiness probe
        # fails closed when these settings leak into its process environment.
        for variable in (
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET_DIR",
            "CARGO_BUILD_BUILD_DIR",
        ):
            self.assertNotIn(variable, dockerfile)
        self.assertIn("USER 1000:1000", dockerfile)
        self.assertIn('org.linura.qualification-evidence="false"', dockerfile)
        guide = (RECIPE / "README.md").read_text()
        for boundary in (
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--memory 2g",
            "--pids-limit 512",
            'git bundle create "$task_bundle" HEAD',
            "outside\nbuild/artifact cleanup directories",
            "never replace Security",
            "physical-workstation evidence",
        ):
            self.assertIn(boundary, guide)
        self.assertNotRegex(guide, r"--privileged|docker\.sock|--network host")

    def test_pinned_rust_and_qt_have_explicit_readiness_commands(self):
        guide = (RECIPE / "README.md").read_text()
        section = guide.split("## Pinned Rust and Qt component readiness", 1)[1].split(
            "## Host-sensitive authority tests", 1
        )[0]
        for required in (
            "tools/codex/doctor.py --profile shell --json",
            "tools/development_workspace.py outputs",
            "cargo xtask check",
            "cmake -S apps/linura-shell/ui",
            "cmake --build /build/linura-ui",
            "cmake -S apps/linura-shell/bridge",
            "cmake --build /build/linura-bridge",
            "--profile editor",
            "Qt compile",
            "does not claim Qt editor/QML runtime imports",
            "new verified digest",
        ):
            self.assertIn(required, section)
        self.assertIn("bash scripts/preflight_codex_environment.sh", guide)
        self.assertIn("tools/codex/versions.env", guide)

    def test_authority_tests_preserve_native_root_owned_tmp(self):
        guide = (RECIPE / "README.md").read_text()
        profile, _, later_profiles = guide.partition(
            "## Optional source-analysis creation profile"
        )
        self.assertIn("## Host-sensitive authority tests", profile)
        for command in (
            "tools/development_workspace.py authority-host",
            "cargo test --locked -p linura-bootstrap",
            "cargo xtask check",
        ):
            self.assertIn(command, profile)
        self.assertIn(
            "native root-owned `/`,\n`/usr/bin/bash` and sticky `/tmp`",
            profile,
        )
        self.assertIn("--recovery-profile ubuntu-v09", profile)
        self.assertIn("require root-owned `/usr/bin/apt`", profile)
        self.assertIn("do not require that package manager", profile)
        self.assertIn("tmpfs declared with `uid=1000`", profile)
        self.assertNotIn("--tmpfs /tmp", profile)
        self.assertTrue(later_profiles)

    def test_private_clone_uses_the_selected_task_commit_in_linked_worktrees(self):
        guide = (RECIPE / "README.md").read_text()
        for fragment in (
            'task_source_sha="$(git rev-parse HEAD)"',
            'git bundle create "$task_bundle" HEAD',
            'git checkout --detach "$task_source_sha"',
            "git clone --no-hardlinks /workspace/linura-task.bundle",
        ):
            self.assertIn(fragment, guide)
        self.assertNotIn("git clone --no-hardlinks /source", guide)
        self.assertNotRegex(guide, r"git checkout --detach [0-9a-f]{40}")

    def test_source_checks_use_main_locks_and_a_fresh_isolated_instance(self):
        guide = (RECIPE / "README.md").read_text()
        profile = guide.split("## Optional source-analysis creation profile", 1)[1]
        for contract in (
            "mkdir /workspace/source-checks",
            "node-v22.23.3-linux-x64.tar.xz",
            "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de",
            "sha256sum --check --strict",
            "/workspace/linura/tools/python-typecheck/package-lock.json",
            "/workspace/linura/tools/source-format/package-lock.json",
            "/workspace/linura/tools/source-format/clang-requirements.lock",
            "--ignore-scripts --omit=optional --no-audit --no-fund",
            "--require-hashes --only-binary=:all: --no-deps",
            "docker network disconnect bridge linura-source-checks",
            "does **not** supply the pinned shfmt or Qt QML formatter",
        ):
            self.assertIn(contract, profile)
        # No host checkout is mounted into a network-enabled preparation instance.
        self.assertNotIn("target=/source", guide)
        self.assertNotIn("--mount ", guide)
        self.assertIn('git bundle create "$source_checks_bundle" HEAD', profile)
        self.assertIn('git checkout --detach "$source_checks_sha"', profile)
        self.assertIn(
            "git clone --no-hardlinks /workspace/linura-source.bundle", profile
        )
        self.assertIn(
            "node-version: '22.23.3'", (ROOT / ".github/workflows/ci.yml").read_text()
        )
        self.assertNotRegex(profile, r"npm install|pip install (?!.*--disable)")


if __name__ == "__main__":
    unittest.main()
