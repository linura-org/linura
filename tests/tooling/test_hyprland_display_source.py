from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import hyprland_display_source as source


def archive_bytes(entries: list[tuple[str, bytes | str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = str(content)
                archive.addfile(member)
            else:
                assert isinstance(content, bytes)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


class HyprlandDisplaySourceTests(unittest.TestCase):
    def test_native_entry_drops_capabilities_before_runtime_and_rejects_anchor_drift(
        self,
    ):
        main = (
            '#include "helpers/env/Env.hpp"\n'
            "int main(int argc, char** argv) {\n    parseArguments();\n"
            "    if (!verifyConfig) {\n        gainRealTime();\n    }\n"
            "    createCompositor();\n}\n"
        )
        patched = source.integration.patch_native_startup(main)
        self.assertIn('#include "native_process_privilege.h"', patched)
        self.assertIn('gnu::section(".preinit_array")', patched)
        self.assertIn("initializeNativeEnvironment", patched)
        self.assertLess(
            patched.index("dropNativeProcessCapabilities"),
            patched.index("gainRealTime"),
        )
        self.assertLess(
            patched.index("dropNativeProcessCapabilities"),
            patched.index("createCompositor"),
        )
        self.assertIn("return 1;", patched)
        self.assertLess(
            patched.index("dropNativeProcessCapabilities"),
            patched.index("parseArguments"),
        )
        self.assertLess(
            patched.index("secureNativeEntry"), patched.index("gainRealTime")
        )
        for changed in (
            main.replace("int main(int argc, char** argv) {", "int main() {"),
            main + "int main(int argc, char** argv) {\n",
            main.replace("    if (!verifyConfig) {", "    if (verifyConfig) {"),
            patched,
            main.replace('#include "helpers/env/Env.hpp"', ""),
        ):
            with self.subTest(changed=changed), self.assertRaises(source.SourceError):
                source.integration.patch_native_startup(changed)

    def test_native_plugin_loading_and_lua_construction_are_permanently_refused(self):
        start = "std::expected<CPlugin*, std::string> CPluginSystem::loadPluginInternal(const std::string& path) {"
        following = (
            "void CPluginSystem::unloadPlugin(const CPlugin* plugin, bool eject) {"
        )
        plugin = (
            start + "\n dlopen(path.c_str(), RTLD_LAZY);\n}\n\n" + following + "\n}\n"
        )
        config = "g_mgr = makeUnique<Lua::CConfigManager>();\n" * 2
        env_start = "std::optional<std::string> CConfigManager::handleEnv(const std::string& command, const std::string& value) {"
        env_next = "std::optional<std::string> CConfigManager::handlePlugin(const std::string& command, const std::string& path) {"
        environment = env_start + "\nsetenv(name, value, 1);\n}\n" + env_next + "\n}\n"
        disabled, legacy, safe_environment = (
            source.integration.reject_in_process_code_loading(
                plugin, config, environment
            )
        )
        self.assertNotIn("setenv(", safe_environment)
        self.assertNotIn("dlopen(", disabled)
        self.assertIn("return std::unexpected(", disabled)
        self.assertNotIn("makeUnique<Lua::CConfigManager>", legacy)
        self.assertEqual(legacy.count("return false;"), 2)
        for bad_plugin, bad_config in [
            (plugin.replace(start, ""), config),
            (plugin + start, config),
            (plugin, config + config),
            (disabled, legacy),
        ]:
            with self.assertRaises(source.SourceError):
                source.integration.reject_in_process_code_loading(
                    bad_plugin, bad_config, environment
                )

    def test_native_environment_refusal_rejects_missing_reordered_or_patched_anchors(
        self,
    ):
        plugin_start = "std::expected<CPlugin*, std::string> CPluginSystem::loadPluginInternal(const std::string& path) {"
        plugin_next = (
            "void CPluginSystem::unloadPlugin(const CPlugin* plugin, bool eject) {"
        )
        plugin = plugin_start + "\n}\n" + plugin_next + "\n}\n"
        config = "g_mgr = makeUnique<Lua::CConfigManager>();\n" * 2
        start = "std::optional<std::string> CConfigManager::handleEnv(const std::string& command, const std::string& value) {"
        following = "std::optional<std::string> CConfigManager::handlePlugin(const std::string& command, const std::string& path) {"
        legacy = start + "\nsetenv(name, value, 1);\n}\n" + following + "\n}\n"
        _, _, patched = source.integration.reject_in_process_code_loading(
            plugin, config, legacy
        )
        for invalid in (
            legacy.replace(start, ""),
            legacy + start,
            following + start,
            patched,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(source.SourceError):
                source.integration.reject_in_process_code_loading(
                    plugin, config, invalid
                )

    def test_recipe_drift_and_symlink_are_refused_before_source_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe = root / "source_integration.py"
            recipe.write_bytes(
                source.RECIPE.read_bytes() + b"\n# changed native hook\n"
            )
            with (
                patch.object(source, "RECIPE", recipe),
                patch.object(source, "extract_verified_archive") as extract,
            ):
                with self.assertRaisesRegex(source.SourceError, "recipe changed"):
                    source.stage(root / "archive", root / "staged")
                extract.assert_not_called()
            recipe.write_bytes(source.RECIPE.read_bytes())
            linked = root / "linked.py"
            linked.symlink_to(recipe)
            with (
                patch.object(source, "RECIPE", linked),
                patch.object(source, "extract_verified_archive") as extract,
            ):
                with self.assertRaisesRegex(source.SourceError, "recipe changed"):
                    source.stage(root / "archive", root / "staged")
                extract.assert_not_called()

    def extract(self, directory: Path, data: bytes, digest: str | None = None) -> Path:
        archive = directory / "source.tar.gz"
        archive.write_bytes(data)
        return source.extract_verified_archive(
            archive,
            directory / "staging",
            digest or hashlib.sha256(data).hexdigest(),
            "native",
        )

    def test_verified_regular_source_and_existing_destination(self) -> None:
        data = archive_bytes(
            [("native/source.cpp", b"reviewed source\n", tarfile.REGTYPE)]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = self.extract(root, data)
            self.assertEqual((staged / "source.cpp").read_bytes(), b"reviewed source\n")
            with self.assertRaises(FileExistsError):
                self.extract(root, data)
            self.assertEqual((staged / "source.cpp").read_bytes(), b"reviewed source\n")

    def test_wrong_digest_never_creates_destination(self) -> None:
        data = archive_bytes([("native/source.cpp", b"unreviewed", tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(source.SourceError, "checksum"):
                self.extract(root, data, "0" * 64)
            self.assertFalse((root / "staging").exists())

    def test_archive_paths_links_and_duplicate_entries_rejected_before_writes(
        self,
    ) -> None:
        cases = [
            [("../escape", b"bad", tarfile.REGTYPE)],
            [("/native/absolute", b"bad", tarfile.REGTYPE)],
            [("native/../escape", b"bad", tarfile.REGTYPE)],
            [("other/source.cpp", b"bad", tarfile.REGTYPE)],
            [("native/link", "../escape", tarfile.SYMTYPE)],
            [("native/link", "native/source.cpp", tarfile.LNKTYPE)],
            [("native/fifo", b"", tarfile.FIFOTYPE)],
            [("native/dev", b"", tarfile.CHRTYPE)],
            [
                ("native/a", b"one", tarfile.REGTYPE),
                ("native/a", b"two", tarfile.REGTYPE),
            ],
            [
                ("native/a/b", b"one", tarfile.REGTYPE),
                ("native/a", b"two", tarfile.REGTYPE),
            ],
            [("native/a\\b", b"bad", tarfile.REGTYPE)],
            [("native/a\nb", b"bad", tarfile.REGTYPE)],
            [("native//a", b"bad", tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(source.SourceError):
                    self.extract(root, archive_bytes(entries))
                self.assertFalse((root / "staging").exists())
                self.assertFalse((root / "escape").exists())

    def test_resource_limits_reject_before_extraction(self) -> None:
        data = archive_bytes([("native/source.cpp", b"12345", tarfile.REGTYPE)])
        for limit, value in [
            ("MAX_UNPACKED", 4),
            ("MAX_MEMBERS", 0),
            ("MAX_ARCHIVE", 4),
        ]:
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with (
                    patch.object(source, limit, value),
                    self.assertRaises(source.SourceError),
                ):
                    self.extract(root, data)
                self.assertFalse((root / "staging").exists())

    def test_archive_in_place_replacement_after_hash_cannot_change_extracted_bytes(
        self,
    ) -> None:
        good = archive_bytes([("native/source.cpp", b"reviewed", tarfile.REGTYPE)])
        bad = archive_bytes([("native/source.cpp", b"attacker", tarfile.REGTYPE)])
        actual_open = tarfile.open
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.tar.gz"
            archive.write_bytes(good)

            def mutate_then_open(*args, **kwargs):
                # An in-place write changes the same inode, defeating the
                # otherwise tempting verify-then-extract-from-open-FD pattern.
                archive.write_bytes(bad)
                return actual_open(*args, **kwargs)

            with patch.object(source.tarfile, "open", side_effect=mutate_then_open):
                staged = source.extract_verified_archive(
                    archive,
                    root / "staging",
                    hashlib.sha256(good).hexdigest(),
                    "native",
                )
            self.assertEqual((staged / "source.cpp").read_bytes(), b"reviewed")
            self.assertEqual(archive.read_bytes(), bad)

    def test_archive_symlink_and_destination_symlink_are_rejected(self) -> None:
        data = archive_bytes([("native/source.cpp", b"reviewed", tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.tar.gz"
            real.write_bytes(data)
            link = root / "link.tar.gz"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                source.extract_verified_archive(
                    link, root / "staging", hashlib.sha256(data).hexdigest(), "native"
                )
            victim = root / "victim"
            victim.mkdir()
            (root / "staging").symlink_to(victim, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                self.extract(root, data)
            self.assertEqual(list(victim.iterdir()), [])

    def test_integration_points_must_match_exactly_without_fuzzy_fallback(self) -> None:
        for text in ["other", "point\npoint"]:
            with self.subTest(text=text), self.assertRaises(source.SourceError):
                source.integration.replace_exact(text, "point", "replacement")
        self.assertEqual(
            source.integration.replace_exact(
                "before\npoint\nafter", "point", "replacement"
            ),
            "before\nreplacement\nafter",
        )

    def test_release_template_keeps_upstream_identity_and_marks_modification(
        self,
    ) -> None:
        commit = "a" * 40
        template = f'#define GIT_COMMIT_HASH    "{commit}"\n#define GIT_DIRTY          "clean"\n#define GIT_TAG            "v0.56.2"\n'
        stamped = source.integration.stamp_version_template(template, commit)
        self.assertIn(commit, stamped)
        self.assertIn('"linura-display-integration"', stamped)
        self.assertIn('"v0.56.2+linura-display-v1"', stamped)
        self.assertNotIn('"clean"', stamped)
        for candidate, pin in (
            (template, "b" * 40),
            (template + template, commit),
            (stamped, commit),
        ):
            with (
                self.subTest(candidate=candidate, pin=pin),
                self.assertRaises(source.SourceError),
            ):
                source.integration.stamp_version_template(candidate, pin)


if __name__ == "__main__":
    unittest.main()
