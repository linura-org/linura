from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from tools.pypi_verify import VerificationError, load_project, local_artifacts, verify_metadata


class PyPIVerificationTests(unittest.TestCase):
    def _artifact(self, root: Path, name: str = "linura-0.0.1-py3-none-any.whl") -> Path:
        path = root / name
        path.write_bytes(b"sealed-wheel")
        return path

    def _metadata(self, artifact: Path) -> dict[str, object]:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        return {
            "info": {"name": "linura", "version": "0.0.1"},
            "urls": [
                {
                    "filename": artifact.name,
                    "digests": {"sha256": digest},
                    "url": f"https://files.pythonhosted.org/packages/{artifact.name}",
                    "yanked": False,
                }
            ],
        }

    def test_project_version_is_pep440_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pyproject = Path(temp_dir) / "pyproject.toml"
            pyproject.write_text(
                '[project]\nname = "linura"\nversion = "0.1.0-rc.1"\n',
                encoding="utf-8",
            )
            self.assertEqual(load_project(pyproject), ("linura", "0.1.0rc1"))

    def test_remote_equivalent_version_spelling_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = self._artifact(root, "linura-0.1.0rc1-py3-none-any.whl")
            metadata = self._metadata(artifact)
            assert isinstance(metadata["info"], dict)
            metadata["info"]["version"] = "0.1.0-rc.1"
            verify_metadata(
                metadata,
                project_name="linura",
                version="0.1.0rc1",
                artifacts=local_artifacts([artifact]),
                download=False,
                timeout=30,
            )

    def test_exact_file_set_and_digest_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = self._artifact(root)
            verify_metadata(
                self._metadata(artifact),
                project_name="linura",
                version="0.0.1",
                artifacts=local_artifacts([artifact]),
                download=False,
                timeout=30,
            )

    def test_extra_remote_distribution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = self._artifact(root)
            metadata = self._metadata(artifact)
            assert isinstance(metadata["urls"], list)
            metadata["urls"].append(
                {
                    "filename": "linura-0.0.1-cp313-cp313-manylinux.whl",
                    "digests": {"sha256": "0" * 64},
                    "url": "https://files.pythonhosted.org/packages/extra.whl",
                    "yanked": False,
                }
            )
            with self.assertRaisesRegex(VerificationError, "file set differs"):
                verify_metadata(
                    metadata,
                    project_name="linura",
                    version="0.0.1",
                    artifacts=local_artifacts([artifact]),
                    download=False,
                    timeout=30,
                )

    def test_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = self._artifact(root)
            metadata = self._metadata(artifact)
            assert isinstance(metadata["urls"], list)
            assert isinstance(metadata["urls"][0], dict)
            metadata["urls"][0]["digests"] = {"sha256": "f" * 64}
            with self.assertRaisesRegex(VerificationError, "metadata digest differs"):
                verify_metadata(
                    metadata,
                    project_name="linura",
                    version="0.0.1",
                    artifacts=local_artifacts([artifact]),
                    download=False,
                    timeout=30,
                )

    def test_yanked_sealed_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = self._artifact(root)
            metadata = self._metadata(artifact)
            assert isinstance(metadata["urls"], list)
            assert isinstance(metadata["urls"][0], dict)
            metadata["urls"][0]["yanked"] = True
            with self.assertRaisesRegex(VerificationError, "is yanked"):
                verify_metadata(
                    metadata,
                    project_name="linura",
                    version="0.0.1",
                    artifacts=local_artifacts([artifact]),
                    download=False,
                    timeout=30,
                )


if __name__ == "__main__":
    unittest.main()
