from __future__ import annotations

import copy
import gzip
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import arch_qualification_package_inputs as inputs
from tools.hyprland_display_environment import CONTRACT, load_contract


def fixture(directory: Path) -> tuple[dict, list[dict]]:
    records = []
    for name in ("alpha", "beta"):
        filename = name + "-1-1-any.pkg.tar.zst"
        payload = (name + "-fixture-only").encode()
        (directory / filename).write_bytes(payload)
        (directory / filename).chmod(0o600)
        (directory / (filename + ".sig")).write_bytes(
            b"fixture-signature-not-native-evidence"
        )
        (directory / (filename + ".sig")).chmod(0o600)
        records.append(
            dict(
                name=name,
                filename=filename,
                sha256=hashlib.sha256(payload).hexdigest(),
                max_bytes=128,
            )
        )
    data = {"repository_package_input": records, "repository_sha256": {}}
    for repository in ("core", "extra"):
        path = directory / (repository + ".db")
        with tarfile.open(path, "w") as archive:
            for record in records if repository == "core" else []:
                text = "".join(
                    f"%{key}%\n{value}\n\n"
                    for key, value in (
                        ("NAME", record["name"]),
                        ("FILENAME", record["filename"]),
                        ("SHA256SUM", record["sha256"]),
                        ("CSIZE", str((directory / record["filename"]).stat().st_size)),
                    )
                ).encode()
                member = tarfile.TarInfo(record["name"] + "/desc")
                member.size = len(text)
                archive.addfile(member, io.BytesIO(text))
        path.chmod(0o600)
        data["repository_sha256"][repository] = inputs.digest(path)
    return data, records


class ArchivePackageInputsTests(unittest.TestCase):
    def test_guest_guard_uses_base_tools_and_rejects_ineligible_or_failed_probes(self):
        # Exercise the generated shell in a deliberately minimal PATH without
        # hostname. These probe fixtures are unit coverage, not VM evidence.
        for fault in (
            "qemu",
            "kvm",
            "hostname",
            "runtime-hostname",
            "hostname-failure",
            "virtualization",
            "virtualization-failure",
            "os",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                helper = (
                    f"#!{sys.executable}\n"
                    + r"""import os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name;fault=os.environ['GUARD_FIXTURE_FAULT']
if name=='uname':
    assert sys.argv[1:]==['-n']
    print('other-host' if fault=='hostname' else 'linura-v010-shell' if fault=='runtime-hostname' else 'linura-v010-substrate')
    sys.exit(1 if fault=='hostname-failure' else 0)
if name=='systemd-detect-virt':
    assert sys.argv[1:]==['--vm']
    print('none' if fault=='virtualization' else 'kvm' if fault=='kvm' else 'qemu')
    sys.exit(1 if fault=='virtualization-failure' else 0)
assert name=='grep' and sys.argv[1:]==['-qx','ID=arch','/etc/os-release']
sys.exit(1 if fault=='os' else 0)
"""
                )
                for name in ("uname", "systemd-detect-virt", "grep"):
                    path = directory / name
                    path.write_text(helper)
                    path.chmod(0o700)
                with patch.object(
                    inputs, "cache_script", return_value="printf 'guard-passed\\n'\n"
                ):
                    script = inputs.guest_script([])
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    env={
                        "PATH": str(directory),
                        "GUARD_FIXTURE_FAULT": fault,
                    },
                    capture_output=True,
                    timeout=10,
                )
                eligible = fault in ("qemu", "kvm")
                self.assertEqual(result.returncode == 0, eligible, result.stderr)
                self.assertEqual(result.stdout, b"guard-passed\n" if eligible else b"")

    def test_reader_is_a_read_only_nonseekable_stream_without_owning_its_source(self):
        source = io.BytesIO(b"bounded repository fixture")
        reader = inputs.RepositoryReader(source)
        self.assertTrue(reader.readable())
        self.assertFalse(reader.writable())
        self.assertFalse(reader.seekable())
        self.assertEqual(reader.read(7), b"bounded")
        for operation in (
            lambda: reader.write(b"changed"),
            lambda: reader.seek(0),
            reader.tell,
        ):
            with self.assertRaises(io.UnsupportedOperation):
                operation()
        reader.close()
        with self.assertRaises(ValueError):
            reader.read()
        # The repository decoder, not this bounded view, owns the input lifetime.
        self.assertFalse(source.closed)
        self.assertEqual(source.read(), b" repository fixture")

    def test_compressed_repository_keeps_raw_digest_and_expansion_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            path = directory / "core.db"
            original = path.read_bytes()
            path.write_bytes(gzip.compress(original))
            expected = inputs.digest(path)
            self.assertEqual(
                set(inputs.repository_records(path, expected)), {"alpha", "beta"}
            )
            with self.assertRaises(ValueError):
                inputs.repository_records(path, data["repository_sha256"]["core"])
            with patch.object(inputs, "MAX_REPOSITORY_EXPANDED_BYTES", 512):
                with self.assertRaises(ValueError):
                    inputs.repository_records(path, expected)
            data["repository_sha256"]["core"] = expected
            inputs.verify_repository_inputs(data, directory, records)

    def test_hashing_and_repository_expansion_reject_growth_and_exhaustion(self):
        self.assertEqual(
            inputs.hash_stream(io.BytesIO(b"abc"), 3),
            hashlib.sha256(b"abc").hexdigest(),
        )
        for payload, size in ((b"abc", 2), (b"ab", 3)):
            with self.assertRaises(ValueError):
                inputs.hash_stream(io.BytesIO(payload), size)
        with patch.object(inputs, "MAX_REPOSITORY_EXPANDED_BYTES", 4):
            reader = inputs.RepositoryReader(io.BytesIO(b"abcde"))
            with self.assertRaises(ValueError):
                reader.read(1000000000)

    def test_real_input_set_preserves_exact_sdk_hashes_and_bounded_names(self):
        data = load_contract(CONTRACT)
        records = inputs.package_inputs(data)
        self.assertEqual(
            {r["name"] for r in records},
            {"gcc", "perl", "hyprland", "llvm-libs", "qt6-declarative"},
        )
        packages = {r["name"]: r for r in data["package"]}
        for record in records:
            if record["name"] in packages:
                self.assertEqual(record["sha256"], packages[record["name"]]["sha256"])

    def test_unsafe_unknown_duplicate_or_unbounded_inputs_refuse(self):
        data = load_contract(CONTRACT)
        for key, value in (
            ("name", "../escape"),
            ("filename", "bad';touch injected"),
            ("filename", "/etc/shadow"),
            ("sha256", "0" * 64),
            ("sha256", "A" * 64),
            ("max_bytes", True),
            ("max_bytes", 0),
            ("max_bytes", 512 * 1024 * 1024 + 1),
            ("extra", "unknown"),
        ):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(data)
                changed["repository_package_input"][0][key] = value
                with self.assertRaises(ValueError):
                    inputs.package_inputs(changed)
        for records in (
            [],
            [data["repository_package_input"][0]] * 2,
            [data["repository_package_input"][0]] * 17,
        ):
            with self.assertRaises(ValueError):
                inputs.package_inputs({"repository_package_input": records})

    def test_both_databases_and_exact_package_resolution_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            inputs.verify_repository_inputs(data, directory, records)
            for field, bad in (
                ("filename", "alpha-2-1-any.pkg.tar.zst"),
                ("sha256", "a" * 64),
                ("max_bytes", 1),
                ("name", "unselected"),
            ):
                changed = copy.deepcopy(records)
                changed[0][field] = bad
                with self.assertRaises(ValueError):
                    inputs.verify_repository_inputs(data, directory, changed)
            for repository in ("core", "extra"):
                path = directory / (repository + ".db")
                original = path.read_bytes()
                path.write_bytes(original + b"corrupt")
                with self.assertRaises(ValueError):
                    inputs.verify_repository_inputs(data, directory, records)
                path.write_bytes(original)

    def test_acquisition_preserves_https_bounds_and_refuses_changed_bytes_or_reuse(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            payload = b"input fixture"
            expected = hashlib.sha256(payload).hexdigest()

            def curl(command, **kwargs):
                self.assertEqual(command[0], "curl")
                self.assertIn("--max-filesize", command)
                self.assertEqual(command[command.index("--proto") + 1], "=https")
                self.assertEqual(command[command.index("--proto-redir") + 1], "=https")
                self.assertEqual(kwargs["timeout"], 310)
                self.assertEqual(command[command.index("--output") + 1], "-")
                kwargs["stdout"].write(payload)

            with patch.object(inputs.subprocess, "run", side_effect=curl):
                inputs.acquire(
                    "https://fixture.invalid/input", directory / "valid", 128, expected
                )
                with self.assertRaises(ValueError):
                    inputs.acquire(
                        "https://fixture.invalid/input",
                        directory / "corrupt",
                        128,
                        "a" * 64,
                    )
                with self.assertRaises(ValueError):
                    inputs.acquire(
                        "https://fixture.invalid/input",
                        directory / "valid",
                        128,
                        expected,
                    )

    def test_stage_rebuilds_instructions_and_transports_only_regular_declared_inputs(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            (directory / "install-inputs.sh").write_text(
                "must never execute cached instructions"
            )
            (directory / "unrelated-secret").write_text("must never enter bundle")

            def ssh(command, **kwargs):
                self.assertEqual(command[0], "ssh")
                self.assertIn("linura@127.0.0.1", command)
                self.assertIn("2223", command)
                self.assertIn("300", command)
                self.assertEqual(kwargs["timeout"], 320)
                with tarfile.open(fileobj=kwargs["stdin"], mode="r") as archive:
                    expected = {"install-inputs.sh"} | {
                        r["filename"] + suffix
                        for r in records
                        for suffix in ("", ".sig")
                    }
                    self.assertEqual(set(archive.getnames()), expected)
                    for member in archive:
                        self.assertTrue(member.isfile())
                        self.assertEqual(member.uid, 0)
                        self.assertEqual(member.gid, 0)
                    script = archive.extractfile("install-inputs.sh")
                    self.assertIsNotNone(script)
                    assert script is not None
                    self.assertEqual(
                        script.read(), inputs.guest_script(records).encode()
                    )

            with patch.object(inputs.subprocess, "run", side_effect=ssh) as run:
                inputs.stage_inputs(data, directory, Path("/private/fixture-key"))
                self.assertEqual(run.call_count, 1)
            self.assertFalse(list(directory.glob("package-inputs-*.tar")))

    def test_corruption_aliases_nonregular_and_oversized_signatures_never_reach_ssh(
        self,
    ):
        for fault in (
            "package",
            "signature-alias",
            "package-link",
            "fifo",
            "signature-size",
            "writable",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                data, records = fixture(directory)
                path = directory / records[0]["filename"]
                signature = path.with_name(path.name + ".sig")
                if fault == "package":
                    path.write_bytes(b"corrupt")
                elif fault == "signature-alias":
                    signature.unlink()
                    signature.symlink_to(path)
                elif fault == "package-link":
                    os.link(path, directory / "alias")
                elif fault == "fifo":
                    signature.unlink()
                    os.mkfifo(signature)
                elif fault == "signature-size":
                    signature.write_bytes(b"x" * (1024 * 1024 + 1))
                else:
                    path.chmod(0o666)
                with patch.object(inputs.subprocess, "run") as run:
                    with self.assertRaises((ValueError, OSError)):
                        inputs.stage_inputs(
                            data, directory, Path("/private/fixture-key")
                        )
                    run.assert_not_called()
                self.assertFalse(list(directory.glob("package-inputs-*.tar")))

    def test_native_verification_precedes_every_publication_and_readback_is_required(
        self,
    ):
        for fault in (
            "none",
            "checksum",
            "signature",
            "readback",
            "signature-readback",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _, records = fixture(directory)
                binary = directory / "bin"
                binary.mkdir()
                helper = (
                    f"#!{sys.executable}\n"
                    + r"""import hashlib,os,pathlib,shutil,sys
root=pathlib.Path(os.environ['INPUT_FIXTURE']);fault=os.environ['INPUT_FAULT'];args=sys.argv[1:]
if pathlib.Path(sys.argv[0]).name=='sha256sum':
    if args[0]=='--':
        print(hashlib.sha256(pathlib.Path(args[1]).read_bytes()).hexdigest()+'  '+args[1])
        sys.exit(0)
    expected,path=sys.stdin.read().strip().split('  ',1)
    actual=root/'published'/pathlib.Path(path).name if path.startswith('/var/cache/pacman/pkg/') else pathlib.Path(path)
    sys.exit(0 if hashlib.sha256(actual.read_bytes()).hexdigest()==expected else 1)
assert args[0]=='-n'
if args[1]=='pacman-key':
    with (root/'actions').open('a') as out:out.write('verify '+args[-1]+'\n')
    if fault=='signature' and args[-1].startswith('beta-'):sys.exit(1)
else:
    assert args[1]=='install'
    if '-d' in args:(root/'published').mkdir()
    else:
        with (root/'actions').open('a') as out:out.write('publish '+args[-2]+'\n')
        target=root/'published'/pathlib.Path(args[-1]).name
        shutil.copyfile(args[-2],target)
        if fault=='readback' or fault=='signature-readback' and target.name.endswith('.sig'):target.write_bytes(b'corrupt')
"""
                )
                for name in ("sudo", "sha256sum"):
                    file = binary / name
                    file.write_text(helper)
                    file.chmod(0o700)
                if fault == "checksum":
                    (directory / records[1]["filename"]).write_bytes(b"corrupt")
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        inputs.cache_script(records),
                        "fixture",
                        str(directory),
                    ],
                    cwd=directory,
                    env={
                        **os.environ,
                        "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                        "INPUT_FIXTURE": str(directory),
                        "INPUT_FAULT": fault,
                    },
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(
                    result.returncode == 0, fault == "none", result.stderr.decode()
                )
                actions = (directory / "actions").read_text().splitlines()
                if fault in ("checksum", "signature"):
                    self.assertFalse(any(x.startswith("publish ") for x in actions))
                if fault == "none":
                    self.assertTrue(all(x.startswith("verify ") for x in actions[:2]))
                    self.assertTrue(all(x.startswith("publish ") for x in actions[2:]))
                    self.assertEqual(len(actions), 2 + 2 * len(records))
                    for record in records:
                        for suffix in ("", ".sig"):
                            name = record["filename"] + suffix
                            self.assertEqual(
                                (directory / "published" / name).read_bytes(),
                                (directory / name).read_bytes(),
                            )
        guard = inputs.guest_script(load_contract(CONTRACT)["repository_package_input"])
        self.assertIn("guest_hostname=$(uname -n)", guard)
        self.assertIn('test "$guest_hostname" = linura-v010-substrate', guard)
        self.assertIn(
            "\nlocal-hostname: linura-v010-substrate\n",
            (
                inputs.ROOT / "qualification/v010/shell-runtime/prepare-substrate.sh"
            ).read_text(),
        )
        self.assertIn("guest_virtualization=$(systemd-detect-virt --vm)", guard)
        self.assertIn('case "$guest_virtualization" in qemu|kvm)', guard)
        self.assertIn("grep -qx 'ID=arch' /etc/os-release", guard)


if __name__ == "__main__":
    unittest.main()
