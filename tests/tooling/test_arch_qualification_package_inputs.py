from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import select
import subprocess
import signal
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tools import arch_qualification_package_inputs as inputs
from tools.hyprland_display_environment import CONTRACT, load_contract


def fixture(
    directory: Path,
    compression: str = "zst",
    names: tuple[str, ...] = ("alpha", "beta"),
) -> tuple[dict, list[dict]]:
    records = []
    for name in names:
        filename = (
            name + "-1-1-any.pkg.tar." + (compression if name == "beta" else "zst")
        )
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
    def test_interrupted_downloads_leave_no_final_or_staging_file_and_retry_cleanly(
        self,
    ):
        for failure in (
            subprocess.CalledProcessError(18, "curl"),
            subprocess.TimeoutExpired("curl", 310),
            OSError("download unavailable"),
            KeyboardInterrupt(),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary)
                destination = directory / "download"
                payload = b"complete verified input"
                expected = hashlib.sha256(payload).hexdigest()

                def interrupted(command, **kwargs):
                    kwargs["stdout"].write(b"partial")
                    kwargs["stdout"].flush()
                    self.assertFalse(destination.exists())
                    raise failure

                with patch.object(inputs.subprocess, "run", side_effect=interrupted):
                    with self.assertRaises(type(failure)):
                        inputs.acquire(
                            "https://fixture.invalid/input", destination, 128, expected
                        )
                self.assertFalse(destination.exists())
                self.assertEqual(list(directory.iterdir()), [])

                def completed(command, **kwargs):
                    self.assertFalse(destination.exists())
                    kwargs["stdout"].write(payload)

                with patch.object(inputs.subprocess, "run", side_effect=completed):
                    inputs.acquire(
                        "https://fixture.invalid/input", destination, 128, expected
                    )
                self.assertEqual(destination.read_bytes(), payload)
                self.assertEqual(destination.stat().st_nlink, 1)
                self.assertEqual(list(directory.iterdir()), [destination])

    def test_invalid_complete_downloads_are_not_published_or_cached(self):
        for payload, maximum, expected in (
            (b"", 128, None),
            (b"too large", 1, None),
            (b"wrong digest", 128, "a" * 64),
        ):
            with (
                self.subTest(payload=payload),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary)
                with patch.object(
                    inputs.subprocess,
                    "run",
                    side_effect=lambda command, **kwargs: kwargs["stdout"].write(
                        payload
                    ),
                ):
                    with self.assertRaises(ValueError):
                        inputs.acquire(
                            "https://fixture.invalid/input",
                            directory / "download",
                            maximum,
                            expected,
                        )
                self.assertEqual(list(directory.iterdir()), [])

    def test_dynamic_cache_retries_failed_acquisition_without_resetting_spent_budgets(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            path = directory / records[0]["filename"]
            payload = path.read_bytes()
            path.unlink()
            cache = inputs.PinnedPackageCache(data, directory)

            def interrupted(command, **kwargs):
                kwargs["stdout"].write(payload[:2])
                raise subprocess.CalledProcessError(18, "curl")

            with patch.object(inputs.subprocess, "run", side_effect=interrupted):
                with self.assertRaises(subprocess.CalledProcessError):
                    cache.open("/" + path.name)
            spent = cache.bytes
            self.assertFalse(path.exists())
            self.assertIn(path.name, cache.files)
            with patch.object(
                inputs.subprocess,
                "run",
                side_effect=lambda command, **kwargs: kwargs["stdout"].write(payload),
            ):
                stream, before = cache.open("/" + path.name)
                with stream:
                    self.assertEqual(stream.read(), payload)
                    self.assertEqual(before.st_nlink, 1)
            self.assertEqual(cache.bytes, spent)
            self.assertEqual(cache.requests, 2)
            self.assertEqual(cache.files, {path.name})

    def test_atomic_publication_never_exposes_partial_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "cache-port"
            partial, finish = threading.Event(), threading.Event()

            def write(stream):
                stream.write(b"12")
                stream.flush()
                partial.set()
                if not finish.wait(timeout=5):
                    raise TimeoutError("component publication barrier expired")
                stream.write(b"345\n")

            with ThreadPoolExecutor(max_workers=1) as worker:
                future = worker.submit(inputs.publish_fresh, path, 6, None, write)
                try:
                    self.assertTrue(partial.wait(timeout=5))
                    self.assertFalse(path.exists())
                    self.assertEqual(len(list(directory.glob(".archive-input-*"))), 1)
                finally:
                    finish.set()
                future.result(timeout=5)
            self.assertEqual(path.read_bytes(), b"12345\n")
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(directory.iterdir()), [path])

    def test_atomic_publication_preserves_a_concurrent_destination_or_symlink(self):
        for kind in ("file", "symlink", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                path, target = directory / "download", directory / "protected"
                target.write_bytes(b"preserve existing bytes")

                def write(stream):
                    stream.write(b"complete staged input")
                    if kind == "file":
                        path.write_bytes(b"concurrent input")
                    elif kind == "symlink":
                        path.symlink_to(target)
                    else:
                        path.mkdir()

                with self.assertRaises(FileExistsError):
                    inputs.publish_fresh(path, 128, None, write)
                self.assertEqual(target.read_bytes(), b"preserve existing bytes")
                self.assertTrue(
                    path.is_symlink() if kind == "symlink" else path.exists()
                )
                if kind == "file":
                    self.assertEqual(path.read_bytes(), b"concurrent input")
                self.assertEqual(list(directory.glob(".archive-input-*")), [])

    def test_fsync_or_publication_failure_never_leaves_partial_final_bytes(self):
        for point in ("file-sync", "rename", "directory-sync"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                path = directory / "download"
                sync = inputs.os.fsync
                calls = 0

                def fail_sync(descriptor):
                    nonlocal calls
                    calls += 1
                    if calls == (1 if point == "file-sync" else 2):
                        raise OSError("injected fsync failure")
                    sync(descriptor)

                with (
                    patch.object(
                        inputs.os,
                        "fsync",
                        side_effect=fail_sync if point != "rename" else sync,
                    ),
                    patch.object(
                        inputs,
                        "rename_fresh",
                        side_effect=OSError("injected rename failure"),
                    )
                    if point == "rename"
                    else patch.object(
                        inputs, "rename_fresh", wraps=inputs.rename_fresh
                    ),
                ):
                    with self.assertRaises(OSError):
                        inputs.publish_fresh(
                            path,
                            128,
                            None,
                            lambda stream: stream.write(b"complete input"),
                        )
                if point == "directory-sync":
                    # Publication succeeded before the durability error. Leave
                    # the complete immutable entry; never replace/delete it.
                    self.assertEqual(path.read_bytes(), b"complete input")
                    self.assertEqual(path.stat().st_nlink, 1)
                else:
                    self.assertFalse(path.exists())
                self.assertEqual(list(directory.glob(".archive-input-*")), [])

    def test_killed_writer_cannot_publish_its_partial_cache_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "download"
            program = """import sys,time
from pathlib import Path
from tools.arch_qualification_package_inputs import publish_fresh
def write(stream):
    stream.write(b'partial')
    stream.flush()
    print('staged', flush=True)
    time.sleep(30)
publish_fresh(Path(sys.argv[1]),128,None,write)
"""
            with subprocess.Popen(
                [sys.executable, "-c", program, str(path)],
                cwd=inputs.ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as process:
                try:
                    assert process.stdout is not None
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0])
                    self.assertEqual(os.read(process.stdout.fileno(), 7), b"staged\n")
                    self.assertFalse(path.exists())
                    process.kill()
                    process.wait(timeout=5)
                    self.assertFalse(path.exists())
                    staged = list(directory.glob(".archive-input-*"))
                    self.assertEqual(len(staged), 1)
                    self.assertEqual(staged[0].read_bytes(), b"partial")
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)

    def test_unknown_staging_substitution_is_preserved_and_never_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "download"
            substituted = None

            def write(stream):
                nonlocal substituted
                stream.write(b"verified bytes")
                stream.flush()
                substituted = directory / next(directory.glob(".archive-input-*")).name
                substituted.unlink()
                substituted.write_bytes(b"unknown substituted file")

            with self.assertRaises(ValueError):
                inputs.publish_fresh(path, 128, None, write)
            self.assertFalse(path.exists())
            assert substituted is not None
            self.assertEqual(substituted.read_bytes(), b"unknown substituted file")

    def test_unavailable_exclusive_rename_and_unsafe_parent_refuse_without_fallback(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "download"
            with patch.object(inputs.ctypes, "CDLL", return_value=object()):
                with self.assertRaises(ValueError):
                    inputs.publish_fresh(
                        path, 128, None, lambda stream: stream.write(b"complete")
                    )
            self.assertEqual(list(directory.iterdir()), [])
            directory.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    inputs.publish_fresh(
                        path, 128, None, lambda stream: stream.write(b"complete")
                    )
                self.assertEqual(list(directory.iterdir()), [])
            finally:
                directory.chmod(0o700)

    def test_real_cache_process_counts_exact_sizes_instead_of_acquisition_ceilings(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(
                directory, names=("alpha", "beta", "gamma", "delta", "epsilon")
            )
            for record in records:
                record["max_bytes"] = 512 * 1024 * 1024
            cache = inputs.PinnedPackageCache(data, directory)
            self.assertEqual(
                cache.bytes,
                sum((directory / r["filename"]).stat().st_size for r in records)
                + len(records) * 1024 * 1024,
            )
            self.assertEqual(cache.initial_files, 10)
            data_path = directory / "cache-process-input.json"
            data_path.write_text(json.dumps(data))
            with (directory / "cache-process.log").open("w+b") as log:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import json,sys; from pathlib import Path; "
                        "from tools.arch_qualification_package_inputs import serve_cache; "
                        "serve_cache(json.loads(Path(sys.argv[1]).read_text()),Path(sys.argv[2]))",
                        str(data_path),
                        str(directory),
                    ],
                    cwd=inputs.ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 10
                    port_path = directory / "cache-port"
                    while not port_path.exists() and time.monotonic() < deadline:
                        if process.poll() is not None:
                            log.seek(0)
                            self.fail(log.read().decode(errors="replace"))
                        time.sleep(0.02)
                    self.assertTrue(port_path.is_file(), "cache readiness exceeded")
                    self.assertEqual(os.getpgid(process.pid), process.pid)
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", int(port_path.read_text()), timeout=5
                    )
                    try:
                        connection.request("GET", "/" + records[0]["filename"])
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(
                            response.read(),
                            (directory / records[0]["filename"]).read_bytes(),
                        )
                    finally:
                        connection.close()
                finally:
                    if process.poll() is None:
                        if os.getpgid(process.pid) == process.pid:
                            os.killpg(process.pid, signal.SIGTERM)
                        else:
                            process.terminate()
                    process.wait(timeout=5)

    def test_initial_cache_pairs_must_match_complete_pinned_catalog(self):
        for field, value in (
            ("name", "unselected"),
            ("filename", "alpha-2-1-any.pkg.tar.zst"),
            ("sha256", "a" * 64),
            ("max_bytes", 1),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                data, records = fixture(directory)
                records[0][field] = value
                with self.assertRaises(ValueError):
                    inputs.PinnedPackageCache(data, directory)

    def test_cache_parallel_downloads_coalesce_without_serializing_other_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            payloads = {
                r["filename"]: (directory / r["filename"]).read_bytes() for r in records
            }
            for name in payloads:
                (directory / name).unlink()
            downloads = []
            downloads_lock = threading.Lock()
            parallel_downloads = threading.Barrier(2)

            def download(url, destination, maximum, expected):
                with downloads_lock:
                    downloads.append(destination.name)
                # Both distinct inputs must enter acquisition together; a
                # single server worker or global acquisition lock fails here.
                parallel_downloads.wait(timeout=5)
                destination.write_bytes(payloads[destination.name])
                destination.chmod(0o600)

            cache = inputs.PinnedPackageCache(data, directory)
            with inputs.cache_server(cache) as server:
                port = server.server_address[1]
                assert isinstance(port, int)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def request(name):
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", port, timeout=10
                    )
                    try:
                        connection.request("GET", "/" + name)
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()

                names = [
                    records[0]["filename"],
                    records[1]["filename"],
                    records[0]["filename"],
                ]
                try:
                    with patch.object(inputs, "acquire", side_effect=download):
                        with ThreadPoolExecutor(max_workers=3) as clients:
                            results = list(clients.map(request, names))
                    self.assertEqual(results, [(200, payloads[name]) for name in names])
                    self.assertCountEqual(downloads, payloads)
                    self.assertEqual(cache.requests, 3)
                    self.assertEqual(len(cache.files), 2)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())

    def test_catalog_keeps_historical_compression_as_opaque_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory, "xz")
            data["repository_package_input"] = records[:1]
            cache = inputs.PinnedPackageCache(data, directory)
            path = directory / records[1]["filename"]
            stream, _ = cache.open("/" + path.name)
            with stream:
                self.assertEqual(stream.read(), path.read_bytes())

    def test_complete_catalog_cache_serves_pinned_pairs_and_bounded_resumption(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            # Native resolution may require an input outside the initial staged
            # exception set. The complete authenticated catalog owns selection.
            data["repository_package_input"] = records[:1]
            package = records[1]["filename"]
            payload = (directory / package).read_bytes()
            signature = (directory / (package + ".sig")).read_bytes()
            (directory / package).unlink()
            (directory / (package + ".sig")).unlink()
            downloads = []

            def curl(command, **kwargs):
                url = command[-1]
                expected = f"{inputs.ORIGIN}/b/beta/{package}"
                self.assertIn(url, (expected, expected + ".sig"))
                self.assertEqual(command[command.index("--proto") + 1], "=https")
                downloads.append(url)
                kwargs["stdout"].write(signature if url.endswith(".sig") else payload)

            cache = inputs.PinnedPackageCache(data, directory)
            with inputs.cache_server(cache) as server:
                self.assertEqual(server.server_address[0], "127.0.0.1")
                port = server.server_address[1]
                self.assertIsInstance(port, int)
                assert isinstance(port, int)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with patch.object(inputs.subprocess, "run", side_effect=curl):
                        for path, headers, expected_status, expected_payload in (
                            ("/health", {}, 200, b"ready\n"),
                            ("/" + package, {}, 200, payload),
                            ("/" + package + ".sig", {}, 200, signature),
                            ("/" + package, {"Range": "bytes=3-"}, 206, payload[3:]),
                        ):
                            connection = http.client.HTTPConnection(
                                "127.0.0.1", port, timeout=5
                            )
                            connection.request("GET", path, headers=headers)
                            response = connection.getresponse()
                            self.assertEqual(response.status, expected_status)
                            self.assertEqual(response.read(), expected_payload)
                            if headers:
                                self.assertEqual(
                                    response.getheader("Content-Range"),
                                    f"bytes 3-{len(payload) - 1}/{len(payload)}",
                                )
                            connection.close()
                        for path, headers, status in (
                            ("/unknown.pkg.tar.zst", {}, 404),
                            ("/../core.db", {}, 404),
                            ("/%2e%2e%2fcore.db", {}, 404),
                            ("/core.db", {}, 404),
                            ("/" + package + "?source=other", {}, 503),
                            ("/" + package, {"Range": "bytes=0-1,3-4"}, 416),
                            ("/" + package, {"Range": "bytes=999999-"}, 416),
                        ):
                            connection = http.client.HTTPConnection(
                                "127.0.0.1", port, timeout=5
                            )
                            connection.request("GET", path, headers=headers)
                            response = connection.getresponse()
                            self.assertEqual(response.status, status)
                            response.read()
                            connection.close()
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
            self.assertEqual(len(downloads), 2)
            self.assertEqual(cache.files, {package, package + ".sig"})

    def test_catalog_cache_refuses_drift_unsafe_inputs_and_exhaustion(self):
        for fault in (
            "database",
            "bytes",
            "link",
            "alias",
            "writable",
            "capacity",
            "count",
            "requests",
            "deadline",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                data, records = fixture(directory)
                path = directory / records[0]["filename"]
                if fault == "database":
                    (directory / "core.db").write_bytes(b"changed")
                    with self.assertRaises(ValueError):
                        inputs.PinnedPackageCache(data, directory)
                    continue
                cache = inputs.PinnedPackageCache(data, directory)
                if fault == "bytes":
                    path.write_bytes(b"changed")
                elif fault == "link":
                    path.unlink()
                    path.symlink_to(directory / records[1]["filename"])
                elif fault == "alias":
                    os.link(path, directory / "alias")
                elif fault == "writable":
                    path.chmod(0o666)
                elif fault == "capacity":
                    cache.bytes = inputs.MAX_TOTAL_BYTES
                elif fault == "count":
                    cache.files = {str(i) for i in range(inputs.MAX_CACHE_FILES)}
                elif fault == "requests":
                    cache.requests = inputs.MAX_CACHE_REQUESTS
                elif fault == "deadline":
                    cache.deadline = 0
                with patch.object(inputs, "acquire") as download:
                    with self.assertRaises((ValueError, OSError)):
                        cache.open("/" + path.name)
                    download.assert_not_called()

    def test_catalog_cache_verifies_new_bytes_before_serving(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data, records = fixture(directory)
            path = directory / records[0]["filename"]
            path.unlink()
            cache = inputs.PinnedPackageCache(data, directory)

            def bad_download(url, destination, maximum, expected):
                destination.write_bytes(b"substituted")
                destination.chmod(0o600)

            with patch.object(inputs, "acquire", side_effect=bad_download):
                with self.assertRaises(ValueError):
                    cache.open("/" + path.name)
            self.assertIn(path.name, cache.files)

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
