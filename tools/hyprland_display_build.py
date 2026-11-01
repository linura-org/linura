#!/usr/bin/env python3
"""Build the source-pinned S21 compositor in a disposable pinned Arch guest.

The sanitized prerequisite is verified and opened as a read-only backing image.
All large generated inputs, VM disks, logs and build outputs use guarded storage.
A successful build is not execution, rollback or S17 qualification evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import development_storage as storage  # noqa: E402
from tools import hyprland_display_source as source  # noqa: E402
from tools import hyprland_display_candidate as candidate  # noqa: E402
from tools.hyprland_display_environment import CONTRACT, load_contract  # noqa: E402

ENVIRONMENT = "arch-hyprland-runtime"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, **kwargs)


def poweroff_guest(ssh: list[str], process: subprocess.Popen, build_log) -> None:
    """Accept SSH disconnect only when QEMU actually exits successfully.

    systemd can stop sshd before reporting the poweroff command's exit code.
    Exit 255 alone is *not* success: a stuck, crashed or killed guest fails.
    """
    command = [*ssh, "sudo", "-n", "systemctl", "poweroff"]
    result = subprocess.run(
        command,
        check=False,
        stdout=build_log,
        stderr=subprocess.STDOUT,
        timeout=20,
    )
    if result.returncode not in (0, 255):
        raise subprocess.CalledProcessError(result.returncode, command)
    exit_code = process.wait(timeout=120)
    if exit_code != 0:
        raise RuntimeError(
            f"build guest failed to power off cleanly (qemu exit {exit_code}; "
            f"ssh exit {result.returncode})"
        )


def reserve_run(run_id: str, development: bool) -> tuple[dict, str, bool]:
    sha = run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(
        run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT,
            capture_output=True,
        ).stdout
    )
    if dirty and not development:
        raise ValueError(
            "exact-source preparation requires a clean checkout; use --development only for non-qualification work"
        )
    # A CI job reserves its provider-owned root once, then this driver creates
    # several fresh prepare/build runs inside it. Revalidate that exact root
    # and every run boundary; never recreate it, relax its permissions or reuse
    # an occupied run. Dedicated-volume preparation retains its existing path.
    prepared_provider_root = (
        os.environ.get("LINURA_STORAGE_CLASS") == "github-hosted-ephemeral"
        and Path(storage.arguments(run_id).storage_root).exists()
    )
    if development or prepared_provider_root:
        paths = storage.run_layout(ROOT, ENVIRONMENT, run_id)
        for role in ("temporary", "vm", "cmake"):
            storage.private_tree(
                Path(storage.arguments(run_id).storage_root),
                storage.role_path(paths, role),
                exclusive=True,
            )
    else:
        storage.prepare(ROOT, ENVIRONMENT, run_id, sha)
        paths = storage.run_layout(ROOT, ENVIRONMENT, run_id)
    return paths, sha, dirty


def prepare_environment(run_id: str, development: bool) -> int:
    contract = load_contract(CONTRACT)
    paths, sha, dirty = reserve_run(run_id, development)
    temporary = storage.require_destination(
        ROOT,
        ENVIRONMENT,
        storage.role_path(paths, "temporary"),
        "temporary",
        run=run_id,
    )
    vm = storage.require_destination(
        ROOT, ENVIRONMENT, storage.role_path(paths, "vm"), "vm", run=run_id
    )
    image = vm / "arch-base.qcow2"
    os.umask(0o077)
    run(
        [
            "curl",
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "900",
            "--retry",
            "2",
            "--max-filesize",
            "2147483648",
            "--output",
            str(image),
            contract["base_image_url"],
        ],
        timeout=2800,
    )
    with image.open("rb") as stream:
        if (
            hashlib.file_digest(stream, "sha256").hexdigest()
            != contract["base_image_sha256"]
        ):
            raise ValueError(
                "downloaded Arch base image differs from the pinned contract"
            )
    inputs = [
        CONTRACT,
        ROOT / contract["builder"],
        ROOT / contract["build_dependency_verifier"],
    ]
    digests = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs
    }
    env = os.environ.copy()
    env.update(
        LINURA_RUN_ID=run_id,
        BASE_IMAGE_URL=contract["base_image_url"],
        BASE_IMAGE_SHA256=contract["base_image_sha256"],
        QUALIFICATION_NIC_MAC="52:54:00:21:02:59",
    )
    prepared, manifest = vm / "s21-hyprland-build.qcow2", vm / "s21-hyprland-build.json"
    with (temporary / "prepare.log").open("xb") as log:
        run(
            [
                "bash",
                str(ROOT / contract["builder"]),
                str(CONTRACT),
                str(image),
                str(prepared),
                str(manifest),
                str(temporary / "substrate-builder"),
            ],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=3600,
        )
    if any(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest
        for path, digest in digests.items()
    ):
        raise ValueError("build environment recipe changed during preparation")
    run(
        [
            sys.executable,
            str(ROOT / contract["verifier"]),
            str(CONTRACT),
            str(ROOT / contract["builder"]),
            str(prepared),
            str(manifest),
        ],
        cwd=ROOT,
    )
    if not development:
        require_source_unchanged(sha)
    (temporary / "prepare-result.json").write_text(
        json.dumps(
            {
                "source_sha": sha,
                "dirty": dirty,
                "development": development,
                "qualification_evidence": False,
                "prepared_image": str(prepared),
                "prepared_manifest": str(manifest),
            },
            indent=2,
        )
        + "\n"
    )
    print("Verified S21-2 build environment: " + str(prepared))
    print("Prepared manifest: " + str(manifest))
    return 0


def build_script(jobs: int) -> str:
    if not 1 <= jobs <= 4:
        raise ValueError("build jobs must be bounded between one and four")
    return f"""set -euo pipefail
cd /home/linura/s21
cmake -S native -B mechanism-build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build mechanism-build --parallel {jobs}
ctest --test-dir mechanism-build --output-on-failure
cmake -S upstream/hyprland-source -B compositor-build -G Ninja \\
    -DCMAKE_BUILD_TYPE=Debug '-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g1' \\
    -DLINURA_DISPLAY_INTEGRATION_DIR=/home/linura/s21/native \\
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
# Compile the integration against real private headers first for useful SDK
# diagnostics, then perform the complete compositor build and upstream tests.
python3 - <<'SDK'
import subprocess
targets = subprocess.run(['ninja', '-C', 'compositor-build', '-t', 'targets', 'all'],
                         text=True, capture_output=True, check=True).stdout.splitlines()
objects = [line.split(':', 1)[0] for line in targets
           if line.split(':', 1)[0].endswith('/pinned_backend.cpp.o')]
if len(objects) != 1:
    raise SystemExit('expected exactly one source-pinned compositor integration object')
subprocess.run(['cmake', '--build', 'compositor-build', '--parallel', '{jobs}',
                '--target', objects[0]], check=True)
SDK
cmake --build compositor-build --parallel {jobs}
ctest --test-dir compositor-build --output-on-failure
# Upstream validates its runtime-directory prerequisite before parsing --version.
# Use a fresh private build directory, never a host desktop/runtime connection.
version_runtime="$(mktemp -d "$PWD/hyprland-version-runtime.XXXXXX")"
XDG_RUNTIME_DIR="$version_runtime" ./compositor-build/Hyprland --version
ldd ./compositor-build/Hyprland
sha256sum ./compositor-build/Hyprland
cmp mechanism-build/linura-display-integration-build.h compositor-build/linura-display/linura-display-integration-build.h
"""


def package_inputs(archive: Path, temporary: Path) -> Path:
    staged = temporary / "upstream"
    source.stage(archive, staged)
    native = ROOT / "apps/linura-hyprland-display"
    files = sorted(path for path in native.rglob("*") if path.is_file())
    if not files or len(files) > 128:
        raise ValueError("native source file count exceeds the staging budget")
    for path in files:
        if (
            any(part.is_symlink() for part in (path, *path.parents))
            or path.stat().st_size > 2 * 1024 * 1024
        ):
            raise ValueError("native source must contain only bounded regular files")
    packed = temporary / "build-input.tar"
    with tarfile.open(packed, "x") as output:
        output.add(
            staged / "hyprland-source",
            arcname="upstream/hyprland-source",
            recursive=True,
        )
        for path in files:
            output.add(
                path,
                arcname="native/" + path.relative_to(native).as_posix(),
                recursive=False,
            )
    return packed


def export_candidate(
    ssh: list[str], temporary: Path, prepared: Path, record: dict, log
) -> None:
    """Export only fixed public build outputs before the disposable guest exits."""
    incoming = temporary / "candidate-inputs"
    incoming.mkdir(mode=0o700)
    inputs = {
        "prepared-substrate.json": prepared,
        "staged-source.json": temporary / "upstream/linura-display-source.json",
    }
    for name, guest_path in (
        ("Hyprland", "/home/linura/s21/compositor-build/Hyprland"),
        (
            "integration-build.h",
            "/home/linura/s21/compositor-build/linura-display/linura-display-integration-build.h",
        ),
    ):
        destination = incoming / name
        # Limit the remote stream as well as checking the retained file. No
        # caller path, archive, guest home directory or credential is exported.
        with destination.open("xb") as output:
            run(
                [*ssh, "head", "-c", str(candidate.FILES[name] + 1), "--", guest_path],
                stdout=output,
                stderr=log,
                timeout=180,
            )
        candidate.regular(destination, candidate.FILES[name])
        inputs[name] = destination
    candidate.retain(
        ROOT, temporary / "candidate", record["source_sha"], inputs, record
    )


def cloud_config(public_key: str, run_id: str) -> str:
    # run_id has already passed the storage namespace validator. JSON strings
    # are also valid YAML scalars; do not interpolate shell/config syntax.
    return (
        """#cloud-config
users:
  - default
  - name: linura
    groups: [wheel]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - """
        + json.dumps(public_key.strip())
        + """
ssh_pwauth: false
disable_root: true
package_update: false
"""
    )


def require_source_unchanged(sha: str) -> None:
    current = run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    dirty = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        capture_output=True,
    ).stdout
    if current != sha or dirty:
        raise ValueError("source changed during the exact-source compositor build")


def extract_sdk(archive: Path, destination: Path, digest: str) -> None:
    """Extract only the digest-verified SDK into a fresh private namespace root.

    Native package absolute symlinks are made relative to this root, preserving
    their meaning inside isolation while preventing access to host paths during
    staging. Python's data filter independently rejects link/path escapes and
    strips ownership and privileged mode bits.
    """
    if (
        archive.is_symlink()
        or not archive.is_file()
        or archive.stat().st_size > 4 * 1024**3
    ):
        raise ValueError("SDK archive must be a bounded regular file")
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError("SDK archive checksum mismatch")
        stream.seek(0)
        with tarfile.open(fileobj=stream) as source_archive:
            members = source_archive.getmembers()
            if (
                len(members) > 200_000
                or sum(member.size for member in members) > 8 * 1024**3
            ):
                raise ValueError("SDK archive exceeds its extraction budget")
            safe = []
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or not path.parts
                    or ".." in path.parts
                    or path.parts[0]
                    not in {"usr", "bin", "sbin", "lib", "lib64", "etc", "var"}
                    or not (
                        member.isfile()
                        or member.isdir()
                        or member.issym()
                        or member.islnk()
                    )
                ):
                    raise ValueError("unsafe SDK archive member")
                if member.issym():
                    target = posixpath.normpath(
                        member.linkname.lstrip("/")
                        if member.linkname.startswith("/")
                        else posixpath.join(str(path.parent), member.linkname)
                    )
                    if target == ".." or target.startswith("../"):
                        raise ValueError("escaping SDK symlink")
                    member = member.replace(
                        linkname=posixpath.relpath(target, str(path.parent))
                    )
                safe.append(member)
            destination.mkdir(mode=0o700, exist_ok=False)
            source_archive.extractall(destination, members=safe, filter="data")


def namespace_command(sdk: Path, workload: Path, doctor: Path) -> list[str]:
    return [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind",
        str(sdk),
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--bind",
        str(workload / "tmp"),
        "/tmp",
        "--tmpfs",
        "/run",
        "--bind",
        str(workload),
        "/home/linura/s21",
        "--ro-bind",
        str(doctor),
        "/workspace",
        "--setenv",
        "HOME",
        "/home/linura",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--chdir",
        "/home/linura/s21",
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-s",
    ]


def namespace_build(args: argparse.Namespace) -> int:
    if not args.archive or not args.sdk_archive or not args.sdk_manifest:
        raise ValueError(
            "namespace-build requires source archive, SDK archive and SDK manifest"
        )
    load_contract(CONTRACT)
    for path in (args.sdk_archive, args.sdk_manifest):
        storage.require_destination(ROOT, ENVIRONMENT, path.parent, "temporary")
        if path.is_symlink() or not path.is_file():
            raise ValueError("SDK input must be a regular checked file")
    metadata = json.loads(args.sdk_manifest.read_text())
    if (
        metadata.get("sdk_exported") is not True
        or metadata.get("qualification_evidence") is not False
        or metadata.get("contract_sha256")
        != hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
    ):
        raise ValueError("SDK export does not match the current pinned build contract")
    paths, sha, dirty = reserve_run(args.run, args.development)
    temporary = storage.require_destination(
        ROOT,
        ENVIRONMENT,
        storage.role_path(paths, "temporary"),
        "temporary",
        run=args.run,
    )
    workload = storage.require_destination(
        ROOT, ENVIRONMENT, storage.role_path(paths, "cmake"), "cmake", run=args.run
    )
    os.umask(0o077)
    sdk = temporary / "sdk-root"
    extract_sdk(args.sdk_archive, sdk, metadata["sdk_archive_sha256"])
    for name in ("home/linura/s21", "tmp", "proc", "dev", "run", "workspace"):
        (sdk / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    packed = package_inputs(args.archive, temporary)
    with tarfile.open(packed) as inputs:
        inputs.extractall(workload, filter="data")
    (workload / "tmp").mkdir(mode=0o700)
    doctor = temporary / "doctor-source"
    for name in (
        "tools/codex/doctor.py",
        "tools/codex/versions.env",
        "tools/check_toolchain_env.py",
        "tools/hyprland_display_environment.py",
        "contracts/s21-hyprland-build-environment.toml",
        "contracts/hyprland-display-integration.toml",
    ):
        destination = doctor / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    command = namespace_command(sdk, workload, doctor)
    script = (
        "python3 /workspace/tools/codex/doctor.py --profile hyprland-build --json\n"
        + build_script(args.jobs)
    )
    # Fail the whole recipe on readiness failure, before any compilation.
    script = "set -euo pipefail\n" + script
    if not args.development:
        require_source_unchanged(sha)
    result = {
        "schema_version": 1,
        "source_sha": sha,
        "dirty": dirty,
        "development": args.development,
        "engine": "unprivileged-namespace",
        "qualification_evidence": False,
        "sdk_archive_sha256": metadata["sdk_archive_sha256"],
        "prepared_image_sha256": metadata["prepared_image_sha256"],
        "contract_sha256": hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
        "build_passed": False,
        "native_execution_qualified": False,
        "rollback_qualified": False,
        "s17_qualified": False,
    }
    result_path = temporary / "build-result.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    with (temporary / "build.log").open("xb") as log:
        run(
            command,
            input=script.encode(),
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=14460,
        )
    if not args.development:
        require_source_unchanged(sha)
    result["build_passed"] = True
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    print("Pinned namespace compositor build result: " + str(result_path))
    return 0


def ci_build(args: argparse.Namespace) -> int:
    """Require a fresh exact-source SDK/compositor build in the existing VM lane.

    Diagnostics are ordinary build results, never native execution evidence.
    Only sanitized prerequisites may be reused by a future cache integration.
    """
    if not args.diagnostics or args.development:
        raise ValueError("ci-build requires checked diagnostics and clean exact source")
    build_script(args.jobs)
    if not 2048 <= args.memory_mib <= 6144:
        raise ValueError("build guest memory must be bounded between 2048 and 6144 MiB")
    diagnostics = storage.require_destination(
        ROOT, ENVIRONMENT, args.diagnostics, "temporary"
    )
    sha = run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    require_source_unchanged(sha)
    pin = tomllib.loads((ROOT / source.PIN).read_text())
    archive = diagnostics / "hyprland-source.tar.gz"
    if archive.exists() or archive.is_symlink():
        raise ValueError("CI source input must be fresh")
    prepare_id, build_id = args.run + "-prepare", args.run + "-compile"
    logs: dict[str, Path] = {}
    try:
        run(
            [
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "900",
                "--retry",
                "2",
                "--max-filesize",
                str(source.MAX_ARCHIVE),
                "--output",
                str(archive),
                pin["source_url"],
            ],
            timeout=2800,
        )
        with archive.open("rb") as stream:
            if (
                hashlib.file_digest(stream, "sha256").hexdigest()
                != pin["source_sha256"]
            ):
                raise ValueError("downloaded compositor source differs from its pin")
        # The source staging step independently verifies immutable archive bytes.
        logs["prepare.log"] = (
            storage.role_path(
                storage.run_layout(ROOT, ENVIRONMENT, prepare_id), "temporary"
            )
            / "prepare.log"
        )
        prepare_environment(prepare_id, False)
        prepared = storage.role_path(
            storage.run_layout(ROOT, ENVIRONMENT, prepare_id), "vm"
        )
        build_temporary = storage.role_path(
            storage.run_layout(ROOT, ENVIRONMENT, build_id), "temporary"
        )
        for name in ("build.log", "qemu.log", "build-result.json"):
            logs[name] = build_temporary / name
        run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "build",
                "--archive",
                str(archive),
                "--prepared-image",
                str(prepared / "s21-hyprland-build.qcow2"),
                "--prepared-manifest",
                str(prepared / "s21-hyprland-build.json"),
                "--run",
                build_id,
                "--acceleration",
                args.acceleration,
                "--memory-mib",
                str(args.memory_mib),
                "--jobs",
                str(args.jobs),
            ],
            cwd=ROOT,
            timeout=15000,
        )
        require_source_unchanged(sha)
        completed = json.loads((build_temporary / "build-result.json").read_text())
        candidate.verify(ROOT, build_temporary / "candidate", sha)
        candidate.retain(
            ROOT,
            diagnostics / "s21-candidate",
            sha,
            {name: build_temporary / "candidate" / name for name in candidate.FILES},
            completed,
        )
        require_source_unchanged(sha)
        return 0
    finally:
        for name, path in logs.items():
            # Never collect guest data, SSH keys, SDK archives or recordings.
            if path.is_file() and not path.is_symlink():
                if path.stat().st_size > 64 * 1024 * 1024:
                    raise ValueError("build diagnostic exceeds its publication budget")
                with (diagnostics / ("s21-" + name)).open("xb") as output:
                    with path.open("rb") as input_stream:
                        shutil.copyfileobj(input_stream, output, 1024 * 1024)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("prepare", "build", "export-sdk", "namespace-build", "ci-build"),
    )
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--prepared-image", type=Path)
    parser.add_argument("--prepared-manifest", type=Path)
    parser.add_argument("--sdk-archive", type=Path)
    parser.add_argument("--sdk-manifest", type=Path)
    parser.add_argument("--diagnostics", type=Path)
    parser.add_argument("--run", required=True)
    parser.add_argument("--acceleration", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--memory-mib", type=int, default=3072)
    parser.add_argument(
        "--development",
        action="store_true",
        help="allow uncommitted source; never qualifies an exact Git head",
    )
    args = parser.parse_args()
    if args.command == "ci-build":
        return ci_build(args)
    if args.command == "namespace-build":
        return namespace_build(args)
    if args.command == "prepare":
        if args.archive or args.prepared_image or args.prepared_manifest:
            parser.error("prepare accepts no source archive or prepared-image inputs")
        return prepare_environment(args.run, args.development)
    if (
        not args.prepared_image
        or not args.prepared_manifest
        or (args.command == "build" and not args.archive)
    ):
        parser.error(
            "build requires --archive, --prepared-image and --prepared-manifest"
        )
    script = build_script(args.jobs)
    if not 2048 <= args.memory_mib <= 6144:
        parser.error("build guest memory must be bounded between 2048 and 6144 MiB")
    contract = load_contract(CONTRACT)
    # Validate reusable input namespaces independently of the new output run.
    for path in (args.prepared_image, args.prepared_manifest):
        storage.require_destination(ROOT, ENVIRONMENT, path.parent, "vm")
        if not path.is_file() or path.is_symlink():
            raise ValueError("prepared input must be a regular checked VM file")
    run(
        [
            sys.executable,
            str(ROOT / contract["verifier"]),
            str(CONTRACT),
            str(ROOT / contract["builder"]),
            str(args.prepared_image),
            str(args.prepared_manifest),
        ],
        cwd=ROOT,
    )
    paths, sha, dirty = reserve_run(args.run, args.development)
    temporary = storage.require_destination(
        ROOT,
        ENVIRONMENT,
        storage.role_path(paths, "temporary"),
        "temporary",
        run=args.run,
    )
    vm = storage.require_destination(
        ROOT, ENVIRONMENT, storage.role_path(paths, "vm"), "vm", run=args.run
    )
    os.umask(0o077)
    packed = (
        package_inputs(args.archive, temporary) if args.command == "build" else None
    )
    if not args.development:
        require_source_unchanged(sha)
    key = temporary / "build-key"
    process = None
    try:
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], timeout=20)
        user_data = temporary / "user-data"
        user_data.write_text(
            cloud_config(key.with_suffix(".pub").read_text(), args.run)
        )
        metadata = temporary / "meta-data"
        metadata.write_text(
            "instance-id: "
            + json.dumps("linura-s21-" + args.run)
            + "\nlocal-hostname: linura-s21-build\n"
        )
        network = temporary / "network-config"
        network.write_text("""version: 2
renderer: networkd
ethernets:
  qualification:
    match:
      macaddress: "52:54:00:21:02:60"
    set-name: eth0
    dhcp4: true
    dhcp6: false
""")
        seed, image = vm / "build-seed.img", vm / "build-guest.qcow2"
        run(
            [
                "cloud-localds",
                "--network-config=" + str(network),
                str(seed),
                str(user_data),
                str(metadata),
            ],
            timeout=30,
        )
        run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(args.prepared_image.resolve()),
                str(image),
            ],
            timeout=30,
        )
        ssh = [
            "ssh",
            "-i",
            str(key),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-p",
            "2224",
            "linura@127.0.0.1",
        ]
        record = {
            "schema_version": 1,
            "source_sha": sha,
            "dirty": dirty,
            "development": args.development,
            "qualification_evidence": False,
            "contract_sha256": hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
            "build_input_sha256": "",
            "build_passed": False,
            "native_execution_qualified": False,
            "rollback_qualified": False,
            "s17_qualified": False,
        }
        if packed:
            with packed.open("rb") as stream:
                record["build_input_sha256"] = hashlib.file_digest(
                    stream, "sha256"
                ).hexdigest()
        result = temporary / "build-result.json"
        result.write_text(json.dumps(record, indent=2) + "\n")
        with (
            (temporary / "qemu.log").open("xb") as vm_log,
            (temporary / "build.log").open("xb") as build_log,
        ):
            process = subprocess.Popen(
                [
                    "bash",
                    str(ROOT / "qualification/v010/shell-runtime/start-vm.sh"),
                    "--source-root",
                    str(ROOT),
                    "--run-id",
                    args.run,
                    "--persistent",
                    "--mode",
                    "automated",
                    "--display",
                    "none",
                    "--acceleration",
                    args.acceleration,
                    "--image",
                    str(image),
                    "--seed",
                    str(seed),
                    "--ssh-port",
                    "2224",
                    "--memory",
                    str(args.memory_mib),
                    "--cpus",
                    "4",
                    "--nic-mac",
                    "52:54:00:21:02:60",
                ],
                cwd=ROOT,
                stdout=vm_log,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 420
            while True:
                if process.poll() is not None:
                    raise RuntimeError(
                        "build guest exited before readiness; inspect qemu.log"
                    )
                ready = subprocess.run(
                    [*ssh, "true"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    check=False,
                )
                if ready.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("build guest SSH readiness deadline exceeded")
                time.sleep(2)
            run(
                [*ssh, "timeout", "240", "cloud-init", "status", "--wait", "--long"],
                stdout=build_log,
                stderr=subprocess.STDOUT,
                timeout=260,
            )
            if args.command == "export-sdk":
                sdk = temporary / "arch-sdk.tar"
                # Only packaged SDK files and public metadata. No /home, SSH
                # host keys, password databases, logs or Linura build outputs.
                with sdk.open("xb") as stream:
                    run(
                        [
                            *ssh,
                            "sudo -n tar --one-file-system -C / -cf - usr bin sbin lib lib64 etc/os-release etc/passwd etc/group etc/ld.so.cache etc/ld.so.conf etc/ld.so.conf.d etc/ssl/certs etc/pacman.conf etc/pacman.d/mirrorlist var/lib/pacman/local var/lib/pacman/sync",
                        ],
                        stdout=stream,
                        stderr=build_log,
                        timeout=900,
                    )
                with sdk.open("rb") as stream:
                    record["sdk_archive_sha256"] = hashlib.file_digest(
                        stream, "sha256"
                    ).hexdigest()
                record["sdk_exported"] = True
                record["prepared_image_sha256"] = json.loads(
                    args.prepared_manifest.read_text()
                )["prepared_image_sha256"]
            else:
                assert packed is not None
                with packed.open("rb") as stream:
                    run(
                        [
                            *ssh,
                            "mkdir -m 700 /home/linura/s21 && tar -xf - -C /home/linura/s21",
                        ],
                        stdin=stream,
                        stdout=build_log,
                        stderr=subprocess.STDOUT,
                        timeout=240,
                    )
                run(
                    [
                        *ssh,
                        "timeout",
                        "--signal=TERM",
                        "--kill-after=30s",
                        "14400",
                        "bash",
                        "-s",
                    ],
                    input=script.encode(),
                    stdout=build_log,
                    stderr=subprocess.STDOUT,
                    timeout=14460,
                )
            if not args.development:
                require_source_unchanged(sha)
            if args.command == "build":
                record["build_passed"] = True
                if not args.development:
                    export_candidate(
                        ssh, temporary, args.prepared_manifest, record, build_log
                    )
                    require_source_unchanged(sha)
            result.write_text(json.dumps(record, indent=2) + "\n")
            poweroff_guest(ssh, process, build_log)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        key.unlink(missing_ok=True)
        key.with_suffix(".pub").unlink(missing_ok=True)
        # user-data retains only a now-unusable ephemeral public key. No private
        # keys or guest credentials enter build results or qualification evidence.
    print("Pinned compositor build result: " + str(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
