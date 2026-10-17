#!/usr/bin/bash
set -euo pipefail

contract_path="${1:-contracts/v010-shell-runtime-substrate.toml}"
base_image="${2:-}"
output_image="${3:-}"
output_manifest="${4:-}"
work_root="${5:?a dedicated-storage substrate workspace is required}"
source_root="${LINURA_SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

[[ -f "$contract_path" && ! -L "$contract_path" ]] || fail "substrate contract is missing or untrusted"
[[ -f "$base_image" && ! -L "$base_image" ]] || fail "pinned Arch base image is missing or untrusted"
[[ -n "$output_image" && -n "$output_manifest" ]] || fail "prepared image and manifest paths are required"

for command_name in cloud-localds qemu-img qemu-system-x86_64 ssh ssh-keygen python3 sha256sum; do
    command -v "$command_name" >/dev/null || fail "required host command is missing: $command_name"
done

contract_values="$(
    python3 -I -S - "$contract_path" <<'PY'
from pathlib import Path
import re
import sys
import tomllib

contract_file = Path(sys.argv[1])
if any(part.is_symlink() for part in (contract_file, *contract_file.parents)):
    raise SystemExit("symlinked substrate contract")
contract = tomllib.loads(contract_file.read_text(encoding="utf-8"))
required = ("base_image_url", "arch_archive_url", "vm_disk_size_gib", "runtime_packages")
if any(key not in contract for key in required):
    raise SystemExit("substrate contract missing required field")

url_pattern = re.compile(r"https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~/$%-]+)*")
urls = (contract["base_image_url"], contract["arch_archive_url"])
if any(not isinstance(url, str) or not url_pattern.fullmatch(url) for url in urls):
    raise SystemExit("substrate URL contains unsafe shell or transport characters")
disk = contract["vm_disk_size_gib"]
if type(disk) is not int or not 1 <= disk <= 512:
    raise SystemExit("substrate disk size is invalid")
packages = contract["runtime_packages"]
if (
    not isinstance(packages, list)
    or not packages
    or len(packages) > 100
    or any(
        not isinstance(package, str)
        or re.fullmatch(r"[a-z0-9@_+][a-z0-9@._+-]*", package) is None
        for package in packages
    )
    or len(set(packages)) != len(packages)
):
    raise SystemExit("unsafe substrate package declaration")
print("\t".join((urls[0], urls[1], str(disk), " ".join(packages))))
PY
)" || fail "substrate contract rejected before data loading"
IFS=$'\t' read -r BASE_IMAGE_URL_CONTRACT ARCH_ARCHIVE_URL_CONTRACT QUALIFICATION_DISK_GIB_CONTRACT RUNTIME_PACKAGES <<<"$contract_values"
: "${BASE_IMAGE_URL_CONTRACT:?}" "${ARCH_ARCHIVE_URL_CONTRACT:?}" "${QUALIFICATION_DISK_GIB_CONTRACT:?}" "${RUNTIME_PACKAGES:?}"

: "${BASE_IMAGE_URL:?}"
: "${BASE_IMAGE_SHA256:?}"
: "${QUALIFICATION_NIC_MAC:?}"

[[ "$BASE_IMAGE_URL" == "$BASE_IMAGE_URL_CONTRACT" ]] || fail "base image URL drifted from substrate contract"
[[ "$BASE_IMAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "base image digest is malformed"
printf '%s  %s\n' "$BASE_IMAGE_SHA256" "$base_image" | sha256sum --check --strict
[[ "$QUALIFICATION_DISK_GIB_CONTRACT" =~ ^[0-9]+$ ]] || fail "substrate disk size is invalid"

storage_args=(--source-root "$source_root" --environment arch-hyprland-runtime --run "${LINURA_RUN_ID:?}")
python3 "$source_root/tools/development_storage.py" "${storage_args[@]}" \
    check --role temporary --path "$work_root" --fresh >/dev/null ||
    fail "substrate scratch must be fresh dedicated-storage output"
python3 "$source_root/tools/development_storage.py" "${storage_args[@]}" \
    check --role vm --path "$(dirname "$base_image")" >/dev/null ||
    fail "substrate input must use checked VM storage"
for destination in "$output_image" "$output_manifest"; do
    python3 "$source_root/tools/development_storage.py" "${storage_args[@]}" \
        check --role vm --path "$(dirname "$destination")" >/dev/null ||
        fail "substrate output must use checked VM storage"
    [[ ! -e "$destination" && ! -L "$destination" ]] || fail "substrate output already exists; retain it and use a fresh run"
done
vm_root="$(dirname "$output_image")"
guest_image="$vm_root/substrate-guest.qcow2"
seed_image="$vm_root/substrate-seed.img"
for destination in "$guest_image" "$seed_image"; do
    [[ ! -e "$destination" && ! -L "$destination" ]] || fail "substrate VM input already exists; retain it and use a fresh run"
done
TMPDIR="$(python3 "$source_root/tools/development_storage.py" "${storage_args[@]}" scratch)" ||
    fail "substrate scratch is unavailable"
export TMPDIR
umask 077
mkdir "$work_root"

ssh_key="$work_root/substrate-key"
vm_log="$work_root/substrate-qemu.log"
user_data="$work_root/user-data"
meta_data="$work_root/meta-data"
network_config="$work_root/network-config"
package_manifest="$work_root/package-versions.txt"
builder_evidence="$work_root/builder-evidence.txt"

cp --reflink=auto "$base_image" "$guest_image"
qemu-img resize "$guest_image" "${QUALIFICATION_DISK_GIB_CONTRACT}G"
ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"
public_key="$(cat "$ssh_key.pub")"

cat >"$user_data" <<EOF
#cloud-config
users:
  - default
  - name: linura
    groups: [wheel]
    shell: /bin/bash
    sudo:
      - ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: false
growpart:
  mode: auto
  devices: ["/"]
  ignore_growroot_disabled: false
resize_rootfs: true
EOF

cat >"$meta_data" <<EOF
instance-id: linura-v010-substrate-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}
local-hostname: linura-v010-substrate
EOF

cat >"$network_config" <<EOF
version: 2
renderer: networkd
ethernets:
  qualification:
    match:
      macaddress: "$QUALIFICATION_NIC_MAC"
    set-name: eth0
    dhcp4: true
    dhcp6: false
EOF

cloud-localds --network-config="$network_config" "$seed_image" "$user_data" "$meta_data"

vm_pid=""
cleanup() {
    set +e
    if [[ -n "$vm_pid" ]] && kill -0 "$vm_pid" 2>/dev/null; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    rm -f "$ssh_key" "$ssh_key.pub"
}
trap cleanup EXIT

bash qualification/v010/shell-runtime/start-vm.sh \
    --persistent \
    --mode automated \
    --display none \
    --image "$guest_image" \
    --seed "$seed_image" \
    --memory 6144 \
    --cpus 4 \
    --nic-mac "$QUALIFICATION_NIC_MAC" \
    --ssh-port 2223 \
    >"$vm_log" 2>&1 &
vm_pid="$!"

ssh_common=(
    -i "$ssh_key"
    -o BatchMode=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=3
)

ready=0
deadline=$((SECONDS + 420))
while ((SECONDS < deadline)); do
    if ! kill -0 "$vm_pid" 2>/dev/null; then
        cat "$vm_log" >&2
        fail "substrate VM exited before SSH readiness"
    fi
    if ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 true >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
[[ "$ready" -eq 1 ]] || {
    cat "$vm_log" >&2
    fail "substrate VM SSH readiness deadline exceeded"
}

ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 'timeout 240 cloud-init status --wait --long'
ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 \
    "printf '%s\n' 'Server = $ARCH_ARCHIVE_URL_CONTRACT' | sudo -n tee /etc/pacman.d/mirrorlist >/dev/null"

install_succeeded=0
for attempt in 1 2 3; do
    echo "prepared substrate package install attempt $attempt/3"
    if ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 \
        "timeout --signal=TERM --kill-after=10s 720 sudo -n pacman -Syu --noconfirm --needed --disable-download-timeout -- $RUNTIME_PACKAGES"; then
        install_succeeded=1
        break
    fi
    if [[ "$attempt" -lt 3 ]]; then
        ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 \
            "sudo -n find /var/cache/pacman/pkg -maxdepth 1 -type f -name '*.pkg.tar.*' -delete"
        sleep $((attempt * 5))
    fi
done
[[ "$install_succeeded" -eq 1 ]] || fail "prepared substrate package installation failed after 3 bounded attempts"

ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 \
    'pacman -Q' | LC_ALL=C sort >"$package_manifest"

ssh "${ssh_common[@]}" -p 2223 linura@127.0.0.1 \
    'set -euo pipefail
     test ! -e /opt/linura-source
     test ! -e /usr/bin/linurad
     sudo -n rm -rf /var/cache/pacman/pkg/*
     sudo -n cloud-init clean --logs --seed
     sudo -n rm -f /home/linura/.ssh/authorized_keys
     sudo -n rm -rf /home/linura/.cache/*
     sudo -n rm -f /etc/ssh/ssh_host_*
     sudo -n truncate -s 0 /etc/machine-id
     sudo -n rm -f /var/lib/dbus/machine-id
     sync
     sudo -n systemctl poweroff' || true

shutdown_deadline=$((SECONDS + 120))
while kill -0 "$vm_pid" 2>/dev/null && ((SECONDS < shutdown_deadline)); do
    sleep 1
done
if kill -0 "$vm_pid" 2>/dev/null; then
    cat "$vm_log" >&2
    fail "prepared substrate VM did not power off cleanly"
fi
wait "$vm_pid" || true
vm_pid=""

qemu-img check "$guest_image"
compacted="$work_root/prepared.compacted.qcow2"
qemu-img convert -p -O qcow2 "$guest_image" "$compacted"
qemu-img check "$compacted"
mv "$compacted" "$output_image"

prepared_sha256="$(sha256sum "$output_image" | awk '{print $1}')"
contract_sha256="$(sha256sum "$contract_path" | awk '{print $1}')"
builder_sha256="$(sha256sum qualification/v010/shell-runtime/prepare-substrate.sh | awk '{print $1}')"
[[ "$prepared_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$contract_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$builder_sha256" =~ ^[0-9a-f]{64}$ ]]

{
    printf 'base_image_sha256=%s\n' "$BASE_IMAGE_SHA256"
    printf 'prepared_image_sha256=%s\n' "$prepared_sha256"
    printf 'contract_sha256=%s\n' "$contract_sha256"
    printf 'builder_sha256=%s\n' "$builder_sha256"
} >"$builder_evidence"

python3 - "$output_manifest" "$contract_path" "$package_manifest" "$prepared_sha256" "$contract_sha256" "$builder_sha256" <<'PY'
import json
import os
import pathlib
import sys
import tomllib

output = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
package_manifest_path = pathlib.Path(sys.argv[3])
prepared_sha256 = sys.argv[4]
contract_sha256 = sys.argv[5]
builder_sha256 = sys.argv[6]
contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
package_versions = package_manifest_path.read_text(encoding="utf-8").splitlines()
evidence = {
    "schema_version": 1,
    "id": contract["id"],
    "claim": "non-authoritative-prepared-substrate",
    "base_image": {
        "url": contract["base_image_url"],
        "sha256": os.environ["BASE_IMAGE_SHA256"],
    },
    "arch_archive": {
        "snapshot": contract["arch_archive_snapshot"],
        "url": contract["arch_archive_url"],
    },
    "contract_sha256": contract_sha256,
    "builder_sha256": builder_sha256,
    "prepared_image_sha256": prepared_sha256,
    "runtime_packages": contract["runtime_packages"],
    "package_versions": package_versions,
    "sanitized": True,
    "contains_linura_source": False,
    "contains_linura_build_outputs": False,
    "qualification_evidence": False,
    "release_support_promotion": False,
}
output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf '%s  %s\n' "$prepared_sha256" "$(basename "$output_image")" >"${output_image}.sha256"
echo "prepared v0.10 shell runtime substrate: $output_image"
