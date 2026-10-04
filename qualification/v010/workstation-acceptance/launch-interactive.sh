#!/usr/bin/bash
set -euo pipefail

prepared_image=""
prepared_manifest=""
display_backend="gtk"
vnc_display=0
ssh_port=2224
record=0
source_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
evidence_dir=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prepared-image) prepared_image="$2"; shift 2 ;;
        --prepared-manifest) prepared_manifest="$2"; shift 2 ;;
        --source-root) source_root="$2"; shift 2 ;;
        --display) display_backend="$2"; shift 2 ;;
        --vnc-display) vnc_display="$2"; shift 2 ;;
        --ssh-port) ssh_port="$2"; shift 2 ;;
        --record) record=1; shift ;;
        --evidence-dir) evidence_dir="$2"; shift 2 ;;
        *) echo "unsupported argument: $1" >&2; exit 2 ;;
    esac
done

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[[ "$display_backend" == "gtk" || "$display_backend" == "vnc" ]] || fail "--display must be gtk or vnc"
[[ "$ssh_port" =~ ^[0-9]+$ ]] && (( ssh_port >= 1 && ssh_port <= 65535 )) || fail "invalid SSH port"
[[ "$vnc_display" =~ ^[0-9]+$ ]] && (( vnc_display <= 99 )) || fail "invalid VNC display"
[[ -n "$source_root" ]] || fail "--source-root must be a Git checkout"
git -C "$source_root" rev-parse --is-inside-work-tree >/dev/null 2>&1     || fail "--source-root must be a Git checkout"
source_root="$(git -C "$source_root" rev-parse --show-toplevel)"
source_root="$(cd "$source_root" && pwd -P)"
source_sha="$(git -C "$source_root" rev-parse HEAD)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "source HEAD is not a commit SHA"
[[ -z "$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)" ]]     || fail "interactive acceptance requires a fully clean exact-source checkout"

[[ -f "$prepared_image" && ! -L "$prepared_image" ]] || fail "prepared image is missing or unsafe"
[[ -f "$prepared_manifest" && ! -L "$prepared_manifest" ]] || fail "prepared manifest is missing or unsafe"

for command_name in qemu-img cloud-localds ssh scp ssh-keygen git python3 cargo rustup tar flock; do
    command -v "$command_name" >/dev/null || fail "required host command is missing: $command_name"
done
work_root="$(mktemp -d -t linura-workstation-live.XXXXXX)"
trap 'rm -rf "$work_root"' EXIT
source_archive="$work_root/source.tar.gz"
build_root="$work_root/source"
mkdir -p "$build_root"
git -C "$source_root" archive --format=tar.gz --output="$source_archive" "$source_sha"
tar -xzf "$source_archive" -C "$build_root"

doctor_args=(doctor --mode interactive --display "$display_backend")
if [[ "$record" -eq 1 ]]; then
    doctor_args+=(--record)
fi
python3 "$build_root/tools/workstation_acceptance.py" "${doctor_args[@]}"

# Reproduce the exact-source release envelope used by the automated v0.10 runtime lane.
# A caller-supplied authority binary is intentionally not accepted, and the build runs
# from the immutable Git archive rather than the developer working tree.
# shellcheck disable=SC1091
source "$build_root/tools/codex/versions.env"
release_target="x86_64-unknown-linux-gnu"
rustup run "$RUST_VERSION" rustc --version >/dev/null 2>&1     || fail "repository-pinned Rust toolchain $RUST_VERSION is not installed"
rustup target list --installed --toolchain "$RUST_VERSION" | grep -Fx "$release_target" >/dev/null     || fail "Rust target $release_target is not installed for $RUST_VERSION"
source_date_epoch="$(git -C "$source_root" show -s --format=%ct "$source_sha")"
(
    cd "$build_root"
    export SOURCE_DATE_EPOCH="$source_date_epoch"
    export CARGO_INCREMENTAL=0
    export TZ=UTC
    export LANG=C.UTF-8
    export LC_ALL=C.UTF-8
    export RUSTFLAGS="--remap-path-prefix=$build_root=/workspace"
    cargo +"$RUST_VERSION" build --workspace --release --locked --target "$release_target"
)
linurad_binary="$build_root/target/$release_target/release/linurad"
[[ -x "$linurad_binary" && ! -L "$linurad_binary" ]]     || fail "exact-source linurad build did not produce the expected binary"
linurad_sha256="$(sha256sum "$linurad_binary" | awk '{print $1}')"
[[ "$linurad_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "exact-source linurad digest is malformed"

substrate_contract="$build_root/contracts/v010-shell-runtime-substrate.toml"
prepared_sha="$(python3 "$build_root/qualification/v010/shell-runtime/verify-substrate.py"     "$substrate_contract"     "$build_root/qualification/v010/shell-runtime/prepare-substrate.sh"     "$prepared_image"     "$prepared_manifest")"
[[ "$prepared_sha" =~ ^[0-9a-f]{64}$ ]] || fail "prepared substrate verification did not return a digest"

vm_image="$work_root/workstation.qcow2"
seed_image="$work_root/seed.img"
ssh_key="$work_root/id_ed25519"
vm_log="$work_root/qemu.log"
nic_mac="52:54:00:12:34:56"
vm_pid=""

if [[ -z "$evidence_dir" ]]; then
    evidence_dir="$source_root/.artifacts/workstation-live-$source_sha"
fi
if [[ -L "$evidence_dir" ]]; then
    fail "interactive evidence directory must not be a symlink"
fi
mkdir -p "$evidence_dir"
evidence_dir="$(cd "$evidence_dir" && pwd -P)"
# Lock the directory inode, not the source SHA or SSH port: explicit and default
# destinations that resolve to the same directory must serialize for the entire
# VM lifetime, guest copy, host verification and EXIT cleanup. A directory FD
# avoids creating a symlinkable or replaceable lock file inside the evidence.
exec {evidence_lock_fd}<"$evidence_dir" || fail "cannot open interactive evidence directory for locking"
flock -n "$evidence_lock_fd" || fail "interactive evidence directory already in use: $evidence_dir"
# Reusing an evidence directory must never present a previous session as the
# current run, including when the new launch fails before guest provisioning.
# Purge only run-owned artifacts after acquiring the directory-inode lock.
rm -f -- "$evidence_dir/live-session.txt" \
    "$evidence_dir/qemu.log" \
    "$evidence_dir/workstation-live.mkv" \
    "$evidence_dir/workstation-live.metadata.json" \
    "$evidence_dir/workstation-live.sha256"

publish_qemu_log() {
    [[ -f "$vm_log" && ! -L "$vm_log" ]] || return 0
    local temporary_log
    temporary_log="$(mktemp "$evidence_dir/.qemu.log.XXXXXXXX")" || return 1
    chmod 0600 "$temporary_log" || {
        rm -f -- "$temporary_log"
        return 1
    }
    if ! cat -- "$vm_log" > "$temporary_log"; then
        rm -f -- "$temporary_log"
        return 1
    fi
    if [[ ! -f "$temporary_log" || -L "$temporary_log" ]] \
        || [[ "$(stat -c %h -- "$temporary_log")" != "1" ]]; then
        rm -f -- "$temporary_log"
        return 1
    fi
    if ! mv -fT -- "$temporary_log" "$evidence_dir/qemu.log"; then
        rm -f -- "$temporary_log"
        return 1
    fi
}

publish_guest_evidence_file() {
    local staged_file="$1"
    local output_name="$2"
    [[ "$output_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || fail "invalid guest evidence output name: $output_name"
    [[ -f "$staged_file" && ! -L "$staged_file" ]] \
        || fail "staged guest evidence is missing or unsafe: $output_name"
    [[ "$(stat -c %h -- "$staged_file")" == "1" ]] \
        || fail "staged guest evidence must be a single-link regular file: $output_name"

    local temporary
    temporary="$(mktemp "$evidence_dir/.${output_name}.XXXXXXXX")" \
        || fail "cannot stage guest evidence publication: $output_name"
    chmod 0600 "$temporary" || {
        rm -f -- "$temporary"
        fail "cannot secure staged guest evidence publication: $output_name"
    }
    if ! cat -- "$staged_file" > "$temporary"; then
        rm -f -- "$temporary"
        fail "cannot copy staged guest evidence: $output_name"
    fi
    if [[ ! -f "$temporary" || -L "$temporary" ]] \
        || [[ "$(stat -c %h -- "$temporary")" != "1" ]]; then
        rm -f -- "$temporary"
        fail "guest evidence publication staging became unsafe: $output_name"
    fi
    if ! mv -fT -- "$temporary" "$evidence_dir/$output_name"; then
        rm -f -- "$temporary"
        fail "cannot atomically publish guest evidence: $output_name"
    fi
}

stage_guest_evidence_file() {
    local output_name="$1"
    local required="$2"
    [[ "$output_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || fail "invalid guest evidence output name: $output_name"
    [[ "$required" == "0" || "$required" == "1" ]] \
        || fail "invalid guest evidence requirement flag: $required"
    local remote_path="/tmp/linura-workstation-live/$output_name"
    local staged_file="$guest_evidence_stage/$output_name"

    if ! ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 "test -e '$remote_path'"; then
        [[ "$required" -eq 0 ]] || fail "required guest evidence is missing: $output_name"
        return 0
    fi
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
        "test -f '$remote_path' && test ! -L '$remote_path' && test \"\$(stat -c %h -- '$remote_path')\" = 1" \
        || fail "guest evidence is not a single-link regular file: $output_name"
    scp "${ssh_common[@]}" -P "$ssh_port" "linura@127.0.0.1:$remote_path" "$staged_file"
    [[ -f "$staged_file" && ! -L "$staged_file" ]] \
        || fail "copied guest evidence is missing or unsafe: $output_name"
    [[ "$(stat -c %h -- "$staged_file")" == "1" ]] \
        || fail "copied guest evidence must be a single-link regular file: $output_name"
    publish_guest_evidence_file "$staged_file" "$output_name"
}

cleanup() {
    set +e
    if [[ -n "$vm_pid" ]] && kill -0 "$vm_pid" 2>/dev/null; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    publish_qemu_log || true
    rm -rf "$work_root"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp --reflink=auto "$prepared_image" "$vm_image"
# The prepared image may be refreshed between verification and copying. Boot only
# the private copy when its bytes still match the verified substrate manifest.
copied_sha="$(sha256sum "$vm_image" | awk '{print $1}')"
[[ "$copied_sha" == "$prepared_sha" ]] || fail "copied substrate differs from the verified prepared image"
qemu-img resize "$vm_image" 16G
ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"
public_key="$(cat "$ssh_key.pub")"

cat > "$work_root/user-data" <<EOF
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
cat > "$work_root/meta-data" <<EOF
instance-id: linura-live-$source_sha
local-hostname: linura-live
EOF
cat > "$work_root/network-config" <<EOF
version: 2
renderer: networkd
ethernets:
  workstation:
    match:
      macaddress: "$nic_mac"
    set-name: eth0
    dhcp4: true
    dhcp6: false
EOF
cloud-localds --network-config="$work_root/network-config"     "$seed_image" "$work_root/user-data" "$work_root/meta-data"

launcher_args=(
    --mode interactive
    --display "$display_backend"
    --image "$vm_image"
    --seed "$seed_image"
    --memory 6144
    --cpus 4
    --nic-mac "$nic_mac"
    --ssh-port "$ssh_port"
)
if [[ "$display_backend" == "vnc" ]]; then
    launcher_args+=(--vnc-display "$vnc_display")
fi
bash "$build_root/qualification/v010/shell-runtime/start-vm.sh" "${launcher_args[@]}" >"$vm_log" 2>&1 &
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
while (( SECONDS < deadline )); do
    kill -0 "$vm_pid" 2>/dev/null || { cat "$vm_log" >&2; fail "interactive VM exited before SSH readiness"; }
    if ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 true >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
[[ "$ready" -eq 1 ]] || fail "interactive VM SSH readiness deadline exceeded"
ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 'timeout 240 cloud-init status --wait --long'

scp "${ssh_common[@]}" -P "$ssh_port" "$source_archive" linura@127.0.0.1:/tmp/linura-source.tar.gz
scp "${ssh_common[@]}" -P "$ssh_port" "$linurad_binary" linura@127.0.0.1:/tmp/linurad-qualification
ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 'bash -se' <<'GUEST'
set -euo pipefail
sudo -n modprobe virtio_gpu
sudo -n udevadm settle --timeout=30
sudo -n install -d -m 0755 /run/systemd/system/seatd.service.d
printf '%s\n' '[Service]' 'Environment=SEATD_VTBOUND=0' |
    sudo -n tee /run/systemd/system/seatd.service.d/10-linura-qualification.conf >/dev/null
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now seatd.service
seat_group="$(stat -c '%G' /run/seatd.sock)"
groups="video,$seat_group"
getent group render >/dev/null && groups="$groups,render"
sudo -n usermod -aG "$groups" linura
sudo -n loginctl enable-linger linura
uid="$(id -u linura)"
sudo -n systemctl restart "user@$uid.service"
GUEST

ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1     'sudo -n rm -rf /opt/linura-source &&
     sudo -n install -d -o root -g root -m 0755 /opt/linura-source &&
     sudo -n tar -xzf /tmp/linura-source.tar.gz -C /opt/linura-source &&
     rm -f /tmp/linura-source.tar.gz &&
     sudo -n bash /opt/linura-source/qualification/v010/shell-runtime/provision-shell-runtime.sh linura /opt/linura-source /tmp/linurad-qualification &&
     rm -f /tmp/linurad-qualification'

installed_sha="$(ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 'sha256sum /usr/bin/linurad | awk "{print \$1}"')"
[[ "$installed_sha" == "$linurad_sha256" ]] || fail "installed linurad differs from the exact-source local build"

set +e
ssh -t "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1     "LINURA_RECORD_VISUAL=$record LINURA_SOURCE_SHA=$source_sha bash /opt/linura-source/qualification/v010/workstation-acceptance/run-live-session.sh /opt/linura-source /tmp/linura-workstation-live"
session_status=$?
set -e

guest_evidence_stage="$work_root/guest-evidence"
mkdir -m 0700 "$guest_evidence_stage"
guest_evidence_required=0
[[ "$session_status" -eq 0 ]] && guest_evidence_required=1
stage_guest_evidence_file "live-session.txt" "$guest_evidence_required"
if [[ "$record" -eq 1 ]]; then
    stage_guest_evidence_file "workstation-live.mkv" "$guest_evidence_required"
    stage_guest_evidence_file "workstation-live.metadata.json" "$guest_evidence_required"
    stage_guest_evidence_file "workstation-live.sha256" "$guest_evidence_required"
fi

if [[ "$record" -eq 1 && "$session_status" -eq 0 ]]; then
    video="$evidence_dir/workstation-live.mkv"
    metadata="$evidence_dir/workstation-live.metadata.json"
    digest_file="$evidence_dir/workstation-live.sha256"
    [[ -f "$video" && ! -L "$video" ]] || fail "interactive recording is missing or unsafe"
    [[ -f "$metadata" && ! -L "$metadata" ]] || fail "interactive recording metadata is missing or unsafe"
    [[ -f "$digest_file" && ! -L "$digest_file" ]] || fail "interactive recording digest is missing or unsafe"

    host_verification="$work_root/workstation-live.host-verification.json"
    python3 "$build_root/tools/workstation_acceptance.py" verify-recording \
        "$video" --source-sha "$source_sha" > "$host_verification"
    python3 - "$metadata" "$host_verification" <<'PY'
import json
from pathlib import Path
import sys

metadata_path = Path(sys.argv[1])
host_path = Path(sys.argv[2])
guest = json.loads(metadata_path.read_text(encoding="utf-8"))
host = json.loads(host_path.read_text(encoding="utf-8"))
if guest != host:
    raise SystemExit("interactive recording guest metadata differs from host verification")
PY
    (
        cd "$evidence_dir"
        sha256sum --check --strict "$(basename "$digest_file")"
    )
fi
exit "$session_status"
