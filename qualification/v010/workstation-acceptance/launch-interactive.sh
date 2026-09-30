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
[[ "$ssh_port" =~ ^[0-9]+$ ]] || fail "invalid SSH port"
[[ "$vnc_display" =~ ^[0-9]+$ ]] || fail "invalid VNC display"
[[ -n "$source_root" && -d "$source_root/.git" ]] || fail "--source-root must be a Git checkout"
source_root="$(cd "$source_root" && pwd)"
source_sha="$(git -C "$source_root" rev-parse HEAD)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "source HEAD is not a commit SHA"
git -C "$source_root" diff --quiet || fail "interactive acceptance requires a clean worktree"
git -C "$source_root" diff --cached --quiet || fail "interactive acceptance requires a clean index"

[[ -f "$prepared_image" && ! -L "$prepared_image" ]] || fail "prepared image is missing or unsafe"
[[ -f "$prepared_manifest" && ! -L "$prepared_manifest" ]] || fail "prepared manifest is missing or unsafe"

for command_name in qemu-img cloud-localds ssh scp ssh-keygen git python3 cargo rustup; do
    command -v "$command_name" >/dev/null || fail "required host command is missing: $command_name"
done
python3 "$source_root/tools/workstation_acceptance.py" doctor --mode interactive --display "$display_backend"

# Reproduce the exact-source release envelope used by the automated v0.10 runtime lane.
# A caller-supplied authority binary is intentionally not accepted.
# shellcheck disable=SC1091
source "$source_root/tools/codex/versions.env"
release_target="x86_64-unknown-linux-gnu"
rustup run "$RUST_VERSION" rustc --version >/dev/null 2>&1     || fail "repository-pinned Rust toolchain $RUST_VERSION is not installed"
rustup target list --installed --toolchain "$RUST_VERSION" | grep -Fx "$release_target" >/dev/null     || fail "Rust target $release_target is not installed for $RUST_VERSION"
source_date_epoch="$(git -C "$source_root" show -s --format=%ct "$source_sha")"
(
    cd "$source_root"
    export SOURCE_DATE_EPOCH="$source_date_epoch"
    export CARGO_INCREMENTAL=0
    export TZ=UTC
    export LANG=C.UTF-8
    export LC_ALL=C.UTF-8
    export RUSTFLAGS="--remap-path-prefix=$source_root=/workspace"
    cargo +"$RUST_VERSION" build --workspace --release --locked --target "$release_target"
)
linurad_binary="$source_root/target/$release_target/release/linurad"
[[ -x "$linurad_binary" && ! -L "$linurad_binary" ]]     || fail "exact-source linurad build did not produce the expected binary"
linurad_sha256="$(sha256sum "$linurad_binary" | awk '{print $1}')"
[[ "$linurad_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "exact-source linurad digest is malformed"

substrate_contract="$source_root/contracts/v010-shell-runtime-substrate.toml"
prepared_sha="$(python3 "$source_root/qualification/v010/shell-runtime/verify-substrate.py"     "$substrate_contract"     "$source_root/qualification/v010/shell-runtime/prepare-substrate.sh"     "$prepared_image"     "$prepared_manifest")"
[[ "$prepared_sha" =~ ^[0-9a-f]{64}$ ]] || fail "prepared substrate verification did not return a digest"

work_root="$(mktemp -d -t linura-workstation-live.XXXXXX)"
vm_image="$work_root/workstation.qcow2"
seed_image="$work_root/seed.img"
ssh_key="$work_root/id_ed25519"
source_archive="$work_root/source.tar.gz"
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
evidence_dir="$(cd "$evidence_dir" && pwd)"

cleanup() {
    set +e
    if [[ -n "$vm_pid" ]] && kill -0 "$vm_pid" 2>/dev/null; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    cp "$vm_log" "$evidence_dir/qemu.log" 2>/dev/null || true
    rm -rf "$work_root"
}
trap cleanup EXIT INT TERM

cp --reflink=auto "$prepared_image" "$vm_image"
qemu-img resize "$vm_image" 16G
ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"
git -C "$source_root" archive --format=tar.gz --output="$source_archive" "$source_sha"
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
bash "$source_root/qualification/v010/shell-runtime/start-vm.sh" "${launcher_args[@]}" >"$vm_log" 2>&1 &
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

scp "${ssh_common[@]}" -P "$ssh_port" -r     linura@127.0.0.1:/tmp/linura-workstation-live/. "$evidence_dir/" 2>/dev/null || true
if [[ "$record" -eq 1 && -f "$evidence_dir/workstation-live.mkv" ]]; then
    python3 "$source_root/tools/workstation_acceptance.py" verify-recording         "$evidence_dir/workstation-live.mkv"         --metadata "$evidence_dir/workstation-live.metadata.json"         --source-sha "$source_sha"
fi
exit "$session_status"
