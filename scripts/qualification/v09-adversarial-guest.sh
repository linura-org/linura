#!/usr/bin/env bash
set -euo pipefail

: "${BASE_IMAGE:?BASE_IMAGE is required}"
: "${BASE_IMAGE_URL:?BASE_IMAGE_URL is required}"
: "${BASE_IMAGE_SHA256:?BASE_IMAGE_SHA256 is required}"
: "${QUALIFICATION_ENVIRONMENT_ID:?QUALIFICATION_ENVIRONMENT_ID is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

V09_SHARD_ID="${V09_SHARD_ID:-full}"
V09_BOUNDARY_START="${V09_BOUNDARY_START:-1}"
V09_BOUNDARY_END="${V09_BOUNDARY_END:-13}"
V09_PRIMARY_SHARD="${V09_PRIMARY_SHARD:-true}"
V09_FINAL_SHARD="${V09_FINAL_SHARD:-true}"

if [[ ! "$V09_SHARD_ID" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]]; then
  echo "invalid V09_SHARD_ID" >&2
  exit 2
fi
if [[ ! "$V09_BOUNDARY_START" =~ ^[0-9]+$ || ! "$V09_BOUNDARY_END" =~ ^[0-9]+$ ]] \
  || (( V09_BOUNDARY_START < 1 || V09_BOUNDARY_END > 13 || V09_BOUNDARY_START > V09_BOUNDARY_END )); then
  echo "invalid v0.9 shard boundary range" >&2
  exit 2
fi
for value in "$V09_PRIMARY_SHARD" "$V09_FINAL_SHARD"; do
  if [[ "$value" != true && "$value" != false ]]; then
    echo "v0.9 shard role flags must be true or false" >&2
    exit 2
  fi
done
if [[ "$V09_PRIMARY_SHARD" == true && "$V09_BOUNDARY_START" != 1 ]]; then
  echo "primary shard must begin at boundary 1" >&2
  exit 2
fi
if [[ "$V09_FINAL_SHARD" == true && "$V09_BOUNDARY_END" != 13 ]]; then
  echo "final shard must end at boundary 13" >&2
  exit 2
fi

SSH_PORT=2224
SSH_GUEST_PORT=22
QUALIFICATION_SSH_GUEST_PORT=2222
SSH_USER=linura-qualification
PREPARER_SSH_USER=linura-preparer
PREPARER_ACTIVE=true
VM_IMAGE="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}.qcow2"
SEED_IMAGE="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}-seed.img"
SSH_KEY="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}-key"
VM_LOG="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}.log"
ARTIFACT_DIR="$RUNNER_TEMP/linura-v09-adversarial-artifacts"
TRANSCRIPT="$ARTIFACT_DIR/guest-qualification-${V09_SHARD_ID}.txt"
ENVIRONMENT="$ARTIFACT_DIR/guest-environment-${V09_SHARD_ID}.env"
ROOT=/var/lib/linura-qualification/v0.9
PRODUCTION_ROOT="$ROOT/production-firstboot"
PUBLIC_BOOTSTRAP_ROOT="$ROOT/public-bootstrap"
HARNESS_ROOT="$ROOT/harness"
Q8_OBSERVER=/usr/local/libexec/linura-v09-q8-observe
PREPARER_SUDOERS=/etc/sudoers.d/99-linura-preparer
VM_PID=""
BOOT_INDEX=0

VM_UUID="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
CLONE_UUID="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"

SSH_COMMON=(
  -i "$SSH_KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=3
)

cleanup() {
  if [[ -n "${VM_PID:-}" ]]; then
    kill "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

remote() {
  ssh "${SSH_COMMON[@]}" -p "$SSH_PORT" "$SSH_USER@127.0.0.1" "$1"
}

preparer_remote() {
  ssh "${SSH_COMMON[@]}" -p "$SSH_PORT" "$PREPARER_SSH_USER@127.0.0.1" "$1"
}

product_remote() {
  if [[ "$PREPARER_ACTIVE" == true ]]; then
    preparer_remote "$1"
  else
    remote "$1"
  fi
}

isolate_canonical_ssh() {
  remote 'set -e; sudo -n systemctl is-active --quiet linura-qualification-transport.service; for unit in ssh.socket sshd.socket ssh.service sshd.service; do sudo -n systemctl disable --now "$unit" >/dev/null 2>&1 || true; done; sudo -n systemctl mask --force ssh.service sshd.service ssh.socket sshd.socket >/dev/null; for unit in ssh.socket sshd.socket ssh.service sshd.service; do if sudo -n systemctl is-active --quiet "$unit"; then printf "canonical SSH unit remained active after isolation: %s\n" "$unit" >&2; exit 1; fi; done'
}

run_security_baseline_step() {
  local output_path="$ROOT/q8-${V09_SHARD_ID}.out"
  local status_path="$ROOT/q8-${V09_SHARD_ID}.status"
  local transient_unit="linura-v09-q8-${V09_SHARD_ID}"
  local ready=0
  local result=""
  local output=""
  local status=""

  remote "sudo -n rm -f '$output_path' '$status_path'; sudo -n systemd-run --quiet --no-block --unit='$transient_unit' --on-active=10s --property=StandardInput=null --property=StandardOutput=journal --property=StandardError=journal '$Q8_OBSERVER' '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA' '$output_path' '$status_path' </dev/null >/dev/null 2>&1"

  for _ in $(seq 1 120); do
    sleep 2
    if result="$(remote "sudo -n sh -c 'test -s \"$status_path\" && { cat \"$status_path\"; printf \"__LINURA_Q8_OUTPUT__\\n\"; cat \"$output_path\"; }'" 2>/dev/null)"; then
      ready=1
      break
    fi
  done
  if [[ "$ready" != 1 ]]; then
    echo "isolated Q8 step did not restore a stable qualification transport" >&2
    return 1
  fi

  status="${result%%$'\n'*}"
  output="${result#*$'\n'}"
  if [[ "$output" != __LINURA_Q8_OUTPUT__* ]]; then
    echo "isolated Q8 result framing is invalid" >&2
    return 1
  fi
  output="${output#__LINURA_Q8_OUTPUT__}"
  output="${output#$'\n'}"
  printf '%s\n' "$output"
  if [[ ! "$status" =~ ^[0-9]+$ || "$status" -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    echo "isolated Q8 step failed with status=${status:-invalid}" >&2
    remote 'sudo -n systemctl list-unit-files --type=service --type=socket --no-legend --no-pager | grep -Ei "ssh|dropbear" || true; sudo -n systemctl list-units --all --type=service --type=socket --no-legend --no-pager | grep -Ei "ssh|dropbear" || true; sudo -n nft list ruleset || true' >&2 || true
    return 1
  fi
}

run_public_bootstrap_isolated() {
  local production_root="${1:?production root is required}"
  local output_path="$ROOT/public-bootstrap-${V09_SHARD_ID}.out"
  local status_path="$ROOT/public-bootstrap-${V09_SHARD_ID}.status"
  local transient_unit="linura-v09-public-bootstrap-${V09_SHARD_ID}"
  local ready=0
  local result=""
  local output=""
  local status=""

  remote "sudo -n rm -f '$output_path' '$status_path'; sudo -n systemd-run --quiet --no-block --unit='$transient_unit' --on-active=10s --property=StandardInput=null --property=StandardOutput=journal --property=StandardError=journal '$Q8_OBSERVER' '$production_root' '$LINURA_FIRSTBOOT_SHA' '$output_path' '$status_path' bootstrap </dev/null >/dev/null 2>&1"
  for _ in $(seq 1 180); do
    sleep 2
    if result="$(remote "sudo -n sh -c 'test -s \"$status_path\" && { cat \"$status_path\"; printf \"__LINURA_PUBLIC_BOOTSTRAP_OUTPUT__\\n\"; cat \"$output_path\"; }'" 2>/dev/null)"; then
      ready=1
      break
    fi
  done
  if [[ "$ready" != 1 ]]; then
    echo 'isolated production bootstrap did not restore a stable qualification transport' >&2
    return 1
  fi
  status="${result%%$'\n'*}"
  output="${result#*$'\n'}"
  if [[ "$output" != __LINURA_PUBLIC_BOOTSTRAP_OUTPUT__* ]]; then
    echo 'isolated production bootstrap result framing is invalid' >&2
    return 1
  fi
  output="${output#__LINURA_PUBLIC_BOOTSTRAP_OUTPUT__}"
  output="${output#$'\n'}"
  printf '%s\n' "$output"
  if [[ ! "$status" =~ ^[0-9]+$ || "$status" -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    echo "isolated production bootstrap failed with status=${status:-invalid}" >&2
    return 1
  fi
}

start_guest() {
  local hardware_uuid="$1"
  local label="$2"
  BOOT_INDEX=$((BOOT_INDEX + 1))
  local log="${VM_LOG}.${BOOT_INDEX}.${label}"
  python3 tools/vm.py start \
    --image "$VM_IMAGE" \
    --seed "$SEED_IMAGE" \
    --ssh-port "$SSH_PORT" \
    --ssh-guest-port "$SSH_GUEST_PORT" \
    --accel tcg \
    --persistent \
    --uuid "$hardware_uuid" \
    >"$log" 2>&1 &
  VM_PID=$!

  local ready=0
  for _ in $(seq 1 120); do
    if ! kill -0 "$VM_PID" 2>/dev/null; then
      cat "$log" >&2
      return 1
    fi
    if remote true >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  if [[ "$ready" != 1 ]]; then
    cat "$log" >&2
    return 1
  fi
  if [[ "$SSH_GUEST_PORT" == "$QUALIFICATION_SSH_GUEST_PORT" ]]; then
    isolate_canonical_ssh
  fi
}

hard_stop() {
  if [[ -n "${VM_PID:-}" ]]; then
    kill -KILL "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
    VM_PID=""
  fi
}

power_cycle() {
  local label="$1"
  hard_stop
  start_guest "$VM_UUID" "$label"
}

install_text_file() {
  local destination="$1"
  local mode="$2"
  local encoded="$3"
  remote "printf '%s' '$encoded' | base64 -d | sudo -n tee '$destination' >/dev/null && sudo -n chown root:root '$destination' && sudo -n chmod '$mode' '$destination'"
}

expect_transition_crash() {
  local point="$1"
  local marker="$2"
  local output=""
  local status=0
  set +e
  output="$(product_remote "sudo -n env LINURA_BOOTSTRAP_QUALIFICATION_CRASH_AFTER='$point' /usr/local/bin/linura-bootstrap-transition-qualification prepare '$PRODUCTION_ROOT'" 2>&1)"
  status=$?
  set -e
  if [[ "$status" -eq 0 || "$output" != *"qualification_crash_after=$point"* ]]; then
    printf 'expected qualification crash at %s, status=%s, output=%s\n' "$point" "$status" "$output" >&2
    return 1
  fi
  printf '%s\n' "$marker" | tee -a "$TRANSCRIPT"
}

verify_preparer_authority_revoked() {
  local production_root="${1:?production root is required}"
  local verify_script=""
  local verify_encoded=""

  if ssh "${SSH_COMMON[@]}" -p "$SSH_PORT" "$PREPARER_SSH_USER@127.0.0.1" true >/dev/null 2>&1; then
    echo 'revoked preparer unexpectedly retained SSH access' >&2
    return 1
  fi

  verify_script="$(cat <<'VERIFY'
set -euo pipefail
production_root="${1:?production root is required}"

if pgrep -u linura-preparer >/dev/null 2>&1; then
  echo 'preparer process authority survived production revocation' >&2
  exit 1
fi
if grep -Eq '^[^:]+:[^:]*:[0-9]+:([^,]*,)*linura-preparer(,|$)' /etc/group; then
  echo 'preparer supplementary-group authority survived production revocation' >&2
  exit 1
fi
shadow="$(getent shadow linura-preparer | cut -d: -f2)"
case "$shadow" in
  '!'*|'*'*) ;;
  *) echo 'preparer password authority survived production revocation' >&2; exit 1 ;;
esac
test ! -e /home/linura-preparer/.ssh
test ! -e /etc/sudoers.d/99-linura-preparer
visudo -cf /etc/sudoers >/dev/null
set +e
sudo_listing="$(LC_ALL=C LANG=C /usr/bin/sudo -n -l -U linura-preparer 2>&1)"
sudo_status=$?
set -e
if printf '%s\n' "$sudo_listing" | grep -F 'User linura-preparer may run the following commands on ' >/dev/null; then
  echo 'preparer effective sudo authority survived production revocation' >&2
  printf '%s\n' "$sudo_listing" >&2
  exit 1
fi
if ! printf '%s\n' "$sudo_listing" | grep -F 'User linura-preparer is not allowed to run sudo on ' >/dev/null; then
  echo "independent sudo observation was ambiguous (status=$sudo_status)" >&2
  printf '%s\n' "$sudo_listing" >&2
  exit 1
fi
for relative in authority/control-receipt-auth.key authority/preparer-revocation.receipt; do
  path="$production_root/$relative"
  test -f "$path" -a ! -L "$path"
  test "$(stat -c '%u:%g:%a' "$path")" = '0:0:600'
done
printf '%s\n' 'preparer_revocation_verifier=independent-qualification-observation'
VERIFY
)"
  verify_encoded="$(printf '%s' "$verify_script" | base64 -w0)"
  remote "printf '%s' '$verify_encoded' | base64 -d | sudo -n /usr/bin/bash -s -- '$production_root'"
}

provision_preparer_authority_fixture() {
  local key_encoded=""
  key_encoded="$(printf '%s\n' "$public_key" | base64 -w0)"
  remote "set -euo pipefail; sudo -n /usr/sbin/usermod -G adm,sudo linura-preparer; sudo -n /usr/bin/passwd -d linura-preparer >/dev/null; sudo -n install -d -o linura-preparer -g linura-preparer -m 0700 /home/linura-preparer/.ssh; printf '%s' '$key_encoded' | base64 -d | sudo -n tee /home/linura-preparer/.ssh/authorized_keys >/dev/null; sudo -n chown linura-preparer:linura-preparer /home/linura-preparer/.ssh/authorized_keys; sudo -n chmod 0600 /home/linura-preparer/.ssh/authorized_keys; printf '%s\n' 'linura-preparer ALL=(ALL) NOPASSWD:ALL' | sudo -n tee '$PREPARER_SUDOERS' >/dev/null; sudo -n chmod 0440 '$PREPARER_SUDOERS'; sudo -n /usr/sbin/visudo -cf /etc/sudoers >/dev/null; sudo -n sync"
  preparer_remote "sudo -n /usr/bin/true"
  printf '%s\n' 'preparer_authority_fixture=hostile-and-observed' | tee -a "$TRANSCRIPT"
}

mkdir -p "$ARTIFACT_DIR"
: > "$TRANSCRIPT"
printf 'qualification_shard=%s\n' "$V09_SHARD_ID" | tee -a "$TRANSCRIPT"
printf 'qualification_boundary_range=%02d-%02d\n' "$V09_BOUNDARY_START" "$V09_BOUNDARY_END" | tee -a "$TRANSCRIPT"

ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
public_key="$(cat "$SSH_KEY.pub")"
cp --reflink=auto "$BASE_IMAGE" "$VM_IMAGE"

cat > "$RUNNER_TEMP/user-data-${V09_SHARD_ID}" <<EOF
#cloud-config
users:
  - default
  - name: linura-qualification
    groups: [adm, sudo]
    shell: /bin/bash
    sudo:
      - ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $public_key
  - name: linura-preparer
    groups: [adm, sudo]
    shell: /bin/bash
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: false
EOF
cat > "$RUNNER_TEMP/meta-data-${V09_SHARD_ID}" <<EOF
instance-id: linura-v09-adversarial-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${V09_SHARD_ID}
local-hostname: linura-v09-adversarial
EOF
cat > "$RUNNER_TEMP/network-config-${V09_SHARD_ID}" <<'EOF'
version: 2
ethernets:
  primary:
    match:
      name: "en*"
    dhcp4: true
EOF
cloud-localds --network-config="$RUNNER_TEMP/network-config-${V09_SHARD_ID}" \
  "$SEED_IMAGE" "$RUNNER_TEMP/user-data-${V09_SHARD_ID}" "$RUNNER_TEMP/meta-data-${V09_SHARD_ID}"

start_guest "$VM_UUID" initial
remote 'cloud-init status --wait --long'

preparer_sudoers="$(printf '%s\n' 'linura-preparer ALL=(ALL) NOPASSWD:ALL' | base64 -w0)"
install_text_file "$PREPARER_SUDOERS" 0440 "$preparer_sudoers"
remote "sudo -n visudo -cf /etc/sudoers >/dev/null && sudo -n sync"

binaries=(
  linura-firstboot
  linura-bootstrap-qualification
  linura-bootstrap-transition-qualification
  linura-migrations-qualification
  linura-update-qualification
  linura-update-evidence-verifier-qualification
)
for binary in "${binaries[@]}"; do
  test -f "target/release/$binary"
  chmod 0755 "target/release/$binary"
  scp "${SSH_COMMON[@]}" -P "$SSH_PORT" "target/release/$binary" "$SSH_USER@127.0.0.1:/tmp/"
  remote "sudo -n install -o root -g root -m 0755 '/tmp/$binary' '/usr/local/bin/$binary' && rm -f '/tmp/$binary'"
  host_sha="$(sha256sum "target/release/$binary" | cut -c1-64)"
  guest_sha="$(remote "sha256sum '/usr/local/bin/$binary' | cut -c1-64")"
  test "$host_sha" = "$guest_sha"
  env_name="$(printf '%s' "$binary" | tr '[:lower:]-' '[:upper:]_')_SHA"
  printf -v "$env_name" '%s' "$host_sha"
  export "$env_name"
done

q8_observer="$(base64 -w0 <<'EOF'
#!/usr/bin/env bash
set -u

production_root="${1:?production root is required}"
firstboot_sha="${2:?firstboot digest is required}"
output_path="${3:?output path is required}"
status_path="${4:?status path is required}"
mode="${5:-step}"
status=0
stop_status=0

ssh_candidate_units() {
  {
    systemctl list-unit-files --type=service --type=socket --no-legend --no-pager \
      | awk '$2 ~ /^(enabled|enabled-runtime|linked|linked-runtime|alias|indirect)$/ { print $1 }'
    systemctl list-units --all --type=service --type=socket --no-legend --no-pager \
      | awk '$3 ~ /^(active|activating|reloading)$/ { print $1 }'
  } | sort -u
}

ssh_serving_properties() {
  grep -Eiq 'sshd|openssh|dropbear|^Id=(ssh\.service|sshd\.service|ssh\.socket|sshd\.socket)$'
}

systemctl disable --now linura-qualification-transport.service >/dev/null 2>&1 || stop_status=$?
for unit in ssh.socket sshd.socket ssh.service sshd.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
systemctl mask --runtime ssh.service sshd.service ssh.socket sshd.socket >/dev/null 2>&1 || true
for unit in $(ssh_candidate_units); do
  properties="$(systemctl show "$unit" --property=Id --property=Names --property=Description --property=ExecStart --property=FragmentPath --property=ActiveState --property=UnitFileState --no-pager 2>/dev/null || true)"
  if printf '%s\n' "$properties" | ssh_serving_properties; then
    systemctl disable --now "$unit" >/dev/null 2>&1 || systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl mask --runtime --force "$unit" >/dev/null 2>&1 || true
  fi
done
for daemon in sshd dropbear tinysshd; do
  pkill -KILL -x "$daemon" >/dev/null 2>&1 || true
done

ssh_quiescent_samples=0
for _ in $(seq 1 50); do
  if ! ps -eo comm= | grep -Eq '^[[:space:]]*(sshd|dropbear|tinysshd)[[:space:]]*$'; then
    ssh_quiescent_samples=$((ssh_quiescent_samples + 1))
  else
    ssh_quiescent_samples=0
  fi
  [ "$ssh_quiescent_samples" -ge 3 ] && break
  sleep 0.1
done
if [ "$ssh_quiescent_samples" -lt 3 ]; then
  printf '%s\n' 'SSH teardown did not reach a stable quiescent state' >"$output_path"
  status=1
fi

if [ "$stop_status" -ne 0 ]; then
  printf 'qualification transport stop failed: %s\n' "$stop_status" >"$output_path"
  status=$stop_status
else
  for unit in ssh.socket sshd.socket ssh.service sshd.service; do
    if systemctl is-active --quiet "$unit"; then
      printf 'canonical SSH unit remained active during Q8: %s\n' "$unit" >"$output_path"
      status=1
      break
    fi
  done
  if [ "$status" -eq 0 ]; then
    case "$mode" in
      step)
        sudo -u linura-preparer /usr/bin/sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step "$production_root" "$firstboot_sha" >"$output_path" 2>&1
        status=$?
        ;;
      bootstrap)
        /usr/local/bin/linura-firstboot --bootstrap "$production_root" >"$output_path" 2>&1
        status=$?
        ;;
      *)
        printf 'unsupported qualification observer mode: %s\n' "$mode" >"$output_path"
        status=2
        ;;
    esac
  fi
fi

if [ "$status" -ne 0 ]; then
  {
    printf '\nqualification Q8 failure snapshot:\n'
    for unit in $(ssh_candidate_units); do
      properties="$(systemctl show "$unit" --property=Id --property=Names --property=Description --property=ExecStart --property=FragmentPath --property=ActiveState --property=UnitFileState --no-pager 2>/dev/null || true)"
      if printf '%s\n' "$properties" | ssh_serving_properties; then
        printf '%s\n' "$properties"
      fi
    done
    command -v ss >/dev/null 2>&1 && ss -H -ltnp || true
    ps -eo pid=,comm= | grep -E '(^|[[:space:]])(sshd|dropbear|tinysshd)$' || true
    grep -R -Ein 'trusted[[:space:]]*=|allow-insecure|allow-weak|allow[_-]downgrade[_-]to[_-]insecure[_-]repositories' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true
  } >>"$output_path"
fi

systemctl enable --now linura-qualification-transport.service >/dev/null 2>&1
restore=$?
stable=0
if [ "$restore" -eq 0 ]; then
  for _ in $(seq 1 20); do
    if systemctl is-active --quiet linura-qualification-transport.service; then
      stable=$((stable + 1))
    else
      stable=0
    fi
    [ "$stable" -ge 5 ] && break
    sleep 0.2
  done
  [ "$stable" -ge 5 ] || restore=1
fi
if [ "$restore" -eq 0 ]; then
  systemctl is-enabled --quiet linura-qualification-transport.service || restore=1
fi
if [ "$restore" -eq 0 ]; then
  sync || restore=1
fi
if [ "$status" -eq 0 ] && [ "$restore" -ne 0 ]; then
  status=$restore
fi
printf '%s\n' "$status" >"$status_path"
exit 0
EOF
)"
remote 'sudo -n install -d -o root -g root -m 0755 /usr/local/libexec'
install_text_file "$Q8_OBSERVER" 0755 "$q8_observer"

transport_unit="$(base64 -w0 <<'EOF'
[Unit]
Description=Linura v0.9 qualification-only transport
After=network.target
Wants=network.target

[Service]
Type=simple
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/sshd -D -e -p 2222 -o PasswordAuthentication=no -o PermitRootLogin=no -o PidFile=/run/linura-qualification-sshd.pid
Restart=on-failure
RestartSec=1
KillMode=control-group
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=network.target
EOF
)"
install_text_file /etc/systemd/system/linura-qualification-transport.service 0644 "$transport_unit"
remote 'sudo -n install -d -o root -g root -m 0755 /etc/systemd/system-generators && sudo -n ln -sfn /dev/null /etc/systemd/system-generators/sshd-socket-generator && test "$(readlink /etc/systemd/system-generators/sshd-socket-generator)" = /dev/null && sudo -n systemctl daemon-reload && sudo -n systemctl enable --now linura-qualification-transport.service >/dev/null && sudo -n systemctl is-active --quiet linura-qualification-transport.service'
remote 'for unit in ssh.service sshd.service ssh.socket sshd.socket; do sudo -n systemctl disable "$unit" >/dev/null 2>&1 || true; done; sudo -n systemctl mask --force ssh.service sshd.service ssh.socket sshd.socket >/dev/null'
remote 'set -e; sudo -n systemctl is-enabled --quiet linura-qualification-transport.service; test "$(readlink /etc/systemd/system-generators/sshd-socket-generator)" = /dev/null; for unit in ssh.service sshd.service ssh.socket sshd.socket; do test "$(readlink "/etc/systemd/system/$unit")" = /dev/null; done; sudo -n sync'
SSH_GUEST_PORT="$QUALIFICATION_SSH_GUEST_PORT"

if (( V09_BOUNDARY_START > 1 )); then
  power_cycle "qualification-transport-handoff"
fi

if ! remote 'command -v nft >/dev/null 2>&1'; then
  remote 'sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends nftables'
fi
nft_rules="$(base64 -w0 <<'EOF'
flush ruleset
table inet linura {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    tcp dport { 22, 2222 } accept comment "qualification bootstrap and isolated transport"
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF
)"
install_text_file /etc/nftables.conf 0600 "$nft_rules"
remote 'sudo -n nft -f /etc/nftables.conf && (sudo -n systemctl enable nftables.service >/dev/null 2>&1 || true)'
policy="$(printf '%s\n' '{"schema_version":1,"inbound":"default-deny","product_ssh":"disabled","package_sources":"trusted-only"}' | base64 -w0)"
remote 'sudo -n install -d -o root -g root -m 0755 /etc/linura'
install_text_file /etc/linura/install-policy.json 0600 "$policy"

remote "sudo -n rm -rf '$ROOT' && sudo -n install -d -o root -g root -m 0700 '$ROOT'"
printf 'preparer_execution_identity=%s\n' "$PREPARER_SSH_USER" | tee -a "$TRANSCRIPT"
product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-init '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" \
  | tee -a "$TRANSCRIPT"

if [[ "$V09_PRIMARY_SHARD" == true ]]; then
  hard_stop
  start_guest "$CLONE_UUID" clone-negative
  if product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" >/dev/null 2>&1; then
    echo 'cloned disk unexpectedly resumed under a different hardware UUID' >&2
    exit 1
  fi
  printf '%s\n' 'clone_machine_binding=cross-hardware-rejected' | tee -a "$TRANSCRIPT"
  hard_stop
  start_guest "$VM_UUID" clone-restore
  printf '%s\n' 'qualification_transport=explicit-out-of-band-ssh' | tee -a "$TRANSCRIPT"
fi

if (( V09_BOUNDARY_START > 1 )); then
  for boundary in $(seq 1 $((V09_BOUNDARY_START - 1))); do
    if [[ "$boundary" -eq 4 ]]; then
      run_security_baseline_step >/dev/null
    else
      product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" >/dev/null
    fi
  done
  printf 'qualification_fast_forwarded_through=%02d\n' "$((V09_BOUNDARY_START - 1))" | tee -a "$TRANSCRIPT"
fi

for boundary in $(seq "$V09_BOUNDARY_START" "$V09_BOUNDARY_END"); do
  if [[ "$V09_PRIMARY_SHARD" == true && "$boundary" -eq 1 ]]; then
    expect_transition_crash anchor-stage 'anchor_crash_after_stage=reconciled'
    power_cycle 'anchor-stage-crash'
    expect_transition_crash ledger-persist 'anchor_crash_after_ledger_persist=reconciled'
    power_cycle 'prepared-1-ledger-persist'
    printf '%s\n' 'prepared_restart_boundary_01=persistent-qemu-power-cycle' | tee -a "$TRANSCRIPT"
  elif [[ "$V09_PRIMARY_SHARD" == true && "$boundary" -eq 2 ]]; then
    expect_transition_crash anchor-finalize 'anchor_crash_after_finalize=reconciled'
    power_cycle 'prepared-2-anchor-finalize'
    printf '%s\n' 'prepared_restart_boundary_02=persistent-qemu-power-cycle' | tee -a "$TRANSCRIPT"
  else
    product_remote "sudo -n /usr/local/bin/linura-bootstrap-transition-qualification prepare '$PRODUCTION_ROOT'" | tee -a "$TRANSCRIPT"
    power_cycle "prepared-${boundary}"
    printf 'prepared_restart_boundary_%02d=persistent-qemu-power-cycle\n' "$boundary" | tee -a "$TRANSCRIPT"
  fi

  case "$boundary" in
    2|3|4|6|11|12)
      product_remote "sudo -n /usr/local/bin/linura-bootstrap-transition-qualification effect-start '$PRODUCTION_ROOT'" | tee -a "$TRANSCRIPT"
      power_cycle "effect-started-${boundary}"
      printf 'effect_started_restart_boundary_%02d=persistent-qemu-power-cycle\n' "$boundary" | tee -a "$TRANSCRIPT"
      ;;
  esac

  if [[ "$boundary" -eq 12 ]]; then
    PREPARER_ACTIVE=false
    remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
    verify_preparer_authority_revoked "$PRODUCTION_ROOT" | tee -a "$TRANSCRIPT"
    printf '%s\n' 'preparer_authority_revoked=actual-preparation-principal' | tee -a "$TRANSCRIPT"
    printf '%s\n' 'preparer_revocation_producer=production-firstboot' | tee -a "$TRANSCRIPT"
  elif [[ "$boundary" -eq 4 ]]; then
    run_security_baseline_step | tee -a "$TRANSCRIPT"
  else
    product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
  fi

  if [[ "$boundary" -eq 2 ]]; then
    managed_sha="$(remote 'sudo -n sha256sum /opt/linura/bin/linura-firstboot | cut -c1-64')"
    test "$managed_sha" = "$LINURA_FIRSTBOOT_SHA"
    {
      printf '%s\n' 'bootstrap_effect_started=durable'
      printf '%s\n' 'bootstrap_effect=linura-installation'
      printf '%s\n' 'bootstrap_installation=managed-atomic-copy'
      printf '%s\n' 'bootstrap_producer=linura-firstboot'
    } | tee -a "$TRANSCRIPT"
  fi

  power_cycle "boundary-${boundary}"
  printf 'restart_boundary_%02d=persistent-qemu-power-cycle\n' "$boundary" | tee -a "$TRANSCRIPT"
  if [[ "$boundary" -eq 1 ]]; then
    printf '%s\n' 'system_restart=persistent-qemu-power-cycle' | tee -a "$TRANSCRIPT"
  fi

  if [[ "$boundary" -eq 4 ]]; then
    mapfile -t encoded_commands < <(python3 - <<'PY'
import base64
import json
from pathlib import Path
fixture = json.loads(Path('tests/acceptance/003-security-baseline.json').read_text())
for step in fixture['steps']:
    print(base64.b64encode(step['command'].encode()).decode())
PY
)
    for encoded in "${encoded_commands[@]}"; do
      command="$(printf '%s' "$encoded" | base64 -d)"
      quoted="$(printf '%q' "$command")"
      remote "sudo -n bash -lc $quoted"
    done
    {
      printf '%s\n' 'security_baseline=q8-fixture-passed'
      printf '%s\n' 'security_baseline=inbound-default-deny'
      printf '%s\n' 'security_baseline=product-ssh-disabled'
      printf '%s\n' 'security_baseline=untrusted-sources-disabled'
      printf '%s\n' 'security_baseline=policy-present'
    } | tee -a "$TRANSCRIPT"
  fi
done

if [[ "$V09_FINAL_SHARD" == true ]]; then
  product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-resume '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"

  provision_preparer_authority_fixture
  remote "sudo -n rm -rf '$PUBLIC_BOOTSTRAP_ROOT'; sudo -n install -d -o root -g root -m 0700 '$PUBLIC_BOOTSTRAP_ROOT'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/.linura-bootstrap-session'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/bootstrap.state'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/authority/control-receipt-auth.key'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/authority/preparer-revocation.receipt'"
  run_public_bootstrap_isolated "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  verify_preparer_authority_revoked "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  printf '%s\n' 'production_bootstrap_entry=release-facing' | tee -a "$TRANSCRIPT"
  printf '%s\n' 'production_bootstrap_fresh_state=verified' | tee -a "$TRANSCRIPT"
  printf '%s\n' 'production_bootstrap_authority_observation=independent' | tee -a "$TRANSCRIPT"
  power_cycle 'production-bootstrap-restart'
  run_public_bootstrap_isolated "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  verify_preparer_authority_revoked "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  printf '%s\n' 'production_bootstrap_restart=reobserved-after-power-cycle' | tee -a "$TRANSCRIPT"
  {
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification bootstrap-start '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification bootstrap-resume '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification owner-enroll '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification interactive-owner '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification unattended-manifest '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-migrations-qualification '$ROOT/q11-migration'"
    remote "sudo -n /usr/local/bin/linura-update-qualification '$ROOT/q11-update'"
    native_recovery_script="$(cat <<'RECOVERY'
set -euo pipefail
test ! -e /usr/local/bin/linura-firstboot
test ! -e /opt/linura/bin/linura-firstboot
root="${PRODUCTION_ROOT:?}"
checkpoint="$root/recovery-checkpoint"
manifest="$checkpoint/checkpoint.manifest"
state="$root/bootstrap.state"
session="$root/.linura-bootstrap-session"
test -f "$manifest" -a -f "$checkpoint/bootstrap.state" -a -f "$checkpoint/.linura-bootstrap-session" -a -f "$checkpoint/generation.anchor"

manifest_integrity="$(sed -n 's/^integrity=//p' "$manifest")"
test -n "$manifest_integrity"
test "$(sed '$d' "$manifest" | sha256sum | cut -d' ' -f1)" = "$manifest_integrity"
state_generation="$(sed -n 's/^state_generation=//p' "$manifest")"
state_sha="$(sed -n 's/^state_sha256=//p' "$manifest")"
session_sha="$(sed -n 's/^session_sha256=//p' "$manifest")"
anchor_sha="$(sed -n 's/^anchor_sha256=//p' "$manifest")"
test "$(sha256sum "$checkpoint/bootstrap.state" | cut -d' ' -f1)" = "$state_sha"
test "$(sha256sum "$checkpoint/.linura-bootstrap-session" | cut -d' ' -f1)" = "$session_sha"
test "$(sha256sum "$checkpoint/generation.anchor" | cut -d' ' -f1)" = "$anchor_sha"

live_before="$(sha256sum "$state" | cut -d' ' -f1)"
test "$live_before" != "$state_sha"

machine="$(tr -d '\r\n' </etc/machine-id)"
hardware="$(tr -d '\r\n' </sys/class/dmi/id/product_uuid)"
scope="$(printf '%s\000%s' "$machine" "$hardware" | sha256sum | cut -d' ' -f1)"
state_identity="$(printf '%s' "$state" | sha256sum | cut -d' ' -f1)"
anchor="/var/lib/linura/bootstrap-anchors/$scope/$state_identity.generation"
test -f "$anchor"

restore_atomic() {
  source="$1"
  target="$2"
  parent="$(dirname "$target")"
  base="$(basename "$target")"
  temporary="$parent/.${base}.native-recovery.$$"
  rm -f "$temporary"
  install -o root -g root -m 0600 "$source" "$temporary"
  sync -f "$temporary"
  mv -fT "$temporary" "$target"
  sync -f "$parent"
}
restore_atomic "$checkpoint/bootstrap.state" "$state"
restore_atomic "$checkpoint/.linura-bootstrap-session" "$session"
restore_atomic "$checkpoint/generation.anchor" "$anchor"

test "$(sha256sum "$state" | cut -d' ' -f1)" = "$state_sha"
test "$(sha256sum "$session" | cut -d' ' -f1)" = "$session_sha"
test "$(sha256sum "$anchor" | cut -d' ' -f1)" = "$anchor_sha"
grep -Fx "generation=$state_generation" "$state" >/dev/null
grep -Fx 'active_stage=recovery-checkpoint' "$state" >/dev/null
grep -Fx 'active_effect=effect-started' "$state" >/dev/null
/usr/bin/apt --version >/dev/null
printf '%s\n' 'native_recovery_restore=checkpoint-bundle-restored'
printf '%s\n' 'native_recovery_state=state-session-anchor-verified'
printf '%s\n' 'native_recovery=available_without_firstboot_network_or_model'
RECOVERY
)"
    native_recovery_encoded="$(printf '%s' "$native_recovery_script" | base64 -w0)"
    remote "set -e; sudo -n mv /usr/local/bin/linura-firstboot /usr/local/bin/linura-firstboot.unavailable; sudo -n mv /opt/linura/bin/linura-firstboot /opt/linura/bin/linura-firstboot.unavailable; cleanup_native(){ sudo -n mv /usr/local/bin/linura-firstboot.unavailable /usr/local/bin/linura-firstboot; sudo -n mv /opt/linura/bin/linura-firstboot.unavailable /opt/linura/bin/linura-firstboot; }; trap cleanup_native EXIT; printf '%s' '$native_recovery_encoded' | base64 -d | sudo -n env PRODUCTION_ROOT='$PRODUCTION_ROOT' unshare --net -- /usr/bin/bash"
  } | tee -a "$TRANSCRIPT"
fi

guest_arch="$(remote 'uname -m')"
guest_virt="$(remote 'systemd-detect-virt')"
guest_os="$(remote "sed -n 's/^ID=//p' /etc/os-release | tr -d '\"'")"
guest_version="$(remote "sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '\"'")"
test "$guest_arch" = x86_64
test "$guest_virt" = qemu
test "$guest_os" = ubuntu
test "$guest_version" = 24.04
cat > "$ENVIRONMENT" <<EOF
architecture=$guest_arch
virtualization=$guest_virt
distribution_id=$guest_os
distribution_version=$guest_version
EOF

export ARTIFACT_DIR TRANSCRIPT ENVIRONMENT
export V09_SHARD_ID V09_BOUNDARY_START V09_BOUNDARY_END V09_PRIMARY_SHARD V09_FINAL_SHARD
export LINURA_FIRSTBOOT_SHA LINURA_BOOTSTRAP_QUALIFICATION_SHA
export LINURA_BOOTSTRAP_TRANSITION_QUALIFICATION_SHA
export LINURA_MIGRATIONS_QUALIFICATION_SHA LINURA_UPDATE_QUALIFICATION_SHA
export LINURA_UPDATE_EVIDENCE_VERIFIER_QUALIFICATION_SHA
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

root = Path.cwd()
artifact = Path(os.environ['ARTIFACT_DIR'])
transcript = Path(os.environ['TRANSCRIPT'])
environment = Path(os.environ['ENVIRONMENT'])
shard_id = os.environ['V09_SHARD_ID']
start = int(os.environ['V09_BOUNDARY_START'])
end = int(os.environ['V09_BOUNDARY_END'])
primary = os.environ['V09_PRIMARY_SHARD'] == 'true'
final = os.environ['V09_FINAL_SHARD'] == 'true'

required = [f'qualification_shard={shard_id}', f'qualification_boundary_range={start:02d}-{end:02d}']
required.extend(f'prepared_restart_boundary_{index:02d}=persistent-qemu-power-cycle' for index in range(start, end + 1))
required.extend(f'effect_started_restart_boundary_{index:02d}=persistent-qemu-power-cycle' for index in (2, 3, 4, 6, 11, 12) if start <= index <= end)
required.extend(f'restart_boundary_{index:02d}=persistent-qemu-power-cycle' for index in range(start, end + 1))
if primary:
    required.extend([
        'bootstrap_effect_started=durable', 'bootstrap_producer=linura-firstboot',
        'system_restart=persistent-qemu-power-cycle', 'clone_machine_binding=cross-hardware-rejected',
        'qualification_transport=explicit-out-of-band-ssh', 'anchor_crash_after_stage=reconciled',
        'anchor_crash_after_ledger_persist=reconciled', 'anchor_crash_after_finalize=reconciled',
    ])
if start <= 4 <= end:
    required.extend([
        'security_baseline=q8-fixture-passed', 'security_baseline=inbound-default-deny',
        'security_baseline=product-ssh-disabled', 'security_baseline=untrusted-sources-disabled',
        'security_baseline=policy-present',
    ])
if final:
    required.extend([
        'bootstrap_restart=reobserved', 'bootstrap_restart_source=production-firstboot',
        'owner_enrollment=owner-enrollment-pending', 'preparer_authority_inherited=false',
        'production_bootstrap_entry=release-facing',
        'production_bootstrap_fresh_state=verified',
        'production_bootstrap_authority_observation=independent',
        'preparer_revocation_producer=production-firstboot',
        'preparer_revocation_verifier=independent-qualification-observation',
        'production_bootstrap_restart=reobserved-after-power-cycle',
        'interactive_owner_restart=enrolled-generation-1', 'manifest_replay=cross-machine-rejected',
        'manifest_command_field=rejected', 'q11_migration=real-v08-sqlite-stores',
        'q11_library=intent-graph-provenance-preserved', 'q11_authority=transaction-history-preserved',
        'q11_backup_restore=injected-library-failure-restored',
        'q11_sqlite_backup=wal-checkpointed-recovery-unit', 'q11_migration_restart=no-replay',
        'q11_update_restart=reobserve-no-blind-replay', 'q11_package_transaction=dpkg-killed-mid-postinst',
        'q11_package_reconcile=dpkg-configure-authoritative', 'q11_package_poststate=authoritatively-verified',
        'q11_package_verifier=independent-authenticated-producer',
        'q11_indeterminate=recovery-required',
        'native_recovery_restore=checkpoint-bundle-restored',
        'native_recovery_state=state-session-anchor-verified',
        'native_recovery=available_without_firstboot_network_or_model',
    ])
text = transcript.read_text(encoding='utf-8')
missing = [marker for marker in required if marker not in text]
if missing:
    raise SystemExit(f'missing shard adversarial evidence: {missing}')
facts = dict(line.split('=', 1) for line in environment.read_text().splitlines())
expected = {'architecture': 'x86_64', 'virtualization': 'qemu', 'distribution_id': 'ubuntu', 'distribution_version': '24.04'}
if facts != expected:
    raise SystemExit(f'qualification environment mismatch: {facts}')
def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
workflow = root / '.github/workflows/v09-adversarial-security.yml'
evidence = {
    'schema_version': 1, 'kind': 'v09-adversarial-shard',
    'repository': os.environ['GITHUB_REPOSITORY'], 'source_sha': os.environ['SOURCE_SHA'], 'result': 'passed',
    'shard': {'id': shard_id, 'boundary_start': start, 'boundary_end': end, 'primary': primary, 'final': final},
    'qualification_environment': {'id': os.environ['QUALIFICATION_ENVIRONMENT_ID'], **facts},
    'base_image': {'url': os.environ['BASE_IMAGE_URL'], 'sha256': os.environ['BASE_IMAGE_SHA256']},
    'qualification_contract': {'path': workflow.relative_to(root).as_posix(), 'sha256': digest(workflow)},
    'binaries': {
        'linura-firstboot': {'sha256': os.environ['LINURA_FIRSTBOOT_SHA']},
        'linura-bootstrap-qualification': {'sha256': os.environ['LINURA_BOOTSTRAP_QUALIFICATION_SHA']},
        'linura-bootstrap-transition-qualification': {'sha256': os.environ['LINURA_BOOTSTRAP_TRANSITION_QUALIFICATION_SHA']},
        'linura-migrations-qualification': {'sha256': os.environ['LINURA_MIGRATIONS_QUALIFICATION_SHA']},
        'linura-update-qualification': {'sha256': os.environ['LINURA_UPDATE_QUALIFICATION_SHA']},
        'linura-update-evidence-verifier-qualification': {'sha256': os.environ['LINURA_UPDATE_EVIDENCE_VERIFIER_QUALIFICATION_SHA']},
    },
    'transcript': {'path': transcript.name, 'sha256': digest(transcript), 'size': transcript.stat().st_size},
    'environment': {'path': environment.name, 'sha256': digest(environment), 'size': environment.stat().st_size},
    'workflow': {'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT'])},
}
evidence_path = artifact / f'V09-ADVERSARIAL-SHARD-{shard_id}.json'
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
checksum = digest(evidence_path)
(artifact / f'V09-ADVERSARIAL-SHARD-{shard_id}.sha256').write_text(f'{checksum}  {evidence_path.name}\n')
PY

hard_stop
trap - EXIT
