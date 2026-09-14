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
VM_IMAGE="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}.qcow2"
SEED_IMAGE="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}-seed.img"
SSH_KEY="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}-key"
VM_LOG="$RUNNER_TEMP/linura-v09-adversarial-${V09_SHARD_ID}.log"
ARTIFACT_DIR="$RUNNER_TEMP/linura-v09-adversarial-artifacts"
TRANSCRIPT="$ARTIFACT_DIR/guest-qualification-${V09_SHARD_ID}.txt"
ENVIRONMENT="$ARTIFACT_DIR/guest-environment-${V09_SHARD_ID}.env"
ROOT=/var/lib/linura-qualification/v0.9
PRODUCTION_ROOT="$ROOT/production-firstboot"
HARNESS_ROOT="$ROOT/harness"
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
  ssh "${SSH_COMMON[@]}" -p "$SSH_PORT" linura@127.0.0.1 "$1"
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
  output="$(remote "sudo -n env LINURA_BOOTSTRAP_QUALIFICATION_CRASH_AFTER='$point' /usr/local/bin/linura-bootstrap-transition-qualification prepare '$PRODUCTION_ROOT'" 2>&1)"
  status=$?
  set -e
  if [[ "$status" -eq 0 || "$output" != *"qualification_crash_after=$point"* ]]; then
    printf 'expected qualification crash at %s, status=%s, output=%s\n' "$point" "$status" "$output" >&2
    return 1
  fi
  printf '%s\n' "$marker" | tee -a "$TRANSCRIPT"
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
  - name: linura
    groups: [adm, sudo]
    shell: /bin/bash
    sudo:
      - ALL=(ALL) NOPASSWD:ALL
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

binaries=(
  linura-firstboot
  linura-bootstrap-qualification
  linura-bootstrap-transition-qualification
  linura-migrations-qualification
  linura-update-qualification
)
for binary in "${binaries[@]}"; do
  test -x "target/release/$binary"
  scp "${SSH_COMMON[@]}" -P "$SSH_PORT" "target/release/$binary" linura@127.0.0.1:/tmp/
  remote "sudo -n install -o root -g root -m 0755 '/tmp/$binary' '/usr/local/bin/$binary' && rm -f '/tmp/$binary'"
  host_sha="$(sha256sum "target/release/$binary" | cut -c1-64)"
  guest_sha="$(remote "sha256sum '/usr/local/bin/$binary' | cut -c1-64")"
  test "$host_sha" = "$guest_sha"
  env_name="$(printf '%s' "$binary" | tr '[:lower:]-' '[:upper:]_')_SHA"
  printf -v "$env_name" '%s' "$host_sha"
  export "$env_name"
done

transport_unit="$(base64 -w0 <<'EOF'
[Unit]
Description=Linura v0.9 qualification-only transport
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PermitRootLogin=no -o PidFile=/run/linura-qualification-sshd.pid
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
)"
install_text_file /etc/systemd/system/linura-qualification-transport.service 0644 "$transport_unit"
remote 'sudo -n systemctl daemon-reload && sudo -n systemctl enable linura-qualification-transport.service >/dev/null'
remote 'for unit in ssh.service sshd.service ssh.socket sshd.socket; do sudo -n systemctl disable "$unit" >/dev/null 2>&1 || true; done'

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
    tcp dport 22 accept comment "qualification-only transport"
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
remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-init '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" \
  | tee -a "$TRANSCRIPT"

if [[ "$V09_PRIMARY_SHARD" == true ]]; then
  hard_stop
  start_guest "$CLONE_UUID" clone-negative
  if remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" >/dev/null 2>&1; then
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
    remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" >/dev/null
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
    remote "sudo -n /usr/local/bin/linura-bootstrap-transition-qualification prepare '$PRODUCTION_ROOT'" | tee -a "$TRANSCRIPT"
    power_cycle "prepared-${boundary}"
    printf 'prepared_restart_boundary_%02d=persistent-qemu-power-cycle\n' "$boundary" | tee -a "$TRANSCRIPT"
  fi

  case "$boundary" in
    2|3|4|6|11|12)
      remote "sudo -n /usr/local/bin/linura-bootstrap-transition-qualification effect-start '$PRODUCTION_ROOT'" | tee -a "$TRANSCRIPT"
      power_cycle "effect-started-${boundary}"
      printf 'effect_started_restart_boundary_%02d=persistent-qemu-power-cycle\n' "$boundary" | tee -a "$TRANSCRIPT"
      ;;
  esac

  remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"

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
  remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-resume '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
  {
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification bootstrap-start '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification bootstrap-resume '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification owner-enroll '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification interactive-owner '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-bootstrap-qualification unattended-manifest '$HARNESS_ROOT'"
    remote "sudo -n /usr/local/bin/linura-migrations-qualification '$ROOT/q11-migration'"
    remote "sudo -n /usr/local/bin/linura-update-qualification '$ROOT/q11-update'"
    remote 'set -e; sudo -n mv /usr/local/bin/linura-firstboot /usr/local/bin/linura-firstboot.unavailable; cleanup_native(){ sudo -n mv /usr/local/bin/linura-firstboot.unavailable /usr/local/bin/linura-firstboot; }; trap cleanup_native EXIT; sudo -n unshare --net -- /usr/bin/bash -lc "test ! -e /usr/local/bin/linura-firstboot; /usr/bin/apt --version >/dev/null; echo native_recovery=available_without_firstboot_network_or_model"'
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
        'security_baseline=q8-fixture-passed', 'security_baseline=inbound-default-deny',
        'security_baseline=product-ssh-disabled', 'security_baseline=untrusted-sources-disabled',
        'security_baseline=policy-present',
    ])
if final:
    required.extend([
        'bootstrap_restart=reobserved', 'bootstrap_restart_source=production-firstboot',
        'owner_enrollment=owner-enrollment-pending', 'preparer_authority_inherited=false',
        'interactive_owner_restart=enrolled-generation-1', 'manifest_replay=cross-machine-rejected',
        'manifest_command_field=rejected', 'q11_migration=real-v08-sqlite-stores',
        'q11_library=intent-graph-provenance-preserved', 'q11_authority=transaction-history-preserved',
        'q11_backup_restore=injected-library-failure-restored', 'q11_migration_restart=no-replay',
        'q11_update_restart=reobserve-no-blind-replay', 'q11_package_transaction=dpkg-killed-mid-postinst',
        'q11_package_reconcile=dpkg-configure-authoritative', 'q11_package_poststate=authoritatively-verified',
        'q11_indeterminate=recovery-required', 'native_recovery=available_without_firstboot_network_or_model',
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
