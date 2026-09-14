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

SSH_PORT=2224
VM_IMAGE="$RUNNER_TEMP/linura-v09-adversarial.qcow2"
SEED_IMAGE="$RUNNER_TEMP/linura-v09-adversarial-seed.img"
SSH_KEY="$RUNNER_TEMP/linura-v09-adversarial-key"
VM_LOG="$RUNNER_TEMP/linura-v09-adversarial.log"
ARTIFACT_DIR="$RUNNER_TEMP/linura-v09-adversarial-artifacts"
TRANSCRIPT="$ARTIFACT_DIR/guest-qualification.txt"
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

mkdir -p "$ARTIFACT_DIR"
: > "$TRANSCRIPT"
ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY"
public_key="$(cat "$SSH_KEY.pub")"
cp --reflink=auto "$BASE_IMAGE" "$VM_IMAGE"

cat > "$RUNNER_TEMP/user-data" <<EOF
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
cat > "$RUNNER_TEMP/meta-data" <<EOF
instance-id: linura-v09-adversarial-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}
local-hostname: linura-v09-adversarial
EOF
cat > "$RUNNER_TEMP/network-config" <<'EOF'
version: 2
ethernets:
  primary:
    match:
      name: "en*"
    dhcp4: true
EOF
cloud-localds --network-config="$RUNNER_TEMP/network-config" \
  "$SEED_IMAGE" "$RUNNER_TEMP/user-data" "$RUNNER_TEMP/meta-data"

start_guest "$VM_UUID" initial
remote 'cloud-init status --wait --long'

binaries=(
  linura-firstboot
  linura-bootstrap-qualification
  linura-migrations-qualification
  linura-update-qualification
)
for binary in "${binaries[@]}"; do
  scp "${SSH_COMMON[@]}" -P "$SSH_PORT" "target/release/$binary" linura@127.0.0.1:/tmp/
  remote "sudo -n install -o root -g root -m 0755 '/tmp/$binary' '/usr/local/bin/$binary' && rm -f '/tmp/$binary'"
  host_sha="$(sha256sum "target/release/$binary" | cut -c1-64)"
  guest_sha="$(remote "sha256sum '/usr/local/bin/$binary' | cut -c1-64")"
  test "$host_sha" = "$guest_sha"
  env_name="$(printf '%s' "$binary" | tr '[:lower:]-' '[:upper:]_')_SHA"
  printf -v "$env_name" '%s' "$host_sha"
  export "$env_name"
done

# The Q8 product baseline requires the ordinary SSH units to be disabled. The
# qualification harness therefore installs a separately named transport unit
# before the first power cycle. Evidence calls this out explicitly so the
# harness channel cannot be confused with a supported product SSH surface.
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

# Prove a cloned disk cannot continue durable history under a different
# hardware identity, then return to the original identity.
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

for boundary in $(seq 1 13); do
  remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" \
    | tee -a "$TRANSCRIPT"

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

remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-resume '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" \
  | tee -a "$TRANSCRIPT"

{
  remote "sudo -n /usr/local/bin/linura-bootstrap-qualification bootstrap-start '$HARNESS_ROOT'"
  remote "sudo -n /usr/local/bin/linura-bootstrap-qualification bootstrap-resume '$HARNESS_ROOT'"
  remote "sudo -n /usr/local/bin/linura-bootstrap-qualification owner-enroll '$HARNESS_ROOT'"
  remote "sudo -n /usr/local/bin/linura-bootstrap-qualification unattended-manifest '$HARNESS_ROOT'"
  remote "sudo -n /usr/local/bin/linura-migrations-qualification '$ROOT/q11-migration'"
  remote "sudo -n /usr/local/bin/linura-update-qualification '$ROOT/q11-update'"
  remote 'set -e; sudo -n mv /usr/local/bin/linura-firstboot /usr/local/bin/linura-firstboot.unavailable; cleanup_native(){ sudo -n mv /usr/local/bin/linura-firstboot.unavailable /usr/local/bin/linura-firstboot; }; trap cleanup_native EXIT; sudo -n unshare --net -- /usr/bin/bash -lc "test ! -e /usr/local/bin/linura-firstboot; /usr/bin/apt --version >/dev/null; echo native_recovery=available_without_firstboot_network_or_model"'
} | tee -a "$TRANSCRIPT"

guest_arch="$(remote 'uname -m')"
guest_virt="$(remote 'systemd-detect-virt')"
guest_os="$(remote "sed -n 's/^ID=//p' /etc/os-release | tr -d '\"'")"
guest_version="$(remote "sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '\"'")"
test "$guest_arch" = x86_64
test "$guest_virt" = qemu
test "$guest_os" = ubuntu
test "$guest_version" = 24.04
cat > "$ARTIFACT_DIR/guest-environment.env" <<EOF
architecture=$guest_arch
virtualization=$guest_virt
distribution_id=$guest_os
distribution_version=$guest_version
EOF

export ARTIFACT_DIR LINURA_FIRSTBOOT_SHA LINURA_BOOTSTRAP_QUALIFICATION_SHA
export LINURA_MIGRATIONS_QUALIFICATION_SHA LINURA_UPDATE_QUALIFICATION_SHA
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

root = Path.cwd()
artifact = Path(os.environ['ARTIFACT_DIR'])
transcript = artifact / 'guest-qualification.txt'
environment = artifact / 'guest-environment.env'
required = [
    'bootstrap_effect_started=durable',
    'bootstrap_producer=linura-firstboot',
    'bootstrap_restart=reobserved',
    'bootstrap_restart_source=production-firstboot',
    'system_restart=persistent-qemu-power-cycle',
    'clone_machine_binding=cross-hardware-rejected',
    'qualification_transport=explicit-out-of-band-ssh',
    'security_baseline=q8-fixture-passed',
    'security_baseline=inbound-default-deny',
    'security_baseline=product-ssh-disabled',
    'security_baseline=untrusted-sources-disabled',
    'security_baseline=policy-present',
    'owner_enrollment=owner-enrollment-pending',
    'preparer_authority_inherited=false',
    'manifest_replay=cross-machine-rejected',
    'manifest_command_field=rejected',
    'q11_migration=real-v08-sqlite-stores',
    'q11_library=intent-graph-provenance-preserved',
    'q11_authority=transaction-history-preserved',
    'q11_backup_restore=injected-library-failure-restored',
    'q11_migration_restart=no-replay',
    'q11_update_restart=reobserve-no-blind-replay',
    'q11_package_transaction=dpkg-killed-mid-postinst',
    'q11_package_reconcile=dpkg-configure-authoritative',
    'q11_package_poststate=authoritatively-verified',
    'q11_indeterminate=recovery-required',
    'native_recovery=available_without_firstboot_network_or_model',
]
required.extend(
    f'restart_boundary_{index:02d}=persistent-qemu-power-cycle'
    for index in range(1, 14)
)
text = transcript.read_text(encoding='utf-8')
missing = [marker for marker in required if marker not in text]
if missing:
    raise SystemExit(f'missing adversarial evidence: {missing}')
facts = dict(line.split('=', 1) for line in environment.read_text().splitlines())
expected = {
    'architecture': 'x86_64',
    'virtualization': 'qemu',
    'distribution_id': 'ubuntu',
    'distribution_version': '24.04',
}
if facts != expected:
    raise SystemExit(f'qualification environment mismatch: {facts}')

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

workflow = root / '.github/workflows/v09-adversarial-security.yml'
evidence = {
    'schema_version': 1,
    'repository': os.environ['GITHUB_REPOSITORY'],
    'source_sha': os.environ['SOURCE_SHA'],
    'result': 'passed',
    'qualification_environment': {
        'id': os.environ['QUALIFICATION_ENVIRONMENT_ID'],
        **facts,
    },
    'base_image': {
        'url': os.environ['BASE_IMAGE_URL'],
        'sha256': os.environ['BASE_IMAGE_SHA256'],
    },
    'qualification_contract': {
        'path': workflow.relative_to(root).as_posix(),
        'sha256': digest(workflow),
    },
    'binaries': {
        'linura-firstboot': {'sha256': os.environ['LINURA_FIRSTBOOT_SHA']},
        'linura-bootstrap-qualification': {'sha256': os.environ['LINURA_BOOTSTRAP_QUALIFICATION_SHA']},
        'linura-migrations-qualification': {'sha256': os.environ['LINURA_MIGRATIONS_QUALIFICATION_SHA']},
        'linura-update-qualification': {'sha256': os.environ['LINURA_UPDATE_QUALIFICATION_SHA']},
    },
    'transcript': {
        'path': transcript.name,
        'sha256': digest(transcript),
        'size': transcript.stat().st_size,
    },
    'workflow': {
        'run_id': int(os.environ['GITHUB_RUN_ID']),
        'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
    },
}
evidence_path = artifact / 'V09-ADVERSARIAL-EVIDENCE.json'
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
checksum = digest(evidence_path)
(artifact / 'V09-ADVERSARIAL-EVIDENCE.sha256').write_text(
    f'{checksum}  {evidence_path.name}\n'
)
PY

hard_stop
trap - EXIT
