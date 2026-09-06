#!/usr/bin/env bash
set -euo pipefail

: "${SSH_KEY:?SSH_KEY is required}"
: "${VM_PID:?VM_PID is required}"
: "${VM_LOG:?VM_LOG is required}"
: "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"

ssh_port="${SSH_PORT:-2222}"
ssh_common=(
  -i "$SSH_KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=3
)

ready=0
for _ in $(seq 1 120); do
  if ! kill -0 "$VM_PID" 2>/dev/null; then
    echo "VM exited before SSH became ready" >&2
    cat "$VM_LOG" >&2
    exit 1
  fi
  if ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 true >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  echo "VM did not become reachable over SSH" >&2
  cat "$VM_LOG" >&2
  exit 1
fi

ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 'cloud-init status --wait --long'
ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
  'sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends dbus polkitd sqlite3'

scp "${ssh_common[@]}" -P "$ssh_port" \
  target/release/linura-authorityd \
  target/release/linura-executor-systemd \
  target/release/v06-qualification-matrix \
  packaging/dbus-1/system.d/org.linura.Authority1.conf \
  packaging/dbus-1/system.d/org.linura.Executor.Systemd1.conf \
  packaging/polkit-1/actions/org.linura.authority.policy \
  packaging/polkit-1/actions/org.linura.executor.systemd.policy \
  packaging/polkit-1/rules.d/50-linura-executor-systemd.rules \
  packaging/systemd/system/linura-authorityd.service \
  packaging/systemd/system/linura-executor-systemd.service \
  tests/acceptance/v06/49-linura-v06-qualification.rules \
  tests/acceptance/v06/linura-managed-v06-qualification.service \
  tests/acceptance/v06/linura-managed-v06-notsatisfied.service \
  tests/acceptance/v06/qualify-guest.sh \
  linura@127.0.0.1:/tmp/

qualification_log="$ARTIFACT_DIR/qualification.log"
failure_log="$ARTIFACT_DIR/qualification-failure.txt"
set +e
ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
  'bash /tmp/qualify-guest.sh' 2>&1 | tee "$qualification_log"
guest_rc=${PIPESTATUS[0]}
set -e

scp "${ssh_common[@]}" -P "$ssh_port" \
  linura@127.0.0.1:/tmp/v06-matrix.log "$ARTIFACT_DIR/v06-matrix.log" >/dev/null 2>&1 || true

if [[ "$guest_rc" -ne 0 ]]; then
  {
    printf 'guest_rc=%s\n' "$guest_rc"
    echo '--- authority status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status linura-authorityd.service --no-pager -l || true'
    echo '--- executor status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status linura-executor-systemd.service --no-pager -l || true'
    echo '--- fixture status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status linura-managed-v06-qualification.service linura-managed-v06-notsatisfied.service --no-pager -l || true'
    echo '--- polkit status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status polkit.service --no-pager -l || true'
    echo '--- authority journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u linura-authorityd.service --no-pager -n 250 || true'
    echo '--- executor journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u linura-executor-systemd.service --no-pager -n 250 || true'
    echo '--- fixture journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u linura-managed-v06-qualification.service -u linura-managed-v06-notsatisfied.service --no-pager -n 200 || true'
    echo '--- polkit journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u polkit.service --no-pager -n 150 || true'
    echo '--- D-Bus ownership ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'busctl --system status org.linura.Authority1 || true; busctl --system status org.linura.Executor.Systemd1 || true'
    echo '--- durable authority files ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n ls -la /var/lib/linura-authority || true; sudo -n sqlite3 /var/lib/linura-authority/authority.sqlite3 "PRAGMA journal_mode; PRAGMA integrity_check; .tables" || true'
    echo '--- dispatch log ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n cat /run/linura-v06-qualification/dispatch.log || true'
  } >"$failure_log" 2>&1 || true
  cat "$failure_log" >&2 || true
  exit "$guest_rc"
fi
