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
  'sudo -n apt-get update && sudo -n apt-get install -y --no-install-recommends dbus polkitd'

scp "${ssh_common[@]}" -P "$ssh_port" \
  target/release/linurad \
  target/release/linuractl \
  target/release/linura-executor-systemd \
  target/release/examples/v05_binding \
  target/release/examples/v05_verify \
  packaging/dbus-1/system.d/org.linura.Executor.Systemd1.conf \
  packaging/polkit-1/actions/org.linura.executor.systemd.policy \
  packaging/systemd/system/linura-executor-systemd.service \
  tests/acceptance/v05/linura-v05-qualification-restart.service \
  tests/acceptance/v05/49-linura-v05-qualification.rules \
  tests/acceptance/v05/49-linura-v05-qualification-dbus.conf \
  tests/acceptance/v05/qualify-guest.sh \
  linura@127.0.0.1:/tmp/

qualification_log="$ARTIFACT_DIR/qualification.log"
failure_log="$ARTIFACT_DIR/qualification-failure.txt"
set +e
ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
  'dbus-run-session -- bash /tmp/qualify-guest.sh' 2>&1 | tee "$qualification_log"
guest_rc=${PIPESTATUS[0]}
set -e

if [[ "$guest_rc" -ne 0 ]]; then
  {
    printf 'guest_rc=%s\n' "$guest_rc"
    echo '--- executor status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status linura-executor-systemd.service --no-pager -l || true'
    echo '--- fixture status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status linura-v05-qualification-restart.service --no-pager -l || true'
    echo '--- polkit status ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n systemctl status polkit.service --no-pager -l || true'
    echo '--- executor journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u linura-executor-systemd.service --no-pager -n 200 || true'
    echo '--- fixture journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u linura-v05-qualification-restart.service --no-pager -n 100 || true'
    echo '--- polkit journal ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'sudo -n journalctl -u polkit.service --no-pager -n 100 || true'
    echo '--- D-Bus ownership ---'
    ssh "${ssh_common[@]}" -p "$ssh_port" linura@127.0.0.1 \
      'busctl --system status org.linura.Executor.Systemd1 || true'
  } >"$failure_log" 2>&1 || true
  cat "$failure_log" >&2 || true
  exit "$guest_rc"
fi
