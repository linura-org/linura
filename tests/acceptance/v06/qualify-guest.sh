#!/usr/bin/env bash
set -Eeuo pipefail

unit="linura-managed-v06-qualification.service"
notsatisfied_unit="linura-managed-v06-notsatisfied.service"
authority_dest="org.linura.Authority1"
authority_path="/org/linura/Authority1"
authority_iface="org.linura.Authority1"
executor_dest="org.linura.Executor.Systemd1"
executor_path="/org/linura/Executor/Systemd1"
executor_iface="org.linura.Executor.Systemd1"
dispatch_log="/run/linura-v06-qualification/dispatch.log"
LAST_FAILURE_OUTPUT=""

stage() {
  printf 'stage=%s\n' "$1"
}

on_error() {
  local rc=$?
  printf 'guest-error rc=%s line=%s command=%q\n' "$rc" "$LINENO" "$BASH_COMMAND" >&2
  exit "$rc"
}
trap on_error ERR

call_authority() {
  sudo -n -u linura-v06-qualifier -- \
    busctl --system call "$authority_dest" "$authority_path" "$authority_iface" \
      ConvergeSystemdActiveState ssss "$1" "$2" "$3" "$4"
}

call_authority_unapproved() {
  busctl --system call "$authority_dest" "$authority_path" "$authority_iface" \
    ConvergeSystemdActiveState ssss "$1" "$2" "$3" "$4"
}

call_executor_direct() {
  busctl --system call "$executor_dest" "$executor_path" "$executor_iface" \
    SetManagedActiveState sssttssss \
    "$unit" active "transaction:v06:qualification" 0 0 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    0000000000000000000000000000000000000000000000000000000000000000
}

call_executor_direct_root() {
  sudo -n busctl --system call "$executor_dest" "$executor_path" "$executor_iface" \
    SetManagedActiveState sssttssss \
    "$unit" active "transaction:v06:root-direct" 0 0 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    0000000000000000000000000000000000000000000000000000000000000000 \
    0000000000000000000000000000000000000000000000000000000000000000
}

dispatch_count() {
  local marker="$1"
  if [[ ! -f "$dispatch_log" ]]; then
    printf '0\n'
    return
  fi
  grep -c -x "$marker" "$dispatch_log" || true
}

expect_failure() {
  local label="$1"
  shift
  local output rc
  if output="$("$@" 2>&1)"; then
    printf '%s unexpectedly succeeded: %s\n' "$label" "$output" >&2
    exit 1
  else
    rc=$?
  fi
  LAST_FAILURE_OUTPUT="$output"
  printf '%s-rc=%s\n' "$label" "$rc"
  printf '%s-output=%q\n' "$label" "$output"
}

stage install-assets
if ! id -u linura-authority >/dev/null 2>&1; then
  sudo -n useradd --system --no-create-home --home-dir /var/lib/linura-authority --shell /usr/sbin/nologin linura-authority
fi
if ! id -u linura-v06-qualifier >/dev/null 2>&1; then
  sudo -n useradd --system --no-create-home --shell /usr/sbin/nologin linura-v06-qualifier
fi
sudo -n install -d -o root -g root -m 0755 /usr/lib/linura /usr/libexec/linura
sudo -n install -o root -g root -m 0755 /tmp/linura-authorityd /usr/lib/linura/linura-authorityd
sudo -n install -o root -g root -m 0755 /tmp/linura-executor-systemd /usr/lib/linura/linura-executor-systemd
sudo -n install -o root -g root -m 0755 /tmp/v06-qualification-matrix /usr/libexec/linura/v06-qualification-matrix
sudo -n install -o root -g root -m 0644 /tmp/org.linura.Authority1.conf /etc/dbus-1/system.d/org.linura.Authority1.conf
sudo -n install -o root -g root -m 0644 /tmp/org.linura.Executor.Systemd1.conf /etc/dbus-1/system.d/org.linura.Executor.Systemd1.conf
sudo -n install -o root -g root -m 0644 /tmp/org.linura.authority.policy /usr/share/polkit-1/actions/org.linura.authority.policy
sudo -n install -o root -g root -m 0644 /tmp/org.linura.executor.systemd.policy /usr/share/polkit-1/actions/org.linura.executor.systemd.policy
sudo -n install -o root -g root -m 0644 /tmp/50-linura-executor-systemd.rules /etc/polkit-1/rules.d/50-linura-executor-systemd.rules
sudo -n install -o root -g root -m 0644 /tmp/49-linura-v06-qualification.rules /etc/polkit-1/rules.d/49-linura-v06-qualification.rules
sudo -n install -o root -g root -m 0644 /tmp/linura-executor-systemd.service /etc/systemd/system/linura-executor-systemd.service
sudo -n install -o root -g root -m 0644 /tmp/linura-authorityd.service /etc/systemd/system/linura-authorityd.service
sudo -n install -o root -g root -m 0644 /tmp/linura-managed-v06-qualification.service /etc/systemd/system/linura-managed-v06-qualification.service
sudo -n install -o root -g root -m 0644 /tmp/linura-managed-v06-notsatisfied.service /etc/systemd/system/linura-managed-v06-notsatisfied.service
sudo -n install -d -o root -g root -m 0755 /run/linura-v06-qualification
sudo -n touch "$dispatch_log"
sudo -n truncate -s 0 "$dispatch_log"

stage activate-system-integration
sudo -n systemctl daemon-reload
sudo -n systemctl restart polkit.service
sudo -n dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
sudo -n systemctl stop "$unit" "$notsatisfied_unit" || true
sudo -n systemctl start linura-executor-systemd.service
sudo -n systemctl start linura-authorityd.service
sudo -n systemctl is-active --quiet linura-executor-systemd.service
sudo -n systemctl is-active --quiet linura-authorityd.service
test -x /usr/bin/pkcheck

stage live-contract-introspection
authority_intro="$(busctl --system introspect "$authority_dest" "$authority_path" "$authority_iface")"
executor_intro="$(busctl --system introspect "$executor_dest" "$executor_path" "$executor_iface")"
grep -F 'ConvergeSystemdActiveState' <<<"$authority_intro"
grep -F 'SetManagedActiveState' <<<"$executor_intro"
echo "live-contracts=present"

stage human-approval-denial
expect_failure unapproved-human call_authority_unapproved \
  vm-unapproved "$unit" active "unapproved qualification request"
test "$(dispatch_count start)" -eq 0
test "$(dispatch_count stop)" -eq 0

stage direct-executor-denial
expect_failure direct-executor-ordinary call_executor_direct
expect_failure direct-executor-root call_executor_direct_root
test "$(dispatch_count start)" -eq 0

stage reject-unsupported-public-requests
expect_failure wrong-namespace call_authority vm-wrong-namespace sshd.service active "wrong namespace"
expect_failure wrong-state call_authority vm-wrong-state "$unit" restarting "wrong active state"
test "$(dispatch_count start)" -eq 0
test "$(dispatch_count stop)" -eq 0

stage inactive-to-active-eleven-stage-success
sudo -n systemctl stop "$unit" || true
first="$(call_authority vm-active-once "$unit" active "qualify inactive to active")"
printf 'active-receipt=%q\n' "$first"
grep -F 'committed' <<<"$first"
grep -F 'request-intent' <<<"$first"
grep -F 'reconcile' <<<"$first"
sudo -n systemctl is-active --quiet "$unit"
test "$(dispatch_count start)" -eq 1
test "$(dispatch_count stop)" -eq 0

stage exact-retry-no-duplicate-dispatch
retry="$(call_authority vm-active-once "$unit" active "qualify inactive to active")"
printf 'retry-receipt=%q\n' "$retry"
grep -F 'committed' <<<"$retry"
grep -F 'true' <<<"$retry"
test "$(dispatch_count start)" -eq 1
test "$(dispatch_count stop)" -eq 0

stage operation-id-request-substitution
expect_failure changed-body-same-operation call_authority \
  vm-active-once "$unit" inactive "qualify inactive to active"
sudo -n systemctl is-active --quiet "$unit"
test "$(dispatch_count start)" -eq 1
test "$(dispatch_count stop)" -eq 0

stage active-to-inactive-eleven-stage-success
inactive="$(call_authority vm-inactive-once "$unit" inactive "qualify active to inactive")"
printf 'inactive-receipt=%q\n' "$inactive"
grep -F 'committed' <<<"$inactive"
grep -F 'request-intent' <<<"$inactive"
grep -F 'reconcile' <<<"$inactive"
sudo -n systemctl is-active --quiet "$unit" && { echo "fixture remained active" >&2; exit 1; } || true
test "$(dispatch_count start)" -eq 1
test "$(dispatch_count stop)" -eq 1

stage already-satisfied-no-external-effect
expect_failure already-satisfied call_authority \
  vm-already-inactive "$unit" inactive "prove no-change is non-mutating"
grep -F 'already holds' <<<"$LAST_FAILURE_OUTPUT"
test "$(dispatch_count start)" -eq 1
test "$(dispatch_count stop)" -eq 1

stage real-verification-not-satisfied-explicit-recovery
sudo -n systemctl stop "$notsatisfied_unit" || true
before_notsatisfied="$(dispatch_count notsatisfied-start)"
expect_failure verification-not-satisfied call_authority \
  vm-not-satisfied "$notsatisfied_unit" active "qualify verification not satisfied"
sleep 1
sudo -n systemctl is-active --quiet "$notsatisfied_unit" && { echo "not-satisfied fixture unexpectedly remained active" >&2; exit 1; } || true
after_notsatisfied="$(dispatch_count notsatisfied-start)"
test "$after_notsatisfied" -eq "$((before_notsatisfied + 1))"
# A failed verification must never cause an autonomous replay while the caller is idle.
sleep 1
test "$(dispatch_count notsatisfied-start)" -eq "$after_notsatisfied"
# A new explicit invocation may consume a freshly approved/revalidated recovery reprepare.
expect_failure verification-retry call_authority \
  vm-not-satisfied "$notsatisfied_unit" active "qualify verification not satisfied"
after_explicit_retry="$(dispatch_count notsatisfied-start)"
test "$after_explicit_retry" -eq "$((after_notsatisfied + 1))"
# The always-NotSatisfied fixture still must not loop or replay in the background after that call.
sleep 1
test "$(dispatch_count notsatisfied-start)" -eq "$after_explicit_retry"
sudo -n systemctl is-active --quiet "$notsatisfied_unit" && { echo "not-satisfied fixture unexpectedly remained active after explicit recovery" >&2; exit 1; } || true

stage crash-restart-after-handoff-explicit-no-effect-recovery
sudo -n systemctl stop "$unit" || true
start_before_crash="$(dispatch_count start)"
sudo -n systemctl stop linura-executor-systemd.service
expect_failure executor-unavailable call_authority \
  vm-crash-after-handoff "$unit" active "qualify restart after executor handoff"
test "$(dispatch_count start)" -eq "$start_before_crash"
sudo -n systemctl restart linura-authorityd.service
sudo -n systemctl start linura-executor-systemd.service
sudo -n systemctl is-active --quiet linura-authorityd.service
sudo -n systemctl is-active --quiet linura-executor-systemd.service
# Restart recovery must not reconstruct a permit or dispatch anything by itself.
sleep 1
test "$(dispatch_count start)" -eq "$start_before_crash"
sudo -n systemctl is-active --quiet "$unit" && { echo "restart recovery blindly replayed execution" >&2; exit 1; } || true
# A later explicit invocation may dispatch exactly once only after fresh verification proves the
# original effect did not happen and fresh recovery approval/reprepare binds new authority.
crash_recovery="$(call_authority \
  vm-crash-after-handoff "$unit" active "qualify restart after executor handoff")"
printf 'crash-recovery-receipt=%q\n' "$crash_recovery"
grep -F 'committed' <<<"$crash_recovery"
grep -F 'true' <<<"$crash_recovery"
test "$(dispatch_count start)" -eq "$((start_before_crash + 1))"
sudo -n systemctl is-active --quiet "$unit"
# Successful explicit recovery is still single-use; it must not create an autonomous loop.
sleep 1
test "$(dispatch_count start)" -eq "$((start_before_crash + 1))"

stage sqlite-wal-and-integrity-evidence
sudo -n test -f /var/lib/linura-authority/authority.sqlite3
journal_mode="$(sudo -n sqlite3 /var/lib/linura-authority/authority.sqlite3 'PRAGMA journal_mode;')"
test "$journal_mode" = "wal"
integrity="$(sudo -n sqlite3 /var/lib/linura-authority/authority.sqlite3 'PRAGMA integrity_check;')"
test "$integrity" = "ok"
printf 'sqlite-journal-mode=%s\n' "$journal_mode"
printf 'sqlite-integrity=%s\n' "$integrity"
sudo -n sqlite3 /var/lib/linura-authority/authority.sqlite3 '.tables'

stage deterministic-fault-matrix-inside-disposable-guest
/usr/libexec/linura/v06-qualification-matrix --test-threads=1 --nocapture 2>&1 | tee /tmp/v06-matrix.log
grep -F 'test result: ok. 11 passed' /tmp/v06-matrix.log

echo "real-authority1-success=qualified"
echo "real-polkit-denial=qualified"
echo "real-direct-executor-denial=qualified"
echo "real-idempotency=qualified"
echo "real-verification-not-satisfied-explicit-recovery=qualified"
echo "real-crash-restart-explicit-no-effect-recovery=qualified"
echo "deterministic-fault-matrix=11/11"
