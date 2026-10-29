#!/usr/bin/env bash
set -Eeuo pipefail

stage() {
    printf 'native-stage=%s\n' "$1"
}

on_error() {
    local rc=$?
    printf 'native-guest-error rc=%s line=%s command=%q\n' "$rc" "$LINENO" "$BASH_COMMAND" >&2
    exit "$rc"
}
trap on_error ERR
LAST_FAILURE_OUTPUT=""

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

service="linura-executor-session.service"
destination="org.linura.Executor.Session1"
path="/org/linura/Executor/Session1"
interface="org.linura.Executor.Session1"
image="/usr/lib/linura/linura-executor-session"
unit="/usr/lib/systemd/system/linura-executor-session.service"
sleep_dropin="/usr/lib/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf"
sleep_conf="/usr/lib/systemd/sleep.conf.d/50-linura-qualified-sleep.conf"

stage install-exact-native-executor-and-privileged-boundary
sudo -n install -o root -g root -m 0755 /tmp/linura-executor-session "$image"
sudo -n install -o root -g root -m 0644 /tmp/linura-executor-session.service "$unit"
sudo -n install -o root -g root -m 0644 /tmp/org.linura.Executor.Session1.conf /etc/dbus-1/system.d/org.linura.Executor.Session1.conf
sudo -n install -o root -g root -m 0644 /tmp/org.linura.executor.session.policy /usr/share/polkit-1/actions/org.linura.executor.session.policy
sudo -n install -o root -g root -m 0644 /tmp/50-linura-executor-session.rules /etc/polkit-1/rules.d/50-linura-executor-session.rules
sudo -n install -d -o root -g root -m 0755 /usr/lib/systemd/system/systemd-suspend.service.d /usr/lib/systemd/sleep.conf.d
sudo -n install -o root -g root -m 0644 /tmp/50-linura-protective-lock.conf "$sleep_dropin"
sudo -n install -o root -g root -m 0644 /tmp/50-linura-qualified-sleep.conf "$sleep_conf"
sudo -n systemctl daemon-reload
sudo -n systemctl restart polkit.service
sudo -n dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig

stage active-native-session-executor
sudo -n systemctl start "$service"
sudo -n systemctl is-active --quiet "$service"
intro="$(busctl --system introspect "$destination" "$path" "$interface")"
grep -F 'SetSecure' <<<"$intro"
grep -F 'ExecuteTransition' <<<"$intro"
test "$(sudo -n systemctl show "$service" --value -p FragmentPath)" = "$unit"
test "$(sudo -n systemctl show "$service" --value -p User)" = "root"
test "$(sudo -n systemctl show "$service" --value -p NoNewPrivileges)" = "yes"
test "$(sudo -n systemctl show "$service" --value -p ProtectSystem)" = "strict"
test "$(sudo -n systemctl show "$service" --value -p AmbientCapabilities)" = ""
test "$(sudo -n systemctl show "$service" --value -p CapabilityBoundingSet)" = ""
pkaction --action-id org.linura.executor.session.set-secure >/dev/null
pkaction --action-id org.linura.executor.session.execute-transition >/dev/null
pkaction --action-id org.linura.executor.session.apply-display-layout >/dev/null
echo "native-session-live-executor=qualified"

stage direct-native-executor-denial
digest=0000000000000000000000000000000000000000000000000000000000000000
resource=session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7
call_native() {
    busctl --system call "$destination" "$path" "$interface" SetSecure sbsttssss \
        "$resource" true "transaction:v06:session-direct" 0 1 \
        "$digest" "$digest" "$digest" "$digest"
}
call_native_root() {
    sudo -n busctl --system call "$destination" "$path" "$interface" SetSecure sbsttssss \
        "$resource" true "transaction:v06:session-root-direct" 0 1 \
        "$digest" "$digest" "$digest" "$digest"
}
expect_failure native-session-ordinary-denied call_native
grep -Eiq 'access.*denied|permission.*denied' <<<"$LAST_FAILURE_OUTPUT"
expect_failure native-session-root-denied call_native_root
grep -Eiq 'access.*denied|permission.*denied' <<<"$LAST_FAILURE_OUTPUT"
expect_failure native-session-polkit-ordinary-denied \
    pkcheck --action-id org.linura.executor.session.set-secure --process "$$"
topology=display:topology:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:seat0:11111111-1111-4111-8111-111111111111:3
baseline="LNDL:1;$topology;1:2:enabled:1920:1080:60000:1000:0:0:0:-;"
desired="LNDL:1;$topology;1:2:enabled:1920:1080:60000:1000:0:100:0:-;"
material="LNDI:1;$resource;$baseline$desired"
call_display() {
    busctl --system call "$destination" "$path" "$interface" ApplyDisplayLayout ststtsssss \
        "$material" 15000 "transaction:v06:display-direct" 0 1 \
        "$digest" "$digest" "$digest" "$digest" "$digest"
}
call_display_root() {
    sudo -n busctl --system call "$destination" "$path" "$interface" ApplyDisplayLayout ststtsssss \
        "$material" 15000 "transaction:v06:display-root-direct" 0 1 \
        "$digest" "$digest" "$digest" "$digest" "$digest"
}
# These prove live bus-policy denial, before body/binding/native processing.
# The Rust executor fixture separately supplies a valid binding to service denial.
expect_failure native-session-display-ordinary-denied call_display
grep -Eiq 'access.*denied|permission.*denied' <<<"$LAST_FAILURE_OUTPUT"
expect_failure native-session-display-root-denied call_display_root
grep -Eiq 'access.*denied|permission.*denied' <<<"$LAST_FAILURE_OUTPUT"
expect_failure native-session-display-polkit-ordinary-denied \
    pkcheck --action-id org.linura.executor.session.apply-display-layout --process "$$"
sudo -n systemctl is-active --quiet "$service"
echo "native-session-direct-denial=qualified"

stage effective-pre-kernel-suspend-policy
test "$(sudo -n systemctl show systemd-suspend.service --value -p DropInPaths)" = "$sleep_dropin"
start_pre="$(sudo -n systemctl show systemd-suspend.service --value -p ExecStartPre)"
grep -F "$image --protect-before-sleep" <<<"$start_pre"
grep -F 'AllowHibernation=no' "$sleep_conf"
grep -F 'AllowHybridSleep=no' "$sleep_conf"
grep -F 'AllowSuspendThenHibernate=no' "$sleep_conf"
# This is intentionally a negative invocation, not a suspend/reboot/power action.
expect_failure non-supervised-sleep-helper sudo -n "$image" --protect-before-sleep
grep -F 'linura-executor-session failed closed:' <<<"$LAST_FAILURE_OUTPUT"
sudo -n systemctl is-active --quiet "$service"
echo "native-session-pre-kernel-gate=qualified"

echo "native-session-live-boundary=qualified"
