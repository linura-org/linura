#!/usr/bin/env bash
set -Eeuo pipefail

unit="linura-v05-qualification-restart.service"
iface="org.linura.Executor.Systemd1"
dest="org.linura.Executor.Systemd1"
path="/org/linura/Executor/Systemd1"

stage() {
  printf 'stage=%s\n' "$1"
}

on_error() {
  local rc=$?
  printf 'guest-error rc=%s line=%s command=%q\n' "$rc" "$LINENO" "$BASH_COMMAND" >&2
  exit "$rc"
}
trap on_error ERR

stage install-assets
sudo -n install -d -o root -g root -m 0755 /usr/lib/linura /usr/libexec/linura
sudo -n install -o root -g root -m 0755 /tmp/linurad /usr/local/bin/linurad
sudo -n install -o root -g root -m 0755 /tmp/linuractl /usr/local/bin/linuractl
sudo -n install -o root -g root -m 0755 /tmp/linura-executor-systemd /usr/lib/linura/linura-executor-systemd
sudo -n install -o root -g root -m 0755 /tmp/v05_binding /usr/libexec/linura/v05-binding
sudo -n install -o root -g root -m 0755 /tmp/v05_verify /usr/libexec/linura/v05-verify
sudo -n install -o root -g root -m 0644 /tmp/org.linura.Executor.Systemd1.conf /etc/dbus-1/system.d/org.linura.Executor.Systemd1.conf
sudo -n install -o root -g root -m 0644 /tmp/49-linura-v05-qualification-dbus.conf /etc/dbus-1/system.d/49-linura-v05-qualification-dbus.conf
sudo -n install -o root -g root -m 0644 /tmp/org.linura.executor.systemd.policy /usr/share/polkit-1/actions/org.linura.executor.systemd.policy
sudo -n install -o root -g root -m 0644 /tmp/linura-executor-systemd.service /etc/systemd/system/linura-executor-systemd.service
sudo -n install -o root -g root -m 0644 /tmp/linura-v05-qualification-restart.service /etc/systemd/system/linura-v05-qualification-restart.service
sudo -n install -o root -g root -m 0644 /tmp/49-linura-v05-qualification.rules /etc/polkit-1/rules.d/49-linura-v05-qualification.rules
if ! id -u linura-v05-qualifier >/dev/null 2>&1; then
  sudo -n useradd --system --no-create-home --shell /usr/sbin/nologin linura-v05-qualifier
fi

stage activate-system-integration
sudo -n systemctl daemon-reload
sudo -n systemctl restart polkit.service
sudo -n dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
sudo -n systemctl start "$unit"
sudo -n systemctl start linura-executor-systemd.service
sudo -n systemctl is-active --quiet "$unit"
sudo -n systemctl is-active --quiet linura-executor-systemd.service
test -x /usr/bin/pkcheck

field() {
  local key="$1"
  local payload="$2"
  sed -n "s/^${key}=//p" <<<"$payload" | head -n 1
}

load_binding() {
  local target="$1"
  # Exact-source helper emits a fixed set of shell assignment names and validated digest values.
  # shellcheck disable=SC1090
  source <(/usr/libexec/linura/v05-binding "$target")
}

call_as_current() {
  busctl --system call "$dest" "$path" "$iface" QualifyRestart ssttssss \
    "$1" "$transaction_id" "$generation" "$state_version" \
    "$authority_binding_digest" "$authority_use_digest" "$effect_digest" "$dispatch_digest"
}

call_as_qualifier() {
  sudo -n -u linura-v05-qualifier -- \
    busctl --system call "$dest" "$path" "$iface" QualifyRestart ssttssss \
    "$1" "$transaction_id" "$generation" "$state_version" \
    "$authority_binding_digest" "$authority_use_digest" "$effect_digest" "$dispatch_digest"
}

stage unauthorized-caller
load_binding "$unit"
if unauthorized="$(call_as_current "$unit" 2>&1)"; then
  echo "unauthorized caller unexpectedly reached the qualification method" >&2
  exit 1
else
  unauthorized_rc=$?
fi
test "$unauthorized_rc" -ne 0
sudo -n systemctl is-active --quiet linura-executor-systemd.service
printf 'unauthorized-output=%q\n' "$unauthorized"
echo "unauthorized-caller=denied"

stage reject-wrong-namespace
wrong_namespace="$(call_as_qualifier sshd.service)"
grep -F 'rejected-before-dispatch' <<<"$wrong_namespace"
echo "wrong-namespace=rejected-before-dispatch"

stage reject-malformed-binding
malformed="$(sudo -n -u linura-v05-qualifier -- \
  busctl --system call "$dest" "$path" "$iface" QualifyRestart ssttssss \
  "$unit" "$transaction_id" "$generation" "$state_version" \
  bad "$authority_use_digest" "$effect_digest" "$dispatch_digest")"
grep -F 'rejected-before-dispatch' <<<"$malformed"
echo "malformed-binding=rejected-before-dispatch"

stage reject-effect-substitution
load_binding linura-v05-qualification-other.service
substituted="$(call_as_qualifier "$unit")"
grep -F 'rejected-before-dispatch' <<<"$substituted"
echo "effect-substitution=rejected-before-dispatch"

stage indeterminate-missing-fixture
load_binding linura-v05-qualification-missing.service
missing="$(call_as_qualifier linura-v05-qualification-missing.service)"
grep -F 'indeterminate' <<<"$missing"
echo "missing-fixture=indeterminate"

stage start-observation-daemon
linurad >/tmp/linurad-v05.log 2>&1 &
daemon=$!
cleanup_daemon() {
  kill "$daemon" 2>/dev/null || true
  wait "$daemon" 2>/dev/null || true
}
trap cleanup_daemon EXIT
ready=0
for _ in $(seq 1 50); do
  if linuractl capabilities >/tmp/v05-capabilities 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  cat /tmp/linurad-v05.log >&2
  exit 1
fi

stage authoritative-pre-observation
pre="$(linuractl observe "systemd:unit:$unit")"
grep -F 'provider=systemd' <<<"$pre"
grep -F "resource=systemd:unit:$unit" <<<"$pre"
grep -F 'capability=systemd.unit.observe' <<<"$pre"
grep -F 'authority=native-api' <<<"$pre"
grep -F 'freshness=current' <<<"$pre"
grep -F 'attribute.load_state=loaded' <<<"$pre"
grep -F 'attribute.active_state=active' <<<"$pre"
pre_ts="$(field attribute.active_enter_timestamp_monotonic "$pre")"
test -n "$pre_ts"
test "$pre_ts" -gt 0

stage dispatch-qualified-restart
load_binding "$unit"
dispatched="$(call_as_qualifier "$unit")"
grep -F 'dispatched' <<<"$dispatched"
grep -F "$dispatch_digest" <<<"$dispatched"
echo "dispatch=acknowledged"

stage authoritative-post-observation
advanced=0
post=""
post_ts=""
for _ in $(seq 1 80); do
  post="$(linuractl observe "systemd:unit:$unit")"
  post_ts="$(field attribute.active_enter_timestamp_monotonic "$post")"
  if [[ -n "$post_ts" ]] && (( post_ts > pre_ts )); then
    advanced=1
    break
  fi
  sleep 0.1
done
test "$advanced" -eq 1
grep -F 'authority=native-api' <<<"$post"
grep -F 'freshness=current' <<<"$post"
grep -F 'attribute.load_state=loaded' <<<"$post"
grep -F 'attribute.active_state=active' <<<"$post"

provider="$(field provider "$post")"
resource="$(field resource "$post")"
capability="$(field capability "$post")"
authority="$(field authority "$post")"
observed_at="$(field observed_at_unix_ms "$post")"
valid_for="$(field valid_for_ms "$post")"
sequence="$(field sequence "$post")"
observed_id="$(field attribute.id "$post")"
load_state="$(field attribute.load_state "$post")"
active_state="$(field attribute.active_state "$post")"
now_ms="$(date +%s%3N)"

stage independent-verification
/usr/libexec/linura/v05-verify satisfied \
  "$unit" "$pre_ts" "$provider" "$resource" "$capability" "$authority" \
  "$observed_at" "$valid_for" "$sequence" "$observed_id" "$load_state" \
  "$active_state" "$post_ts" "$now_ms"
/usr/libexec/linura/v05-verify not-satisfied \
  "$unit" "$post_ts" "$provider" "$resource" "$capability" "$authority" \
  "$observed_at" "$valid_for" "$sequence" "$observed_id" "$load_state" \
  "$active_state" "$post_ts" "$now_ms"
stale_now="$((observed_at + valid_for + 1))"
/usr/libexec/linura/v05-verify inconclusive \
  "$unit" "$pre_ts" "$provider" "$resource" "$capability" "$authority" \
  "$observed_at" "$valid_for" "$sequence" "$observed_id" "$load_state" \
  "$active_state" "$post_ts" "$stale_now"

echo "pre-active-enter-timestamp-monotonic=$pre_ts"
echo "post-active-enter-timestamp-monotonic=$post_ts"
echo "independent-verification=satisfied"
