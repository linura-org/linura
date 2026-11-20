#!/usr/bin/bash
set -euo pipefail

source_root="${1:-/opt/linura-source}"
evidence_root="${2:-/tmp/linura-workstation-live}"
record="${LINURA_RECORD_VISUAL:-0}"
source_sha="${LINURA_SOURCE_SHA:-}"
native_s21="${LINURA_NATIVE_S21:-0}"
[[ "$native_s21" == "0" || "$native_s21" == "1" ]] || exit 2
if [[ "$native_s21" == "1" && "$source_root" != "/opt/linura-source" ]]; then
    echo "native S21 requires the fixed root-owned guest source tree" >&2
    exit 2
fi
native_pid=""
native_invocation=""
native_exec_identity=""
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "exact lowercase 40-hex LINURA_SOURCE_SHA is required" >&2
    exit 2
}
recording_path="$evidence_root/workstation-live.mkv"
recorder="$source_root/qualification/v010/workstation-acceptance/record-session.sh"
recording_started=0
recording_duration_budget=0
recording_start_seconds=0

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local original_status=$?
    local cleanup_status=0
    trap - EXIT
    set +e
    if [[ "$recording_started" -eq 1 ]]; then
        LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha" "$recorder" stop "$recording_path" || cleanup_status=$?
        recording_started=0
    fi
    systemctl --user stop linura-shell-live.service >/dev/null 2>&1 || true
    systemctl --user stop linura-hyprland-live.service >/dev/null 2>&1 || true
    if [[ "$native_s21" == "1" ]]; then
        sudo -n systemctl stop linura-s17-session.service >/dev/null 2>&1 || cleanup_status=1
    fi
    systemctl --user stop linurad.service >/dev/null 2>&1 || true
    systemctl --user stop wireplumber.service >/dev/null 2>&1 || true
    systemctl --user stop pipewire.service >/dev/null 2>&1 || true
    if [[ "$original_status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
        exit "$cleanup_status"
    fi
    exit "$original_status"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

for command_name in Hyprland qs hyprctl systemd-run systemctl; do
    command -v "$command_name" >/dev/null || fail "required command is missing: $command_name"
done
[[ -d "$source_root/apps/linura-shell" ]] || fail "exact-source shell tree is missing"
[[ -x /usr/bin/linurad && ! -L /usr/bin/linurad ]] || fail "exact-source linurad is missing"

mkdir -p "$evidence_root"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export LIBSEAT_BACKEND=seatd
[[ "$native_s21" == "0" ]] || export LIBSEAT_BACKEND=logind
export AQ_NO_KMS_REQUIREMENT=1
export LIBGL_ALWAYS_SOFTWARE=1
export WLR_RENDERER_ALLOW_SOFTWARE=1
export XDG_CURRENT_DESKTOP=Hyprland
export XDG_SESSION_DESKTOP=Hyprland
export XDG_SESSION_TYPE=wayland
export QT_QPA_PLATFORM=wayland
export QML2_IMPORT_PATH=/usr/local/lib/qt6/qml
export QT_QUICK_BACKEND=software

drm_cards=()
for node in /sys/class/drm/card*; do
    [[ -e "$node" ]] || continue
    name="$(basename "$node")"
    [[ "$name" =~ ^card[0-9]+$ ]] && drm_cards+=("$name")
done
[[ "${#drm_cards[@]}" -eq 1 ]] || fail "interactive VM expects exactly one qualification DRM card"
export AQ_DRM_DEVICES="/dev/dri/${drm_cards[0]}"

cat >/tmp/linura-hyprland-live.conf <<'EOF'
debug:disable_logs = false
misc:disable_hyprland_logo = true
misc:disable_splash_rendering = true
EOF

systemctl --user import-environment XDG_RUNTIME_DIR LIBSEAT_BACKEND AQ_DRM_DEVICES AQ_NO_KMS_REQUIREMENT LIBGL_ALWAYS_SOFTWARE WLR_RENDERER_ALLOW_SOFTWARE XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP XDG_SESSION_TYPE QT_QPA_PLATFORM QML2_IMPORT_PATH QT_QUICK_BACKEND

if [[ "$native_s21" == "1" ]]; then
    # This is the same genuine logind/S17 bootstrap as Level A. Its report
    # explicitly claims bootstrap only, never S21 mutation or B acceptance.
    sudo -n python3 /opt/linura-source/qualification/v010/session-security/check-native-session.py \
        > "$evidence_root/native-session-bootstrap.json"
    native_pid="$(sudo -n systemctl show --property=MainPID --value linura-s17-session.service)"
    native_invocation="$(sudo -n systemctl show --property=InvocationID --value linura-s17-session.service)"
    [[ "$native_pid" =~ ^[1-9][0-9]{0,9}$ && "$native_invocation" =~ ^[0-9a-f]{32}$ ]] \
        || fail "native compositor service identity unavailable"
    # The native compositor deliberately denies same-UID /proc inspection.
    # Only the disposable fixture's root read observes its executing inode;
    # never relax its nondumpability or native peer-admission guards.
    native_exec_identity="$(sudo -n /usr/bin/stat -Lc '%d:%i' "/proc/$native_pid/exe")"
    [[ "$native_exec_identity" == "$(stat -Lc '%d:%i' /usr/bin/Hyprland)" ]] \
        || fail "native compositor executable identity changed"
else
    systemd-run --user --unit=linura-hyprland-live.service --collect --quiet --service-type=exec /usr/bin/Hyprland --config /tmp/linura-hyprland-live.conf
fi

compositor_current() {
    if [[ "$native_s21" == "0" ]]; then
        systemctl --user is-active --quiet linura-hyprland-live.service
        return
    fi
    sudo -n systemctl is-active --quiet linura-s17-session.service &&
        [[ "$(sudo -n systemctl show --property=MainPID --value linura-s17-session.service)" == "$native_pid" &&
        "$(sudo -n systemctl show --property=InvocationID --value linura-s17-session.service)" == "$native_invocation" &&
        "$(sudo -n /usr/bin/stat -Lc '%d:%i' "/proc/$native_pid/exe")" == "$native_exec_identity" ]]
}

wayland_socket=""
for _ in $(seq 1 150); do
    candidate="$(find "$XDG_RUNTIME_DIR" -maxdepth 1 -type s -name 'wayland-*' -print -quit 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
        wayland_socket="$candidate"
        break
    fi
    compositor_current || fail "Hyprland exited before Wayland became ready"
    sleep 0.2
done
[[ -n "$wayland_socket" ]] || fail "interactive Hyprland Wayland readiness deadline exceeded"
export WAYLAND_DISPLAY="$(basename "$wayland_socket")"

hyprland_signature=""
for _ in $(seq 1 100); do
    for socket in "$XDG_RUNTIME_DIR"/hypr/*/.socket.sock; do
        if [[ -S "$socket" ]]; then
            hyprland_signature="$(basename "$(dirname "$socket")")"
            break 2
        fi
    done
    sleep 0.1
done
[[ -n "$hyprland_signature" ]] || fail "interactive Hyprland IPC signature was not published"
export HYPRLAND_INSTANCE_SIGNATURE="$hyprland_signature"
if [[ "$native_s21" == "1" ]]; then
    compositor_current || fail "native compositor changed before socket binding"
    python3 - "$native_pid" "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" \
        "$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket.sock" <<'PY'
import os
import socket
import struct
import sys

expected = (int(sys.argv[1]), os.getuid())
for path in sys.argv[2:]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(2)
        peer.connect(path)
        pid, uid, _gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if (pid, uid) != expected:
            raise SystemExit("native compositor socket belongs to another process/user")
PY
    compositor_current || fail "native compositor changed after socket binding"
fi
systemctl --user import-environment WAYLAND_DISPLAY HYPRLAND_INSTANCE_SIGNATURE

systemctl --user start pipewire.service
systemctl --user start wireplumber.service
systemctl --user start linurad.service

systemd-run --user --unit=linura-shell-live.service --collect --quiet --service-type=exec --setenv="QS_DISABLE_FILE_WATCHER=1" --setenv="QML2_IMPORT_PATH=/usr/local/lib/qt6/qml" --setenv="QT_QUICK_BACKEND=software" --setenv="WAYLAND_DISPLAY=$WAYLAND_DISPLAY" /usr/bin/qs -p "$source_root/apps/linura-shell"

for _ in $(seq 1 100); do
    systemctl --user is-active --quiet linura-shell-live.service && break
    sleep 0.1
done
systemctl --user is-active --quiet linura-shell-live.service || {
    journalctl --user -u linura-shell-live.service --no-pager >&2 || true
    fail "Linura Shell did not remain active"
}

{
    printf 'source_root=%s\n' "$source_root"
    printf 'source_sha=%s\n' "$source_sha"
    printf 'wayland_display=%s\n' "$WAYLAND_DISPLAY"
    printf 'hyprland_instance_signature=%s\n' "$HYPRLAND_INSTANCE_SIGNATURE"
    printf 'drm_device=%s\n' "$AQ_DRM_DEVICES"
    hyprctl monitors -j
} >"$evidence_root/live-session.txt"

if [[ "$record" == "1" ]]; then
    # Reserve margin for stop delivery, muxer finalization and verification.
    recording_duration_budget="$(
        python3 - "$source_root/contracts/v010-workstation-acceptance.toml" <<'PY'
import sys
import tomllib
with open(sys.argv[1], "rb") as handle:
    maximum = float(tomllib.load(handle)["recording"]["maximum_duration_seconds"])
if not 30 < maximum <= 86400:
    raise SystemExit("invalid bounded Level B recording duration")
print(int(maximum) - 30)
PY
    )"
    [[ "$recording_duration_budget" =~ ^[1-9][0-9]*$ ]] ||
        fail "Level B recording duration budget is invalid"
    LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha" "$recorder" start "$recording_path"
    recording_started=1
    recording_start_seconds="$SECONDS"
fi

printf '%s\n' "Linura interactive workstation session is live."
printf '%s\n' "Use the QEMU GTK window or configured VNC display. Press Ctrl-C here to stop."
while true; do
    compositor_current ||
        fail "interactive Hyprland session exited unexpectedly"
    systemctl --user is-active --quiet linura-shell-live.service ||
        fail "Linura Shell exited during interactive acceptance"
    systemctl --user is-active --quiet linurad.service ||
        fail "linurad exited during interactive acceptance"
    if [[ "$recording_started" -eq 1 ]]; then
        systemctl --user is-active --quiet linura-workstation-recorder.service ||
            fail "interactive recorder exited before requested stop"
    fi
    if [[ "$recording_started" -eq 1 ]] &&
        ((SECONDS - recording_start_seconds >= recording_duration_budget)); then
        printf '%s\n' "Level B recording budget reached; finalizing interactive evidence."
        break
    fi
    sleep 1
done
