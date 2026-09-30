#!/usr/bin/bash
set -euo pipefail

source_root="${1:-/opt/linura-source}"
evidence_root="${2:-/tmp/linura-workstation-live}"
record="${LINURA_RECORD_VISUAL:-0}"
source_sha="${LINURA_SOURCE_SHA:-}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "exact lowercase 40-hex LINURA_SOURCE_SHA is required" >&2
    exit 2
}
recording_path="$evidence_root/workstation-live.mkv"
recorder="$source_root/qualification/v010/workstation-acceptance/record-session.sh"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    set +e
    if [[ "$record" == "1" ]]; then
        LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha"             "$recorder" stop "$recording_path" >/dev/null 2>&1 || true
    fi
    systemctl --user stop linura-shell-live.service >/dev/null 2>&1 || true
    systemctl --user stop linura-hyprland-live.service >/dev/null 2>&1 || true
    systemctl --user stop linurad.service >/dev/null 2>&1 || true
    systemctl --user stop wireplumber.service >/dev/null 2>&1 || true
    systemctl --user stop pipewire.service >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for command_name in Hyprland qs hyprctl systemd-run systemctl; do
    command -v "$command_name" >/dev/null || fail "required command is missing: $command_name"
done
[[ -d "$source_root/apps/linura-shell" ]] || fail "exact-source shell tree is missing"
[[ -x /usr/bin/linurad && ! -L /usr/bin/linurad ]] || fail "exact-source linurad is missing"

mkdir -p "$evidence_root"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export LIBSEAT_BACKEND=seatd
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

cat > /tmp/linura-hyprland-live.conf <<'EOF'
debug:disable_logs = false
misc:disable_hyprland_logo = true
misc:disable_splash_rendering = true
EOF

systemctl --user import-environment     XDG_RUNTIME_DIR LIBSEAT_BACKEND AQ_DRM_DEVICES AQ_NO_KMS_REQUIREMENT     LIBGL_ALWAYS_SOFTWARE WLR_RENDERER_ALLOW_SOFTWARE XDG_CURRENT_DESKTOP     XDG_SESSION_DESKTOP XDG_SESSION_TYPE QT_QPA_PLATFORM QML2_IMPORT_PATH QT_QUICK_BACKEND

systemd-run --user --unit=linura-hyprland-live.service --collect --quiet --service-type=exec     /usr/bin/Hyprland --config /tmp/linura-hyprland-live.conf

wayland_socket=""
for _ in $(seq 1 150); do
    candidate="$(find "$XDG_RUNTIME_DIR" -maxdepth 1 -type s -name 'wayland-*' -print -quit 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
        wayland_socket="$candidate"
        break
    fi
    systemctl --user is-active --quiet linura-hyprland-live.service || fail "Hyprland exited before Wayland became ready"
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
systemctl --user import-environment WAYLAND_DISPLAY HYPRLAND_INSTANCE_SIGNATURE

systemctl --user start pipewire.service
systemctl --user start wireplumber.service
systemctl --user start linurad.service

systemd-run --user     --unit=linura-shell-live.service     --collect     --quiet     --service-type=exec     --setenv="QS_DISABLE_FILE_WATCHER=1"     --setenv="QML2_IMPORT_PATH=/usr/local/lib/qt6/qml"     --setenv="QT_QUICK_BACKEND=software"     --setenv="WAYLAND_DISPLAY=$WAYLAND_DISPLAY"     /usr/bin/qs -p "$source_root/apps/linura-shell"

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
} > "$evidence_root/live-session.txt"

if [[ "$record" == "1" ]]; then
    LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha"         "$recorder" start "$recording_path"
fi

printf '%s\n' "Linura interactive workstation session is live."
printf '%s\n' "Use the QEMU GTK window or configured VNC display. Press Ctrl-C here to stop."
while systemctl --user is-active --quiet linura-hyprland-live.service; do
    sleep 1
done
