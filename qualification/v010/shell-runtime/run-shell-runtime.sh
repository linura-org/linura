#!/usr/bin/bash
set -euo pipefail

source_root="${1:-/opt/linura-source}"
evidence_root="${2:-/tmp/linura-shell-runtime/evidence}"
shell_root="$source_root/apps/linura-shell"
controller_config="$shell_root/qualification-controller.qml"
palette_config="$shell_root/qualification-palette.qml"
applications_dir="$HOME/.local/share/applications"

mkdir -p "$evidence_root" /tmp/linura-shell-runtime
: > "$evidence_root/cases.tsv"

pass_case() {
    printf '%s\tpassed\n' "$1" | tee -a "$evidence_root/cases.tsv"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

wait_until() {
    local description="$1"
    shift
    for _ in $(seq 1 100); do
        if "$@"; then
            return 0
        fi
        sleep 0.1
    done
    fail "timeout waiting for $description"
}

cleanup() {
    set +e
    systemctl --user stop linura-palette-qualification.service >/dev/null 2>&1
    systemctl --user stop linura-shell-qualification.service >/dev/null 2>&1
    while read -r unit; do
        [[ -n "$unit" ]] && systemctl --user stop "$unit" >/dev/null 2>&1
    done < <(systemctl --user list-units --all --plain --no-legend 'linura-app-launch-*.service' 2>/dev/null | awk '{print $1}')
    systemctl --user stop linura-hyprland-qualification.service >/dev/null 2>&1
}
trap cleanup EXIT

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
test -d "$XDG_RUNTIME_DIR" || fail "XDG_RUNTIME_DIR is unavailable"
command -v Hyprland >/dev/null || fail "Hyprland is missing"
command -v seatd >/dev/null || fail "seatd is missing"
command -v quickshell >/dev/null || fail "Quickshell is missing"
command -v qs >/dev/null || fail "Quickshell qs CLI is missing"
command -v systemd-run >/dev/null || fail "systemd-run is missing"
command -v systemctl >/dev/null || fail "systemctl is missing"

ui_module_dir=/usr/local/lib/qt6/qml/org/linura/UI
ui_plugin="$ui_module_dir/liblinura-uiplugin.so"
ui_backing="$ui_module_dir/liblinura-ui.so"
[[ -f "$ui_plugin" ]] || fail "Linura UI QML plugin is missing: $ui_plugin"
[[ -f "$ui_backing" ]] || fail "Linura UI QML backing library is missing: $ui_backing"
ui_linkage_file="$evidence_root/ui-module-linkage.txt"
ldd "$ui_plugin" > "$ui_linkage_file"
if grep -Fq 'not found' "$ui_linkage_file"; then
    cat "$ui_linkage_file" >&2
    fail "Linura UI QML plugin has unresolved installed dependencies"
fi
grep -Fq "liblinura-ui.so => $ui_backing" "$ui_linkage_file" || {
    cat "$ui_linkage_file" >&2
    fail "Linura UI QML plugin did not resolve its backing library from the module directory"
}

systemctl is-active --quiet seatd.service || fail "seatd.service is not active"
seat_socket=/run/seatd.sock
[[ -S "$seat_socket" ]] || fail "seatd socket is unavailable"
seat_group="$(stat -c '%G' "$seat_socket")"
[[ -n "$seat_group" ]] || fail "seatd socket has no owning group"
id -nG | tr ' ' '\n' | grep -Fxq "$seat_group" || fail "qualification user is not a member of seatd socket group $seat_group"

qualification_gpu_pci_bdf="0000:00:02.0"
qualification_gpu_vendor_id="0x1af4"
qualification_gpu_device_id="0x1050"

drm_cards=()
for node in /sys/class/drm/card*; do
    [[ -e "$node" ]] || continue
    card_name="$(basename "$node")"
    [[ "$card_name" =~ ^card[0-9]+$ ]] || continue
    drm_cards+=("$card_name")
done
[[ "${#drm_cards[@]}" -eq 1 ]] || fail "expected exactly one DRM card in the bounded qualification VM, found ${#drm_cards[@]}"

qualification_card="${drm_cards[0]}"
qualification_device="$(readlink -f "/sys/class/drm/$qualification_card/device")"
[[ -d "$qualification_device" ]] || fail "qualification DRM device sysfs path is unavailable: $qualification_card"
qualification_bdf="$(basename "$qualification_device")"
qualification_vendor="$(tr '[:upper:]' '[:lower:]' < "$qualification_device/vendor")"
qualification_device_id="$(tr '[:upper:]' '[:lower:]' < "$qualification_device/device")"
[[ "$qualification_bdf" == "$qualification_gpu_pci_bdf" ]] || fail "qualification DRM PCI BDF mismatch: expected $qualification_gpu_pci_bdf, got $qualification_bdf"
[[ "$qualification_vendor" == "$qualification_gpu_vendor_id" ]] || fail "qualification DRM PCI vendor mismatch: expected $qualification_gpu_vendor_id, got $qualification_vendor"
[[ "$qualification_device_id" == "$qualification_gpu_device_id" ]] || fail "qualification DRM PCI device mismatch: expected $qualification_gpu_device_id, got $qualification_device_id"

virtio_drm="/dev/dri/$qualification_card"
[[ -c "$virtio_drm" ]] || fail "selected qualification DRM node is unavailable: $virtio_drm"
[[ -r "$virtio_drm" && -w "$virtio_drm" ]] || fail "qualification user cannot access $virtio_drm"

{
    printf '%s\n' '-- seatd --'
    systemctl is-active seatd.service
    systemctl show seatd.service -p ActiveState -p SubState -p ExecMainStatus -p Environment
    printf 'socket=%s\n' "$seat_socket"
    printf 'socket_group=%s\n' "$seat_group"
    printf '%s\n' '-- identity --'
    id
    printf '%s\n' '-- drm --'
    printf 'selected=%s\n' "$virtio_drm"
    printf 'pci_bdf=%s\n' "$qualification_bdf"
    printf 'pci_vendor_id=%s\n' "$qualification_vendor"
    printf 'pci_device_id=%s\n' "$qualification_device_id"
    printf 'pci_transport_driver=%s\n' "$(basename "$(readlink -f "$qualification_device/driver" 2>/dev/null || true)")"
    ls -l /dev/dri
    udevadm info -q property -n "$virtio_drm"
} > "$evidence_root/seat-drm-preflight.txt"
pass_case "seat-drm-readiness"

cat > /tmp/linura-hyprland-qualification.conf <<'EOF'
debug:disable_logs = false
EOF
export LIBSEAT_BACKEND=seatd
export AQ_DRM_DEVICES="$virtio_drm"
export AQ_NO_KMS_REQUIREMENT=1
export LIBGL_ALWAYS_SOFTWARE=1
export WLR_RENDERER_ALLOW_SOFTWARE=1
export XDG_CURRENT_DESKTOP=Hyprland
export XDG_SESSION_DESKTOP=Hyprland
export XDG_SESSION_TYPE=wayland
export QT_QPA_PLATFORM=wayland
export QML2_IMPORT_PATH=/usr/local/lib/qt6/qml
export QT_QUICK_BACKEND=software

systemctl --user import-environment     XDG_RUNTIME_DIR LIBSEAT_BACKEND AQ_DRM_DEVICES AQ_NO_KMS_REQUIREMENT LIBGL_ALWAYS_SOFTWARE     WLR_RENDERER_ALLOW_SOFTWARE XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP     XDG_SESSION_TYPE QT_QPA_PLATFORM QML2_IMPORT_PATH QT_QUICK_BACKEND

systemd-run --user     --unit=linura-hyprland-qualification.service     --collect     --quiet     --service-type=exec     /usr/bin/Hyprland --config /tmp/linura-hyprland-qualification.conf

wayland_socket=""
for _ in $(seq 1 150); do
    candidate="$(find "$XDG_RUNTIME_DIR" -maxdepth 1 -type s -name 'wayland-*' -print -quit 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
        wayland_socket="$candidate"
        break
    fi
    if ! systemctl --user is-active --quiet linura-hyprland-qualification.service; then
        journalctl --user -u linura-hyprland-qualification.service --no-pager >&2 || true
        fail "Hyprland exited before exposing a Wayland socket"
    fi
    sleep 0.2
done
[[ -n "$wayland_socket" ]] || fail "headless Hyprland did not expose a Wayland socket"
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
[[ -n "$hyprland_signature" ]] || fail "Hyprland IPC signature was not published"
export HYPRLAND_INSTANCE_SIGNATURE="$hyprland_signature"

systemctl --user import-environment WAYLAND_DISPLAY HYPRLAND_INSTANCE_SIGNATURE

hyprland_monitors_tmp="$evidence_root/hyprland-monitors.json.tmp"
hyprland_ipc_last_error="$evidence_root/hyprland-ipc-last-error.log"
hyprland_ipc_ready=0
hyprland_ipc_deadline=$((SECONDS + 45))
while (( SECONDS < hyprland_ipc_deadline )); do
    : > "$hyprland_ipc_last_error"
    if hyprctl monitors -j > "$hyprland_monitors_tmp" 2>> "$hyprland_ipc_last_error"; then
        mv "$hyprland_monitors_tmp" "$evidence_root/hyprland-monitors.json"
        hyprland_ipc_ready=1
        break
    fi
    {
        printf '%s\n' '--- hyprctl stdout ---'
        cat "$hyprland_monitors_tmp" 2>/dev/null || true
    } >> "$hyprland_ipc_last_error"
    rm -f "$hyprland_monitors_tmp"
    if ! systemctl --user is-active --quiet linura-hyprland-qualification.service; then
        cat "$hyprland_ipc_last_error" >&2 || true
        journalctl --user -u linura-hyprland-qualification.service --no-pager >&2 || true
        fail "Hyprland exited before IPC became responsive"
    fi
    sleep 0.5
done
if [[ "$hyprland_ipc_ready" -ne 1 ]]; then
    cat "$hyprland_ipc_last_error" >&2 || true
    journalctl --user -u linura-hyprland-qualification.service --no-pager >&2 || true
    fail "Hyprland IPC readiness deadline exceeded"
fi
rm -f "$hyprland_ipc_last_error"

{
    printf 'wayland_display=%s\n' "$WAYLAND_DISPLAY"
    printf 'hyprland_instance_signature=%s\n' "$HYPRLAND_INSTANCE_SIGNATURE"
} > "$evidence_root/hyprland-session.env"
pass_case "headless-hyprland-runtime"

systemctl --user daemon-reload

qt_quick_rendering_file="$evidence_root/qt-quick-rendering.env"
{
    printf 'backend=%s\n' "$QT_QUICK_BACKEND"
    for service_name in linura-shell-qualification.service linura-palette-qualification.service; do
        service_environment="$(systemctl --user show "$service_name" -p Environment --value)"
        if ! grep -Eq '(^| )QT_QUICK_BACKEND=software( |$)' <<<"$service_environment"; then
            fail "$service_name did not retain the qualification-only Qt Quick software backend"
        fi
        printf '%s=%s\n' "$service_name" "$service_environment"
    done
} > "$qt_quick_rendering_file"

systemctl --user start linura-shell-qualification.service

controller_qs() {
    QS_CONFIG_PATH="$controller_config" qs ipc "$@"
}
palette_qs() {
    QS_CONFIG_PATH="$palette_config" qs ipc "$@"
}

checked_palette_call() {
    local output
    local status
    set +e
    output="$(palette_qs call "$@" 2>&1)"
    status=$?
    set -e
    if [[ "$status" -ne 0 ]]; then
        printf '%s\n' "$output" >&2
        journalctl --user -u linura-palette-qualification.service --no-pager >&2 || true
        fail "palette IPC call failed with status $status: $*"
    fi
    printf '%s\n' "$output"
}

wait_for_ipc_target() {
    local description="$1"
    local service_name="$2"
    local config_path="$3"
    local target="$4"
    local deadline=$((SECONDS + 20))

    while (( SECONDS < deadline )); do
        if ! systemctl --user is-active --quiet "$service_name"; then
            journalctl --user -u "$service_name" --no-pager >&2 || true
            fail "$service_name exited before publishing $target"
        fi
        if QS_CONFIG_PATH="$config_path" qs ipc show 2>/dev/null | grep -Fq "target $target"; then
            return 0
        fi
        sleep 0.2
    done

    journalctl --user -u "$service_name" --no-pager >&2 || true
    fail "timeout waiting for $description"
}

wait_for_ipc_target     "controller IPC"     linura-shell-qualification.service     "$controller_config"     linura.shell-qualification

[[ "$(controller_qs call linura.shell-qualification hasApplication org.linura.QualificationVisible)" == "true" ]]     || fail "visible desktop entry missing"
pass_case "visible-application-discovery"

[[ "$(controller_qs call linura.shell-qualification hasApplication org.linura.QualificationHidden)" == "false" ]]     || fail "NoDisplay desktop entry leaked into the launcher catalog"
pass_case "nodisplay-filtering"

[[ "$(controller_qs call linura.shell-qualification hasApplication org.linura.QualificationTerminal)" == "true" ]]     || fail "terminal desktop entry missing from bounded catalog"
[[ "$(controller_qs call linura.shell-qualification applicationIsTerminal org.linura.QualificationTerminal)" == "true" ]]     || fail "terminal desktop entry lost terminal metadata"
[[ "$(controller_qs call linura.shell-qualification launch org.linura.QualificationTerminal 7)" == "terminal-unsupported" ]]     || fail "terminal desktop entry did not fail closed"
[[ "$(controller_qs call linura.shell-qualification launchInFlight)" == "false" ]]     || fail "terminal rejection incorrectly entered launch-in-flight state"
pass_case "terminal-entry-rejection"

stale_path="$applications_dir/org.linura.QualificationStale.desktop"
[[ "$(controller_qs call linura.shell-qualification hasApplication org.linura.QualificationStale)" == "true" ]]     || fail "stale fixture missing before removal"
rm -f "$stale_path"
stale_gone() {
    [[ "$(controller_qs call linura.shell-qualification hasApplication org.linura.QualificationStale 2>/dev/null)" == "false" ]]
}
wait_until "desktop-entry removal propagation" stale_gone
[[ "$(controller_qs call linura.shell-qualification launch org.linura.QualificationStale 8)" == "not-found" ]]     || fail "removed desktop entry was retargeted or retained"
pass_case "exact-id-reresolution"

controller_qs call linura.shell-qualification resetCompletion >/dev/null
[[ "$(controller_qs call linura.shell-qualification launch org.linura.QualificationVisible 11)" == "accepted" ]]     || fail "visible application launch was not accepted"
visible_completed() {
    [[ "$(controller_qs call linura.shell-qualification lastStatus 2>/dev/null)" == "launched" ]]
}
wait_until "visible application broker completion" visible_completed
[[ "$(controller_qs call linura.shell-qualification lastGeneration)" == "11" ]]     || fail "launch completion generation mismatch"
pass_case "bounded-systemd-run-dispatch"

wait_until "visible helper pid" test -s /tmp/linura-shell-runtime/visible.pid
visible_pid="$(cat /tmp/linura-shell-runtime/visible.pid)"
kill -0 "$visible_pid" || fail "visible application is not alive"
visible_cgroup="$(awk -F: '$1 == "0" {print $3}' /tmp/linura-shell-runtime/visible.cgroup)"
[[ "$visible_cgroup" == */app.slice/linura-app-launch-*.service ]]     || fail "visible application is not isolated under app.slice: $visible_cgroup"
[[ "$visible_cgroup" != *linura-shell-qualification.service* ]]     || fail "visible application remained in the shell qualification cgroup"
visible_unit="$(basename "$visible_cgroup")"
[[ "$(systemctl --user show "$visible_unit" -p Slice --value)" == "app.slice" ]]     || fail "transient application unit is not in app.slice"
[[ "$(systemctl --user show "$visible_unit" -p ExitType --value)" == "cgroup" ]]     || fail "transient application unit does not use ExitType=cgroup"
{
    printf 'pid=%s\n' "$visible_pid"
    printf 'cgroup=%s\n' "$visible_cgroup"
    printf 'unit=%s\n' "$visible_unit"
    systemctl --user show "$visible_unit" -p Slice -p ExitType -p ControlGroup -p ActiveState
} > "$evidence_root/visible-application-systemd.txt"
pass_case "app-slice-isolation"

systemctl --user restart linura-shell-qualification.service
wait_for_ipc_target     "controller IPC after shell restart"     linura-shell-qualification.service     "$controller_config"     linura.shell-qualification
kill -0 "$visible_pid" || fail "application died when the shell service restarted"
pass_case "shell-service-restart-survival"

controller_qs call linura.shell-qualification resetCompletion >/dev/null
[[ "$(controller_qs call linura.shell-qualification launch org.linura.QualificationForking 12)" == "accepted" ]]     || fail "forking application launch was not accepted"
fork_completed() {
    [[ "$(controller_qs call linura.shell-qualification lastStatus 2>/dev/null)" == "launched" ]]
}
wait_until "forking application broker completion" fork_completed
wait_until "forking child pid" test -s /tmp/linura-shell-runtime/fork-child.pid
fork_pid="$(cat /tmp/linura-shell-runtime/fork-child.pid)"
kill -0 "$fork_pid" || fail "forking application child did not survive parent exit"
fork_cgroup="$(awk -F: '$1 == "0" {print $3}' /tmp/linura-shell-runtime/fork-child.cgroup)"
fork_unit="$(basename "$fork_cgroup")"
[[ "$fork_cgroup" == */app.slice/linura-app-launch-*.service ]]     || fail "forking child is not under the transient app.slice unit"
[[ "$(systemctl --user show "$fork_unit" -p ExitType --value)" == "cgroup" ]]     || fail "forking application transient unit lost ExitType=cgroup"
systemctl --user is-active --quiet "$fork_unit"     || fail "forking application transient unit stopped while child remained"
{
    printf 'pid=%s\n' "$fork_pid"
    printf 'cgroup=%s\n' "$fork_cgroup"
    printf 'unit=%s\n' "$fork_unit"
    systemctl --user show "$fork_unit" -p Slice -p ExitType -p ControlGroup -p ActiveState
} > "$evidence_root/forking-application-systemd.txt"
pass_case "forking-application-cgroup-lifetime"

systemctl --user start linura-palette-qualification.service
wait_for_ipc_target     "palette IPC"     linura-palette-qualification.service     "$palette_config"     linura.palette-qualification

checked_palette_call linura.palette-qualification openPalette >/dev/null
generation_one="$(checked_palette_call linura.palette-qualification generation)"
checked_palette_call linura.palette-qualification closePalette >/dev/null
checked_palette_call linura.palette-qualification openPalette >/dev/null
generation_two="$(checked_palette_call linura.palette-qualification generation)"
(( generation_two > generation_one )) || fail "palette generation did not advance after reopen"

checked_palette_call linura.palette-qualification complete launched "$generation_one" >/dev/null
[[ "$(checked_palette_call linura.palette-qualification isOpen)" == "true" ]]     || fail "stale successful completion closed a new palette session"
[[ -z "$(checked_palette_call linura.palette-qualification status)" ]]     || fail "stale completion changed the new palette session status"

checked_palette_call linura.palette-qualification complete broker-failed "$generation_two" >/dev/null
[[ "$(checked_palette_call linura.palette-qualification isOpen)" == "true" ]]     || fail "current failure unexpectedly closed the palette"
[[ -n "$(checked_palette_call linura.palette-qualification status)" ]]     || fail "current failure did not surface status"

checked_palette_call linura.palette-qualification complete launched "$generation_two" >/dev/null
[[ "$(checked_palette_call linura.palette-qualification isOpen)" == "false" ]]     || fail "current successful completion did not close the palette"
{
    printf 'generation_one=%s\n' "$generation_one"
    printf 'generation_two=%s\n' "$generation_two"
} > "$evidence_root/palette-session.txt"
pass_case "palette-session-generation-isolation"

{
    uname -a
    printf '\n-- systemd --\n'
    systemctl --version
    printf '\n-- Hyprland --\n'
    Hyprland --version
    printf '\n-- Quickshell --\n'
    quickshell --version
} > "$evidence_root/runtime-versions.txt"

pacman -Q systemd hyprland quickshell qt6-base qt6-declarative qt6-wayland mesa vulkan-swrast seatd \
    | LC_ALL=C sort > "$evidence_root/package-versions.txt"

expected_cases=11
actual_cases="$(wc -l < "$evidence_root/cases.tsv")"
[[ "$actual_cases" -eq "$expected_cases" ]]     || fail "expected $expected_cases runtime cases, recorded $actual_cases"

echo "v0.10 shell runtime qualification passed"
