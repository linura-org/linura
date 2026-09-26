#!/usr/bin/bash
set -euo pipefail

source_root="${1:-/opt/linura-source}"
evidence_root="${2:-/tmp/linura-shell-runtime/evidence}"
shell_root="$source_root/apps/linura-shell"
controller_config="$shell_root/qualification-controller.qml"
palette_config="$shell_root/qualification-palette.qml"
quick_settings_config="$shell_root/qualification-quick-settings.qml"
applications_dir="$HOME/.local/share/applications"
audio_helper=/usr/lib/linura/linura-session-audio.lua
audio_audit="$HOME/.local/state/linura/transient-effects.sqlite3"
pipewire_fixture_dir="${XDG_CONFIG_HOME:-$HOME/.config}/pipewire/pipewire.conf.d"
pipewire_fixture_config="$pipewire_fixture_dir/90-linura-qualification-sink.conf"

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
    systemctl --user stop linura-quick-settings-qualification.service >/dev/null 2>&1
    systemctl --user stop linura-palette-qualification.service >/dev/null 2>&1
    systemctl --user stop linura-shell-qualification.service >/dev/null 2>&1
    systemctl --user stop linurad.service >/dev/null 2>&1
    systemctl --user stop wireplumber.service >/dev/null 2>&1
    systemctl --user stop pipewire.service >/dev/null 2>&1
    rm -f "$pipewire_fixture_config"
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
command -v busctl >/dev/null || fail "busctl is missing"
command -v pw-cli >/dev/null || fail "pw-cli is missing"
command -v wpctl >/dev/null || fail "wpctl is missing"
command -v wpexec >/dev/null || fail "wpexec is missing"
command -v sqlite3 >/dev/null || fail "sqlite3 is missing"
[[ -x /usr/bin/linurad && ! -L /usr/bin/linurad ]] || fail "exact-source linurad runtime is missing or untrusted"
[[ -f "$audio_helper" && ! -L "$audio_helper" ]] || fail "session-audio helper is missing or untrusted"
audio_helper_uid="$(stat -c '%u' "$audio_helper")"
audio_helper_gid="$(stat -c '%g' "$audio_helper")"
audio_helper_mode="$(stat -c '%a' "$audio_helper")"
audio_helper_links="$(stat -c '%h' "$audio_helper")"
[[ "$audio_helper_uid" == "0" && "$audio_helper_gid" == "0" ]] || fail "session-audio helper is not host root-owned"
[[ "$audio_helper_mode" == "644" ]] || fail "session-audio helper mode is not 0644: $audio_helper_mode"
[[ "$audio_helper_links" == "1" ]] || fail "session-audio helper has hard-link aliases: $audio_helper_links"
cmp -s "$audio_helper" "$source_root/packaging/wireplumber/linura-session-audio.lua" || fail "installed session-audio helper differs from exact source"

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

bridge_module_dir=/usr/local/lib/qt6/qml/org/linura/ShellBridge
bridge_plugin="$bridge_module_dir/liblinura-shell-bridgeplugin.so"
bridge_backing="$bridge_module_dir/liblinura-shell-bridge.so"
[[ -f "$bridge_plugin" ]] || fail "Linura ShellBridge QML plugin is missing: $bridge_plugin"
[[ -f "$bridge_backing" ]] || fail "Linura ShellBridge backing library is missing: $bridge_backing"
bridge_linkage_file="$evidence_root/bridge-module-linkage.txt"
ldd "$bridge_plugin" > "$bridge_linkage_file"
if grep -Fq 'not found' "$bridge_linkage_file"; then
    cat "$bridge_linkage_file" >&2
    fail "Linura ShellBridge QML plugin has unresolved installed dependencies"
fi
grep -Fq "liblinura-shell-bridge.so => $bridge_backing" "$bridge_linkage_file" || {
    cat "$bridge_linkage_file" >&2
    fail "Linura ShellBridge QML plugin did not resolve its backing library from the module directory"
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

install -d -m 0700 "$pipewire_fixture_dir"
cat > "$pipewire_fixture_config" <<'PIPEWIRE_FIXTURE'
context.objects = [
  {
    factory = adapter
    args = {
      factory.name = support.null-audio-sink
      node.name = linura-qualification-sink
      node.description = "Linura Qualification Sink"
      media.class = Audio/Sink
      object.linger = true
      audio.position = [ FL FR ]
      monitor.channel-volumes = true
    }
  }
]
PIPEWIRE_FIXTURE
chmod 0600 "$pipewire_fixture_config"
cp "$pipewire_fixture_config" "$evidence_root/pipewire-fixture-create.txt"

systemctl --user start pipewire.service
systemctl --user start wireplumber.service
wait_until "PipeWire user service" systemctl --user is-active --quiet pipewire.service
wait_until "WirePlumber user service" systemctl --user is-active --quiet wireplumber.service

audio_snapshot() {
    /usr/bin/wpexec "$audio_helper" '{ action = "observe" }'
}

audio_sink_present() {
    audio_snapshot 2>/dev/null | awk -F '\t' '
        $1 == "sink" && $4 == "linura-qualification-sink" { count += 1 }
        END { exit count == 1 ? 0 : 1 }
    '
}

audio_fixture_ready=0
for _ in $(seq 1 100); do
    if audio_sink_present; then
        audio_fixture_ready=1
        break
    fi
    sleep 0.1
done
if [[ "$audio_fixture_ready" -ne 1 ]]; then
    {
        printf '%s\n' '--- fixture config ---'
        cat "$pipewire_fixture_config"
        printf '%s\n' '--- PipeWire nodes ---'
        pw-cli ls Node || true
        printf '%s\n' '--- authoritative audio snapshot ---'
        audio_snapshot || true
        printf '%s\n' '--- PipeWire/WirePlumber status ---'
        systemctl --user status pipewire.service wireplumber.service --no-pager || true
        printf '%s\n' '--- PipeWire/WirePlumber journal ---'
        journalctl --user -u pipewire.service -u wireplumber.service --no-pager || true
    } > "$evidence_root/pipewire-fixture-diagnostics.txt" 2>&1
    cat "$evidence_root/pipewire-fixture-diagnostics.txt" >&2
    fail "timeout waiting for deterministic PipeWire qualification sink"
fi

sink_snapshot="$(audio_snapshot)"
printf '%s\n' "$sink_snapshot" > "$evidence_root/pipewire-snapshot-initial.txt"
sink_record="$(printf '%s\n' "$sink_snapshot" | awk -F '\t' '$1 == "sink" && $4 == "linura-qualification-sink" { print }')"
[[ "$(printf '%s\n' "$sink_record" | sed '/^$/d' | wc -l)" -eq 1 ]] || fail "qualification audio sink identity is ambiguous"
IFS=$'\t' read -r sink_tag qualification_sink_id qualification_sink_serial qualification_sink_name qualification_sink_default qualification_sink_volume qualification_sink_muted <<<"$sink_record"
[[ "$sink_tag" == "sink" && "$qualification_sink_name" == "linura-qualification-sink" ]] || fail "qualification audio sink record is malformed"
[[ "$qualification_sink_id" =~ ^[0-9]+$ && "$qualification_sink_serial" =~ ^[0-9]+$ ]] || fail "qualification audio sink identity is not canonical"

wpctl set-default "$qualification_sink_id"
audio_sink_default() {
    audio_snapshot 2>/dev/null | awk -F '\t' -v id="$qualification_sink_id" '
        $1 == "sink" && $2 == id && $3 ~ /^[0-9]+$/ && $4 == "linura-qualification-sink" && $5 == "1" { found = 1 }
        END { exit found ? 0 : 1 }
    '
}
wait_until "qualification sink to become default" audio_sink_default

set_fixture_volume() {
    local volume="$1"
    local arguments
    printf -v arguments '{ action = "set-volume", node_id = %s, object_serial = "%s", node_name = "%s", volume_percent = %s }' "$qualification_sink_id" "$qualification_sink_serial" "$qualification_sink_name" "$volume"
    /usr/bin/wpexec "$audio_helper" "$arguments" >/dev/null
}
set_fixture_volume 40

audio_sink_matches_volume() {
    local expected="$1"
    audio_snapshot 2>/dev/null | awk -F '\t' -v id="$qualification_sink_id" -v serial="$qualification_sink_serial" -v expected="$expected" '
        $1 == "sink" && $2 == id && $3 == serial && $4 == "linura-qualification-sink" && $5 == "1" && $6 == expected { found = 1 }
        END { exit found ? 0 : 1 }
    '
}
wait_until "qualification sink initial volume" audio_sink_matches_volume 40

{
    printf 'node_id=%s\n' "$qualification_sink_id"
    printf 'object_serial=%s\n' "$qualification_sink_serial"
    printf 'node_name=%s\n' "$qualification_sink_name"
    audio_snapshot
} > "$evidence_root/quick-settings-audio-fixture.txt"

systemctl --user start linurad.service
wait_until "linurad user service" systemctl --user is-active --quiet linurad.service
control_bus_ready() {
    busctl --user status org.linura.Control1 >/dev/null 2>&1
}
wait_until "org.linura.Control1 session-bus ownership" control_bus_ready

{
    sha256sum /usr/bin/linurad "$audio_helper"
    stat -c '%U:%G %a %h %n' /usr/bin/linurad "$audio_helper"
    systemctl --user show linurad.service -p ActiveState -p SubState -p MainPID -p StateDirectory
    busctl --user status org.linura.Control1
} > "$evidence_root/authority-runtime-integrity.txt"

qt_quick_rendering_file="$evidence_root/qt-quick-rendering.env"
{
    printf 'backend=%s\n' "$QT_QUICK_BACKEND"
    for service_name in linura-shell-qualification.service linura-palette-qualification.service linura-quick-settings-qualification.service; do
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
quick_settings_qs() {
    QS_CONFIG_PATH="$quick_settings_config" qs ipc "$@"
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

checked_quick_settings_call() {
    local output
    local status
    set +e
    output="$(quick_settings_qs call "$@" 2>&1)"
    status=$?
    set -e
    if [[ "$status" -ne 0 ]]; then
        printf '%s\n' "$output" >&2
        journalctl --user -u linura-quick-settings-qualification.service -u linurad.service --no-pager >&2 || true
        fail "Quick Settings IPC call failed with status $status: $*"
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

systemctl --user start linura-quick-settings-qualification.service
wait_for_ipc_target "Quick Settings IPC" linura-quick-settings-qualification.service "$quick_settings_config" linura.quick-settings-qualification

audit_count_before="$(sqlite3 "$audio_audit" 'SELECT count(*) FROM transient_effect_audit;' 2>/dev/null || printf '0')"
checked_quick_settings_call linura.quick-settings-qualification openSettings >/dev/null
quick_settings_bind_draft() {
    [[ "$(checked_quick_settings_call linura.quick-settings-qualification beginDraft 2>/dev/null)" == "begun" ]]
}
quick_settings_draft_bound=0
quick_settings_draft_deadline=$((SECONDS + 60))
while (( SECONDS < quick_settings_draft_deadline )); do
    if quick_settings_bind_draft; then
        quick_settings_draft_bound=1
        break
    fi
    sleep 0.1
done
if [[ "$quick_settings_draft_bound" -ne 1 ]]; then
    {
        for method in isOpen state status freshness authority nodeId volumePercent canApply canCommitDraft; do
            printf '%s=' "$method"
            quick_settings_qs call linura.quick-settings-qualification "$method" 2>&1 || true
        done
        printf '%s\n' '-- independent Control1 observation --'
        busctl --user call org.linura.Control1 /org/linura/Control1 org.linura.Control1 Observe \
            sss pipewire audio:session:default-output audio.session.observe || true
        printf '%s\n' '-- independent PipeWire snapshot --'
        audio_snapshot || true
        printf '%s\n' '-- runtime service journal --'
        journalctl --user -u linura-quick-settings-qualification.service -u linurad.service --no-pager || true
    } > "$evidence_root/quick-settings-readiness-failure.txt" 2>&1
    cat "$evidence_root/quick-settings-readiness-failure.txt" >&2
    fail "timeout waiting for authoritative Quick Settings draft binding"
fi
[[ "$(checked_quick_settings_call linura.quick-settings-qualification canCommitDraft)" == "true" ]] || fail "Quick Settings lost the bound draft before pre-dispatch revalidation"
[[ "$(checked_quick_settings_call linura.quick-settings-qualification authority)" == "native-api" ]] || fail "Quick Settings did not expose native authoritative state"
[[ "$(checked_quick_settings_call linura.quick-settings-qualification nodeId)" == "$qualification_sink_id" ]] || fail "Quick Settings resolved a different default sink"
[[ "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)" == "40" ]] || fail "Quick Settings initial volume does not match authoritative PipeWire state"
{
    printf 'state=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification state)"
    printf 'authority=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification authority)"
    printf 'freshness=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification freshness)"
    printf 'node_id=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification nodeId)"
    printf 'volume_percent=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)"
    printf 'draft_bound=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification canCommitDraft)"
} > "$evidence_root/quick-settings-observation.txt"
pass_case "quick-settings-authoritative-observation"

[[ "$(checked_quick_settings_call linura.quick-settings-qualification commitVolume 63)" == "requested" ]] || fail "Quick Settings did not dispatch the bounded volume request"
quick_settings_verified_63() {
    [[ "$(checked_quick_settings_call linura.quick-settings-qualification state 2>/dev/null)" == "ready" ]] && [[ "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent 2>/dev/null)" == "63" ]] && [[ "$(checked_quick_settings_call linura.quick-settings-qualification receiptStatus 2>/dev/null)" == "verified" ]]
}
quick_settings_effect_verified=0
quick_settings_effect_deadline=$((SECONDS + 30))
while (( SECONDS < quick_settings_effect_deadline )); do
    if quick_settings_verified_63; then
        quick_settings_effect_verified=1
        break
    fi
    sleep 0.1
done
if [[ "$quick_settings_effect_verified" -ne 1 ]]; then
    {
        for method in state status freshness authority nodeId volumePercent canApply receiptStatus evidenceId; do
            printf '%s=' "$method"
            quick_settings_qs call linura.quick-settings-qualification "$method" 2>&1 || true
        done
        printf '%s\n' '-- independent Control1 observation --'
        busctl --user call org.linura.Control1 /org/linura/Control1 org.linura.Control1 Observe \
            sss pipewire audio:session:default-output audio.session.observe || true
        printf '%s\n' '-- independent PipeWire snapshot --'
        audio_snapshot || true
        printf '%s\n' '-- transient audit --'
        if [[ -f "$audio_audit" && ! -L "$audio_audit" ]]; then
            sqlite3 -header -column "$audio_audit" \
                'SELECT rowid,request_id,resource,disposition,failure_code,pre_effect_evidence_id,post_effect_evidence_id FROM transient_effect_audit ORDER BY rowid DESC LIMIT 3;' || true
        else
            printf '%s\n' 'audit database unavailable'
        fi
        printf '%s\n' '-- runtime service journal --'
        journalctl --user -u linura-quick-settings-qualification.service -u linurad.service -u pipewire.service -u wireplumber.service --no-pager || true
    } > "$evidence_root/quick-settings-session1-failure.txt" 2>&1
    cat "$evidence_root/quick-settings-session1-failure.txt" >&2
    fail "timeout waiting for verified Quick Settings Session1 volume effect"
fi
wait_until "independent PipeWire volume 63" audio_sink_matches_volume 63
[[ -n "$(checked_quick_settings_call linura.quick-settings-qualification evidenceId)" ]] || fail "verified Quick Settings effect did not retain evidence identity"
{
    printf 'receipt_status=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification receiptStatus)"
    printf 'evidence_id=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification evidenceId)"
    printf 'volume_percent=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)"
    audio_snapshot
} > "$evidence_root/quick-settings-session1-effect.txt"
pass_case "quick-settings-session1-volume-effect"

[[ -f "$audio_audit" && ! -L "$audio_audit" ]] || fail "durable transient audit database is missing or untrusted"
audit_mode="$(stat -c '%a' "$audio_audit")"
audit_links="$(stat -c '%h' "$audio_audit")"
audit_uid="$(stat -c '%u' "$audio_audit")"
audit_gid="$(stat -c '%g' "$audio_audit")"
audit_size="$(stat -c '%s' "$audio_audit")"
[[ "$audit_mode" == "600" ]] || fail "transient audit database mode is not 0600: $audit_mode"
[[ "$audit_links" == "1" ]] || fail "transient audit database has hard-link aliases: $audit_links"
[[ "$audit_uid" == "$(id -u)" && "$audit_gid" == "$(id -g)" ]] || fail "transient audit database ownership does not match the session principal"
(( audit_size <= 536870912 )) || fail "transient audit database exceeds the 512 MiB bound"
audit_application_id="$(sqlite3 "$audio_audit" 'PRAGMA application_id;')"
audit_user_version="$(sqlite3 "$audio_audit" 'PRAGMA user_version;')"
audit_journal_mode="$(sqlite3 "$audio_audit" 'PRAGMA journal_mode;')"
audit_synchronous="$(sqlite3 "$audio_audit" 'PRAGMA synchronous;')"
audit_quick_check="$(sqlite3 "$audio_audit" 'PRAGMA quick_check(1);')"
audit_table_sql="$(sqlite3 "$audio_audit" "SELECT sql FROM sqlite_schema WHERE type='table' AND name='transient_effect_audit';")"
[[ "$audit_application_id" == "1280201810" ]] || fail "transient audit application_id is not LNTR"
[[ "$audit_user_version" == "1" ]] || fail "transient audit schema version is not 1"
[[ "${audit_journal_mode,,}" == "wal" ]] || fail "transient audit journal mode is not WAL"
[[ "$audit_synchronous" == "2" ]] || fail "transient audit synchronous mode is not FULL"
[[ "$audit_quick_check" == "ok" ]] || fail "transient audit quick_check failed: $audit_quick_check"
[[ "$audit_table_sql" == *"STRICT"* ]] || fail "transient audit table is not STRICT"
audit_wal="${audio_audit}-wal"
if [[ -e "$audit_wal" ]]; then
    [[ -f "$audit_wal" && ! -L "$audit_wal" ]] || fail "transient audit WAL is not a regular file"
    audit_wal_links="$(stat -c '%h' "$audit_wal")"
    audit_wal_size="$(stat -c '%s' "$audit_wal")"
    [[ "$audit_wal_links" == "1" ]] || fail "transient audit WAL has hard-link aliases"
    (( audit_wal_size <= 16777216 )) || fail "transient audit WAL exceeds the 16 MiB bound"
fi
audit_count_after="$(sqlite3 "$audio_audit" 'SELECT count(*) FROM transient_effect_audit;')"
(( audit_count_after == audit_count_before + 1 )) || fail "verified Quick Settings effect did not append exactly one durable audit record"
audit_row="$(sqlite3 -separator $'\t' "$audio_audit" "SELECT principal,operation_id,provider,resource,observation_capability,risk,disposition,pre_effect_evidence_id,post_effect_evidence_id FROM transient_effect_audit ORDER BY rowid DESC LIMIT 1;")"
IFS=$'\t' read -r audit_principal audit_operation audit_provider audit_resource audit_capability audit_risk audit_disposition audit_pre audit_post <<<"$audit_row"
[[ "$audit_principal" == "unix:uid:$(id -u)" ]] || fail "transient audit principal does not match the authenticated session user"
[[ "$audit_operation" == "operation:audio.output.set-session-volume" ]] || fail "transient audit operation identity drifted"
[[ "$audit_provider" == "pipewire" ]] || fail "transient audit provider identity drifted"
[[ "$audit_resource" == "audio:session:output:$qualification_sink_id" ]] || fail "transient audit resource is not exact-node bound"
[[ "$audit_capability" == "audio.session.observe" ]] || fail "transient audit observation capability drifted"
[[ "$audit_risk" == "user-state" && "$audit_disposition" == "verified" ]] || fail "transient audit risk/disposition is not the qualified verified result"
[[ -n "$audit_pre" && -n "$audit_post" ]] || fail "verified transient audit is missing pre/post evidence identity"
{
    stat -c 'mode=%a links=%h owner=%U:%G size=%s path=%n' "$audio_audit"
    sqlite3 "$audio_audit" 'PRAGMA application_id; PRAGMA user_version; PRAGMA journal_mode; PRAGMA synchronous; PRAGMA quick_check(1);'
    sqlite3 -header -column "$audio_audit" 'SELECT audit_attempt_sha256,principal,operation_id,plan_id,request_id,provider,resource,observation_capability,risk,policy_id,policy_revision_id,risk_classification_revision,pre_effect_evidence_id,post_effect_evidence_id,disposition,failure_code FROM transient_effect_audit ORDER BY rowid DESC LIMIT 1;'
} > "$evidence_root/quick-settings-audit.txt"
pass_case "quick-settings-durable-audit-lineage"

[[ "$(checked_quick_settings_call linura.quick-settings-qualification beginDraft)" == "begun" ]] || fail "Quick Settings could not begin the precondition-drift qualification draft"
set_fixture_volume 72
wait_until "external concurrent volume 72" audio_sink_matches_volume 72
audit_count_before_drift="$(sqlite3 "$audio_audit" 'SELECT count(*) FROM transient_effect_audit;')"
[[ "$(checked_quick_settings_call linura.quick-settings-qualification commitVolume 55)" == "requested" ]] || fail "Quick Settings did not enter pre-dispatch revalidation"
quick_settings_drift_rejected() {
    [[ "$(checked_quick_settings_call linura.quick-settings-qualification state 2>/dev/null)" == "ready" ]] && [[ "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent 2>/dev/null)" == "72" ]]
}
wait_until "Quick Settings precondition drift rejection" quick_settings_drift_rejected
wait_until "concurrent PipeWire volume remains 72" audio_sink_matches_volume 72
audit_count_after_drift="$(sqlite3 "$audio_audit" 'SELECT count(*) FROM transient_effect_audit;')"
[[ "$audit_count_after_drift" == "$audit_count_before_drift" ]] || fail "precondition drift rejection incorrectly reached durable effect audit"
{
    printf 'controller_volume=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)"
    printf 'audit_count_before=%s\n' "$audit_count_before_drift"
    printf 'audit_count_after=%s\n' "$audit_count_after_drift"
    audio_snapshot
} > "$evidence_root/quick-settings-precondition-drift.txt"
pass_case "quick-settings-precondition-drift-rejection"

systemctl --user stop linurad.service
control_bus_gone() {
    ! busctl --user status org.linura.Control1 >/dev/null 2>&1
}
wait_until "linurad session-bus name release" control_bus_gone
checked_quick_settings_call linura.quick-settings-qualification refresh >/dev/null
quick_settings_unavailable() {
    [[ "$(checked_quick_settings_call linura.quick-settings-qualification state 2>/dev/null)" == "unavailable" ]] && [[ "$(checked_quick_settings_call linura.quick-settings-qualification canApply 2>/dev/null)" == "false" ]]
}
wait_until "Quick Settings fail-closed service-loss state" quick_settings_unavailable
[[ "$(checked_quick_settings_call linura.quick-settings-qualification beginDraft)" == "not-ready" ]] || fail "Quick Settings accepted a draft while linurad was unavailable"
wait_until "PipeWire state unchanged during service loss" audio_sink_matches_volume 72
{
    printf 'state=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification state)"
    printf 'can_apply=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification canApply)"
    printf 'volume_percent=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)"
} > "$evidence_root/quick-settings-service-loss.txt"
pass_case "quick-settings-service-loss-fail-closed"

systemctl --user start linurad.service
wait_until "linurad restart" systemctl --user is-active --quiet linurad.service
wait_until "org.linura.Control1 after restart" control_bus_ready
checked_quick_settings_call linura.quick-settings-qualification refresh >/dev/null
quick_settings_recovered() {
    [[ "$(checked_quick_settings_call linura.quick-settings-qualification state 2>/dev/null)" == "ready" ]]
}
wait_until "Quick Settings recovery after linurad restart" quick_settings_recovered
[[ "$(checked_quick_settings_call linura.quick-settings-qualification nodeId)" == "$qualification_sink_id" ]] || fail "Quick Settings restart recovery changed authoritative sink identity"
[[ "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)" == "72" ]] || fail "Quick Settings restart recovery did not reobserve current PipeWire state"
{
    systemctl --user show linurad.service -p ActiveState -p SubState -p MainPID
    printf 'state=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification state)"
    printf 'authority=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification authority)"
    printf 'freshness=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification freshness)"
    printf 'node_id=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification nodeId)"
    printf 'volume_percent=%s\n' "$(checked_quick_settings_call linura.quick-settings-qualification volumePercent)"
} > "$evidence_root/quick-settings-restart-recovery.txt"
pass_case "quick-settings-restart-recovery"

{
    uname -a
    printf '\n-- systemd --\n'
    systemctl --version
    printf '\n-- PipeWire --\n'
    pipewire --version
    printf '\n-- WirePlumber --\n'
    wireplumber --version
    printf '\n-- linurad --\n'
    sha256sum /usr/bin/linurad
    printf '\n-- Hyprland --\n'
    Hyprland --version
    printf '\n-- Quickshell --\n'
    quickshell --version
} > "$evidence_root/runtime-versions.txt"

pacman -Q systemd hyprland quickshell qt6-base qt6-declarative qt6-wayland mesa vulkan-swrast seatd pipewire pipewire-audio wireplumber networkmanager sqlite \
    | LC_ALL=C sort > "$evidence_root/package-versions.txt"

expected_cases=17
actual_cases="$(wc -l < "$evidence_root/cases.tsv")"
[[ "$actual_cases" -eq "$expected_cases" ]]     || fail "expected $expected_cases runtime cases, recorded $actual_cases"

echo "v0.10 shell runtime qualification passed"
