#!/usr/bin/bash
set -euo pipefail

command_name="${1:-}"
recording_path="${2:-}"
requested_output="${3:-}"
source_root="${LINURA_SOURCE_ROOT:-/opt/linura-source}"
unit="linura-workstation-recorder.service"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

safe_recording_path() {
    local candidate="$1"
    [[ "$candidate" = /* ]] || fail "recording path must be absolute"
    [[ "$candidate" == *.mkv ]] || fail "recording path must end in .mkv"
    local canonical
    canonical="$(realpath -m "$candidate")"
    case "$canonical" in
        /tmp/linura-shell-runtime/evidence/*.mkv|/tmp/linura-workstation-live/*.mkv|"$HOME"/.local/state/linura/acceptance/*.mkv)
            printf '%s\n' "$canonical"
            ;;
        *)
            fail "recording path is outside the bounded acceptance evidence roots"
            ;;
    esac
}

select_output() {
    if [[ -n "$requested_output" ]]; then
        printf '%s\n' "$requested_output"
        return
    fi
    mapfile -t outputs < <(
        hyprctl monitors -j |
            python3 -c 'import json,sys; data=json.load(sys.stdin); [print(x["name"]) for x in data if isinstance(x,dict) and isinstance(x.get("name"),str) and x["name"]]'
    )
    [[ "${#outputs[@]}" -eq 1 ]] || fail "recording output must be explicit when the session has zero or multiple monitors"
    printf '%s\n' "${outputs[0]}"
}

verify() {
    local path="$1"
    local metadata="${path%.mkv}.metadata.json"
    local digest_file="${path%.mkv}.sha256"
    local verify_args=(verify-recording "$path" --metadata "$metadata")
    if [[ -n "${LINURA_SOURCE_SHA:-}" ]]; then
        verify_args+=(--source-sha "$LINURA_SOURCE_SHA")
    fi
    python3 "$source_root/tools/workstation_acceptance.py" "${verify_args[@]}"
    local digest
    digest="$(sha256sum "$path" | awk '{print $1}')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "recording digest is malformed"
    printf '%s  %s\n' "$digest" "$(basename "$path")" > "$digest_file"
}

case "$command_name" in
    start)
        [[ -n "$recording_path" ]] || fail "start requires a recording path"
        command -v wf-recorder >/dev/null || fail "wf-recorder is missing"
        command -v ffprobe >/dev/null || fail "ffprobe is missing"
        command -v hyprctl >/dev/null || fail "hyprctl is missing"
        command -v systemctl >/dev/null || fail "systemctl is missing"
        : "${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}"
        : "${WAYLAND_DISPLAY:?WAYLAND_DISPLAY is required}"
        path="$(safe_recording_path "$recording_path")"
        [[ ! -e "$path" ]] || fail "recording path already exists: $path"
        install -d -m 0700 "$(dirname "$path")"
        if systemctl --user is-active --quiet "$unit"; then
            fail "workstation recorder is already active"
        fi
        output="$(select_output)"
        systemd-run --user             --unit="$unit"             --collect             --quiet             --service-type=exec             --setenv="XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"             --setenv="WAYLAND_DISPLAY=$WAYLAND_DISPLAY"             /usr/bin/wf-recorder -o "$output" -c ffv1 -f "$path"
        for _ in $(seq 1 50); do
            systemctl --user is-active --quiet "$unit" && [[ -f "$path" ]] && exit 0
            sleep 0.1
        done
        journalctl --user -u "$unit" --no-pager >&2 || true
        fail "workstation recorder did not become active"
        ;;
    stop)
        [[ -n "$recording_path" ]] || fail "stop requires a recording path"
        path="$(safe_recording_path "$recording_path")"
        if systemctl --user is-active --quiet "$unit"; then
            systemctl --user kill --kill-who=main --signal=INT "$unit"
            for _ in $(seq 1 100); do
                systemctl --user is-active --quiet "$unit" || break
                sleep 0.1
            done
        fi
        systemctl --user is-active --quiet "$unit" && fail "workstation recorder did not stop"
        [[ -f "$path" && ! -L "$path" ]] || fail "workstation recording was not finalized"
        verify "$path"
        ;;
    verify)
        [[ -n "$recording_path" ]] || fail "verify requires a recording path"
        path="$(safe_recording_path "$recording_path")"
        verify "$path"
        ;;
    *)
        fail "usage: record-session.sh {start|stop|verify} /absolute/path.mkv [output-name]"
        ;;
esac
