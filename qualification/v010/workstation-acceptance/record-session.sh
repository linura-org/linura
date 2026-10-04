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

runtime_state_dir() {
    : "${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}"
    printf '%s\n' "$XDG_RUNTIME_DIR/linura-acceptance"
}

recorder_status_path() {
    printf '%s/workstation-recorder.status\n' "$(runtime_state_dir)"
}

recorder_helper_pid_path() {
    printf '%s/workstation-recorder-helper.pid\n' "$(runtime_state_dir)"
}

recorder_helper_start_time() {
    local proc_stat
    local -a fields=()
    proc_stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    proc_stat="${proc_stat##*) }"
    read -r -a fields <<<"$proc_stat"
    [[ "${fields[0]:-}" != Z && "${fields[19]:-}" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${fields[19]}"
}

recorder_helper_is_live() {
    local observed
    observed="$(recorder_helper_start_time "$helper_pid")" || return 1
    [[ "$observed" == "$helper_start" ]]
}

verify() {
    local path="$1"
    local metadata="${path%.mkv}.metadata.json"
    local digest_file="${path%.mkv}.sha256"
    local verify_args=(verify-recording "$path" --metadata "$metadata")
    if [[ -n "${LINURA_SOURCE_SHA:-}" ]]; then
        verify_args+=(--source-sha "$LINURA_SOURCE_SHA")
    fi
    python3 "$source_root/tools/workstation_acceptance.py" "${verify_args[@]}" \
        --digest-file "$digest_file"
}

abort_recorder_state() {
    local path="$1"
    local status_file helper_pid_file helper_pid helper_start
    status_file="$(recorder_status_path)"
    helper_pid_file="$(recorder_helper_pid_path)"

    # Stop the global recorder first, even if shared helper identity is damaged.
    # Shared files are cleared only after the registered helper is proven dead.
    systemctl --user kill --kill-who=main --signal=INT "$unit" >/dev/null 2>&1 || true
    systemctl --user stop "$unit" >/dev/null 2>&1 || true

    [[ -f "$helper_pid_file" && ! -L "$helper_pid_file" ]] \
        || fail "cannot prove recorder helper has terminated"
    read -r helper_pid helper_start < "$helper_pid_file" \
        || fail "cannot inspect recorder helper"
    [[ "$helper_pid" =~ ^[1-9][0-9]*$ && "$helper_start" =~ ^[0-9]+$ ]] \
        || fail "recorder helper identity is malformed"

    for _ in $(seq 1 50); do
        recorder_helper_is_live || break
        sleep 0.1
    done
    if recorder_helper_is_live; then
        kill -TERM "$helper_pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            recorder_helper_is_live || break
            sleep 0.1
        done
    fi
    if recorder_helper_is_live; then
        kill -KILL "$helper_pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            recorder_helper_is_live || break
            sleep 0.1
        done
    fi
    if recorder_helper_is_live; then
        fail "recorder helper remains alive; refusing to clear its shared state"
    fi
    if systemctl --user is-active --quiet "$unit"; then
        fail "workstation recorder service remains active after abort"
    fi
    rm -f -- "$status_file" "$helper_pid_file" "$path" \
        "${path%.mkv}.metadata.json" "${path%.mkv}.sha256"
}

case "$command_name" in
    start)
        [[ -n "$recording_path" ]] || fail "start requires a recording path"
        command -v wf-recorder >/dev/null || fail "wf-recorder is missing"
        command -v ffprobe >/dev/null || fail "ffprobe is missing"
        command -v hyprctl >/dev/null || fail "hyprctl is missing"
        command -v systemctl >/dev/null || fail "systemctl is missing"
        command -v systemd-run >/dev/null || fail "systemd-run is missing"
        : "${WAYLAND_DISPLAY:?WAYLAND_DISPLAY is required}"
        path="$(safe_recording_path "$recording_path")"
        [[ ! -e "$path" && ! -L "$path" ]] || fail "recording path already exists: $path"
        install -d -m 0700 "$(dirname "$path")"
        state_dir="$(runtime_state_dir)"
        install -d -m 0700 "$state_dir"
        status_file="$(recorder_status_path)"
        helper_pid_file="$(recorder_helper_pid_path)"
        if [[ -f "$helper_pid_file" ]]; then
            read -r helper_pid helper_start < "$helper_pid_file" \
                || fail "cannot inspect previous recorder helper"
            [[ "$helper_pid" =~ ^[1-9][0-9]*$ && "$helper_start" =~ ^[0-9]+$ ]] \
                || fail "previous recorder helper identity is malformed"
            if recorder_helper_is_live; then
                fail "previous workstation recorder helper has not exited"
            fi
        fi
        rm -f "$status_file" "$helper_pid_file"
        if systemctl --user is-active --quiet "$unit"; then
            fail "workstation recorder is already active"
        fi
        output="$(select_output)"
        # A failed start must stop the service: the caller marks recording_started
        # only after this command succeeds, so caller cleanup cannot handle it.
        startup_cleanup() {
            local original_status=$?
            trap - EXIT
            systemctl --user kill --kill-who=main --signal=INT "$unit" >/dev/null 2>&1 || true
            systemctl --user stop "$unit" >/dev/null 2>&1 || true
            if [[ -n "${helper_pid:-}" ]]; then
                for _ in $(seq 1 50); do
                    kill -0 "$helper_pid" 2>/dev/null || break
                    sleep 0.1
                done
                kill "$helper_pid" 2>/dev/null || true
                wait "$helper_pid" 2>/dev/null || true
            fi
            rm -f -- "$status_file" "$helper_pid_file" "$path" \
                "${path%.mkv}.metadata.json" "${path%.mkv}.sha256"
            exit "$original_status"
        }
        trap startup_cleanup EXIT
        (
            set +e
            systemd-run --user \
                --unit="$unit" \
                --wait \
                --collect \
                --quiet \
                --service-type=exec \
                --setenv="XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" \
                --setenv="WAYLAND_DISPLAY=$WAYLAND_DISPLAY" \
                /usr/bin/wf-recorder -o "$output" -c ffv1 -f "$path"
            recorder_status=$?
            umask 077
            temp_status="$status_file.tmp.$$"
            printf '%s\n' "$recorder_status" > "$temp_status"
            mv -f "$temp_status" "$status_file"
            exit 0
        ) >/dev/null 2>&1 &
        helper_pid=$!
        helper_start="$(recorder_helper_start_time "$helper_pid")" \
            || fail "workstation recorder helper exited before registration"
        printf '%s %s\n' "$helper_pid" "$helper_start" > "$helper_pid_file"
        for _ in $(seq 1 50); do
            if [[ -f "$status_file" ]]; then
                recorder_status="$(cat "$status_file")"
                journalctl --user -u "$unit" --no-pager >&2 || true
                fail "workstation recorder exited during startup with status $recorder_status"
            fi
            if systemctl --user is-active --quiet "$unit" && [[ -f "$path" ]]; then
                trap - EXIT
                exit 0
            fi
            kill -0 "$helper_pid" 2>/dev/null || fail "workstation recorder status helper exited during startup"
            sleep 0.1
        done
        journalctl --user -u "$unit" --no-pager >&2 || true
        fail "workstation recorder did not become active"
        ;;
    stop)
        [[ -n "$recording_path" ]] || fail "stop requires a recording path"
        path="$(safe_recording_path "$recording_path")"
        status_file="$(recorder_status_path)"
        helper_pid_file="$(recorder_helper_pid_path)"
        systemctl --user is-active --quiet "$unit" \
            || fail "workstation recorder exited before requested stop"
        systemctl --user kill --kill-who=main --signal=INT "$unit"
        for _ in $(seq 1 150); do
            [[ -f "$status_file" ]] && break
            sleep 0.1
        done
        if [[ ! -f "$status_file" ]]; then
            journalctl --user -u "$unit" --no-pager >&2 || true
            abort_recorder_state "$path"
            fail "workstation recorder did not publish its final exit status"
        fi
        recorder_status="$(cat "$status_file")"
        [[ "$recorder_status" =~ ^[0-9]+$ ]] || fail "workstation recorder final status is malformed"
        if [[ "$recorder_status" -ne 0 ]]; then
            journalctl --user -u "$unit" --no-pager >&2 || true
            fail "workstation recorder failed while finalizing with status $recorder_status"
        fi
        systemctl --user is-active --quiet "$unit" && fail "workstation recorder remained active after successful finalization"
        [[ -f "$path" && ! -L "$path" ]] || fail "workstation recording was not finalized"
        [[ -f "$helper_pid_file" && ! -L "$helper_pid_file" ]] \
            || fail "recorder helper identity is missing"
        if [[ -f "$helper_pid_file" ]]; then
            read -r helper_pid helper_start < "$helper_pid_file" \
                || fail "cannot inspect recorder helper"
            [[ "$helper_pid" =~ ^[1-9][0-9]*$ && "$helper_start" =~ ^[0-9]+$ ]] \
                || fail "recorder helper identity is malformed"
            for _ in $(seq 1 50); do
                recorder_helper_is_live || break
                sleep 0.1
            done
            if recorder_helper_is_live; then
                fail "recorder helper did not exit after status publication"
            fi
        fi
        rm -f "$helper_pid_file"
        verify "$path"
        ;;
    abort)
        [[ -n "$recording_path" ]] || fail "abort requires a recording path"
        path="$(safe_recording_path "$recording_path")"
        abort_recorder_state "$path"
        ;;
    verify)
        [[ -n "$recording_path" ]] || fail "verify requires a recording path"
        path="$(safe_recording_path "$recording_path")"
        verify "$path"
        ;;
    *)
        fail "usage: record-session.sh {start|stop|abort|verify} /absolute/path.mkv [output-name]"
        ;;
esac
