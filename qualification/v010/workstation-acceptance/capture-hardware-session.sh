#!/usr/bin/bash
set -euo pipefail

fixture_id=""
fixture_contract="/etc/linura/qualification-fixture.json"
evidence_root=""
output_name=""
record=0
source_root="${LINURA_SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixture-id) fixture_id="$2"; shift 2 ;;
        --fixture-contract) fixture_contract="$2"; shift 2 ;;
        --evidence-root) evidence_root="$2"; shift 2 ;;
        --output) output_name="$2"; shift 2 ;;
        --record) record=1; shift ;;
        *) echo "unsupported argument: $1" >&2; exit 2 ;;
    esac
done

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

[[ "$fixture_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "fixture id must be a bounded identifier"
[[ -n "$evidence_root" ]] || fail "--evidence-root is required"
[[ -n "${WAYLAND_DISPLAY:-}" && -n "${HYPRLAND_INSTANCE_SIGNATURE:-}" ]] \
    || fail "Level C capture requires an existing Hyprland Wayland session"
[[ -f "$source_root/contracts/v010-workstation-acceptance.toml" ]] \
    || fail "Linura source root is missing the acceptance contract"
for command_name in git python3 sha256sum systemd-detect-virt Hyprland hyprctl install systemctl; do
    command -v "$command_name" >/dev/null || fail "required Level C command is missing: $command_name"
done
if [[ "$record" -eq 1 ]]; then
    for command_name in wf-recorder ffprobe systemd-run journalctl; do
        command -v "$command_name" >/dev/null || fail "recorded Level C capture requires: $command_name"
    done
fi

source_checkout_matches() {
    local current_sha current_status
    current_sha="$(git -C "$source_root" rev-parse HEAD 2>/dev/null)" || return 1
    [[ "$current_sha" == "$source_sha" ]] || return 1
    current_status="$(git -C "$source_root" status --porcelain=v1 --untracked-files=all 2>/dev/null)" || return 1
    [[ -z "$current_status" ]]
}

source_sha="$(git -C "$source_root" rev-parse HEAD)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "source HEAD is not an exact Git SHA"
source_checkout_matches || fail "Level C evidence requires a fully clean exact-source checkout"
fixture_check="$(python3 "$source_root/tools/workstation_acceptance.py" fixture-check \
    --fixture-contract "$fixture_contract" \
    --fixture-id "$fixture_id")"
fixture_contract_sha256="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])' <<<"$fixture_check")"
[[ "$fixture_contract_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "fixture contract digest is malformed"

set +e
virtualization="$(systemd-detect-virt 2>/dev/null)"
virtualization_status=$?
set -e
if [[ "$virtualization_status" -eq 0 ]]; then
    fail "Level C requires physical hardware; detected virtualization: ${virtualization:-unknown}"
fi
[[ "$virtualization_status" -eq 1 ]] \
    || fail "Level C physicality probe failed with status $virtualization_status"
[[ -z "$virtualization" || "$virtualization" == "none" ]] \
    || fail "Level C physicality probe returned an unexpected result: $virtualization"
virtualization="none"


# The recorder unit and its status files are global, so hold one global Level C
# lock across all fixture IDs, including unrecorded capture and publication.
# Refuse contention before inspecting the recorder or touching existing evidence.
capture_state_dir="$HOME/.local/state/linura/acceptance"
[[ ! -L "$capture_state_dir" ]] || fail "Level C capture state must not be a symlink"
install -d -m 0700 "$capture_state_dir"
capture_lock="$capture_state_dir/hardware-capture.lock"
umask 077
# A shell redirection would follow aliases and can truncate a hard-linked
# target before flock checks it. The helper opens O_NOFOLLOW/O_NONBLOCK without
# truncation, validates the directory and descriptor, then holds flock until
# this shell closes the coprocess pipe (including on EXIT/signals).
coproc capture_lock_holder {
    python3 -u "$source_root/tools/workstation_capture_lock.py" "$capture_lock"
}
if ! IFS= read -r capture_lock_state <&"${capture_lock_holder[0]}"; then
    fail "Level C capture lock helper exited before acquiring the global lock"
fi
case "$capture_lock_state" in
    LOCKED) ;;
    BUSY) fail "Level C capture already in progress (global recorder is reserved)" ;;
    *) fail "Level C capture lock is unsafe or unavailable" ;;
esac
# Also catch recorders started by older capture scripts, which held no lock.
recorder_unit="linura-workstation-recorder.service"
# A fresh or --collect-unloaded transient service is idle. Querying a missing
# unit with "show" can fail, so first verify the user manager via list-units.
recorder_units="$(systemctl --user list-units --all --full --plain --no-legend "$recorder_unit" 2>/dev/null)" \
    || fail "cannot inspect the Level C recorder service before capture"
if [[ -n "$recorder_units" ]]; then
    recorder_state="$(systemctl --user show --property=ActiveState --value "$recorder_unit" 2>/dev/null)" \
        || fail "cannot inspect the Level C recorder state before capture"
    [[ "$recorder_state" == "inactive" ]] \
        || fail "Level C recorder service is not idle: ${recorder_state:-unknown}"
fi


if [[ -L "$evidence_root" ]]; then
    fail "Level C evidence root must not be a symlink"
fi
evidence_root="$(realpath -m "$evidence_root")"
mkdir -p "$evidence_root"
evidence_root="$(cd "$evidence_root" && pwd)"
evidence_basename="hardware-$fixture_id"
snapshot_names=(virtualization.txt fixture-contract.sha256 hardware-session.txt)
safe_snapshot_destination() {
    local destination="$1"
    [[ ! -L "$destination" ]] || fail "Level C snapshot destination is a symlink: $destination"
    if [[ -e "$destination" ]]; then
        [[ -f "$destination" ]] \
            || fail "Level C snapshot destination is not a regular file: $destination"
        [[ "$(stat -c %h -- "$destination")" -eq 1 ]] \
            || fail "Level C snapshot destination has multiple hard links: $destination"
    fi
}
for snapshot_name in "${snapshot_names[@]}"; do
    safe_snapshot_destination "$evidence_root/$snapshot_name"
done
# One evidence root describes exactly one current fixture. Purge all fixture-keyed
# recordings and sidecars before replacing its globally named snapshots, even
# when the new capture is not recorded. Unlinking never opens a stale artifact.
stale_recordings=()
for stale_recording in "$evidence_root"/hardware-*.mkv \
        "$evidence_root"/hardware-*.metadata.json \
        "$evidence_root"/hardware-*.sha256; do
    [[ -e "$stale_recording" || -L "$stale_recording" ]] || continue
    [[ ! -d "$stale_recording" ]] || fail "stale Level C artifact is a directory: $stale_recording"
    stale_recordings+=("$stale_recording")
done
# Preflight every destination before unlinking any of them.
for stale_recording in "${stale_recordings[@]}"; do
    rm -f -- "$stale_recording" || fail "could not purge stale Level C evidence"
done
# Generate all snapshot data in fresh private files; never redirect into reused outputs.
snapshot_temporary_dir="$(mktemp -d "$evidence_root/.linura-snapshot.XXXXXXXX")"
trap 'rm -rf -- "$snapshot_temporary_dir"' EXIT
printf '%s\n' "$virtualization" > "$snapshot_temporary_dir/virtualization.txt"
printf '%s\n' "$fixture_contract_sha256" > "$snapshot_temporary_dir/fixture-contract.sha256"

{
    printf 'fixture_id=%s\n' "$fixture_id"
    printf 'fixture_contract_sha256=%s\n' "$fixture_contract_sha256"
    printf 'source_sha=%s\n' "$source_sha"
    printf 'virtualization=%s\n' "$virtualization"
    printf 'kernel=%s\n' "$(uname -srmo)"
    printf 'hyprland=%s\n' "$(Hyprland --version | head -n 1)"
    printf '%s\n' '-- monitors --'
    hyprctl monitors -j | python3 "$source_root/tools/workstation_acceptance.py" sanitize-monitors
    printf '%s\n' '-- drm --'
    for card in /sys/class/drm/card[0-9]*; do
        [[ -e "$card" ]] || continue
        device="$(readlink -f "$card/device" 2>/dev/null || true)"
        printf 'card=%s bdf=%s vendor=%s device=%s driver=%s\n' \
            "$(basename "$card")" \
            "$(basename "$device")" \
            "$(cat "$device/vendor" 2>/dev/null || true)" \
            "$(cat "$device/device" 2>/dev/null || true)" \
            "$(basename "$(readlink -f "$device/driver" 2>/dev/null || true)")"
    done
} > "$snapshot_temporary_dir/hardware-session.txt"
source_checkout_matches || fail "Level C source checkout changed before snapshot publication"
for snapshot_name in "${snapshot_names[@]}"; do
    safe_snapshot_destination "$evidence_root/$snapshot_name"
    mv -fT -- "$snapshot_temporary_dir/$snapshot_name" "$evidence_root/$snapshot_name"
done
rmdir "$snapshot_temporary_dir"
trap - EXIT

if [[ "$record" -eq 0 ]]; then
    if ! source_checkout_matches; then
        rm -f "$evidence_root/hardware-session.txt" \
            "$evidence_root/virtualization.txt" \
            "$evidence_root/fixture-contract.sha256"
        fail "Level C source checkout changed before snapshot finalization"
    fi
    printf 'Level C physical snapshot captured for maintained fixture %s without screen recording.\n' "$fixture_id"
    printf '%s\n' "This snapshot is supporting evidence only; all Q11 cases must pass before support promotion."
    exit 0
fi

# Stop intentionally before the verifier's hard duration limit, leaving a
# bounded margin for interrupt delivery and recorder finalization.
recording_duration_budget="$(python3 - "$source_root/contracts/v010-workstation-acceptance.toml" <<'PY'
import sys
import tomllib
with open(sys.argv[1], "rb") as handle:
    maximum = float(tomllib.load(handle)["recording"]["maximum_duration_seconds"])
if not 30 < maximum <= 86400:
    raise SystemExit("invalid bounded Level C recording duration")
print(int(maximum) - 30)
PY
)"
[[ "$recording_duration_budget" =~ ^[1-9][0-9]*$ ]] \
    || fail "Level C recording duration budget is invalid"
recording="$capture_state_dir/hardware-$fixture_id.mkv"
rm -f "$recording" "${recording%.mkv}.metadata.json" "${recording%.mkv}.sha256"
recorder="$source_root/qualification/v010/workstation-acceptance/record-session.sh"
recording_started=0
verified_recording_sha256=""
publication_tmp=""
cleanup() {
    local original_status=$?
    local cleanup_status=0
    local evidence_valid=1
    local recording_verification=""
    local recorder_stop_status=0
    local digest_parse_status=0
    local publication_digest_output=""
    local publication_digest=""
    local publication_verification=""
    local publication_sha256=""
    trap - EXIT
    set +e

    if ! source_checkout_matches; then
        printf 'FAIL: Level C source checkout changed before recording finalization\n' >&2
        cleanup_status=1
        evidence_valid=0
    fi

    if [[ "$recording_started" -eq 1 ]]; then
        if [[ "$evidence_valid" -eq 1 ]]; then
            recording_verification="$(
                LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha" \
                    "$recorder" stop "$recording" "$output_name"
            )"
            recorder_stop_status=$?
            if [[ "$recorder_stop_status" -ne 0 ]]; then
                cleanup_status="$recorder_stop_status"
                evidence_valid=0
            else
                verified_recording_sha256="$(
                    python3 -c 'import json,sys; value=json.load(sys.stdin).get("sha256"); print(value if isinstance(value,str) else "")' \
                        <<<"$recording_verification"
                )"
                digest_parse_status=$?
                if [[ "$digest_parse_status" -ne 0 || ! "$verified_recording_sha256" =~ ^[0-9a-f]{64}$ ]]; then
                    printf 'FAIL: Level C recorder did not return a valid verified recording digest\n' >&2
                    cleanup_status=1
                    evidence_valid=0
                fi
            fi
        else
            # Abort also waits for the status-writing helper to exit before
            # this EXIT trap releases the global capture lock.
            LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha" \
                "$recorder" abort "$recording" "$output_name" || cleanup_status=1
        fi
        recording_started=0
    fi

    if [[ "$evidence_valid" -eq 1 ]] && ! source_checkout_matches; then
        printf 'FAIL: Level C source checkout changed during recording finalization\n' >&2
        cleanup_status=1
        evidence_valid=0
    fi

    if [[ "$evidence_valid" -eq 1 ]]; then
        if [[ ! -f "$recording" || -L "$recording" ]]; then
            printf 'FAIL: Level C recording disappeared before evidence publication\n' >&2
            cleanup_status=1
            evidence_valid=0
        else
            publication_tmp="$(mktemp "$evidence_root/.${evidence_basename}.mkv.XXXXXXXX")"
            if [[ "$?" -ne 0 || -z "$publication_tmp" ]]; then
                printf 'FAIL: could not allocate private Level C recording publication file\n' >&2
                cleanup_status=1
                evidence_valid=0
            elif ! cp --reflink=never -- "$recording" "$publication_tmp"; then
                cleanup_status=1
                evidence_valid=0
            else
                publication_digest_output="$(sha256sum -- "$publication_tmp")"
                if [[ "$?" -ne 0 ]]; then
                    cleanup_status=1
                    evidence_valid=0
                else
                    publication_digest="${publication_digest_output%% *}"
                    if [[ ! "$publication_digest" =~ ^[0-9a-f]{64}$ ]]; then
                        printf 'FAIL: Level C publication digest is malformed\n' >&2
                        cleanup_status=1
                        evidence_valid=0
                    elif [[ "$publication_digest" != "$verified_recording_sha256" ]]; then
                        printf 'FAIL: Level C recording changed after recorder verification\n' >&2
                        cleanup_status=1
                        evidence_valid=0
                    elif ! mv -fT -- "$publication_tmp" "$evidence_root/$evidence_basename.mkv"; then
                        cleanup_status=1
                        evidence_valid=0
                    else
                        publication_tmp=""
                    fi
                fi
            fi
        fi
    fi

    if [[ -n "$publication_tmp" ]]; then
        rm -f -- "$publication_tmp"
        publication_tmp=""
    fi

    if [[ "$evidence_valid" -eq 1 ]]; then
        publication_verification="$(
            LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha" \
                python3 "$source_root/tools/workstation_acceptance.py" verify-recording \
                    "$evidence_root/$evidence_basename.mkv" \
                    --metadata "$evidence_root/$evidence_basename.metadata.json" \
                    --digest-file "$evidence_root/$evidence_basename.sha256" \
                    --source-sha "$source_sha"
        )"
        if [[ "$?" -ne 0 ]]; then
            cleanup_status=1
            evidence_valid=0
        else
            publication_sha256="$(
                python3 -c 'import json,sys; value=json.load(sys.stdin).get("sha256"); print(value if isinstance(value,str) else "")' \
                    <<<"$publication_verification"
            )"
            digest_parse_status=$?
            if [[ "$digest_parse_status" -ne 0 || ! "$publication_sha256" =~ ^[0-9a-f]{64}$ ]]; then
                printf 'FAIL: Level C published recording verifier returned an invalid digest\n' >&2
                cleanup_status=1
                evidence_valid=0
            elif [[ "$publication_sha256" != "$verified_recording_sha256" ]]; then
                printf 'FAIL: Level C published recording differs from the recorder-verified artifact\n' >&2
                cleanup_status=1
                evidence_valid=0
            fi
        fi
    fi

    if [[ "$evidence_valid" -eq 1 ]] && ! source_checkout_matches; then
        printf 'FAIL: Level C source checkout changed during evidence publication\n' >&2
        cleanup_status=1
        evidence_valid=0
    fi

    if [[ "$evidence_valid" -ne 1 ]]; then
        rm -f "$evidence_root/$evidence_basename.mkv" \
            "$evidence_root/$evidence_basename.metadata.json" \
            "$evidence_root/$evidence_basename.sha256"
    fi

    if ! source_checkout_matches; then
        rm -f "$evidence_root/hardware-session.txt" \
            "$evidence_root/virtualization.txt" \
            "$evidence_root/fixture-contract.sha256"
    fi

    if [[ "$original_status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
        exit "$cleanup_status"
    fi
    exit "$original_status"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

source_checkout_matches || fail "Level C source checkout changed before recorder start"
LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha" \
    "$recorder" start "$recording" "$output_name"
recording_started=1
capture_start_seconds="$SECONDS"
printf 'Level C physical capture active for maintained fixture %s. Press Ctrl-C to stop (automatic stop after %s seconds).\n' \
    "$fixture_id" "$recording_duration_budget"
printf '%s\n' "This capture is supporting evidence only; all Q11 cases must pass before support promotion."
while true; do
    systemctl --user is-active --quiet linura-workstation-recorder.service \
        || {
            echo "Level C recorder exited before requested stop" >&2
            exit 1
        }
    if (( SECONDS - capture_start_seconds >= recording_duration_budget )); then
        printf 'Level C recording budget reached; stopping recorder before the contract limit.\n'
        break
    fi
    sleep 1
done
