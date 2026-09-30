#!/usr/bin/bash
set -euo pipefail

fixture_id=""
evidence_root=""
output_name=""
source_root="${LINURA_SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixture-id) fixture_id="$2"; shift 2 ;;
        --evidence-root) evidence_root="$2"; shift 2 ;;
        --output) output_name="$2"; shift 2 ;;
        *) echo "unsupported argument: $1" >&2; exit 2 ;;
    esac
done

[[ "$fixture_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || {
    echo "fixture id must be a bounded identifier" >&2
    exit 2
}
[[ -n "$evidence_root" ]] || {
    echo "--evidence-root is required" >&2
    exit 2
}
[[ -n "${WAYLAND_DISPLAY:-}" && -n "${HYPRLAND_INSTANCE_SIGNATURE:-}" ]] || {
    echo "Level C capture requires an existing Hyprland Wayland session" >&2
    exit 2
}
[[ -f "$source_root/contracts/v010-workstation-acceptance.toml" ]] || {
    echo "Linura source root is missing the acceptance contract" >&2
    exit 2
}
source_sha="$(git -C "$source_root" rev-parse HEAD)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
if ! git -C "$source_root" diff --quiet || ! git -C "$source_root" diff --cached --quiet; then
    echo "Level C evidence requires a clean exact-source checkout" >&2
    exit 1
fi

if [[ -L "$evidence_root" ]]; then
    echo "Level C evidence root must not be a symlink" >&2
    exit 1
fi
evidence_root="$(realpath -m "$evidence_root")"
mkdir -p "$evidence_root"
recording="$HOME/.local/state/linura/acceptance/hardware-$fixture_id.mkv"
rm -f "$recording" "${recording%.mkv}.metadata.json" "${recording%.mkv}.sha256"

{
    printf 'fixture_id=%s\n' "$fixture_id"
    printf 'source_sha=%s\n' "$source_sha"
    printf 'kernel=%s\n' "$(uname -srmo)"
    printf 'hyprland=%s\n' "$(Hyprland --version | head -n 1)"
    printf '%s\n' '-- monitors --'
    hyprctl monitors -j
    printf '%s\n' '-- drm --'
    for card in /sys/class/drm/card[0-9]*; do
        [[ -e "$card" ]] || continue
        device="$(readlink -f "$card/device" 2>/dev/null || true)"
        printf 'card=%s bdf=%s vendor=%s device=%s driver=%s\n'             "$(basename "$card")"             "$(basename "$device")"             "$(cat "$device/vendor" 2>/dev/null || true)"             "$(cat "$device/device" 2>/dev/null || true)"             "$(basename "$(readlink -f "$device/driver" 2>/dev/null || true)")"
    done
} > "$evidence_root/hardware-session.txt"

recorder="$source_root/qualification/v010/workstation-acceptance/record-session.sh"
recording_started=0
cleanup() {
    set +e
    if [[ "$recording_started" -eq 1 ]]; then
        LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha"             "$recorder" stop "$recording" "$output_name"
        recording_started=0
    fi
    cp "$recording" "$evidence_root/workstation-hardware.mkv" 2>/dev/null || true
    cp "${recording%.mkv}.metadata.json" "$evidence_root/workstation-hardware.metadata.json" 2>/dev/null || true
    cp "${recording%.mkv}.sha256" "$evidence_root/workstation-hardware.sha256" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

LINURA_SOURCE_ROOT="$source_root" LINURA_SOURCE_SHA="$source_sha"     "$recorder" start "$recording" "$output_name"
recording_started=1
printf 'Level C hardware capture active for fixture %s. Press Ctrl-C to stop.\n' "$fixture_id"
while true; do sleep 1; done
