#!/usr/bin/bash
set -euo pipefail

command_name="${1:-}"
shift || true
source_root="${LINURA_SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
tool="$source_root/tools/workstation_acceptance.py"
orchestrator="$source_root/tools/workstation_q11_runner.py"
capture="$source_root/qualification/v010/workstation-acceptance/capture-hardware-session.sh"

case "$command_name" in
    plan)
        exec python3 "$tool" plan --mode hardware --display none --json "$@"
        ;;
    doctor)
        exec python3 "$tool" doctor --mode hardware --display none "$@"
        ;;
    cases)
        exec python3 "$tool" hardware-cases --json "$@"
        ;;
    case-request)
        exec python3 "$tool" hardware-case-request "$@"
        ;;
    run-requests)
        exec python3 "$tool" hardware-run-requests "$@"
        ;;
    begin-run)
        exec python3 "$orchestrator" begin-run --source-root "$source_root" "$@"
        ;;
    record-case)
        exec python3 "$orchestrator" record-case --source-root "$source_root" "$@"
        ;;
    finalize-run)
        state_root=""
        state_root_count=0
        arguments=("$@")
        for ((index = 0; index < ${#arguments[@]}; index++)); do
            argument="${arguments[$index]}"
            case "$argument" in
                --state-root)
                    state_root_count=$((state_root_count + 1))
                    [[ "$state_root_count" -eq 1 ]] || {
                        printf '%s\n' "finalize-run accepts exactly one --state-root" >&2
                        exit 2
                    }
                    next=$((index + 1))
                    [[ "$next" -lt "${#arguments[@]}" && "${arguments[$next]}" != --* ]] || {
                        printf '%s\n' "finalize-run requires a value for --state-root" >&2
                        exit 2
                    }
                    state_root="${arguments[$next]}"
                    index=$next
                    ;;
                --state-root=*)
                    state_root_count=$((state_root_count + 1))
                    [[ "$state_root_count" -eq 1 ]] || {
                        printf '%s\n' "finalize-run accepts exactly one --state-root" >&2
                        exit 2
                    }
                    state_root="${argument#--state-root=}"
                    [[ -n "$state_root" ]] || {
                        printf '%s\n' "finalize-run requires a value for --state-root" >&2
                        exit 2
                    }
                    ;;
            esac
        done
        [[ "$state_root_count" -eq 1 && -n "$state_root" ]] || {
            printf '%s\n' "finalize-run requires --state-root for execution-envelope publication" >&2
            exit 2
        }
        python3 "$orchestrator" finalize-run --source-root "$source_root" "$@"
        source_sha="$(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/git -C "$source_root" rev-parse HEAD)"
        envelope="$state_root/qualification-execution-envelope.json"
        /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
            /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" \
            create-physical --state-root "$state_root" --output "$envelope"
        /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
            /usr/bin/python3 -I "$source_root/tools/qualification_envelope.py" --root "$source_root" \
            verify --envelope "$envelope" --source-sha "$source_sha"
        ;;
    status)
        exec python3 "$orchestrator" status --source-root "$source_root" "$@"
        ;;
    fixture-check)
        exec python3 "$tool" fixture-check "$@"
        ;;
    capture)
        exec "$capture" "$@"
        ;;
    *)
        printf '%s\n' "usage: run-hardware-qualification.sh {plan|doctor|cases|case-request|run-requests|begin-run|record-case|finalize-run|status|fixture-check|capture} [arguments]" >&2
        printf '%s\n' "Level C is the physical Q11 execution boundary; this runner cannot set release evidence readiness." >&2
        exit 2
        ;;
esac
