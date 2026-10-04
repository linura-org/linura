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
        exec python3 "$orchestrator" finalize-run --source-root "$source_root" "$@"
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
