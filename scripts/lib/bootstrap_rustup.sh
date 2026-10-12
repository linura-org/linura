# shellcheck shell=bash

# Bootstrap a pinned rustup-init binary without leaking installer state into the
# caller. rustup-init is a multicall binary and must execute with the canonical
# `rustup-init` basename so argv[0]-based dispatch cannot treat a random mktemp
# basename as a rustup proxy name.
bootstrap_rustup() (
    set -euo pipefail

    if [[ $# -ne 3 ]]; then
        printf 'bootstrap_rustup expects URL, SHA-256, and target triple\n' >&2
        exit 64
    fi

    local -r rustup_init_url="$1"
    local -r rustup_init_sha256="$2"
    local -r rustup_target="$3"
    local rustup_init_dir rustup_init_path

    rustup_init_dir="$(mktemp -d)"
    rustup_init_path="${rustup_init_dir}/rustup-init"
    trap 'rm -rf -- "$rustup_init_dir"' EXIT

    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "$rustup_init_path" \
        "$rustup_init_url"
    printf '%s  %s\n' "$rustup_init_sha256" "$rustup_init_path" | sha256sum --check --strict
    chmod 0755 "$rustup_init_path"
    "$rustup_init_path" \
        -y \
        --no-modify-path \
        --profile minimal \
        --default-host "$rustup_target" \
        --default-toolchain none
)
