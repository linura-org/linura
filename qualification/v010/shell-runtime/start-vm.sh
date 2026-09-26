#!/usr/bin/bash
set -euo pipefail

image=""
seed=""
ssh_port=2223
memory=6144
cpus=4
nic_mac=""
persistent=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) image="$2"; shift 2 ;;
        --seed) seed="$2"; shift 2 ;;
        --ssh-port) ssh_port="$2"; shift 2 ;;
        --memory) memory="$2"; shift 2 ;;
        --cpus) cpus="$2"; shift 2 ;;
        --nic-mac) nic_mac="$2"; shift 2 ;;
        --persistent) persistent=1; shift ;;
        *) echo "unsupported argument: $1" >&2; exit 2 ;;
    esac
done

[[ -f "$image" ]] || { echo "image not found: $image" >&2; exit 2; }
[[ -f "$seed" ]] || { echo "seed not found: $seed" >&2; exit 2; }
[[ "$ssh_port" =~ ^[0-9]+$ ]] || { echo "invalid ssh port" >&2; exit 2; }
[[ "$memory" =~ ^[0-9]+$ ]] || { echo "invalid memory" >&2; exit 2; }
[[ "$cpus" =~ ^[0-9]+$ ]] || { echo "invalid cpu count" >&2; exit 2; }
[[ "$nic_mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || { echo "invalid NIC MAC" >&2; exit 2; }

snapshot_args=(-snapshot)
if [[ "$persistent" -eq 1 ]]; then
    snapshot_args=()
fi

exec qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -cpu max \
    -m "$memory" \
    -smp "$cpus" \
    -drive "file=$image,if=virtio,format=qcow2" \
    -drive "file=$seed,if=virtio,format=raw,readonly=on" \
    -vga none \
    -device virtio-gpu-pci,id=linura-qualification-gpu,bus=pcie.0,addr=0x2 \
    -nic "user,model=virtio-net-pci,mac=$nic_mac,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -display none \
    -serial mon:stdio \
    "${snapshot_args[@]}"
