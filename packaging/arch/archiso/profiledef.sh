#!/usr/bin/env bash
# shellcheck shell=bash
iso_name="linura"
iso_label="LINURA_DEV"
iso_publisher="Linura Project"
iso_application="Linura OS development image"
iso_version="0.1.0-dev"
install_dir="linura"
buildmodes=("iso")
bootmodes=("bios.syslinux.mbr" "bios.syslinux.eltorito" "uefi-x64.systemd-boot.esp" "uefi-x64.systemd-boot.eltorito")
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=("-comp" "zstd" "-Xcompression-level" "15")
file_permissions=(
  ["/usr/lib/linura/linura-session-audio.lua"]="0:0:0644"
)
