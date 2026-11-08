#!/usr/bin/bash
# Fixed package-transaction operation for the pinned compositor. Never run by
# Control, an agent, a session client or ordinary task-time environment setup.
set -euo pipefail
[[ "$EUID" = 0 && "$#" = 0 ]] || exit 78
for directory in / /etc /usr /usr/bin /usr/lib /usr/lib/sysusers.d; do
    [[ -d "$directory" && ! -L "$directory" ]] || exit 78
    read -r owner mode < <(/usr/bin/stat -c '%u %a' -- "$directory")
    [[ "$owner" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || exit 78
    (((8#$mode & 0022) == 0)) || exit 78
done
group_file=/usr/lib/sysusers.d/linura-display-entry.conf
image=/usr/bin/Hyprland
for file in "$group_file" "$image"; do
    [[ -f "$file" && ! -L "$file" ]] || exit 78
    read -r owner links mode < <(/usr/bin/stat -c '%u %h %a' -- "$file")
    [[ "$owner" = 0 && "$links" = 1 && "$mode" =~ ^[0-7]{3,4}$ ]] || exit 78
    (((8#$mode & 0022) == 0)) || exit 78
done
[[ -x "$image" && ("$mode" = 755 || "$mode" = 2755) ]] || exit 78
file_capabilities=$(/usr/bin/getcap -n "$image") || exit 78
[[ -z "$file_capabilities" ]] || exit 78
/usr/bin/systemd-sysusers "$group_file"
for database in /etc/group /etc/passwd; do
    [[ -f "$database" && ! -L "$database" ]] || exit 78
    read -r owner links mode size < <(/usr/bin/stat -c '%u %h %a %s' -- "$database")
    [[ "$owner" = 0 && "$links" = 1 && "$mode" =~ ^[0-7]{3,4}$ ]] || exit 78
    (((8#$mode & 0022) == 0 && size <= 262144)) || exit 78
done
# Local files only: NSS must not select the product's secure-entry identity.
entry_gid=$(/usr/bin/awk -F: '
    /^#/ || /^$/ { next }
    NF != 4 || $3 !~ /^(0|[1-9][0-9]*)$/ || length($3) > 10 || $3 >= 4294967295 { bad=1; exit 78 }
    { count[$3]++ }
    $1 == "linura-display-entry" { selected++; gid=$3; if ($4 != "" || $3 == 0) { bad=1; exit 78 } }
    END { if (bad || selected != 1 || count[gid] != 1) exit 78; print gid }
' /etc/group)
/usr/bin/awk -F: -v entry_gid="$entry_gid" '
    /^#/ || /^$/ { next }
    NF != 7 || $4 !~ /^(0|[1-9][0-9]*)$/ || length($4) > 10 || $4 >= 4294967295 || $4 == entry_gid { exit 78 }
' /etc/passwd
# This group owns no Linura state, devices, sockets or privileged mechanism.
# It exists solely for the kernel's exec-time loader protection. The compositor
# drops it to the original login group before reading configuration.
# Remove setgid before any ownership change; a failed or ambiguous transition
# must leave ordinary non-elevated permissions. Force a numeric GID: GNU chgrp
# otherwise prefers an identically named numeric group from NSS.
/usr/bin/chmod 0755 -- "$image"
/usr/bin/chgrp -- "+$entry_gid" "$image"
read -r owner actual_gid mode links < <(/usr/bin/stat -c '%u %g %a %h' -- "$image")
[[ "$owner" = 0 && "$actual_gid" = "$entry_gid" && "$mode" = 755 && "$links" = 1 ]] || exit 78
/usr/bin/chmod 2755 -- "$image"
read -r owner actual_gid mode links < <(/usr/bin/stat -c '%u %g %a %h' -- "$image")
[[ "$owner" = 0 && "$actual_gid" = "$entry_gid" && "$mode" = 2755 && "$links" = 1 ]] || exit 78
