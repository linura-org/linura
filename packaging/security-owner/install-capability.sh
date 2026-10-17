#!/usr/bin/bash
# Fixed package-install operation, not a privileged runtime API. Run only inside
# the target image/package transaction after its final ownership is established.
set -euo pipefail
[[ "$EUID" = 0 && "$#" = 0 ]] || exit 78
for directory in /usr /usr/lib /usr/lib/linura; do
    [[ -d "$directory" && ! -L "$directory" ]] || exit 78
    read -r owner mode < <(/usr/bin/stat -c '%u %a' -- "$directory")
    [[ "$owner" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || exit 78
    (((8#$mode & 0022) == 0)) || exit 78
done
image=/usr/lib/linura/linura-security-owner
[[ -f "$image" && ! -L "$image" && -x "$image" ]] || exit 78
read -r owner links mode < <(/usr/bin/stat -c '%u %h %a' -- "$image")
[[ "$owner" = 0 && "$links" = 1 && "$mode" = 755 ]] || exit 78
/usr/bin/setcap cap_ipc_lock=ep "$image"
[[ "$(/usr/bin/getcap -n "$image")" = "$image cap_ipc_lock=ep" ]] || exit 78
