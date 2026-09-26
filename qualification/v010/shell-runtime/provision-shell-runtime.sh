#!/usr/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "provision-shell-runtime.sh must run as root" >&2
    exit 2
fi

user_name="${1:-linura}"
source_root="${2:-/opt/linura-source}"
linurad_binary="${3:-/tmp/linurad-qualification}"
user_home="$(getent passwd "$user_name" | cut -d: -f6)"

test -n "$user_home"
test -d "$source_root"
test -f "$source_root/apps/linura-shell/ui/CMakeLists.txt"
test -f "$source_root/apps/linura-shell/bridge/CMakeLists.txt"
test -f "$source_root/packaging/wireplumber/linura-session-audio.lua"
test -f "$source_root/packaging/systemd/user/linurad.service"
[[ -f "$linurad_binary" && ! -L "$linurad_binary" ]] || {
    echo "exact-source linurad qualification binary is missing or untrusted" >&2
    exit 1
}

install -d -o root -g root -m 0755 /usr/local/lib/linura-qualification
install -o root -g root -m 0755     "$source_root/qualification/v010/shell-runtime/fixtures/linger-app"     /usr/local/lib/linura-qualification/linger-app
install -o root -g root -m 0755     "$source_root/qualification/v010/shell-runtime/fixtures/forking-app"     /usr/local/lib/linura-qualification/forking-app

install -d -o "$user_name" -g "$user_name" -m 0755 "$user_home/.local/share/applications"
for desktop in "$source_root"/qualification/v010/shell-runtime/fixtures/*.desktop; do
    install -o "$user_name" -g "$user_name" -m 0644         "$desktop" "$user_home/.local/share/applications/$(basename "$desktop")"
done

install -d -o "$user_name" -g "$user_name" -m 0755 "$user_home/.config/systemd/user"
install -o "$user_name" -g "$user_name" -m 0644     "$source_root/qualification/v010/shell-runtime/fixtures/linura-shell-qualification.service"     "$user_home/.config/systemd/user/linura-shell-qualification.service"
install -o "$user_name" -g "$user_name" -m 0644     "$source_root/qualification/v010/shell-runtime/fixtures/linura-palette-qualification.service"     "$user_home/.config/systemd/user/linura-palette-qualification.service"
install -o "$user_name" -g "$user_name" -m 0644     "$source_root/qualification/v010/shell-runtime/fixtures/linura-quick-settings-qualification.service"     "$user_home/.config/systemd/user/linura-quick-settings-qualification.service"
install -o "$user_name" -g "$user_name" -m 0644     "$source_root/packaging/systemd/user/linurad.service"     "$user_home/.config/systemd/user/linurad.service"

install -o root -g root -m 0755 "$linurad_binary" /usr/bin/linurad
install -d -o root -g root -m 0755 /usr/lib/linura
install -o root -g root -m 0644     "$source_root/packaging/wireplumber/linura-session-audio.lua"     /usr/lib/linura/linura-session-audio.lua

bridge_build_dir=/tmp/linura-shell-bridge-qualification-build
rm -rf "$bridge_build_dir"
cmake     -S "$source_root/apps/linura-shell/bridge"     -B "$bridge_build_dir"     -G Ninja     -DCMAKE_BUILD_TYPE=Release     -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build "$bridge_build_dir" --parallel 2
cmake --install "$bridge_build_dir"

bridge_module_dir=/usr/local/lib/qt6/qml/org/linura/ShellBridge
bridge_plugin="$bridge_module_dir/liblinura-shell-bridgeplugin.so"
bridge_backing="$bridge_module_dir/liblinura-shell-bridge.so"
if [[ ! -f "$bridge_module_dir/qmldir" || ! -f "$bridge_plugin" || ! -f "$bridge_backing" ]]; then
    echo "Linura ShellBridge QML module dependency closure did not install to the expected qualification prefix" >&2
    find "$bridge_module_dir" -maxdepth 1 -type f -print 2>/dev/null >&2 || true
    exit 1
fi
bridge_linkage="$(ldd "$bridge_plugin")"
printf '%s\n' "$bridge_linkage"
if grep -Fq 'not found' <<<"$bridge_linkage"; then
    echo "Linura ShellBridge QML plugin has unresolved installed dependencies" >&2
    exit 1
fi
grep -Fq "liblinura-shell-bridge.so => $bridge_backing" <<<"$bridge_linkage" || {
    echo "Linura ShellBridge QML plugin did not resolve its backing library from the module directory" >&2
    exit 1
}

build_dir=/tmp/linura-ui-qualification-build
rm -rf "$build_dir"
cmake     -S "$source_root/apps/linura-shell/ui"     -B "$build_dir"     -G Ninja     -DCMAKE_BUILD_TYPE=Release     -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build "$build_dir" --parallel 2
cmake --install "$build_dir"

ui_module_dir=/usr/local/lib/qt6/qml/org/linura/UI
ui_plugin="$ui_module_dir/liblinura-uiplugin.so"
ui_backing="$ui_module_dir/liblinura-ui.so"
if [[ ! -f "$ui_module_dir/qmldir" || ! -f "$ui_plugin" || ! -f "$ui_backing" ]]; then
    echo "Linura UI QML module dependency closure did not install to the expected qualification prefix" >&2
    find "$ui_module_dir" -maxdepth 1 -type f -print 2>/dev/null >&2 || true
    exit 1
fi

ui_linkage="$(ldd "$ui_plugin")"
printf '%s\n' "$ui_linkage"
if grep -Fq 'not found' <<<"$ui_linkage"; then
    echo "Linura UI QML plugin has unresolved installed dependencies" >&2
    exit 1
fi
grep -Fq "liblinura-ui.so => $ui_backing" <<<"$ui_linkage" || {
    echo "Linura UI QML plugin did not resolve its backing library from the module directory" >&2
    exit 1
}

loginctl enable-linger "$user_name"
chown -R "$user_name:$user_name" "$user_home/.config" "$user_home/.local"

{
    sha256sum /usr/bin/linurad
    sha256sum /usr/lib/linura/linura-session-audio.lua
    stat -c '%U:%G %a %h %n' /usr/bin/linurad /usr/lib/linura/linura-session-audio.lua
}

echo "v0.10 shell runtime guest provisioning complete"
