#!/usr/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "provision-shell-runtime.sh must run as root" >&2
    exit 2
fi

user_name="${1:-linura}"
source_root="${2:-/opt/linura-source}"
user_home="$(getent passwd "$user_name" | cut -d: -f6)"

test -n "$user_home"
test -d "$source_root"
test -f "$source_root/apps/linura-shell/ui/CMakeLists.txt"

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

echo "v0.10 shell runtime guest provisioning complete"
