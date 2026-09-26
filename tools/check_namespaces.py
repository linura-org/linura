#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib
import xml.etree.ElementTree as ET

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_STATUS = {"active", "reserved"}
ALLOWED_KINDS = {
    "application-id",
    "dbus-interface",
    "dbus-service",
    "desktop-id",
    "polkit-action",
    "qml-uri",
    "systemd-unit",
}
SYSTEMD_SUFFIXES = {
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".slice",
    ".swap",
}
RUST_CONST_PATTERN = re.compile(
    r'\b(?:pub\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"\s*;'
)
RUST_SERVE_AT_PATTERN = re.compile(
    r'\.serve_at\s*\(\s*([A-Z][A-Z0-9_]*|"[^"]+")\s*,'
)
RUST_BUS_NAME_PATTERN = re.compile(
    r'\.name\s*\(\s*([A-Z][A-Z0-9_]*|"[^"]+")\s*\)'
)
RUST_ZBUS_INTERFACE_PATTERN = re.compile(
    r'#\s*\[\s*(?:zbus::)?interface\s*\((.*?)\)\s*\]',
    re.DOTALL,
)
RUST_ZBUS_NAME_PATTERN = re.compile(r'\bname\s*=\s*"([^"]+)"')
RUST_AUTHORIZE_CALL_PATTERN = re.compile(
    r'\bauthorize_caller\s*\(\s*[^,]+,\s*([A-Z][A-Z0-9_]*|"[^"]+")\s*,',
    re.DOTALL,
)
RUST_ACTION_ARG_PATTERN = re.compile(
    r'"--action-id"(?:\s*\.to_owned\(\))?\s*,\s*([A-Z][A-Z0-9_]*|"[^"]+")'
)
CMAKE_QML_MODULE_PATTERN = re.compile(r"\bqt_add_qml_module\s*\((.*?)\)", re.DOTALL)
CMAKE_URI_PATTERN = re.compile(r"(?:^|\s)URI\s+([A-Za-z0-9_.]+)(?=\s|$)")
SYSTEMD_BUS_NAME_PATTERN = re.compile(
    r"(?m)^\s*BusName\s*=\s*([A-Za-z0-9_.-]+)\s*(?:#.*)?$"
)
DBUS_ACTIVATION_NAME_PATTERN = re.compile(
    r"(?m)^\s*Name\s*=\s*([A-Za-z0-9_.-]+)\s*(?:#.*)?$"
)
SYSTEMD_ALIAS_PATTERN = re.compile(
    r"(?m)^\s*Alias\s*=\s*([^#\n]*)"
)
RUST_SERVE_AT_BINDING_PATTERN = re.compile(
    r'\.serve_at\s*\(\s*([A-Z][A-Z0-9_]*|"[^"]+")\s*,\s*([A-Za-z_][A-Za-z0-9_:]*)\s*\)'
)


def _load_contract(root: Path) -> tuple[dict[str, object] | None, list[str]]:
    path = root / "contracts/namespaces.toml"
    if not path.is_file():
        return None, ["missing namespace contract: contracts/namespaces.toml"]
    try:
        return tomllib.loads(path.read_text(encoding="utf-8")), []
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, [f"cannot parse contracts/namespaces.toml: {error}"]


def _xml_values(path: Path, tag: str, attribute: str) -> list[str]:
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    return [
        value
        for node in root.iter(tag)
        if isinstance((value := node.attrib.get(attribute)), str) and value
    ]


def _xml_attribute_values(path: Path, attributes: tuple[str, ...]) -> set[str]:
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    values: set[str] = set()
    for node in root.iter():
        for attribute in attributes:
            value = node.attrib.get(attribute)
            if isinstance(value, str) and value:
                values.add(value)
    return values


CFG_TEST_PATTERN = re.compile(
    r'#\s*\[\s*cfg\s*\([^\]]*\btest\b[^\]]*\)\s*\]',
    re.DOTALL,
)


def _blank_non_newlines(characters: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(characters))):
        if characters[index] != "\n":
            characters[index] = " "


def _raw_string_end(text: str, start: int) -> int | None:
    if start >= len(text) or text[start] != "r":
        return None
    cursor = start + 1
    hash_count = 0
    while cursor < len(text) and text[cursor] == "#":
        hash_count += 1
        cursor += 1
    if cursor >= len(text) or text[cursor] != '"':
        return None
    terminator = '"' + ("#" * hash_count)
    end = text.find(terminator, cursor + 1)
    return len(text) if end < 0 else end + len(terminator)


def _skip_quoted_rust_token(text: str, start: int) -> int | None:
    raw_end = _raw_string_end(text, start)
    if raw_end is not None:
        return raw_end
    if text[start] != '"':
        return None
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _strip_rust_comments(text: str) -> str:
    characters = list(text)
    cursor = 0
    while cursor < len(text):
        quoted_end = _skip_quoted_rust_token(text, cursor)
        if quoted_end is not None:
            cursor = quoted_end
            continue
        if text.startswith("//", cursor):
            end = text.find("\n", cursor + 2)
            if end < 0:
                end = len(text)
            _blank_non_newlines(characters, cursor, end)
            cursor = end
            continue
        if text.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            _blank_non_newlines(characters, cursor, end)
            cursor = end
            continue
        cursor += 1
    return "".join(characters)


def _rust_item_end(text: str, start: int) -> int:
    cursor = start
    paren_depth = 0
    bracket_depth = 0
    while cursor < len(text):
        quoted_end = _skip_quoted_rust_token(text, cursor)
        if quoted_end is not None:
            cursor = quoted_end
            continue
        character = text[cursor]
        if character == "(":
            paren_depth += 1
        elif character == ")":
            paren_depth = max(0, paren_depth - 1)
        elif character == "[":
            bracket_depth += 1
        elif character == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif character == ";" and paren_depth == 0 and bracket_depth == 0:
            return cursor + 1
        elif character == "{" and paren_depth == 0 and bracket_depth == 0:
            depth = 1
            cursor += 1
            while cursor < len(text) and depth:
                quoted_end = _skip_quoted_rust_token(text, cursor)
                if quoted_end is not None:
                    cursor = quoted_end
                    continue
                if text[cursor] == "{":
                    depth += 1
                elif text[cursor] == "}":
                    depth -= 1
                cursor += 1
            return cursor
        cursor += 1
    return len(text)


def _strip_cfg_test_items(text: str) -> str:
    characters = list(text)
    spans: list[tuple[int, int]] = []
    for match in CFG_TEST_PATTERN.finditer(text):
        item_end = _rust_item_end(text, match.end())
        spans.append((match.start(), item_end))
    for start, end in reversed(spans):
        _blank_non_newlines(characters, start, end)
    return "".join(characters)


def _runtime_rust_text(path: Path) -> str:
    return _strip_cfg_test_items(_strip_rust_comments(path.read_text(encoding="utf-8")))


def _rust_sources(root: Path) -> list[Path]:
    workspace_manifest = root / "Cargo.toml"
    if not workspace_manifest.is_file():
        return []

    try:
        workspace = tomllib.loads(workspace_manifest.read_text(encoding="utf-8")).get("workspace", {})
    except (OSError, tomllib.TOMLDecodeError):
        return []

    members = workspace.get("members", []) if isinstance(workspace, dict) else []
    if not isinstance(members, list):
        return []

    paths: set[Path] = set()
    repository_root = root.resolve()
    for member in members:
        if not isinstance(member, str) or not member:
            continue
        if Path(member).is_absolute():
            continue
        if any(character in member for character in "*?["):
            member_roots = root.glob(member)
        else:
            member_roots = (root / member,)
        for member_root in member_roots:
            if not member_root.is_dir():
                continue
            resolved_member = member_root.resolve()
            try:
                resolved_member.relative_to(repository_root)
            except ValueError:
                continue
            source_root = resolved_member / "src"
            if source_root.is_dir():
                paths.update(path for path in source_root.rglob("*.rs") if path.is_file())
    return sorted(paths)


def _resolve_rust_constant(
    name: str,
    local: dict[str, str],
    global_values: dict[str, set[str]],
) -> str | None:
    if name in local:
        return local[name]
    values = global_values.get(name, set())
    if len(values) == 1:
        return next(iter(values))
    return None


def _rust_dbus_surfaces(
    root: Path,
) -> tuple[set[str], set[str], dict[str, set[str]], dict[str, set[str]], list[str]]:
    sources = _rust_sources(root)
    local_constants: dict[Path, dict[str, str]] = {}
    global_values: dict[str, set[str]] = {}
    texts: dict[Path, str] = {}
    failures: list[str] = []
    names: set[str] = set()
    services: set[str] = set()
    runtime_paths: dict[str, set[str]] = {}
    runtime_service_interfaces: dict[str, set[str]] = {}

    for path in sources:
        text = _runtime_rust_text(path)
        texts[path] = text
        constants = dict(RUST_CONST_PATTERN.findall(text))
        local_constants[path] = constants
        for name, value in constants.items():
            global_values.setdefault(name, set()).add(value)

        zbus_names: list[str] = []
        for arguments in RUST_ZBUS_INTERFACE_PATTERN.findall(text):
            interface_match = RUST_ZBUS_NAME_PATTERN.search(arguments)
            if interface_match is None:
                failures.append(
                    f"zbus::interface must declare a literal name in {path.relative_to(root)}"
                )
                continue
            zbus_names.append(interface_match.group(1))

        if zbus_names:
            interface_constants = {
                value
                for name, value in constants.items()
                if name == "INTERFACE_NAME" or name.endswith("_INTERFACE_NAME")
            }
            if len(zbus_names) != 1 or len(interface_constants) != 1:
                failures.append(
                    f"cannot bind zbus::interface to one local interface contract in {path.relative_to(root)}"
                )
            else:
                zbus_name = zbus_names[0]
                interface_name = next(iter(interface_constants))
                if zbus_name != interface_name:
                    failures.append(
                        f"zbus::interface/runtime contract mismatch in {path.relative_to(root)}: "
                        f"attribute {zbus_name}, local interface {interface_name}"
                    )
                names.add(zbus_name)

    for path in sources:
        text = texts[path]
        if "zbus" not in text:
            continue
        local = local_constants[path]

        if ".name" in text:
            for match in RUST_BUS_NAME_PATTERN.finditer(text):
                token = match.group(1)
                interface_name: str | None = None
                if token.startswith('"'):
                    service_name = token[1:-1]
                    interface_candidates = {
                        value
                        for name, value in local.items()
                        if name == "INTERFACE_NAME" or name.endswith("_INTERFACE_NAME")
                    }
                    if len(interface_candidates) == 1:
                        interface_name = next(iter(interface_candidates))
                else:
                    service_name = _resolve_rust_constant(token, local, global_values)
                    if service_name is None:
                        failures.append(
                            f"cannot resolve D-Bus service-name constant {token} in {path.relative_to(root)}"
                        )
                        continue
                    if token == "SERVICE_NAME":
                        interface_token = "INTERFACE_NAME"
                    elif token.endswith("_SERVICE_NAME"):
                        interface_token = f"{token[:-len('_SERVICE_NAME')]}_INTERFACE_NAME"
                    else:
                        interface_token = ""
                    if interface_token:
                        interface_name = _resolve_rust_constant(
                            interface_token,
                            local,
                            global_values,
                        )

                services.add(service_name)
                if interface_name is not None:
                    runtime_service_interfaces.setdefault(service_name, set()).add(interface_name)

        if ".serve_at" not in text:
            continue
        for match in RUST_SERVE_AT_PATTERN.finditer(text):
            token = match.group(1)
            if token.startswith('"'):
                object_path = token[1:-1]
                interface_candidates = [
                    value
                    for name, value in local.items()
                    if name == "INTERFACE_NAME" or name.endswith("_INTERFACE_NAME")
                ]
                if len(set(interface_candidates)) != 1:
                    failures.append(
                        f"cannot bind literal D-Bus serve_at path to one interface in {path.relative_to(root)}"
                    )
                    continue
                interface_name = interface_candidates[0]
            else:
                object_path = _resolve_rust_constant(token, local, global_values)
                if object_path is None:
                    failures.append(
                        f"cannot resolve D-Bus serve_at path constant {token} in {path.relative_to(root)}"
                    )
                    continue
                if token == "OBJECT_PATH":
                    interface_token = "INTERFACE_NAME"
                elif token.endswith("_OBJECT_PATH"):
                    interface_token = f"{token[:-len('_OBJECT_PATH')]}_INTERFACE_NAME"
                else:
                    failures.append(
                        f"cannot derive D-Bus interface constant for serve_at({token}, ...) in {path.relative_to(root)}"
                    )
                    continue
                interface_name = _resolve_rust_constant(
                    interface_token,
                    local,
                    global_values,
                )
                if interface_name is None:
                    failures.append(
                        f"cannot resolve D-Bus interface constant {interface_token} in {path.relative_to(root)}"
                    )
                    continue

            if not object_path.startswith("/"):
                continue
            names.add(interface_name)
            runtime_paths.setdefault(interface_name, set()).add(object_path)

    return names, services, runtime_paths, runtime_service_interfaces, failures


def _rust_polkit_actions(root: Path) -> tuple[set[str], list[str]]:
    sources = _rust_sources(root)
    local_constants: dict[Path, dict[str, str]] = {}
    global_values: dict[str, set[str]] = {}
    texts: dict[Path, str] = {}
    failures: list[str] = []
    actions: set[str] = set()

    for path in sources:
        text = _runtime_rust_text(path)
        texts[path] = text
        constants = dict(RUST_CONST_PATTERN.findall(text))
        local_constants[path] = constants
        for name, value in constants.items():
            global_values.setdefault(name, set()).add(value)

    for path in sources:
        text = texts[path]
        local = local_constants[path]
        tokens = list(RUST_AUTHORIZE_CALL_PATTERN.findall(text))
        tokens.extend(RUST_ACTION_ARG_PATTERN.findall(text))
        for token in tokens:
            if token.startswith('"'):
                action = token[1:-1]
            else:
                action = _resolve_rust_constant(token, local, global_values)
                if action is None:
                    failures.append(
                        f"cannot resolve Polkit action constant {token} in {path.relative_to(root)}"
                    )
                    continue
            actions.add(action)

    return actions, failures


def _runtime_binding_surfaces(
    root: Path,
) -> tuple[
    set[tuple[str, str, str]],
    set[tuple[str, str, str]],
    dict[tuple[str, str], str],
    dict[str, set[str]],
]:
    dbus_registrations: set[tuple[str, str, str]] = set()
    polkit_calls: set[tuple[str, str, str]] = set()
    constants: dict[tuple[str, str], str] = {}
    global_constants: dict[str, set[str]] = {}

    for path in _rust_sources(root):
        text = _runtime_rust_text(path)
        relative = path.relative_to(root).as_posix()
        local = dict(RUST_CONST_PATTERN.findall(text))
        for name, value in local.items():
            constants[(relative, name)] = value
            global_constants.setdefault(name, set()).add(value)

        for path_token, object_token in RUST_SERVE_AT_BINDING_PATTERN.findall(text):
            dbus_registrations.add((relative, path_token, object_token))

        for token in RUST_AUTHORIZE_CALL_PATTERN.findall(text):
            polkit_calls.add((relative, "authorize-caller", token))
        for token in RUST_ACTION_ARG_PATTERN.findall(text):
            polkit_calls.add((relative, "action-arg", token))

    return dbus_registrations, polkit_calls, constants, global_constants


def _resolve_runtime_binding_constant(
    source: str,
    token: str,
    constants: dict[tuple[str, str], str],
    global_constants: dict[str, set[str]],
) -> str | None:
    local_value = constants.get((source, token))
    if local_value is not None:
        return local_value
    values = global_constants.get(token, set())
    if len(values) == 1:
        return next(iter(values))
    return None


def _discover(
    root: Path,
) -> tuple[
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, set[str]],
    list[str],
]:
    discovered = {
        "application-id": set(),
        "dbus-interface": set(),
        "dbus-service": set(),
        "desktop-id": set(),
        "polkit-action": set(),
        "qml-uri": set(),
        "systemd-unit": set(),
    }
    failures: list[str] = []

    dbus_dir = root / "interfaces/dbus"
    if dbus_dir.is_dir():
        for path in sorted(dbus_dir.glob("*.xml")):
            try:
                names = _xml_values(path, "interface", "name")
            except (OSError, ET.ParseError) as error:
                failures.append(f"cannot inspect D-Bus interface {path.relative_to(root)}: {error}")
                continue
            if len(names) != 1:
                failures.append(
                    f"{path.relative_to(root)} must declare exactly one D-Bus interface, found {len(names)}"
                )
                continue
            name = names[0]
            if path.stem != name:
                failures.append(
                    f"D-Bus filename/interface mismatch: {path.relative_to(root)} declares {name!r}"
                )
            discovered["dbus-interface"].add(name)

    for relative_dir in ("packaging/dbus-1/system.d", "packaging/dbus-1/session.d"):
        dbus_policy_dir = root / relative_dir
        if not dbus_policy_dir.is_dir():
            continue
        for path in sorted(dbus_policy_dir.glob("*.conf")):
            try:
                owned_names = _xml_attribute_values(path, ("own",))
                owned_prefixes = _xml_attribute_values(path, ("own_prefix",))
            except (OSError, ET.ParseError) as error:
                failures.append(f"cannot inspect D-Bus policy {path.relative_to(root)}: {error}")
                continue
            discovered["dbus-service"].update(owned_names)
            for prefix in sorted(owned_prefixes):
                failures.append(
                    f"D-Bus policy {path.relative_to(root)} uses unsupported own_prefix {prefix!r}; "
                    "declare exact first-party names with own= instead"
                )

    for relative_dir in ("packaging/dbus-1/system-services", "packaging/dbus-1/services"):
        activation_dir = root / relative_dir
        if not activation_dir.is_dir():
            continue
        for path in sorted(activation_dir.glob("*.service")):
            text = path.read_text(encoding="utf-8")
            names = DBUS_ACTIVATION_NAME_PATTERN.findall(text)
            if len(names) != 1:
                failures.append(
                    f"{path.relative_to(root)} must declare exactly one D-Bus activation Name=, "
                    f"found {len(names)}"
                )
                continue
            discovered["dbus-service"].add(names[0])

    apps_dir = root / "apps"
    if apps_dir.is_dir():
        for path in sorted(apps_dir.rglob("CMakeLists.txt")):
            text = re.sub(r"(?m)#.*$", "", path.read_text(encoding="utf-8"))
            for arguments in CMAKE_QML_MODULE_PATTERN.findall(text):
                match = CMAKE_URI_PATTERN.search(arguments)
                if match is not None:
                    discovered["qml-uri"].add(match.group(1))

    for application_root in (root / "apps", root / "packaging"):
        if not application_root.is_dir():
            continue
        for path in sorted(application_root.rglob("*.desktop")):
            discovered["desktop-id"].add(path.stem)

        appstream_paths = set(application_root.rglob("*.metainfo.xml"))
        appstream_paths.update(application_root.rglob("*.appdata.xml"))
        for path in sorted(appstream_paths):
            try:
                document = ET.fromstring(path.read_text(encoding="utf-8"))
            except (OSError, ET.ParseError) as error:
                failures.append(f"cannot inspect AppStream metadata {path.relative_to(root)}: {error}")
                continue
            component_id = document.find("id")
            if component_id is None or not (component_id.text or "").strip():
                failures.append(f"{path.relative_to(root)} must declare a non-empty AppStream <id>")
                continue
            discovered["application-id"].add((component_id.text or "").strip())

    polkit_dir = root / "packaging/polkit-1/actions"
    if polkit_dir.is_dir():
        for path in sorted(polkit_dir.glob("*.policy")):
            try:
                discovered["polkit-action"].update(_xml_values(path, "action", "id"))
            except (OSError, ET.ParseError) as error:
                failures.append(f"cannot inspect Polkit policy {path.relative_to(root)}: {error}")

    systemd_dir = root / "packaging/systemd"
    if systemd_dir.is_dir():
        for path in sorted(systemd_dir.rglob("*")):
            if not path.is_file() or path.suffix not in SYSTEMD_SUFFIXES:
                continue
            discovered["systemd-unit"].add(path.name)
            text = path.read_text(encoding="utf-8")
            discovered["dbus-service"].update(SYSTEMD_BUS_NAME_PATTERN.findall(text))
            for alias_value in SYSTEMD_ALIAS_PATTERN.findall(text):
                discovered["systemd-unit"].update(alias_value.split())

        for path in sorted(systemd_dir.rglob("*.d/*.conf")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            discovered["dbus-service"].update(SYSTEMD_BUS_NAME_PATTERN.findall(text))
            for alias_value in SYSTEMD_ALIAS_PATTERN.findall(text):
                discovered["systemd-unit"].update(alias_value.split())

    rust_names, rust_services, runtime_paths, runtime_service_interfaces, rust_failures = (
        _rust_dbus_surfaces(root)
    )
    discovered["dbus-interface"].update(rust_names)
    discovered["dbus-service"].update(rust_services)
    failures.extend(rust_failures)

    rust_actions, rust_polkit_failures = _rust_polkit_actions(root)
    discovered["polkit-action"].update(rust_actions)
    failures.extend(rust_polkit_failures)

    return discovered, runtime_paths, runtime_service_interfaces, failures


def check(root: Path) -> list[str]:
    contract, failures = _load_contract(root)
    if contract is None:
        return failures

    if contract.get("schema_version") != 1:
        failures.append("contracts/namespaces.toml schema_version must be 1")

    authority = contract.get("authority")
    if not isinstance(authority, dict):
        failures.append("namespace contract must declare [authority]")
        return failures
    domain = authority.get("domain")
    reverse_dns = authority.get("reverse_dns")
    if domain != "linura.org":
        failures.append("namespace authority domain must remain linura.org")
    if reverse_dns != "org.linura":
        failures.append("reverse-DNS root must remain org.linura")
    reverse_prefix = f"{reverse_dns}." if isinstance(reverse_dns, str) else "org.linura."

    local = contract.get("local")
    if not isinstance(local, dict):
        failures.append("namespace contract must declare [local]")
    else:
        expected_local = {
            "bare_name": "linura",
            "component_prefix": "linura-",
            "daemon": "linurad",
            "control_cli": "linuractl",
        }
        for key, expected in expected_local.items():
            if local.get(key) != expected:
                failures.append(f"local namespace {key} must remain {expected!r}")

    filesystem = contract.get("filesystem")
    if not isinstance(filesystem, dict):
        failures.append("namespace contract must declare [filesystem]")
    else:
        expected_paths = {
            "config": "/etc/linura",
            "lib": "/usr/lib/linura",
            "share": "/usr/share/linura",
            "xdg_subdir": "linura",
        }
        for key, expected in expected_paths.items():
            if filesystem.get(key) != expected:
                failures.append(f"filesystem namespace {key} must remain {expected!r}")

    raw_identifiers = contract.get("identifier", [])
    if not isinstance(raw_identifiers, list) or not raw_identifiers:
        failures.append("namespace contract must declare at least one [[identifier]]")
        return failures

    declared: dict[tuple[str, str], str] = {}
    declared_dbus_paths: dict[str, str] = {}
    declared_dbus_service_interfaces: dict[str, str] = {}
    for index, item in enumerate(raw_identifiers, 1):
        if not isinstance(item, dict):
            failures.append(f"identifier #{index} must be a table")
            continue
        identifier = item.get("id")
        kind = item.get("kind")
        status = item.get("status")
        if not isinstance(identifier, str) or not identifier:
            failures.append(f"identifier #{index} has invalid id")
            continue
        if kind not in ALLOWED_KINDS:
            failures.append(f"{identifier}: unsupported namespace kind {kind!r}")
            continue
        if status not in ALLOWED_STATUS:
            failures.append(f"{identifier}: unsupported namespace status {status!r}")
            continue
        key = (kind, identifier)
        if key in declared:
            failures.append(f"duplicate namespace identifier: {kind} {identifier}")
        declared[key] = status

        if kind in {"application-id", "dbus-interface", "dbus-service", "desktop-id", "polkit-action", "qml-uri"}:
            if not identifier.startswith(reverse_prefix):
                failures.append(f"{kind} {identifier!r} must use {reverse_prefix}*")
        if kind == "systemd-unit":
            if not (identifier.startswith("linura-") or identifier.startswith("linurad.")):
                failures.append(f"systemd unit {identifier!r} must use the Linura unit namespace")

        if kind == "dbus-interface":
            object_path = item.get("object_path")
            if not isinstance(object_path, str) or not object_path.startswith("/org/linura/"):
                failures.append(f"{identifier}: D-Bus interface must declare /org/linura/* object_path")
            else:
                declared_dbus_paths[identifier] = object_path
            if "primary_interface" in item:
                failures.append(f"{identifier}: primary_interface is valid only for dbus-service entries")
        elif kind == "dbus-service":
            primary_interface = item.get("primary_interface")
            if not isinstance(primary_interface, str) or not primary_interface.startswith(reverse_prefix):
                failures.append(
                    f"{identifier}: D-Bus service must declare an {reverse_prefix}* primary_interface"
                )
            else:
                declared_dbus_service_interfaces[identifier] = primary_interface
            if "object_path" in item:
                failures.append(f"{identifier}: object_path is valid only for dbus-interface entries")
        else:
            if "object_path" in item:
                failures.append(f"{identifier}: object_path is valid only for dbus-interface entries")
            if "primary_interface" in item:
                failures.append(f"{identifier}: primary_interface is valid only for dbus-service entries")

    for service_name, primary_interface in sorted(declared_dbus_service_interfaces.items()):
        if ("dbus-interface", primary_interface) not in declared:
            failures.append(
                f"D-Bus service {service_name} references undeclared primary interface "
                f"{primary_interface}"
            )

    dbus_registration_items = contract.get("dbus_registration", [])
    polkit_binding_items = contract.get("polkit_binding", [])
    if not isinstance(dbus_registration_items, list):
        failures.append("namespace contract dbus_registration must be an array of tables")
        dbus_registration_items = []
    if not isinstance(polkit_binding_items, list):
        failures.append("namespace contract polkit_binding must be an array of tables")
        polkit_binding_items = []

    (
        runtime_dbus_registrations,
        runtime_polkit_calls,
        rust_constants,
        global_rust_constants,
    ) = _runtime_binding_surfaces(root)

    declared_runtime_dbus: set[tuple[str, str, str]] = set()
    for index, item in enumerate(dbus_registration_items, 1):
        if not isinstance(item, dict):
            failures.append(f"dbus_registration #{index} must be a table")
            continue
        source = item.get("source")
        path_token = item.get("path_token")
        object_token = item.get("object_token")
        interface = item.get("interface")
        if not all(isinstance(value, str) and value for value in (source, path_token, object_token, interface)):
            failures.append(f"dbus_registration #{index} has invalid fields")
            continue
        key = (source, path_token, object_token)
        if key in declared_runtime_dbus:
            failures.append(f"duplicate dbus_registration: {source}:{path_token}:{object_token}")
        declared_runtime_dbus.add(key)
        if ("dbus-interface", interface) not in declared:
            failures.append(
                f"dbus_registration {source}:{path_token}:{object_token} references undeclared interface {interface}"
            )
            continue
        if key not in runtime_dbus_registrations:
            failures.append(
                f"missing D-Bus runtime registration {source}: serve_at({path_token}, {object_token})"
            )
        object_path = _resolve_runtime_binding_constant(
            source,
            path_token,
            rust_constants,
            global_rust_constants,
        )
        expected_path = declared_dbus_paths.get(interface)
        if object_path is None:
            failures.append(
                f"cannot resolve D-Bus registration path token {path_token} in {source}"
            )
        elif expected_path is not None and object_path != expected_path:
            failures.append(
                f"D-Bus registration binding mismatch for {interface}: "
                f"{source}:{path_token} resolves to {object_path}, expected {expected_path}"
            )

    for source, path_token, object_token in sorted(runtime_dbus_registrations):
        if (source, path_token, object_token) not in declared_runtime_dbus:
            failures.append(
                f"undeclared D-Bus runtime registration {source}: "
                f"serve_at({path_token}, {object_token})"
            )

    declared_polkit_bindings: set[tuple[str, str, str]] = set()
    for index, item in enumerate(polkit_binding_items, 1):
        if not isinstance(item, dict):
            failures.append(f"polkit_binding #{index} must be a table")
            continue
        source = item.get("source")
        usage = item.get("usage")
        token = item.get("token")
        action = item.get("action")
        if not all(isinstance(value, str) and value for value in (source, usage, token, action)):
            failures.append(f"polkit_binding #{index} has invalid fields")
            continue
        if usage not in {"authorize-caller", "action-arg"}:
            failures.append(f"polkit_binding #{index} has unsupported usage {usage!r}")
            continue
        key = (source, usage, token)
        if key in declared_polkit_bindings:
            failures.append(f"duplicate polkit_binding: {source}:{usage}:{token}")
        declared_polkit_bindings.add(key)
        if ("polkit-action", action) not in declared:
            failures.append(
                f"polkit_binding {source}:{usage}:{token} references undeclared action {action}"
            )
        if key not in runtime_polkit_calls:
            failures.append(
                f"missing Polkit runtime binding {source}:{usage}:{token}"
            )
        resolved_action = _resolve_runtime_binding_constant(
            source,
            token,
            rust_constants,
            global_rust_constants,
        )
        if resolved_action is None:
            failures.append(f"cannot resolve Polkit action token {token} in {source}")
        elif resolved_action != action:
            failures.append(
                f"Polkit runtime binding mismatch for {source}:{usage}:{token}: "
                f"resolved {resolved_action}, expected {action}"
            )

    for source, usage, token in sorted(runtime_polkit_calls):
        if (source, usage, token) not in declared_polkit_bindings:
            failures.append(
                f"undeclared Polkit runtime binding {source}:{usage}:{token}"
            )

    discovered, runtime_paths, runtime_service_interfaces, discovery_failures = _discover(root)
    failures.extend(discovery_failures)
    for kind, values in discovered.items():
        for identifier in sorted(values):
            if (kind, identifier) not in declared:
                failures.append(f"undeclared repository {kind}: {identifier}")

    for interface_name, paths in sorted(runtime_paths.items()):
        expected_path = declared_dbus_paths.get(interface_name)
        if expected_path is None:
            continue
        for runtime_path in sorted(paths):
            if runtime_path != expected_path:
                failures.append(
                    f"D-Bus runtime object path mismatch for {interface_name}: "
                    f"declared {expected_path}, registered {runtime_path}"
                )

    for service_name, interfaces in sorted(runtime_service_interfaces.items()):
        expected_interface = declared_dbus_service_interfaces.get(service_name)
        if expected_interface is None:
            continue
        for runtime_interface in sorted(interfaces):
            if runtime_interface != expected_interface:
                failures.append(
                    f"D-Bus runtime service/interface mismatch for {service_name}: "
                    f"declared {expected_interface}, registered with {runtime_interface}"
                )

    for (kind, identifier), status in sorted(declared.items()):
        if kind in discovered and status == "active" and identifier not in discovered[kind]:
            failures.append(f"active {kind} is not present in repository surfaces: {identifier}")

    return failures


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: check_namespaces.py [root]", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_ROOT
    failures = check(root)
    if failures:
        for failure in failures:
            print(f"namespace contract failed: {failure}", file=sys.stderr)
        return 1
    print("namespace contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
