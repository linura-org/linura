#!/usr/bin/env python3
"""Validate Linura's canonical desktop application identity.

This is intentionally a repository-level pre-Flathub gate. It validates stable
identity and cross-file invariants without pretending the planned graphical
client is already releasable. Full Flathub/AppStream linting is enabled only
once real application screenshots, release metadata, and a buildable Flatpak
manifest exist.
"""

from __future__ import annotations

import configparser
import hashlib
from pathlib import Path
import xml.etree.ElementTree as ET


APP_ID = "org.linura.Linura"
BRAND_BLUE = "#ADF2FF"
BASE = Path("apps/linura-control-center/data")
METAINFO = BASE / f"{APP_ID}.metainfo.xml"
DESKTOP = BASE / f"{APP_ID}.desktop"
ICON = BASE / "icons/hicolor/scalable/apps" / f"{APP_ID}.svg"
# Git blob ID of linura-platform's canonical blue transparent square SVG:
# public/brand/blue/exports/icons/pwa-icon-512x512-transparent.svg
CANONICAL_ICON_GIT_BLOB = "b3bf10b29762d605ad0818dfb081d86fe03e0a98"


def fail(message: str) -> None:
    raise SystemExit(f"desktop identity validation failed: {message}")


def require_text(element: ET.Element | None, expected: str, field: str) -> None:
    if element is None or (element.text or "").strip() != expected:
        fail(f"{field} must be {expected!r}")


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


for required in (METAINFO, DESKTOP, ICON):
    if not required.is_file():
        fail(f"missing required file: {required}")

try:
    metainfo_root = ET.parse(METAINFO).getroot()
except ET.ParseError as exc:
    fail(f"invalid MetaInfo XML: {exc}")

if local_name(metainfo_root.tag) != "component":
    fail("MetaInfo root must be <component>")
if metainfo_root.get("type") != "desktop-application":
    fail('MetaInfo component type must be "desktop-application"')

require_text(metainfo_root.find("id"), APP_ID, "MetaInfo id")
require_text(metainfo_root.find("name"), "Linura", "MetaInfo name")
require_text(
    metainfo_root.find("summary"),
    "The intelligent system layer for Linux",
    "MetaInfo summary",
)
require_text(
    metainfo_root.find("metadata_license"),
    "CC0-1.0",
    "MetaInfo metadata license",
)
require_text(
    metainfo_root.find("project_license"),
    "Apache-2.0",
    "MetaInfo project license",
)

developer = metainfo_root.find("developer")
if developer is None or developer.get("id") != "org.linura":
    fail('MetaInfo developer id must be "org.linura"')
require_text(developer.find("name"), "Linura", "MetaInfo developer name")

launchables = metainfo_root.findall("launchable")
if len(launchables) != 1:
    fail("MetaInfo must contain exactly one launchable")
launchable = launchables[0]
if launchable.get("type") != "desktop-id":
    fail('MetaInfo launchable type must be "desktop-id"')
require_text(launchable, f"{APP_ID}.desktop", "MetaInfo launchable")

homepage = None
for url in metainfo_root.findall("url"):
    if url.get("type") == "homepage":
        homepage = (url.text or "").strip()
        break
if homepage != "https://linura.org":
    fail("MetaInfo homepage must be https://linura.org")

brand_colors = {
    (color.get("type"), color.get("scheme_preference")): (color.text or "").strip()
    for color in metainfo_root.findall("./branding/color")
}
for scheme in ("light", "dark"):
    if brand_colors.get(("primary", scheme)) != BRAND_BLUE:
        fail(f"MetaInfo {scheme} primary brand color must be {BRAND_BLUE}")

for control in metainfo_root.findall("./requires/control"):
    fail(
        "input controls must not be hard installation requirements; "
        f"move {((control.text or '').strip() or '<empty>')!r} under <recommends>"
    )

recommended_controls = {
    (control.text or "").strip()
    for control in metainfo_root.findall("./recommends/control")
}
if recommended_controls != {"keyboard", "pointing"}:
    fail(
        "MetaInfo must recommend exactly the keyboard and pointing controls "
        f"(got {sorted(recommended_controls)!r})"
    )

parser = configparser.ConfigParser(interpolation=None, strict=True)
parser.optionxform = str
try:
    with DESKTOP.open("r", encoding="utf-8") as handle:
        parser.read_file(handle)
except configparser.Error as exc:
    fail(f"invalid desktop entry: {exc}")

if parser.sections() != ["Desktop Entry"]:
    fail("desktop file must contain exactly one [Desktop Entry] section")

entry = parser["Desktop Entry"]
expected_desktop = {
    "Type": "Application",
    "Name": "Linura",
    "Comment": "The intelligent system layer for Linux",
    "Exec": "linura-control-center",
    "Icon": APP_ID,
    "Terminal": "false",
}
for key, expected in expected_desktop.items():
    if entry.get(key) != expected:
        fail(f"desktop field {key} must be {expected!r}")

icon_bytes = ICON.read_bytes()
git_blob_payload = f"blob {len(icon_bytes)}\0".encode("ascii") + icon_bytes
icon_git_blob = hashlib.sha1(git_blob_payload).hexdigest()
if icon_git_blob != CANONICAL_ICON_GIT_BLOB:
    fail(
        "icon bytes must exactly match the pinned canonical blue transparent "
        f"asset (expected Git blob {CANONICAL_ICON_GIT_BLOB}, got {icon_git_blob})"
    )

try:
    svg_root = ET.fromstring(icon_bytes)
except ET.ParseError as exc:
    fail(f"invalid SVG icon: {exc}")

if local_name(svg_root.tag) != "svg":
    fail("icon root must be <svg>")
if svg_root.get("viewBox") != "0 0 512 512":
    fail('icon must preserve the square "0 0 512 512" brand canvas')
if (svg_root.get("color") or "").upper() != BRAND_BLUE:
    fail(f"icon must preserve canonical blue {BRAND_BLUE}")

print(f"validated canonical desktop identity: {APP_ID}")
