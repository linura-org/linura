#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement for {old!r}, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "crates/linura-library/tests/v07_qualification.rs",
    "    assert_eq!(reopened.schema_version(), Ok(LIBRARY_SCHEMA_VERSION));",
    '''    assert_eq!(
        reopened
            .schema_version()
            .unwrap_or_else(|error| unreachable!("{error}")),
        LIBRARY_SCHEMA_VERSION
    );''',
)
replace_once(
    "crates/linura-library/tests/v07_qualification.rs",
    "    assert_eq!(reopened.integrity_check(), Ok(()));",
    '''    reopened
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));''',
)
replace_once(
    "crates/linura-library/tests/v07_qualification.rs",
    "    assert_eq!(restored.integrity_check(), Ok(()));",
    '''    restored
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));''',
)
replace_once(
    "crates/linura-library/tests/v07_qualification.rs",
    "    assert_eq!(preserved.integrity_check(), Ok(()));",
    '''    preserved
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));''',
)
