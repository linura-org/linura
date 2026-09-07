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
    "crates/linura-library/src/adoption.rs",
    "use crate::{\n    AdoptionReport, IntentRevisionRef, LibraryError, LifecycleRecordKind, LocalLibrary,\n    SetupRevisionRef, StoredIntent, StoredSetup,\n};",
    "use crate::{\n    AdoptionReport, LibraryError, LifecycleRecordKind, LocalLibrary, StoredIntent, StoredSetup,\n};",
)
replace_once(
    "crates/linura-library/src/adoption.rs",
    "    use linura_intent::{Intent, Setup};",
    "    use linura_intent::{Intent, Setup};\n    use crate::{IntentRevisionRef, SetupRevisionRef};",
)
replace_once(
    "crates/linura-library/src/adoption.rs",
    '''        assert_eq!(
            library
                .intent_history(&id(IntentId::new("intent:portable")))
                .map(|v| v.len()),
            Ok(1)
        );''',
    '''        assert_eq!(
            library
                .intent_history(&id(IntentId::new("intent:portable")))
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            1
        );''',
)
replace_once(
    "crates/linura-library/src/store.rs",
    '''        (None, None) if proposed > 0 => Ok(()),
        (None, Some(expected)) => Err(LibraryError::RevisionConflict {''',
    '''        (None, None) if proposed > 0 => Ok(()),
        (None, None) => Err(LibraryError::Validation(format!(
            "{kind} revision must be positive"
        ))),
        (None, Some(expected)) => Err(LibraryError::RevisionConflict {''',
)
