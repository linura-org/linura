#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement for {old!r}, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def expose_store_helpers() -> None:
    path = ROOT / "crates/linura-library/src/store.rs"
    text = path.read_text(encoding="utf-8")
    old = "pub struct LocalLibrary {\n    connection: Connection,\n    path: Option<PathBuf>,\n}"
    new = "pub struct LocalLibrary {\n    pub(crate) connection: Connection,\n    path: Option<PathBuf>,\n}"
    if old not in text:
        raise SystemExit("LocalLibrary connection marker not found")
    text = text.replace(old, new, 1)
    names = [
        "insert_intent_revision",
        "load_intent_revision",
        "current_intent_state",
        "insert_setup_revision",
        "load_setup_revision",
        "insert_profile_revision",
        "load_profile_revision",
        "latest_setup_revision",
        "latest_profile_revision",
        "append_lifecycle_record_tx",
        "record_operation",
        "replay_operation",
    ]
    for name in names:
        pattern = rf"(?m)^fn {re.escape(name)}\("
        text, count = re.subn(pattern, f"pub(crate) fn {name}(", text, count=1)
        if count != 1:
            raise SystemExit(f"store helper {name} not found exactly once")
    path.write_text(text, encoding="utf-8")


def fix_profile_closure() -> None:
    path = ROOT / "crates/linura-library/src/portable.rs"
    text = path.read_text(encoding="utf-8")
    old = '''    for reference in &bundle.profile.setup_revisions {
        let key = (reference.id.as_str().to_owned(), reference.revision);
        if !setup_map.contains_key(&key) {
            return Err(LibraryError::PortableFormat(format!(
                "profile references missing setup {}@{}",
                reference.id.as_str(),
                reference.revision
            )));
        }
        validate_reachable_setup_closure(&key, &setup_map, &intent_map)?;
    }
    Ok(())
}'''
    new = '''    for reference in &bundle.profile.setup_revisions {
        let key = (reference.id.as_str().to_owned(), reference.revision);
        if !setup_map.contains_key(&key) {
            return Err(LibraryError::PortableFormat(format!(
                "profile references missing setup {}@{}",
                reference.id.as_str(),
                reference.revision
            )));
        }
    }
    validate_profile_closure(&bundle.profile, &setup_map, &intent_map)
}'''
    if old not in text:
        raise SystemExit("profile closure loop marker not found")
    text = text.replace(old, new, 1)
    marker = "\nfn detect_setup_cycles("
    helper = r'''
fn validate_profile_closure(
    profile: &StoredProfile,
    setups: &BTreeMap<(String, u32), &StoredSetup>,
    intents: &BTreeMap<(String, u64), &StoredIntent>,
) -> Result<(), LibraryError> {
    let mut pending = profile
        .setup_revisions
        .iter()
        .map(|reference| (reference.id.as_str().to_owned(), reference.revision))
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    let mut referenced_intents = profile
        .intent_revisions
        .iter()
        .map(|reference| (reference.id.as_str().to_owned(), reference.revision))
        .collect::<BTreeSet<_>>();

    while let Some(key) = pending.pop() {
        if !visited.insert(key.clone()) {
            continue;
        }
        let setup = setups.get(&key).ok_or_else(|| {
            LibraryError::PortableFormat("profile closure contains missing setup revision".into())
        })?;
        for reference in &setup.intent_revisions {
            referenced_intents.insert((reference.id.as_str().to_owned(), reference.revision));
        }
        for reference in &setup.included_revisions {
            pending.push((reference.id.as_str().to_owned(), reference.revision));
        }
    }

    if visited.len() != setups.len() {
        return Err(LibraryError::PortableFormat(
            "profile bundle contains unrelated setup revisions outside the profile closure".into(),
        ));
    }
    if referenced_intents.len() != intents.len()
        || referenced_intents
            .iter()
            .any(|key| !intents.contains_key(key))
    {
        return Err(LibraryError::PortableFormat(
            "profile bundle contains missing or unrelated intent revisions".into(),
        ));
    }
    Ok(())
}
'''
    if marker not in text:
        raise SystemExit("portable cycle marker not found")
    text = text.replace(marker, "\n" + helper + marker, 1)
    path.write_text(text, encoding="utf-8")


def update_contracts() -> None:
    replace_once(
        "contracts/components.toml",
        'scope = "typed intent/setup semantics; durable intent lifecycle remains v0.7.0"',
        'scope = "typed intent/setup semantics integrated with the durable local Library lifecycle at v0.7.0"',
    )
    components = ROOT / "contracts/components.toml"
    text = components.read_text(encoding="utf-8")
    marker = '[[component]]\nid = "linura-persistence-sqlite"'
    addition = '''[[component]]
id = "linura-library"
path = "crates/linura-library"
kind = "crate"
workspace_member = true
maturity = "integrated-experimental"
activation_milestone = "v0.7.0"
release_artifact = false
authority_role = "declarative-library"
scope = "local-first durable intent/setup/profile Library and portable adoption; no approval or executor authority"

'''
    if marker not in text:
        raise SystemExit("components insertion marker not found")
    text = text.replace(marker, addition + marker, 1)
    components.write_text(text, encoding="utf-8")

    layering = ROOT / "contracts/layering.toml"
    text = layering.read_text(encoding="utf-8")
    marker = '[[rules]]\npackage = "linura-control"'
    addition = '''[[rules]]
package = "linura-library"
forbid_local = ["linura-dbus", "linura-linux-observation", "linura-observation-control", "linura-provider-sdk", "linura-control", "linura-policy", "linura-agent-runtime", "linura-transaction", "linura-persistence-sqlite"]
forbid_local_prefixes = ["linura-executor-", "linura-verifier-"]
forbid_external = ["zbus"]

'''
    if marker not in text:
        raise SystemExit("layering insertion marker not found")
    text = text.replace(marker, addition + marker, 1)
    layering.write_text(text, encoding="utf-8")

    replace_once(
        "scripts/check_repository.py",
        '    "crates/linura-planner/Cargo.toml", "crates/linura-provenance/Cargo.toml", "crates/linura-agent-runtime/Cargo.toml",',
        '    "crates/linura-planner/Cargo.toml", "crates/linura-provenance/Cargo.toml", "crates/linura-library/Cargo.toml", "crates/linura-agent-runtime/Cargo.toml",',
    )

    sdk = ROOT / "crates/linura-sdk/src/lib.rs"
    text = sdk.read_text(encoding="utf-8")
    old = "pub use linura_library::{\n    AdoptionReport,"
    new = "pub use linura_library::{\n    AdoptionContext, AdoptionReport,"
    if old not in text:
        raise SystemExit("SDK Library export marker not found")
    sdk.write_text(text.replace(old, new, 1), encoding="utf-8")


if __name__ == "__main__":
    expose_store_helpers()
    fix_profile_closure()
    update_contracts()
