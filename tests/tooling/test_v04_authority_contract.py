from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "crates/linura-control/src/durable_authority.rs"
TRANSACTION = ROOT / "crates/linura-transaction/src/lib.rs"
SQLITE_STORE = ROOT / "crates/linura-persistence-sqlite/src/store.rs"
SQLITE_SCHEMA = ROOT / "crates/linura-persistence-sqlite/src/schema.rs"
SQLITE_VALIDATION = ROOT / "crates/linura-persistence-sqlite/src/validation.rs"
SQLITE_INTEGRITY = ROOT / "crates/linura-persistence-sqlite/src/integrity.rs"
MIGRATION_V1_DESCRIPTOR = (
    ROOT / "migrations/system/0001-hardened-authority-transactions.json"
)
MIGRATION_V2_DESCRIPTOR = (
    ROOT / "migrations/system/0002-terminal-recovery-opener-headroom.json"
)
ADR = ROOT / "docs/adr/0020-sealed-durable-mutation-authority.md"


class V04AuthorityContractTests(unittest.TestCase):
    def test_authority_key_consumes_non_copy_container(self) -> None:
        text = TRANSACTION.read_text(encoding="utf-8")
        self.assertIn("pub fn new(mut bytes: Vec<u8>)", text)
        self.assertNotIn("bytes: [u8; AUTHORITY_MUTATION_KEY_BYTES]", text)
        self.assertIn("validate_authority_key_bytes(&mut bytes)?", text)
        validation = text[
            text.index("fn validate_authority_key_bytes") : text.index(
                "impl TransactionAuthorityKey"
            )
        ]
        self.assertIn("bytes.zeroize();", validation)
        self.assertIn("InvalidAuthorityKey", validation)
        self.assertEqual(text.count("self.bytes.zeroize();"), 3)

    def test_all_sensitive_mutations_are_sealed(self) -> None:
        text = TRANSACTION.read_text(encoding="utf-8")
        self.assertIn("pub fn verify_handoff", text)
        self.assertIn("pub fn verify_recovery", text)
        self.assertIn("pub fn verify_commit", text)
        self.assertIn("authorized_at_unix_ms", text)
        self.assertIn("expires_at_unix_ms", text)
        commit = text[text.index("pub struct CommitRequest") : text.index("pub struct AbortRequest")]
        self.assertNotIn("pub transaction_id:", commit)
        self.assertIn("authority_tag:", commit)

    def test_control_startup_cleanup_and_commit_are_mandatory(self) -> None:
        text = CONTROL.read_text(encoding="utf-8")
        constructor = text[text.index("pub fn new(") : text.index("pub fn candidate(")]
        self.assertIn("control.abort_prepared_after_restart()?", constructor)
        self.assertIn("pub fn commit_verified", text)
        self.assertNotIn("pub fn into_store", text)
        self.assertIn("VerifiedDurableAuthority", text)

    def test_sqlite_checks_freshness_under_lock_and_blocks_replace_delete(self) -> None:
        store = SQLITE_STORE.read_text(encoding="utf-8")
        schema = SQLITE_SCHEMA.read_text(encoding="utf-8")
        validation = SQLITE_VALIDATION.read_text(encoding="utf-8")
        self.assertIn("enforce_authority_window", store)
        self.assertIn("verify_commit(request)", store)
        self.assertIn("PRAGMA recursive_triggers=ON", validation)
        self.assertIn("CREATE TRIGGER generations_no_delete", schema)
        self.assertIn("CREATE TRIGGER transactions_no_delete", schema)
        self.assertIn("integrity_tag", schema)

    def test_integrity_key_uses_non_elidable_atomic_scrubbing(self) -> None:
        text = SQLITE_INTEGRITY.read_text(encoding="utf-8")
        self.assertIn("AtomicU8::from_mut(byte).store(0, Ordering::SeqCst)", text)
        self.assertIn("validate_integrity_key_bytes(&mut bytes)?", text)
        self.assertNotIn("self.bytes.fill(0)", text)

    def test_authority_store_migration_chain_is_registered_and_ledger_verified(self) -> None:
        v1 = json.loads(MIGRATION_V1_DESCRIPTOR.read_text(encoding="utf-8"))
        v2 = json.loads(MIGRATION_V2_DESCRIPTOR.read_text(encoding="utf-8"))
        schema = SQLITE_SCHEMA.read_text(encoding="utf-8")
        validation = SQLITE_VALIDATION.read_text(encoding="utf-8")

        self.assertEqual(v1["schema_version"], 1)
        self.assertEqual(v1["id"], "0001-v04-hardened-authority-transactions")
        self.assertEqual(v1["introduced_in"], "0.4.0")
        self.assertEqual(v1["scope"], "system")
        self.assertFalse(v1["reversible"])
        self.assertFalse(v1["requires_snapshot"])
        self.assertIn("sqlite.application_id == 0", v1["preconditions"])
        self.assertIn("sqlite.user_version == 0", v1["preconditions"])
        self.assertIn(
            "sqlite_schema contains no non-SQLite application objects",
            v1["preconditions"],
        )
        self.assertEqual(v1["verification"]["ledger"], "schema_migrations")
        self.assertEqual(
            v1["verification"]["ledger_id"],
            "0001-v04-hardened-authority-transactions",
        )
        self.assertEqual(
            v1["verification"]["checksum_domain"],
            "linura.sqlite.migration.v1",
        )

        self.assertEqual(v2["schema_version"], 1)
        self.assertEqual(v2["id"], "0002-v04-terminal-recovery-opener-headroom")
        self.assertEqual(v2["introduced_in"], "0.4.0")
        self.assertEqual(v2["scope"], "system")
        self.assertFalse(v2["reversible"])
        self.assertFalse(v2["requires_snapshot"])
        self.assertIn("sqlite.user_version == 1", v2["preconditions"])
        self.assertIn(
            "schema_migrations contains exactly the canonical 0001-v04-hardened-authority-transactions checksum",
            v2["preconditions"],
        )
        self.assertIn(
            "installed SQLite schema fingerprint matches immutable MIGRATION_V1",
            v2["preconditions"],
        )
        self.assertEqual(v2["verification"]["ledger"], "schema_migrations")
        self.assertEqual(
            v2["verification"]["ledger_id"],
            "0002-v04-terminal-recovery-opener-headroom",
        )
        self.assertEqual(
            v2["verification"]["checksum_domain"],
            "linura.sqlite.migration.v2",
        )

        self.assertIn(
            'MIGRATION_ID: &str = "0001-v04-hardened-authority-transactions"',
            schema,
        )
        self.assertIn(
            'MIGRATION_V2_ID: &str = "0002-v04-terminal-recovery-opener-headroom"',
            schema,
        )
        self.assertIn("pub(crate) const MIGRATION_V2: &str", schema)
        self.assertIn("SELECT length(CAST(checksum AS BLOB))", validation)
        self.assertIn("migration_v1_checksum()", validation)
        self.assertIn("migration_v2_checksum()", validation)
        self.assertIn(
            "validate_migration_entry(connection, MIGRATION_ID",
            validation,
        )
        self.assertIn(
            "validate_migration_entry(connection, MIGRATION_V2_ID",
            validation,
        )
        self.assertIn("expected_v1_schema_fingerprint()", validation)

    def test_adr_describes_keyed_tamper_detection_not_sql_gate(self) -> None:
        text = ADR.read_text(encoding="utf-8")
        lower = text.lower()
        self.assertNotIn("linura_internal_mutation_gate", text)
        self.assertIn("raw sqlite writes can physically alter", lower)
        self.assertIn("record-integrity", lower)
        self.assertIn("coherent rollback", lower)


if __name__ == "__main__":
    unittest.main()
