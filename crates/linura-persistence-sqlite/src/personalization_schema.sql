CREATE TABLE personalization_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    integrity_fingerprint TEXT NOT NULL CHECK (length(integrity_fingerprint) = 71),
    authority_fingerprint TEXT NOT NULL CHECK (length(authority_fingerprint) = 71),
    schema_digest TEXT NOT NULL CHECK (length(schema_digest) = 71),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 0 AND 4096),
    chain_tip TEXT NOT NULL CHECK (length(chain_tip) = 71),
    last_write_unix_ms INTEGER NOT NULL CHECK (last_write_unix_ms >= 0),
    integrity_tag BLOB NOT NULL CHECK (length(integrity_tag) = 32)
) STRICT;
CREATE TABLE personalization_records (
    position INTEGER PRIMARY KEY CHECK (position BETWEEN 1 AND 4096),
    owner TEXT NOT NULL CHECK (length(CAST(owner AS BLOB)) BETWEEN 1 AND 256),
    request_id TEXT NOT NULL CHECK (length(CAST(request_id AS BLOB)) BETWEEN 1 AND 256),
    canonical BLOB NOT NULL CHECK (length(canonical) BETWEEN 1 AND 4096),
    record_digest TEXT NOT NULL CHECK (length(record_digest) = 71),
    chain_digest TEXT NOT NULL CHECK (length(chain_digest) = 71),
    issued_at_unix_ms INTEGER NOT NULL CHECK (issued_at_unix_ms > 0),
    expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms > issued_at_unix_ms),
    authority_tag BLOB NOT NULL CHECK (length(authority_tag) = 32),
    integrity_tag BLOB NOT NULL CHECK (length(integrity_tag) = 32),
    UNIQUE (owner, request_id)
) STRICT;
