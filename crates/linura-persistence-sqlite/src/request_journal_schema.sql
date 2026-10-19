CREATE TABLE request_journal_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    format INTEGER NOT NULL CHECK (format = 1),
    integrity_fingerprint TEXT NOT NULL CHECK (length(integrity_fingerprint) = 71),
    schema_digest TEXT NOT NULL CHECK (length(schema_digest) = 71),
    integrity_tag BLOB NOT NULL CHECK (length(integrity_tag) = 32)
) STRICT;
CREATE TABLE retained_requests (
    principal TEXT NOT NULL CHECK (length(CAST(principal AS BLOB)) BETWEEN 1 AND 256),
    request_id TEXT NOT NULL CHECK (length(CAST(request_id AS BLOB)) BETWEEN 1 AND 256),
    format INTEGER NOT NULL CHECK (format = 1),
    canonical BLOB NOT NULL CHECK (length(canonical) BETWEEN 1 AND 262144),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    integrity_tag BLOB NOT NULL CHECK (length(integrity_tag) = 32),
    PRIMARY KEY (principal, request_id)
) STRICT, WITHOUT ROWID;
