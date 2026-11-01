# S26 WIP offline read-only CLI

The new linuractl library-list command enumerates the existing user's
SQLite local Library with bounded keyset pagination, exact stable identity
and immutable revision. It requires an existing database path. It does
not create a Library, run a migration, authenticate for writes, invoke
Control, declare machine convergence or use a model provider.

Example:
  linuractl library-list /path/to/library.db setups 32
  linuractl library-list /path/to/library.db profiles 32 profile:previous-id

The app uses the SDK and actual LocalLibrary typed catalog, not an
alternative UI schema. An optional exact after-ID cursor is only
navigation, not a consistent cross-page epoch. The SQLite connection is
opened READ_ONLY; the database content cannot be written by this handle,
although SQLite WAL coordination may use filesystem sidecars.

Command metadata and help are updated. Source-only WIP, pending pinned
fmt, Clippy, actual Rust/CLI tests and native qualification.
