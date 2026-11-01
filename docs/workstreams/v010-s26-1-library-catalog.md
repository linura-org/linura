# S26-1 bounded catalog implementation boundary

This is a read-only addition to the released LocalLibrary database. It does
not register new Control operations, enable a machine effect, create a shadow
SQLite database, change durable schema v1 or portable format v1, or assert
physical workstation qualification.

The typed SDK exposes CatalogPage and MAX_CATALOG_PAGE_SIZE. Three LocalLibrary
methods perform ordered keyset pagination over actual stored Intent, Setup and
MachineProfile rows. Each page is read in a single SQLite read transaction and
includes the exact current immutable revision and stored child revision refs.
Page sizes are restricted to 1 through 128. Missing, invalid and corrupt records
fail closed. The existing APIs own full graph closure, revision histories,
causal ownership and portable export; this implementation does not duplicate
those mechanisms.

A pagination cursor is not a database epoch, current authorization, complete
catalog snapshot or machine-state proof. Multiple pages can observe different
commits. Before local save or OS planning, callers must reopen the exact source,
revalidate current principal and exact revision/closure and use trusted Control.

Native tests cover duplicate titles, exact old revision, page boundaries,
SQLite close/reopen, profile references, invalid sizes and read-only behavior.
Run the new test and released v0.7 through v0.9 regressions, rustfmt, clippy,
canonical CI, security and applicable native qualification on the exact PR SHA.
This commit is not a claim of completed S26, GUI functionality, fresh
authenticated transport, Q10, Q11 or other S26 PR outcomes.
