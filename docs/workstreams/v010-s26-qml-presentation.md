# S26 workstation QML presentation on the WIP branch

These four first-party QML views consume only host-supplied, bounded Library
projection data: catalog navigation, Setup draft, MachineProfile draft, and
untrusted portable import review. They use the native Linura UI module;
LinuraText renders plain text, not markup. Selection and draft saves are
signals for a trusted host to validate, not local authority or executor access.

By default all write actions are disabled, and import review exposes no
commit button. Labels explicitly distinguish locally saved revisions from
actual verified OS state. All views remain disconnected until a qualified,
authenticated ShellBridge-to-Control source is implemented, tested, and
independently accepted. No QML element directly opens paths or invokes
external system effects.

The native QML and shell-module builds, interactive accessibility, evidence
recordings, and physical Q11 qualification are NOT executed by adding these
files. These are work-in-progress presentation components, not a claim that
S26-6 is complete.
