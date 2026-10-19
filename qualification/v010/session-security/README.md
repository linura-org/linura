# S17 native qualification fixture

This fixture extends the repository's existing pinned Arch/Hyprland QEMU lane.
It is not a new workstation runner, production credential store or support
promotion mechanism. The VM uses the exact triggering source, fresh Linura
release binaries and production image asset installer. Native bootstrap retains
the unchanged secure-exec, native session, Polkit and root-supervision guards.

See the [candidate internal review and open acceptance boundary](../../../docs/qualification/s17-internal-review.md).

`provision-native-session.py` refuses non-root, non-QEMU/KVM, wrong-hostname,
non-Arch and non-root-immutable source contexts. It creates a genuine local
PAM/logind Wayland session with Hyprland executing as its actual leader.
`check-native-session.py` checks automatic first-login owner activation, native
identity, installed capability and post-drop process state. Its report explicitly
does **not** qualify PAM authentication or complete S17.
It also compares the installed suspend gate, restricted sleep-mode configuration,
private bus policy and private XML against bounded root-immutable exact-source
bytes, retaining their digests. Installed-byte checks explicitly do not qualify
gate enforcement, automatic locking or suspend/resume correctness.

`run-same-uid-probes.py` runs the unprivileged owner's real memory/environment/
auxiliary-vector open and `PTRACE_SEIZE` denial probes. It temporarily removes
Yama inside the disposable guest, so ambient Yama restrictions cannot be mistaken
for the owner's secure-exec protection. It restores the original reversible
setting on ordinary errors, deadlines and handled cancellation. Forced process
death cannot guarantee cleanup; the workflow discards that VM and cannot admit a
passing report. The probe never reads protected bytes, stops the owner, injects
signals or enables ptrace `EXITKILL`. A permitted attach is a failure, not evidence
to be relabelled. These cases do not prove compositor integrity, authentication,
pointer/accessibility, power transitions or the entire security matrix.

`native_input.py` is a bounded private QMP hardware-input adapter for subsequent
native authentication/interaction cases. The shared VM launcher accepts an
optional `--qmp-socket` only inside a runner-owned mode-0700 directory, never TCP
or a reused socket. It adds a qualification-only USB tablet. The adapter exposes
only hardware key/pointer events and a narrowly bounded native-suspend wake;
no human-monitor command, shell, guest agent or arbitrary QMP operation. Wake
requires actual machine support and independently observed suspended state,
and never authorizes or initiates guest sleep. Component fake-server tests are
not execution evidence. These checks follow the official
[QMP wake contract](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-system-wakeup).
There are no retained positive PAM/power cases merely because this input channel
is implemented; those native cases and digest-bound retained reports remain
required before S17 acceptance.

`qualify-native-auth.py` extends that same lane with real hardware confirmation,
the unchanged distribution PAM/Polkit owner conversation, Control restart and
observe-only committed-lock recovery, explicit enable/revoke consent, superseded
consent history, native cancellation, one incorrect-response denial and exact
verified managed unlock. A timeout on the incorrect response proves only that it
did not complete unlock, not the PAM stack's specific rejection reason. It uses
fresh random responses through private stdin and QMP only. The fixed guest helper
refuses every non-disposable context and an initially usable account password;
it does not replace PAM, relax production checks or add a Polkit allow rule.
Cleanup locks the disposable account, including after ordinary failures. A forced
runner death cannot guarantee cleanup: discard that VM, never retain it.
It also independently locks the disposable account password and requires the
correct response not to complete unlock while that lock is present. The same
ephemeral response is restored only through private stdin before the positive
unlock. This proves noncompletion under the independently observed account
condition, not a particular PAM error message or full account-expiry coverage.
Account rejection may precede a prompt; that case alone accepts an actual early
exit-1 denial without sending input. SSH failure, timeout and exit-0 success
remain failures. Cancellation and wrong-response cases still require interaction.
The runner respects the native five-second failure cooldown between negative
conversations; it never restarts the owner, resets attempts or shortens that
production protection to obtain a later positive result.
Authentication and suspend reports retain the validated nonsecret managed
receipts, not just check booleans. Restart recovery must preserve every original
request/resource/transaction/effect field; valid-looking replacement digests fail.
Consent history must preserve the approved record, and unlock history must name
the same committed transaction. Native assistive reports retain the exact owner
invocation/start identity and phase. No response bytes, account hashes, approval
seals or executor credentials enter these reports.

Reports are emitted only after all assertions and cleanup succeed, then bound to
bootstrap, exact-source binary identity and runner-source digests. They explicitly
do not qualify power, hotplug, compositor failure, native accessibility, physical
Q11 or complete S17. Component/mocked tests of this runner are not native evidence.
The new native cases have not yet been executed or retained as S17 acceptance.

The authentication runner also requires actual AT-SPI registry discovery of the
supervised native owner's locked and password-prompt presentations. The separate
`native-assistive-probe.cpp` client is built from exact source in the disposable
guest, with no product install target or authentication/input handles. A fixed
root guest wrapper validates immutable fixture ancestry, an unprivileged and
capability-free probe image, and the owner's PID, systemd invocation and process
start identity before and after each probe. The host binds that invocation to
the exact lock resource. Transport errors, owner replacement, unexpected report
fields and type aliases cannot become positive evidence.

These cases inspect the native registry's actual application/dialog/password
tree and require remote edit, action and relabel attempts to be rejected. Reports
and the built probe/source digests are retained with authentication evidence.
They remain **unexecuted** until that lane runs. They do not qualify Orca speech,
pointer interaction, scaling, hotplug or physical Q11, and never assert complete
accessibility or S17 support.

`qualify-native-suspend.py` adds actual managed suspend/resume, independently
verified kernel-cycle/secure-coverage completion, Control restart with observe-only
transition recovery, then purpose-bound owner unlock. Its fixed guest helper
submits through production `linuractl` from a supervised service, after the SSH
login ends. Other-session predicates, inhibitors, native administrator PAM and
the protective gate are never bypassed. The helper cannot accept arbitrary
commands, native direct-suspend requests or response text. Private bounded records
are not execution authority; a queue receipt, transport failure, QMP wake reply or
historical transaction alone cannot qualify completion. The original queue
identity and exact lock/transition generation must survive every result check.

`qualify-native-transition.py` adds logout, reboot and power-off cases. A fixed
root-supervised disposable-guest helper submits one production managed request
as the actual owner after other logins end. Its root-private write-once submission
record prevents worker restart from resubmitting; queued state is not authority
or evidence of dispatch. File and parent-directory synchronization retain the
exact request, purpose and original lock generation across orderly shutdown.

Reboot/power-off require a guest-originated QMP event, then an independently
different boot and production native postcondition verification. Host signals,
disconnects, acknowledgements and generic awake snapshots cannot pass. Logout
requires the original session to disappear on the same boot. All three require
two Control restarts with observe-only recovery of the SAME transaction/effect
and independently verified disposable-account relocking before any positive
report. An incomplete handoff explicitly requires cleanup; forced death or
cleanup failure invalidates the case and the private VM must be discarded.

The workflow boots only its freshly copied disposable disk with persistence,
never the prepared substrate/cache. After real power-off, it boots that SAME
private disk using the unchanged pinned topology and a new private QMP socket;
it does not resubmit the original request. Earlier shell-runtime evidence keeps
its original execution identity; terminating reports retain distinct original
and observed boot IDs, exact source, request, transaction and effect digests.
The [official QMP event contract](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#event-shutdown)
provides supporting event observations, not product execution authority.
The development runtime contract explicitly selects this disk mode for S17:
`guard-disposable-disk.py` independently rejects symlinks, hardlinks, public or
non-owned copies, excessive images, source/copy aliasing and initial digest drift.
It rechecks the original cached substrate digest after the destructive cases.
The gate admits exactly the two pinned private-copy launch commands; substituting
the prepared image, adding persistent boots or removing either guard fails.
The shared launcher still defaults to snapshot mode for every ordinary caller.
Disk guards alone are not execution or qualification evidence.

These suspend and terminating cases are wired into the same pinned lane but have
NOT run. Their mocked/component tests are not native evidence. Protective-consent
failure cases, multi-output, compositor failure and native accessibility remain
outstanding qualification work. S17 and Q11 are not promoted by these runners.
