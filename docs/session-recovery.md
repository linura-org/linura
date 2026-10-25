# S17 deterministic session recovery

These are recovery procedures, not substitutes for qualification evidence. The
[recorded Level A native S17 run](https://github.com/linura-org/linura/actions/runs/40141305916)
exercised bounded observe-only recovery for its scoped authentication, suspend,
logout, reboot and power-off cases. Complete S17 acceptance and physical
workstation Q11 remain unqualified. No model, network service or conversation
history is required. Never interpret a lock hint, shell receipt, awake screen or successful
command submission as proof of secure coverage or a completed power transition.

## Preserve the original request

The shell retains its exact non-secret request ID before sending an action.
Keep that ID after a timeout, service failure, suspend or shell restart. Do not
press the power action again or make a replacement request to test whether the
first one happened. The shell's recovery control does not resume an abandoned
lock-to-power or lock-to-consent sequence.

From an independently authenticated local console as the original owner, use
the corresponding deterministic read/recovery command with that exact ID:

```sh
linuractl session-lock-status <original-request-id>
linuractl recover-session-lock <original-request-id>
linuractl session-transition-status <original-request-id>
linuractl recover-session-transition <original-request-id>
linuractl protective-lock-setting-status <original-request-id>
```

Choose only the matching request family. These lookups cannot authenticate an
unlock, reenroll protective permission, mint execution authority or replay an
uncertain power operation. History is not a current-security assertion. A
successful old-boot recovery proves only the original boot ended, not that the
requested action caused it or that the machine is currently powered off.

If Control is unavailable, an administrator may restore the packaged service
through the distribution's authenticated native console, then repeat the SAME
observe-only lookup. Do not replace journals, regenerate their keys, delete
ambiguous requests, edit policy or weaken service protections to clear an error.
Preserve authenticated transaction/request/consent state and relevant sanitized
diagnostics before repair. Corruption, a replaced login/owner generation or
unknown native evidence must remain a denial, not an invented successful recovery.

## Locker or compositor failure

A failed protected owner must leave the conformant compositor's native lock
closed. Starting another owner, restarting the ordinary shell, changing
`LockedHint`, calling `loginctl unlock-session`, or authenticating a new process
does not safely release the abandoned native lock. Do not automate these as a
fallback. Native restart cannot reconstruct the old process's one-shot permit.

When live recovery cannot establish the original scope, use the distribution's
separate, authenticated local-console/recovery-boot procedure. An administrator
may need to end the exact original graphical login, losing its unsaved work,
before starting a new login. Independently inspect its UID, native session ID,
creation generation and compositor leader first; never terminate an ambient
"current" login or every session. This is explicit native break-glass recovery,
not a Linura unlock, a policy bypass exposed to clients/models, or a managed
transition success claim. If a trusted local console is unavailable, use the
distribution's authenticated recovery-boot route; do not assert the desktop is
secure merely because it is black. Actual console/compositor failure behavior
still requires native qualification on the pinned profile.

## Failed sleep protection

An unavailable locker, missing/revoked login-scoped protective permission,
inhibitor, unknown session, changed native entry or failed coverage fence can
prevent sleep on enforceable native paths. A closed laptop may still be running:
keep it ventilated and verify its actual state before putting it in a bag.
Do not mask this condition by ignoring the pre-sleep gate, shortening a security
deadline, enabling unqualified sleep modes or assuming an administrator/root
request cannot bypass Linux enforcement. Root/kernel/thermal bypasses are outside
the declared managed route; they are never reported as a secure sleep success.

Enable/revoke protective permission only through the explicit S17 owner-PAM
control. Its grant belongs to that login epoch and never grants an unlock or
machine power permission. A new login needs its own explicit decision; historical
consent cannot be silently carried forward.
