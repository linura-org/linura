# Shell and Control Center task guide

The shell is a client, not the authority or process supervisor.

- Use semantic design tokens.
- Privileged actions go through public typed APIs.
- UI elements invoke registered typed operations; they never assign or downgrade `OperationClass`. Ephemeral navigation may stay local, while transient/managed external effects remain Control-mediated according to ADR 0032.
- Approval surfaces display actual effects/risk/why and appear only when trusted policy requires approval; do not manufacture approval fatigue for policy-allowed low-risk actions.
- Maintain keyboard, accessibility, reduced-motion, scaling, and offline/error states.
- Long-lived applications should use explicit supervision rather than compositor ownership.
