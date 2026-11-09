# S18 integrated development reference and extraction boundaries

> **Development snapshot, not qualification or release approval.** The WIP branch `wip/v010-s18-network` is the cumulative source reference. Do not merge it directly into `main`; never interpret its content, a green CI check, or a PR reservation as permission to enable NetworkManager effects.

## Branch and review topology

- Integration reference: `wip/v010-s18-network`, updated from the architecture and source changes of #267–#270 plus the future-feature reservation documents of #271–#276.
- Immutable-by-process review baseline: `base/v010-s18-review` at `27a79297956f1b4e0112dc0bad0a595ac969a6d9`. This is an **extraction base**, not another moving implementation authority.
- Review chain for implemented slices: #267 (architecture) → #268 (observation) → #269 (Control semantics) → #270 (protected credentials). Each branch has one scope-limited commit; the GitHub PR base points at its predecessor.
- #271–#274 are independent reserved downstream scopes relative to #270. #275 and #276 require an **explicit reviewed integration** of all #271–#274 sources and cannot rely on a single predecessor branch to prove their multiple dependencies.
- Existing historical branch names like S19, S20 and S25 on reserved PRs do not confer ownership. PR number, decomposition contract and changed-file boundaries decide S18 scope.
- Never force-update WIP or any PR branch without verifying the expected old head and retaining a recoverable commit; keep PR timelines free of progress chatter.

## Source inventory and qualification state

| Slice | PR | What the WIP snapshot contains | Not established by the snapshot |
| --- | --- | --- | --- |
| S18-1 | #267 | ADR 0048, typed operation design and security/qualification contracts, architectural negative tests | Architecture review acceptance; native effect authorization |
| S18-2 | #268 | NetworkManager identity and read-only observation sources and tests | Real source-pinned native NetworkManager Level A acceptance, complete bounded multiobject observation |
| S18-3 | #269 | Control-owned managed effect semantics and recovery-related source | Independently qualified end-to-end native dispatch, postconditions or crash recovery |
| S18-4 | #270 | Protected-entry and original-subject authorization scaffolding | Live registered NetworkManager SecretAgent, genuine GetSecrets path, real Polkit adversarial qualification |
| S18-5–S18-8 | #271–#274 | Scope and acceptance documents only | Implemented native scan, radio, connection or profile mutation |
| S18-9–S18-10 | #275–#276 | User-facing control and integrated qualification plans only | Completed UI, integrated exact-head qualification or Level C/Q11 hardware |

All nine declared network-changing operations remain unregistered and inactive. Unsupported VPN, hotspot, mobile broadband and arbitrary settings forwarding remain denied. Missing tests and hardware are recorded as blockers, not silently declared complete.

## Extraction and acceptance rules

1. Review the exact file-level delta from `base/v010-s18-review` through #267, #268, #269 and #270. Do not smuggle unrelated slice changes into an individual commit.
2. Validate exact-head canonical CI, CodeQL/security and native qualifications independently; do not infer Level A/B/C from unit tests, mocks or a green workflow alone.
3. Require real NetworkManager unique-owner and sender checks, logind/Polkit subject binding, cancel/zeroization and durable fail-closed recovery before enabling any live effect.
4. Compare the cumulative PR tree against WIP and document intended differences. WIP remains a **development reference**, never a second source of runtime authority.
5. Retarget individually reviewed PRs to their accepted landing bases after dependency integration; do not directly merge WIP or promote incomplete reservation documents.
