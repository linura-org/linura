#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text(encoding='utf-8')
    count = source.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one match, found {count}')
    path.write_text(source.replace(old, new, 1), encoding='utf-8')

script = Path('scripts/qualification/v09-adversarial-guest.sh')
replace_once(
    script,
    '  local transient_unit="linura-v09-public-bootstrap-${V09_SHARD_ID}"',
    '  local transient_unit="linura-v09-public-bootstrap-${V09_SHARD_ID}-${BOOT_INDEX}"',
    'make production-bootstrap transient unit power-cycle unique',
)

canonical = Path('docs/qualification/v0.9.0.md')
replace_once(
    canonical,
    '''Product bootstrap operations execute through `linura-preparer` while preparer authority is active. At boundary 12 the harness kills preparer processes, removes supplementary groups, SSH keys/password and dedicated sudo authority, scans/validates sudo state, verifies SSH access is gone, obtains authenticated revocation evidence, and only then switches to the separate qualification identity. The transcript binds the actual preparation identity and revocation outcome.''',
    '''Product bootstrap operations execute through `linura-preparer` while preparer authority is active. At boundary 12 the qualification harness does not perform the security transition: exact-source production First Boot terminates preparer processes, removes supplementary groups, locks the password, removes SSH and dedicated sudo authority, validates effective sudo policy, and mints the authenticated revocation receipt. The qualification identity is only an out-of-band launcher/observer that survives revocation of the preparation principal. After production returns, qualification independently observes process, supplementary-group, password, SSH, sudo-policy and protected receipt/key postconditions without reproducing the mutation algorithm. The transcript binds the actual preparation identity, production producer identity and independent verifier result.''',
    'replace harness-owned revocation claim',
)
replace_once(
    canonical,
    '''The production bootstrap may issue only `linura-firstboot-preparer-revocation-v1` evidence after directly proving the fixed preparer process/group/password/SSH/sudo postconditions. Final-owner enrollment signing remains outside First Boot. `--qualification-environment` derives its lifecycle status from the frozen workspace version: readiness builds report candidate status, while the mechanically prepared 0.9.0 release build reports `release-qualified-experimental`.
''',
    '''The production bootstrap may issue only `linura-firstboot-preparer-revocation-v1` evidence after directly proving the fixed preparer process/group/password/SSH/sudo postconditions. Final-owner enrollment signing remains outside First Boot. `--qualification-environment` derives its lifecycle status from the frozen workspace version: readiness builds report candidate status, while the mechanically prepared 0.9.0 release build reports `release-qualified-experimental`.

The canonical release-facing proof is black-box and starts from a fresh protected state root with hostile preparer authority present. The exact-source production `linura-firstboot --bootstrap <absolute-state-root>` entry point must itself converge the deferred-owner transition, create authenticated revocation evidence, and leave no effective preparer authority. Qualification then independently observes those externally visible postconditions, performs a persistent QEMU power cycle, invokes the same production entry point again against the same state root, and requires restart convergence without recovering historical authority. Qualification-only transition binaries remain supplemental fault-injection coverage for prepared/effect-started crash windows; they cannot substitute for this production-entry proof.
''',
    'add canonical black-box production proof',
)

contract = Path('tests/tooling/test_v09_adversarial_transport_contract.py')
source = contract.read_text(encoding='utf-8')
needle = '''        self.assertIn('run_public_bootstrap_isolated "$PUBLIC_BOOTSTRAP_ROOT"', source)'''
if source.count(needle) != 1:
    raise SystemExit('fresh bootstrap contract assertion changed')
source = source.replace(
    needle,
    needle + '''\n        self.assertIn('linura-v09-public-bootstrap-${V09_SHARD_ID}-${BOOT_INDEX}', source)''',
    1,
)
contract.write_text(source, encoding='utf-8')
