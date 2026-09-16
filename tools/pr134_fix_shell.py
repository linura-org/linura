#!/usr/bin/env python3
from pathlib import Path

path = Path('scripts/qualification/v09-adversarial-guest.sh')
source = path.read_text(encoding='utf-8')


def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one match, found {count}')
    source = source.replace(old, new, 1)

replace_once(
    '    return 1\n  fi\n\nrun_public_bootstrap_isolated() {',
    '    return 1\n  fi\n}\n\nrun_public_bootstrap_isolated() {',
    'close Q8 runner before public bootstrap runner',
)
replace_once(
    "        printf 'unsupported qualification observer mode: %s\n' \"$mode\" >\"$output_path\"",
    "        printf 'unsupported qualification observer mode: %s\\n' \"$mode\" >\"$output_path\"",
    'normalize observer-mode printf',
)
replace_once(
    "    printf '%s\n' 'preparer_authority_revoked=actual-preparation-principal' | tee -a \"$TRANSCRIPT\"",
    "    printf '%s\\n' 'preparer_authority_revoked=actual-preparation-principal' | tee -a \"$TRANSCRIPT\"",
    'normalize revocation marker printf',
)
replace_once(
    "    printf '%s\n' 'preparer_revocation_producer=production-firstboot' | tee -a \"$TRANSCRIPT\"",
    "    printf '%s\\n' 'preparer_revocation_producer=production-firstboot' | tee -a \"$TRANSCRIPT\"",
    'normalize producer marker printf',
)

path.write_text(source, encoding='utf-8')
