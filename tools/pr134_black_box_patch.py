#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, found {count}")
    return updated


main_path = ROOT / "apps/linura-firstboot/src/main.rs"
main = main_path.read_text(encoding="utf-8")
main = replace_once(
    main,
    "mod bootstrap_runtime;\n",
    "mod bootstrap_runtime;\nmod sudo_policy;\n",
    "wire sudo policy module",
)
main = regex_once(
    main,
    r"fn preparer_has_effective_sudo_authority\(\) -> Result<bool, String> \{.*?\n\}\n\nfn run_fixed",
    '''fn preparer_has_effective_sudo_authority() -> Result<bool, String> {
    let output = Command::new("/usr/bin/sudo")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(["-n", "-l", "-U", PREPARER_USER])
        .output()
        .map_err(io_string)?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "sudo policy query returned non-UTF-8 stdout".to_owned())?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| "sudo policy query returned non-UTF-8 stderr".to_owned())?;
    let observed = format!("{stdout}\\n{stderr}");
    sudo_policy::listing_grants_authority(&observed, PREPARER_USER)
        .map_err(|_| "cannot authoritatively evaluate preparer effective sudo policy".to_owned())
}

fn run_fixed''',
    "replace sudo exit-status inference",
)
main_path.write_text(main, encoding="utf-8")

script_path = ROOT / "scripts/qualification/v09-adversarial-guest.sh"
script = script_path.read_text(encoding="utf-8")
script = replace_once(
    script,
    'PRODUCTION_ROOT="$ROOT/production-firstboot"\nHARNESS_ROOT="$ROOT/harness"',
    'PRODUCTION_ROOT="$ROOT/production-firstboot"\nPUBLIC_BOOTSTRAP_ROOT="$ROOT/public-bootstrap"\nHARNESS_ROOT="$ROOT/harness"',
    "add public bootstrap root",
)

replacement_functions = r'''verify_preparer_authority_revoked() {
  local production_root="${1:?production root is required}"
  local verify_script=""
  local verify_encoded=""

  if ssh "${SSH_COMMON[@]}" -p "$SSH_PORT" "$PREPARER_SSH_USER@127.0.0.1" true >/dev/null 2>&1; then
    echo 'revoked preparer unexpectedly retained SSH access' >&2
    return 1
  fi

  verify_script="$(cat <<'VERIFY'
set -euo pipefail
production_root="${1:?production root is required}"

if pgrep -u linura-preparer >/dev/null 2>&1; then
  echo 'preparer process authority survived production revocation' >&2
  exit 1
fi
if grep -Eq '^[^:]+:[^:]*:[0-9]+:([^,]*,)*linura-preparer(,|$)' /etc/group; then
  echo 'preparer supplementary-group authority survived production revocation' >&2
  exit 1
fi
shadow="$(getent shadow linura-preparer | cut -d: -f2)"
case "$shadow" in
  '!'*|'*'*) ;;
  *) echo 'preparer password authority survived production revocation' >&2; exit 1 ;;
esac
test ! -e /home/linura-preparer/.ssh
test ! -e /etc/sudoers.d/99-linura-preparer
visudo -cf /etc/sudoers >/dev/null
set +e
sudo_listing="$(LC_ALL=C LANG=C /usr/bin/sudo -n -l -U linura-preparer 2>&1)"
sudo_status=$?
set -e
if printf '%s\n' "$sudo_listing" | grep -F 'User linura-preparer may run the following commands on ' >/dev/null; then
  echo 'preparer effective sudo authority survived production revocation' >&2
  printf '%s\n' "$sudo_listing" >&2
  exit 1
fi
if ! printf '%s\n' "$sudo_listing" | grep -F 'User linura-preparer is not allowed to run sudo on ' >/dev/null; then
  echo "independent sudo observation was ambiguous (status=$sudo_status)" >&2
  printf '%s\n' "$sudo_listing" >&2
  exit 1
fi
for relative in authority/control-receipt-auth.key authority/preparer-revocation.receipt; do
  path="$production_root/$relative"
  test -f "$path" -a ! -L "$path"
  test "$(stat -c '%u:%g:%a' "$path")" = '0:0:600'
done
printf '%s\n' 'preparer_revocation_verifier=independent-qualification-observation'
VERIFY
)"
  verify_encoded="$(printf '%s' "$verify_script" | base64 -w0)"
  remote "printf '%s' '$verify_encoded' | base64 -d | sudo -n /usr/bin/bash -s -- '$production_root'"
}

provision_preparer_authority_fixture() {
  local key_encoded=""
  key_encoded="$(printf '%s\n' "$public_key" | base64 -w0)"
  remote "set -euo pipefail; sudo -n /usr/sbin/usermod -G adm,sudo linura-preparer; sudo -n /usr/bin/passwd -d linura-preparer >/dev/null; sudo -n install -d -o linura-preparer -g linura-preparer -m 0700 /home/linura-preparer/.ssh; printf '%s' '$key_encoded' | base64 -d | sudo -n tee /home/linura-preparer/.ssh/authorized_keys >/dev/null; sudo -n chown linura-preparer:linura-preparer /home/linura-preparer/.ssh/authorized_keys; sudo -n chmod 0600 /home/linura-preparer/.ssh/authorized_keys; printf '%s\n' 'linura-preparer ALL=(ALL) NOPASSWD:ALL' | sudo -n tee '$PREPARER_SUDOERS' >/dev/null; sudo -n chmod 0440 '$PREPARER_SUDOERS'; sudo -n /usr/sbin/visudo -cf /etc/sudoers >/dev/null; sudo -n sync"
  preparer_remote "sudo -n /usr/bin/true"
  printf '%s\n' 'preparer_authority_fixture=hostile-and-observed' | tee -a "$TRANSCRIPT"
}

mkdir -p'''
script = regex_once(
    script,
    r"revoke_preparer_authority\(\) \{.*?\n\}\n\nmkdir -p",
    replacement_functions,
    "replace harness-owned revocation",
)

script = replace_once(
    script,
    'status_path="${4:?status path is required}"\nstatus=0',
    'status_path="${4:?status path is required}"\nmode="${5:-step}"\nstatus=0',
    "add observer mode",
)
script = replace_once(
    script,
    '''  if [ "$status" -eq 0 ]; then
    sudo -u linura-preparer sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step "$production_root" "$firstboot_sha" >"$output_path" 2>&1
    status=$?
  fi''',
    '''  if [ "$status" -eq 0 ]; then
    case "$mode" in
      step)
        sudo -u linura-preparer /usr/bin/sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step "$production_root" "$firstboot_sha" >"$output_path" 2>&1
        status=$?
        ;;
      bootstrap)
        /usr/local/bin/linura-firstboot --bootstrap "$production_root" >"$output_path" 2>&1
        status=$?
        ;;
      *)
        printf 'unsupported qualification observer mode: %s\n' "$mode" >"$output_path"
        status=2
        ;;
    esac
  fi''',
    "make Q8 observer production-entry capable",
)

public_runner = r'''

run_public_bootstrap_isolated() {
  local production_root="${1:?production root is required}"
  local output_path="$ROOT/public-bootstrap-${V09_SHARD_ID}.out"
  local status_path="$ROOT/public-bootstrap-${V09_SHARD_ID}.status"
  local transient_unit="linura-v09-public-bootstrap-${V09_SHARD_ID}"
  local ready=0
  local result=""
  local output=""
  local status=""

  remote "sudo -n rm -f '$output_path' '$status_path'; sudo -n systemd-run --quiet --no-block --unit='$transient_unit' --on-active=10s --property=StandardInput=null --property=StandardOutput=journal --property=StandardError=journal '$Q8_OBSERVER' '$production_root' '$LINURA_FIRSTBOOT_SHA' '$output_path' '$status_path' bootstrap </dev/null >/dev/null 2>&1"
  for _ in $(seq 1 180); do
    sleep 2
    if result="$(remote "sudo -n sh -c 'test -s \"$status_path\" && { cat \"$status_path\"; printf \"__LINURA_PUBLIC_BOOTSTRAP_OUTPUT__\\n\"; cat \"$output_path\"; }'" 2>/dev/null)"; then
      ready=1
      break
    fi
  done
  if [[ "$ready" != 1 ]]; then
    echo 'isolated production bootstrap did not restore a stable qualification transport' >&2
    return 1
  fi
  status="${result%%$'\n'*}"
  output="${result#*$'\n'}"
  if [[ "$output" != __LINURA_PUBLIC_BOOTSTRAP_OUTPUT__* ]]; then
    echo 'isolated production bootstrap result framing is invalid' >&2
    return 1
  fi
  output="${output#__LINURA_PUBLIC_BOOTSTRAP_OUTPUT__}"
  output="${output#$'\n'}"
  printf '%s\n' "$output"
  if [[ ! "$status" =~ ^[0-9]+$ || "$status" -ne 0 ]]; then
    printf '%s\n' "$output" >&2
    echo "isolated production bootstrap failed with status=${status:-invalid}" >&2
    return 1
  fi
}
'''
script = replace_once(
    script,
    '\n}\n\nstart_guest() {',
    public_runner + '\nstart_guest() {',
    "add isolated production bootstrap runner",
)

script = replace_once(
    script,
    '''  if [[ "$boundary" -eq 12 ]]; then
    revoke_preparer_authority
  fi
  if [[ "$boundary" -eq 4 ]]; then
    run_security_baseline_step | tee -a "$TRANSCRIPT"
  else
    product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
  fi''',
    '''  if [[ "$boundary" -eq 12 ]]; then
    PREPARER_ACTIVE=false
    remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
    verify_preparer_authority_revoked "$PRODUCTION_ROOT" | tee -a "$TRANSCRIPT"
    printf '%s\n' 'preparer_authority_revoked=actual-preparation-principal' | tee -a "$TRANSCRIPT"
    printf '%s\n' 'preparer_revocation_producer=production-firstboot' | tee -a "$TRANSCRIPT"
  elif [[ "$boundary" -eq 4 ]]; then
    run_security_baseline_step | tee -a "$TRANSCRIPT"
  else
    product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-step '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
  fi''',
    "make production own boundary-12 revocation",
)

script = replace_once(
    script,
    '''  product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-resume '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"
  remote "sudo -n /usr/local/bin/linura-firstboot --bootstrap '$PRODUCTION_ROOT'" | tee -a "$TRANSCRIPT"
  printf '%s\\n' 'production_bootstrap_entry=release-facing' | tee -a "$TRANSCRIPT"
  power_cycle 'production-bootstrap-restart'
  remote "sudo -n /usr/local/bin/linura-firstboot --bootstrap '$PRODUCTION_ROOT'" | tee -a "$TRANSCRIPT"
  printf '%s\\n' 'production_bootstrap_restart=reobserved-after-power-cycle' | tee -a "$TRANSCRIPT"''',
    '''  product_remote "sudo -n /usr/local/bin/linura-firstboot --durable-bootstrap-resume '$PRODUCTION_ROOT' '$LINURA_FIRSTBOOT_SHA'" | tee -a "$TRANSCRIPT"

  provision_preparer_authority_fixture
  remote "sudo -n rm -rf '$PUBLIC_BOOTSTRAP_ROOT'; sudo -n install -d -o root -g root -m 0700 '$PUBLIC_BOOTSTRAP_ROOT'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/.linura-bootstrap-session'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/bootstrap.state'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/authority/control-receipt-auth.key'; sudo -n test ! -e '$PUBLIC_BOOTSTRAP_ROOT/authority/preparer-revocation.receipt'"
  run_public_bootstrap_isolated "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  verify_preparer_authority_revoked "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  printf '%s\\n' 'production_bootstrap_entry=release-facing' | tee -a "$TRANSCRIPT"
  printf '%s\\n' 'production_bootstrap_fresh_state=verified' | tee -a "$TRANSCRIPT"
  printf '%s\\n' 'production_bootstrap_authority_observation=independent' | tee -a "$TRANSCRIPT"
  power_cycle 'production-bootstrap-restart'
  run_public_bootstrap_isolated "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  verify_preparer_authority_revoked "$PUBLIC_BOOTSTRAP_ROOT" | tee -a "$TRANSCRIPT"
  printf '%s\\n' 'production_bootstrap_restart=reobserved-after-power-cycle' | tee -a "$TRANSCRIPT"''',
    "replace converged-root public bootstrap with fresh-state proof",
)

script = replace_once(
    script,
    "        'production_bootstrap_entry=release-facing',\n        'production_bootstrap_restart=reobserved-after-power-cycle',",
    "        'production_bootstrap_entry=release-facing',\n        'production_bootstrap_fresh_state=verified',\n        'production_bootstrap_authority_observation=independent',\n        'preparer_revocation_producer=production-firstboot',\n        'preparer_revocation_verifier=independent-qualification-observation',\n        'production_bootstrap_restart=reobserved-after-power-cycle',",
    "bind black-box production markers",
)

if "revoke_preparer_authority()" in script:
    raise SystemExit("harness-owned revocation function survived patch")
script_path.write_text(script, encoding="utf-8")

# Update the exact-source tooling contract to prevent regression back to harness-owned mutation.
test_path = ROOT / "tests/tooling/test_v09_adversarial_transport_contract.py"
test_source = test_path.read_text(encoding="utf-8")
test_source = regex_once(
    test_source,
    r"    def test_product_bootstrap_uses_the_revocable_preparer_until_handoff\(self\) -> None:.*?\n    def test_release_facing_bootstrap_is_exercised_and_reobserved_after_restart",
    '''    def test_product_bootstrap_uses_the_revocable_preparer_until_production_handoff(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PREPARER_SSH_USER=linura-preparer", source)
        self.assertIn("PREPARER_ACTIVE=true", source)
        self.assertIn("preparer_remote() {", source)
        self.assertIn("product_remote() {", source)
        self.assertNotIn("revoke_preparer_authority()", source)
        self.assertIn("verify_preparer_authority_revoked()", source)
        verify_start = source.index("verify_preparer_authority_revoked() {")
        verify_end = source.index("\\n}\\n\\nprovision_preparer_authority_fixture", verify_start)
        verifier = source[verify_start:verify_end]
        for mutator in ("pkill -KILL", "usermod -G ''", "passwd -l", "rm -rf", "rm -f /etc/sudoers.d"):
            self.assertNotIn(mutator, verifier)
        self.assertIn("preparer_revocation_producer=production-firstboot", source)
        self.assertIn("preparer_revocation_verifier=independent-qualification-observation", source)
        boundary = source[source.index('if [[ "$boundary" -eq 12 ]]'):]
        self.assertLess(
            boundary.index("/usr/local/bin/linura-firstboot --durable-bootstrap-step"),
            boundary.index('verify_preparer_authority_revoked "$PRODUCTION_ROOT"'),
        )

    def test_release_facing_bootstrap_is_exercised_and_reobserved_after_restart''',
    "update transport contract ownership test",
)
test_source = replace_once(
    test_source,
    '''        self.assertIn("--bootstrap '$PRODUCTION_ROOT'", source)
        self.assertIn("production_bootstrap_entry=release-facing", source)
        self.assertIn('power_cycle \\'production-bootstrap-restart\\'', source)
        self.assertIn(
            "production_bootstrap_restart=reobserved-after-power-cycle",
            source,
        )''',
    '''        self.assertIn('PUBLIC_BOOTSTRAP_ROOT="$ROOT/public-bootstrap"', source)
        self.assertIn('run_public_bootstrap_isolated "$PUBLIC_BOOTSTRAP_ROOT"', source)
        self.assertIn("production_bootstrap_entry=release-facing", source)
        self.assertIn("production_bootstrap_fresh_state=verified", source)
        self.assertIn("production_bootstrap_authority_observation=independent", source)
        self.assertIn("test ! -e '$PUBLIC_BOOTSTRAP_ROOT/bootstrap.state'", source)
        self.assertIn('power_cycle \\'production-bootstrap-restart\\'', source)
        self.assertIn(
            "production_bootstrap_restart=reobserved-after-power-cycle",
            source,
        )''',
    "update fresh production bootstrap test",
)
test_path.write_text(test_source, encoding="utf-8")

# Bind the new source contract into the canonical qualification receipt.
qualification_path = ROOT / ".github/workflows/v09-qualification.yml"
qualification = qualification_path.read_text(encoding="utf-8")
qualification = replace_once(
    qualification,
    '                  "production-firstboot-persistent-power-cycle-recovery",\n',
    '                  "production-firstboot-persistent-power-cycle-recovery",\n                  "production-firstboot-black-box-authority-transition",\n',
    "bind production black-box source contract",
)
qualification_path.write_text(qualification, encoding="utf-8")

print("PR #134 surgical patch applied")
