const MAX_BOOTSTRAP_POSTCONDITION_BYTES: usize = 16 * 1024;
const BOOTSTRAP_VERIFICATION_MAX_AGE_MS: u64 = 5 * 60 * 1000;
const BOOTSTRAP_VERIFICATION_FUTURE_SKEW_MS: u64 = 30 * 1000;
const SYSTEM_BOOTSTRAP_VERIFIER_ID: &str = "linura-bootstrap-system-verifier-v2";
const MANAGED_FIRSTBOOT_PATH: &str = "/opt/linura/bin/linura-firstboot";
const RECOVERY_CHECKPOINT_SCHEMA: &str = "linura-bootstrap-recovery-checkpoint-v3";
const RECOVERY_CHECKPOINT_MANIFEST: &str = "checkpoint.manifest";
const RECOVERY_CHECKPOINT_STATE: &str = "bootstrap.state";
const RECOVERY_CHECKPOINT_SESSION: &str = ".linura-bootstrap-session";
const RECOVERY_CHECKPOINT_ANCHOR: &str = "generation.anchor";
const MAX_RECOVERY_CHECKPOINT_MANIFEST_BYTES: u64 = 4096;
const MAX_RECOVERY_CHECKPOINT_SESSION_BYTES: u64 = 512;

/// Exact, fresh postcondition evidence required before an effectful bootstrap
/// stage may be recorded complete.
///
/// Fields are intentionally private and normal production builds expose no
/// caller-authored constructor. Evidence is issued by the stage-specific
/// authoritative probes on `DurableBootstrapCoordinator`. Qualification builds
/// have an explicit synthetic constructor so the state machine can be tested
/// without confusing fixture evidence with production authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapVerificationEvidence {
    stage: BootstrapStage,
    operation_id: String,
    session_id: String,
    machine_id: String,
    verifier_id: String,
    observation_id: String,
    postcondition_sha256: String,
    observed_unix_ms: u64,
}

impl BootstrapVerificationEvidence {
    fn issue(
        stage: BootstrapStage,
        operation_id: impl Into<String>,
        session_id: impl Into<String>,
        machine_id: impl Into<String>,
        verifier_id: impl Into<String>,
        observation_id: impl Into<String>,
        canonical_postcondition: &[u8],
    ) -> Result<Self, DurableBootstrapError> {
        if !stage_requires_effect_boundary(stage) {
            return Err(DurableBootstrapError::VerificationEvidenceUnexpected(stage));
        }
        if canonical_postcondition.is_empty()
            || canonical_postcondition.len() > MAX_BOOTSTRAP_POSTCONDITION_BYTES
        {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "canonical postcondition is empty or exceeds the supported bound",
            ));
        }
        let observed_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DurableBootstrapError::Io(std::io::Error::other(error.to_string()))
            })?
            .as_millis()
            .try_into()
            .map_err(|_| {
                DurableBootstrapError::Io(std::io::Error::other(
                    "bootstrap verification timestamp exceeds u64",
                ))
            })?;
        Ok(Self {
            stage,
            operation_id: normalize_identifier(
                "bootstrap verification operation id",
                &operation_id.into(),
            )?,
            session_id: normalize_identifier(
                "bootstrap verification session id",
                &session_id.into(),
            )?,
            machine_id: normalize_identifier(
                "bootstrap verification machine id",
                &machine_id.into(),
            )?,
            verifier_id: normalize_identifier(
                "bootstrap verification producer id",
                &verifier_id.into(),
            )?,
            observation_id: normalize_identifier(
                "bootstrap verification observation id",
                &observation_id.into(),
            )?,
            postcondition_sha256: sha256(canonical_postcondition),
            observed_unix_ms,
        })
    }

    /// Qualification-only state-machine evidence. This constructor is excluded
    /// from normal/release builds so product integrations cannot self-attest.
    #[cfg(any(test, feature = "qualification-harness"))]
    pub fn qualification_observation(
        stage: BootstrapStage,
        operation_id: impl Into<String>,
        session_id: impl Into<String>,
        machine_id: impl Into<String>,
        observation_id: impl Into<String>,
        canonical_postcondition: &[u8],
    ) -> Result<Self, DurableBootstrapError> {
        Self::issue(
            stage,
            operation_id,
            session_id,
            machine_id,
            "linura-bootstrap-qualification-fixture-v1",
            observation_id,
            canonical_postcondition,
        )
    }

    #[must_use]
    pub const fn stage(&self) -> BootstrapStage {
        self.stage
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    #[must_use]
    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    #[must_use]
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    #[must_use]
    pub fn postcondition_sha256(&self) -> &str {
        &self.postcondition_sha256
    }

    #[must_use]
    pub const fn observed_unix_ms(&self) -> u64 {
        self.observed_unix_ms
    }

    fn validate_binding(
        &self,
        active: &ActiveBootstrapStage,
        expected_session_id: &str,
        expected_machine_id: &str,
    ) -> Result<(), DurableBootstrapError> {
        if self.stage != active.stage
            || self.operation_id != active.operation_id
            || self.session_id != expected_session_id
            || self.machine_id != expected_machine_id
        {
            return Err(DurableBootstrapError::VerificationEvidenceBindingMismatch);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DurableBootstrapError::Io(std::io::Error::other(error.to_string()))
            })?
            .as_millis();
        let now: u64 = now.try_into().map_err(|_| {
            DurableBootstrapError::Io(std::io::Error::other(
                "bootstrap verification timestamp exceeds u64",
            ))
        })?;
        if self.observed_unix_ms > now.saturating_add(BOOTSTRAP_VERIFICATION_FUTURE_SKEW_MS)
            || now.saturating_sub(self.observed_unix_ms) > BOOTSTRAP_VERIFICATION_MAX_AGE_MS
        {
            return Err(DurableBootstrapError::VerificationEvidenceStale);
        }
        if self.postcondition_sha256.len() != 64
            || !self
                .postcondition_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "postcondition digest is not SHA-256",
            ));
        }
        Ok(())
    }
}

impl From<&BootstrapVerificationEvidence> for CompletedEffectVerification {
    fn from(evidence: &BootstrapVerificationEvidence) -> Self {
        Self {
            stage: evidence.stage,
            operation_id: evidence.operation_id.clone(),
            verifier_id: evidence.verifier_id.clone(),
            observation_id: evidence.observation_id.clone(),
            postcondition_sha256: evidence.postcondition_sha256.clone(),
            observed_unix_ms: evidence.observed_unix_ms,
        }
    }
}

impl DurableBootstrapState {
    fn complete_effect_verified(
        &mut self,
        evidence: &BootstrapVerificationEvidence,
    ) -> Result<(), DurableBootstrapError> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if !stage_requires_effect_boundary(active.stage) {
            return Err(DurableBootstrapError::VerificationEvidenceUnexpected(
                active.stage,
            ));
        }
        if active.effect_state != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(active.stage));
        }
        evidence.validate_binding(active, &self.session_id, &self.machine_id)?;
        self.effect_verifications
            .push(CompletedEffectVerification::from(evidence));
        self.completed.push(active.stage);
        self.active = None;
        self.validate()
    }

    fn enter_recovery_owner_resolution(&mut self) -> Result<(), DurableBootstrapError> {
        let active = self.active_stage_for(BootstrapStage::OwnerEnrollmentResolution)?;
        if active.effect_state != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(
                BootstrapStage::OwnerEnrollmentResolution,
            ));
        }
        if self.provisioning.mode != Some(ProvisioningMode::Recovery) {
            return Err(DurableBootstrapError::RecoveryOwnerResolutionNotAllowed);
        }
        if self.provisioning.owner_enrollment != OwnerEnrollmentState::Unresolved {
            return Err(DurableBootstrapError::OwnerStateAlreadyResolved);
        }
        self.provisioning.owner_authority = None;
        self.provisioning.authority_generation = 0;
        self.provisioning.preparer_authority_retired = false;
        self.provisioning.owner_enrollment = OwnerEnrollmentState::RecoveryResolved;
        self.provisioning.validate()?;
        self.validate()
    }
}

fn protected_regular_file_sha256(path: &Path) -> Result<String, DurableBootstrapError> {
    let before = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(DurableBootstrapError::Io)?;
    let opened = file.metadata().map_err(DurableBootstrapError::Io)?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != 0
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o022 != 0
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(DurableBootstrapError::Io)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn protected_regular_file_bytes(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, DurableBootstrapError> {
    validate_state_parent(path)?;
    let expected_uid = current_effective_uid()?;
    let before = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != expected_uid
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > max_bytes
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(DurableBootstrapError::Io)?;
    let opened = file.metadata().map_err(DurableBootstrapError::Io)?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != expected_uid
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o022 != 0
        || opened.len() != before.len()
        || opened.len() > max_bytes
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(DurableBootstrapError::Io)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    let after = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
    if after.file_type().is_symlink()
        || !after.file_type().is_file()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.uid() != expected_uid
        || after.nlink() != 1
        || after.permissions().mode() & 0o022 != 0
        || after.len() != opened.len()
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    Ok(bytes)
}

#[derive(Debug, Eq, PartialEq)]
struct RecoveryCheckpointManifest {
    state_generation: u64,
    state_sha256: String,
    session_sha256: String,
    anchor_sha256: String,
}

fn validate_checkpoint_sha256(value: &str) -> Result<String, DurableBootstrapError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint contains an invalid SHA-256",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_recovery_checkpoint_manifest(
    bytes: &[u8],
) -> Result<RecoveryCheckpointManifest, DurableBootstrapError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECOVERY_CHECKPOINT_MANIFEST_BYTES {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest is empty or oversized",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest is not UTF-8",
        )
    })?;
    let integrity_index = text
        .rfind("\nintegrity=")
        .map(|index| index + 1)
        .ok_or(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest integrity record is missing",
        ))?;
    let (payload, integrity_line) = text.split_at(integrity_index);
    let expected_integrity = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest integrity record is malformed",
        ))?;
    let expected_integrity = validate_checkpoint_sha256(expected_integrity)?;
    let actual_integrity = sha256(payload.as_bytes());
    if !constant_time_ascii_eq(actual_integrity.as_bytes(), expected_integrity.as_bytes()) {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest integrity does not match its payload",
        ));
    }

    let mut lines = payload.lines();
    if lines.next() != Some(RECOVERY_CHECKPOINT_SCHEMA) {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "unsupported recovery checkpoint manifest schema",
        ));
    }
    let state_generation = lines
        .next()
        .and_then(|line| line.strip_prefix("state_generation="))
        .ok_or(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest lacks state generation",
        ))?
        .parse::<u64>()
        .map_err(|_| {
            DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint state generation is invalid",
            )
        })?;
    let state_sha256 = validate_checkpoint_sha256(
        lines
            .next()
            .and_then(|line| line.strip_prefix("state_sha256="))
            .ok_or(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint manifest lacks state digest",
            ))?,
    )?;
    let session_sha256 = validate_checkpoint_sha256(
        lines
            .next()
            .and_then(|line| line.strip_prefix("session_sha256="))
            .ok_or(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint manifest lacks session digest",
            ))?,
    )?;
    let anchor_sha256 = validate_checkpoint_sha256(
        lines
            .next()
            .and_then(|line| line.strip_prefix("anchor_sha256="))
            .ok_or(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint manifest lacks generation-anchor digest",
            ))?,
    )?;
    if lines
        .next()
        .and_then(|line| line.strip_prefix("resume_stage="))
        != Some("recovery-checkpoint")
        || lines.next().is_some()
    {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest has an invalid resume stage or unexpected fields",
        ));
    }
    Ok(RecoveryCheckpointManifest {
        state_generation,
        state_sha256,
        session_sha256,
        anchor_sha256,
    })
}

fn verify_checkpoint_digest(
    bytes: &[u8],
    expected: &str,
    label: &'static str,
) -> Result<(), DurableBootstrapError> {
    let actual = sha256(bytes);
    if !constant_time_ascii_eq(actual.as_bytes(), expected.as_bytes()) {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(label));
    }
    Ok(())
}

fn nft_tokens(rules: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in rules.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        if ch == '"' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            quoted = true;
            continue;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            current.push(ch.to_ascii_lowercase());
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            if matches!(ch, '{' | '}' | ';') {
                tokens.push(ch.to_string());
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn nft_input_base_chain_default_deny(rules: &str) -> bool {
    let tokens = nft_tokens(rules);
    let mut index = 0;
    while index + 2 < tokens.len() {
        if tokens[index] != "chain" || tokens[index + 2] != "{" {
            index += 1;
            continue;
        }
        index += 3;
        let mut depth = 1_u32;
        let mut input_hook = false;
        let mut deny_policy = false;
        while index < tokens.len() && depth > 0 {
            match tokens[index].as_str() {
                "{" => depth = depth.saturating_add(1),
                "}" => depth = depth.saturating_sub(1),
                "hook" if depth == 1 && tokens.get(index + 1).is_some_and(|v| v == "input") => {
                    input_hook = true;
                }
                "policy"
                    if depth == 1
                        && tokens
                            .get(index + 1)
                            .is_some_and(|v| v == "drop" || v == "reject") =>
                {
                    deny_policy = true;
                }
                _ => {}
            }
            index += 1;
        }
        if input_hook && deny_policy {
            return true;
        }
    }
    false
}

fn command_output(program: &str, args: &[&str]) -> Result<std::process::Output, DurableBootstrapError> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(DurableBootstrapError::Io)
}

fn systemd_candidate_units() -> Result<std::collections::BTreeSet<String>, DurableBootstrapError> {
    let mut units = std::collections::BTreeSet::new();
    let unit_files = command_output(
        "systemctl",
        &["list-unit-files", "--type=service", "--type=socket", "--no-legend", "--no-pager"],
    )?;
    if !unit_files.status.success() {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "systemd unit-file state could not be observed",
        ));
    }
    for line in String::from_utf8_lossy(&unit_files.stdout).lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(unit) = fields.next() else { continue; };
        let Some(state) = fields.next() else { continue; };
        if matches!(
            state,
            "enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias" | "indirect"
        ) {
            units.insert(unit.to_owned());
        }
    }

    let runtime = command_output(
        "systemctl",
        &["list-units", "--all", "--type=service", "--type=socket", "--no-legend", "--no-pager"],
    )?;
    if !runtime.status.success() {
        return Err(DurableBootstrapError::InvalidVerificationEvidence(
            "systemd runtime service state could not be observed",
        ));
    }
    for line in String::from_utf8_lossy(&runtime.stdout).lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() >= 3 && matches!(fields[2], "active" | "activating" | "reloading") {
            units.insert(fields[0].to_owned());
        }
    }
    Ok(units)
}

fn ssh_serving_unit(properties: &str) -> bool {
    let lower = properties.to_ascii_lowercase();
    lower.contains("sshd")
        || lower.contains("openssh")
        || lower.contains("dropbear")
        || lower.lines().any(|line| {
            matches!(
                line.strip_prefix("id="),
                Some("ssh.service" | "sshd.service" | "ssh.socket" | "sshd.socket")
            )
        })
}

fn ssh_unit_exposes_runtime_or_boot(properties: &str) -> bool {
    properties.lines().any(|line| {
        matches!(
            line.strip_prefix("ActiveState="),
            Some("active" | "activating" | "reloading")
        ) || matches!(
            line.strip_prefix("UnitFileState="),
            Some("enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias" | "indirect")
        )
    })
}

fn tcp22_listening(path: &Path) -> Result<bool, DurableBootstrapError> {
    let text = fs::read_to_string(path).map_err(DurableBootstrapError::Io)?;
    for line in text.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || fields[3] != "0A" {
            continue;
        }
        let Some((_, port)) = fields[1].rsplit_once(':') else {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "kernel TCP listener table is malformed",
            ));
        };
        let port = u16::from_str_radix(port, 16).map_err(|_| {
            DurableBootstrapError::InvalidVerificationEvidence(
                "kernel TCP listener port is malformed",
            )
        })?;
        if port == 22 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ssh_enabled() -> Result<bool, DurableBootstrapError> {
    for unit in systemd_candidate_units()? {
        let output = command_output(
            "systemctl",
            &[
                "show",
                &unit,
                "--property=Id",
                "--property=Names",
                "--property=Description",
                "--property=ExecStart",
                "--property=FragmentPath",
                "--property=ActiveState",
                "--property=UnitFileState",
                "--no-pager",
            ],
        )?;
        if !output.status.success() {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "systemd candidate service properties could not be observed",
            ));
        }
        let properties = String::from_utf8_lossy(&output.stdout);
        if ssh_serving_unit(&properties) && ssh_unit_exposes_runtime_or_boot(&properties) {
            return Ok(true);
        }
    }
    Ok(tcp22_listening(Path::new("/proc/net/tcp"))?
        || tcp22_listening(Path::new("/proc/net/tcp6"))?)
}

fn firewall_default_deny() -> Result<bool, DurableBootstrapError> {
    let output = command_output("nft", &["list", "ruleset"])?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(nft_input_base_chain_default_deny(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AptSourceFormat {
    OneLine,
    Deb822,
}

fn apt_security_field(name: &str) -> bool {
    let normalized = name
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    matches!(
        normalized.as_str(),
        "trusted" | "allowinsecure" | "allowweak" | "allowdowngradetoinsecurerepositories"
    )
}

fn apt_affirmative(value: &str) -> bool {
    value
        .split(|ch: char| ch.is_ascii_whitespace() || ch == ',')
        .any(|token| matches!(token.to_ascii_lowercase().as_str(), "yes" | "true" | "1"))
}

fn one_line_apt_source_fail_closed(line: &str) -> bool {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return true;
    }
    let Some(open) = line.find('[') else {
        return true;
    };
    let Some(close_offset) = line[open + 1..].find(']') else {
        return false;
    };
    let options = &line[open + 1..open + 1 + close_offset];
    let normalized = options
        .replace(" =", "=")
        .replace("= ", "=")
        .to_ascii_lowercase();
    for token in normalized.split_ascii_whitespace() {
        if let Some((name, value)) = token.split_once('=')
            && apt_security_field(name)
            && apt_affirmative(value)
        {
            return false;
        }
    }
    true
}

fn apt_source_text_fail_closed(text: &str, format: AptSourceFormat) -> bool {
    match format {
        AptSourceFormat::OneLine => text.lines().all(one_line_apt_source_fail_closed),
        AptSourceFormat::Deb822 => {
            let mut current_field: Option<String> = None;
            for raw in text.lines() {
                let trimmed = raw.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    current_field = None;
                    continue;
                }
                if raw.chars().next().is_some_and(char::is_whitespace) {
                    if current_field.as_deref().is_some_and(apt_security_field)
                        && apt_affirmative(trimmed)
                    {
                        return false;
                    }
                    continue;
                }
                let Some((name, value)) = raw.split_once(':') else {
                    return false;
                };
                current_field = Some(name.trim().to_owned());
                if apt_security_field(name) && apt_affirmative(value) {
                    return false;
                }
            }
            true
        }
    }
}

fn apt_sources_fail_closed() -> Result<bool, DurableBootstrapError> {
    fn check_file(path: &Path, format: AptSourceFormat) -> Result<bool, DurableBootstrapError> {
        let text = fs::read_to_string(path).map_err(DurableBootstrapError::Io)?;
        Ok(apt_source_text_fail_closed(&text, format))
    }

    let primary = Path::new("/etc/apt/sources.list");
    if primary.exists() && !check_file(primary, AptSourceFormat::OneLine)? {
        return Ok(false);
    }
    let directory = Path::new("/etc/apt/sources.list.d");
    if directory.exists() {
        for entry in fs::read_dir(directory).map_err(DurableBootstrapError::Io)? {
            let path = entry.map_err(DurableBootstrapError::Io)?.path();
            if !path.is_file() {
                continue;
            }
            let format = match path.extension().and_then(|value| value.to_str()) {
                Some("list") => Some(AptSourceFormat::OneLine),
                Some("sources") => Some(AptSourceFormat::Deb822),
                _ => None,
            };
            if let Some(format) = format
                && !check_file(&path, format)?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl DurableBootstrapCoordinator {
    fn active_effect_context(
        &self,
        required: BootstrapStage,
    ) -> Result<(&str, &str, &str), DurableBootstrapError> {
        let active = self
            .state
            .active()
            .ok_or(DurableBootstrapError::NoActiveStage)?;
        if active.stage() != required {
            return Err(DurableBootstrapError::StageContextRequired(required));
        }
        if active.effect_state() != BootstrapEffectState::EffectStarted {
            return Err(DurableBootstrapError::EffectNotStarted(required));
        }
        Ok((
            active.operation_id(),
            self.state.session_id(),
            self.state.machine_id(),
        ))
    }

    fn issue_system_evidence(
        &self,
        stage: BootstrapStage,
        observation_id: &str,
        canonical_postcondition: &[u8],
    ) -> Result<BootstrapVerificationEvidence, DurableBootstrapError> {
        let (operation_id, session_id, machine_id) = self.active_effect_context(stage)?;
        BootstrapVerificationEvidence::issue(
            stage,
            operation_id,
            session_id,
            machine_id,
            SYSTEM_BOOTSTRAP_VERIFIER_ID,
            observation_id,
            canonical_postcondition,
        )
    }

    /// Low-level completion remains public for verifier integrations that
    /// receive an opaque evidence value, but production builds expose no public
    /// constructor for that value.
    pub fn complete_effect_verified(
        &mut self,
        evidence: &BootstrapVerificationEvidence,
    ) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.complete_effect_verified(evidence)?;
        self.commit(candidate)
    }

    /// Verify the exact managed Linura First Boot installation from protected
    /// filesystem state. The caller supplies only the expected source digest;
    /// verifier identity, operation/session/machine bindings and observation
    /// bytes are produced inside this crate.
    pub fn verify_linura_installation(
        &mut self,
        expected_sha256: &str,
    ) -> Result<(), DurableBootstrapError> {
        validate_anchor_sha256(expected_sha256)?;
        let observed = protected_regular_file_sha256(Path::new(MANAGED_FIRSTBOOT_PATH))?;
        if !constant_time_ascii_eq(observed.as_bytes(), expected_sha256.as_bytes()) {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "managed First Boot installation digest does not match exact source",
            ));
        }
        let postcondition = format!(
            "managed_path={MANAGED_FIRSTBOOT_PATH};sha256={observed};root_owned=true;protected=true"
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::LinuraInstallation,
            "managed-installation-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_persistent_state_root(
        &mut self,
        root: &Path,
    ) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::PersistentStateInitialization)?;
        let metadata = fs::symlink_metadata(root).map_err(DurableBootstrapError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || metadata.uid() != current_effective_uid()?
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(DurableBootstrapError::UntrustedStatePath);
        }
        let postcondition = format!(
            "root={};uid={};mode={:o};dev={};ino={}",
            root.display(),
            metadata.uid(),
            metadata.permissions().mode() & 0o7777,
            metadata.dev(),
            metadata.ino(),
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::PersistentStateInitialization,
            "protected-state-root-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_security_baseline(&mut self) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::SecurityBaseline)?;
        if ssh_enabled()? || !firewall_default_deny()? || !apt_sources_fail_closed()? {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "Q8 security baseline is not fail-closed",
            ));
        }
        let postcondition = b"disk-encryption-claim=absent;inbound-firewall=default-deny;ssh-enabled=false;untrusted-package-sources=false";
        let evidence = self.issue_system_evidence(
            BootstrapStage::SecurityBaseline,
            "q8-system-security-observation",
            postcondition,
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_connectivity_observation(&mut self) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::BootstrapConnectivityResolution)?;
        let mut interfaces = fs::read_dir("/sys/class/net")
            .map_err(DurableBootstrapError::Io)?
            .map(|entry| {
                entry
                    .map_err(DurableBootstrapError::Io)?
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        DurableBootstrapError::InvalidVerificationEvidence(
                            "network interface name is not UTF-8",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        interfaces.sort();
        if interfaces.is_empty() {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "no network interface was authoritatively observed",
            ));
        }

        let mut operational_non_loopback = Vec::new();
        for interface in &interfaces {
            if interface == "lo" {
                continue;
            }
            let state_path = Path::new("/sys/class/net").join(interface).join("operstate");
            let state = fs::read_to_string(&state_path).map_err(DurableBootstrapError::Io)?;
            let carrier_path = Path::new("/sys/class/net").join(interface).join("carrier");
            let carrier = fs::read_to_string(&carrier_path).unwrap_or_else(|_| "0".into());
            if matches!(state.trim(), "up" | "unknown" | "dormant") || carrier.trim() == "1" {
                operational_non_loopback.push(interface.clone());
            }
        }

        let selection = self.state.provisioning().manifest_connectivity();
        match selection {
            Some(BootstrapConnectivity::Offline) if !operational_non_loopback.is_empty() => {
                return Err(DurableBootstrapError::InvalidVerificationEvidence(
                    "offline Provisioning Manifest selection conflicts with active non-loopback connectivity",
                ));
            }
            Some(BootstrapConnectivity::BoundedNetwork) if operational_non_loopback.is_empty() => {
                return Err(DurableBootstrapError::InvalidVerificationEvidence(
                    "bounded-network Provisioning Manifest selection has no operational non-loopback interface",
                ));
            }
            _ => {}
        }

        let selection = match selection {
            Some(BootstrapConnectivity::Offline) => "offline",
            Some(BootstrapConnectivity::BoundedNetwork) => "bounded-network",
            None => "unspecified",
        };
        let postcondition = format!(
            "selection={selection};interfaces={};operational_non_loopback={}",
            interfaces.join(","),
            operational_non_loopback.join(",")
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::BootstrapConnectivityResolution,
            "kernel-network-interface-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_recovery_checkpoint_manifest(
        &mut self,
        manifest: &Path,
    ) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::RecoveryCheckpoint)?;
        if manifest.file_name().and_then(|name| name.to_str()) != Some(RECOVERY_CHECKPOINT_MANIFEST) {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint manifest has a non-canonical filename",
            ));
        }
        let directory = manifest.parent().ok_or(DurableBootstrapError::InvalidVerificationEvidence(
            "recovery checkpoint manifest has no parent directory",
        ))?;
        let directory_metadata = fs::symlink_metadata(directory).map_err(DurableBootstrapError::Io)?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.file_type().is_dir()
            || directory_metadata.uid() != current_effective_uid()?
            || directory_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(DurableBootstrapError::UntrustedControlPath);
        }

        let manifest_bytes =
            protected_regular_file_bytes(manifest, MAX_RECOVERY_CHECKPOINT_MANIFEST_BYTES)?;
        let parsed = parse_recovery_checkpoint_manifest(&manifest_bytes)?;
        if parsed.state_generation != self.state.generation() {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint generation does not match the active durable state",
            ));
        }

        let state_path = directory.join(RECOVERY_CHECKPOINT_STATE);
        let session_path = directory.join(RECOVERY_CHECKPOINT_SESSION);
        let anchor_path = directory.join(RECOVERY_CHECKPOINT_ANCHOR);
        let state_bytes = protected_regular_file_bytes(&state_path, MAX_BOOTSTRAP_STATE_BYTES)?;
        let session_bytes =
            protected_regular_file_bytes(&session_path, MAX_RECOVERY_CHECKPOINT_SESSION_BYTES)?;
        let anchor_bytes = protected_regular_file_bytes(&anchor_path, MAX_GENERATION_ANCHOR_BYTES)?;
        verify_checkpoint_digest(
            &state_bytes,
            &parsed.state_sha256,
            "recovery checkpoint state digest does not match manifest",
        )?;
        verify_checkpoint_digest(
            &session_bytes,
            &parsed.session_sha256,
            "recovery checkpoint session digest does not match manifest",
        )?;
        verify_checkpoint_digest(
            &anchor_bytes,
            &parsed.anchor_sha256,
            "recovery checkpoint anchor digest does not match manifest",
        )?;

        let checkpoint_state = parse_state(&state_bytes)?;
        if checkpoint_state != self.state {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint state is not the exact active durable state",
            ));
        }
        let expected_session = format!("{}\n", self.state.session_id());
        if session_bytes.as_slice() != expected_session.as_bytes() {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint session identity is not exact-bound",
            ));
        }
        let checkpoint_anchor = parse_generation_anchor(&anchor_bytes)?;
        let expected_state_digest = bootstrap_state_digest(&self.state);
        if checkpoint_anchor.committed_generation != self.state.generation()
            || !constant_time_ascii_eq(
                checkpoint_anchor.committed_state_sha256.as_bytes(),
                expected_state_digest.as_bytes(),
            )
            || checkpoint_anchor.pending_generation.is_some()
            || checkpoint_anchor.pending_state_sha256.is_some()
        {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "recovery checkpoint generation anchor is not committed to the exact active state",
            ));
        }

        let digest = sha256(&manifest_bytes);
        let postcondition = format!(
            "checkpoint_manifest={};sha256={digest};state_generation={};bundle_members=state,session,anchor;protected=true",
            manifest.display(),
            parsed.state_generation,
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::RecoveryCheckpoint,
            "recovery-checkpoint-bundle-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    pub fn verify_owner_resolution(&mut self) -> Result<(), DurableBootstrapError> {
        self.active_effect_context(BootstrapStage::OwnerEnrollmentResolution)?;
        if self.state.provisioning().owner_enrollment() == OwnerEnrollmentState::Unresolved {
            return Err(DurableBootstrapError::InvalidVerificationEvidence(
                "owner enrollment remains unresolved",
            ));
        }
        let postcondition = format!(
            "owner-state={};authority-generation={};preparer-retired={}",
            self.state.provisioning().owner_enrollment().as_str(),
            self.state.provisioning().authority_generation(),
            self.state.provisioning().preparer_authority_retired(),
        );
        let evidence = self.issue_system_evidence(
            BootstrapStage::OwnerEnrollmentResolution,
            "durable-owner-resolution-observation",
            postcondition.as_bytes(),
        )?;
        self.complete_effect_verified(&evidence)
    }

    /// Resolve the owner stage for Recovery without creating, inheriting or
    /// deferring final-owner authority.
    pub fn enter_recovery_owner_resolution(&mut self) -> Result<(), DurableBootstrapError> {
        let mut candidate = self.state.clone();
        candidate.enter_recovery_owner_resolution()?;
        self.commit(candidate)
    }
}

#[cfg(test)]
mod effect_verifier_tests {
    use super::*;

    #[test]
    fn firewall_policy_must_belong_to_the_input_base_chain() {
        let wrong_chain = r#"
            table inet linura {
                chain input { type filter hook input priority 0; policy accept; }
                chain forward { type filter hook forward priority 0; policy drop; }
            }
        "#;
        assert!(!nft_input_base_chain_default_deny(wrong_chain));

        let correct = r#"
            table inet linura {
                chain input {
                    type filter hook input priority 0; policy drop;
                    comment "policy accept text in a quoted comment is ignored"
                }
                chain forward { type filter hook forward priority 0; policy accept; }
            }
        "#;
        assert!(nft_input_base_chain_default_deny(correct));
    }

    #[test]
    fn apt_sources_reject_one_line_and_deb822_security_overrides() {
        assert!(!apt_source_text_fail_closed(
            "deb [arch=amd64 trusted=yes] https://example.invalid stable main\n",
            AptSourceFormat::OneLine,
        ));
        assert!(!apt_source_text_fail_closed(
            "deb [arch=amd64 trusted = yes] https://example.invalid stable main\n",
            AptSourceFormat::OneLine,
        ));
        assert!(!apt_source_text_fail_closed(
            "Types: deb\nURIs: https://example.invalid\nTrusted: yes\n",
            AptSourceFormat::Deb822,
        ));
        assert!(!apt_source_text_fail_closed(
            "Types: deb\nURIs: https://example.invalid\nAllow-Insecure: YES\n",
            AptSourceFormat::Deb822,
        ));
        assert!(!apt_source_text_fail_closed(
            "Types: deb\nURIs: https://example.invalid\nAllow-Weak:\n true\n",
            AptSourceFormat::Deb822,
        ));
        assert!(apt_source_text_fail_closed(
            "Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nTrusted: no\n",
            AptSourceFormat::Deb822,
        ));
    }

    #[test]
    fn checkpoint_manifest_parser_rejects_arbitrary_protected_file_content() {
        assert!(matches!(
            parse_recovery_checkpoint_manifest(b"127.0.0.1 localhost\n"),
            Err(DurableBootstrapError::InvalidVerificationEvidence(_))
        ));
    }

    #[test]
    fn checkpoint_manifest_is_strict_and_integrity_bound() {
        let mut payload = concat!(
            "linura-bootstrap-recovery-checkpoint-v3\n",
            "state_generation=7\n",
            "state_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            "session_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            "anchor_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
            "resume_stage=recovery-checkpoint\n"
        )
        .to_owned();
        let integrity = sha256(payload.as_bytes());
        payload.push_str(&format!("integrity={integrity}\n"));
        let parsed = parse_recovery_checkpoint_manifest(payload.as_bytes())
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(parsed.state_generation, 7);

        let mut tampered = payload.into_bytes();
        let index = tampered
            .iter()
            .position(|byte| *byte == b'7')
            .unwrap_or_else(|| unreachable!("generation byte missing"));
        tampered[index] = b'8';
        assert!(matches!(
            parse_recovery_checkpoint_manifest(&tampered),
            Err(DurableBootstrapError::InvalidVerificationEvidence(_))
        ));
    }
}
