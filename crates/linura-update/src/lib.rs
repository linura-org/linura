#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const JOURNAL_MAGIC: &str = "linura-update-journal-v1";
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const O_NOFOLLOW: i32 = 0o400000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStage {
    AcquireLock,
    Preflight,
    DiskSpace,
    Snapshot,
    PackageTransaction,
    Migrations,
    Reconcile,
    RestartAssessment,
    Verify,
    Complete,
    RecoveryRequired,
}

impl UpdateStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AcquireLock => "acquire-lock",
            Self::Preflight => "preflight",
            Self::DiskSpace => "disk-space",
            Self::Snapshot => "snapshot",
            Self::PackageTransaction => "package-transaction",
            Self::Migrations => "migrations",
            Self::Reconcile => "reconcile",
            Self::RestartAssessment => "restart-assessment",
            Self::Verify => "verify",
            Self::Complete => "complete",
            Self::RecoveryRequired => "recovery-required",
        }
    }

    fn parse(value: &str) -> Result<Self, UpdateError> {
        match value {
            "acquire-lock" => Ok(Self::AcquireLock),
            "preflight" => Ok(Self::Preflight),
            "disk-space" => Ok(Self::DiskSpace),
            "snapshot" => Ok(Self::Snapshot),
            "package-transaction" => Ok(Self::PackageTransaction),
            "migrations" => Ok(Self::Migrations),
            "reconcile" => Ok(Self::Reconcile),
            "restart-assessment" => Ok(Self::RestartAssessment),
            "verify" => Ok(Self::Verify),
            "complete" => Ok(Self::Complete),
            "recovery-required" => Ok(Self::RecoveryRequired),
            _ => Err(UpdateError::CorruptJournal("unknown update stage".into())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalEffectState {
    None,
    Prepared,
    DispatchStarted,
    Verified,
}

impl ExternalEffectState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Prepared => "prepared",
            Self::DispatchStarted => "dispatch-started",
            Self::Verified => "verified",
        }
    }

    fn parse(value: &str) -> Result<Self, UpdateError> {
        match value {
            "none" => Ok(Self::None),
            "prepared" => Ok(Self::Prepared),
            "dispatch-started" => Ok(Self::DispatchStarted),
            "verified" => Ok(Self::Verified),
            _ => Err(UpdateError::CorruptJournal(
                "unknown external-effect state".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdatePolicy {
    pub minimum_free_bytes: u64,
    pub require_snapshot_when_available: bool,
    pub inhibit_suspend: bool,
    pub verify_after_restart: bool,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            minimum_free_bytes: 10 * 1024 * 1024 * 1024,
            require_snapshot_when_available: true,
            inhibit_suspend: true,
            verify_after_restart: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateState {
    pub stage: UpdateStage,
    pub snapshot_id: Option<String>,
    pub transaction_id: Option<String>,
    pub recovery_reason: Option<String>,
    pub external_effect: ExternalEffectState,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            stage: UpdateStage::AcquireLock,
            snapshot_id: None,
            transaction_id: None,
            recovery_reason: None,
            external_effect: ExternalEffectState::None,
        }
    }
}

impl UpdateState {
    pub fn transition(&mut self, next: UpdateStage) -> Result<(), UpdateError> {
        if next == UpdateStage::RecoveryRequired {
            self.stage = next;
            self.external_effect = ExternalEffectState::None;
            return Ok(());
        }
        if !valid_transition(self.stage, next) {
            return Err(UpdateError::InvalidTransition {
                from: self.stage,
                to: next,
            });
        }
        if self.stage == UpdateStage::PackageTransaction
            && next == UpdateStage::Migrations
            && self.external_effect != ExternalEffectState::Verified
        {
            return Err(UpdateError::ExternalEffectNotVerified);
        }
        self.stage = next;
        if next == UpdateStage::Migrations {
            self.external_effect = ExternalEffectState::None;
        }
        Ok(())
    }

    pub fn require_recovery(&mut self, reason: impl Into<String>) -> Result<(), UpdateError> {
        let reason = normalize_text("recovery reason", reason.into(), 4096)?;
        self.stage = UpdateStage::RecoveryRequired;
        self.recovery_reason = Some(reason);
        self.external_effect = ExternalEffectState::None;
        Ok(())
    }
}

fn valid_transition(from: UpdateStage, to: UpdateStage) -> bool {
    use UpdateStage as S;
    matches!(
        (from, to),
        (S::AcquireLock, S::Preflight)
            | (S::Preflight, S::DiskSpace)
            | (S::DiskSpace, S::Snapshot)
            | (S::Snapshot, S::PackageTransaction)
            | (S::PackageTransaction, S::Migrations)
            | (S::Migrations, S::Reconcile)
            | (S::Reconcile, S::RestartAssessment)
            | (S::RestartAssessment, S::Verify)
            | (S::Verify, S::Complete)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateResumeDecision {
    Continue(UpdateStage),
    SafeToDispatchPrepared,
    ReobserveBeforeContinuing,
    SafeToAdvanceAfterVerification,
    ManualRecoveryRequired,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateJournalStore {
    path: PathBuf,
}

impl UpdateJournalStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<UpdateState, UpdateError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(UpdateState::default());
            }
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(UpdateError::UntrustedJournalPath);
        }
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(UpdateError::CorruptJournal(
                "update journal exceeds supported size bound".into(),
            ));
        }
        parse_journal(&fs::read(&self.path).map_err(io_error)?)
    }

    pub fn persist(&self, state: &UpdateState) -> Result<(), UpdateError> {
        atomic_write(&self.path, &serialize_journal(state))
    }

    fn acquire_exclusive(&self) -> Result<fs::File, UpdateError> {
        let lock_path = sidecar_path(&self.path, "lock")?;
        let parent = lock_path
            .parent()
            .ok_or_else(|| UpdateError::Io("update lock path has no parent".into()))?;
        fs::create_dir_all(parent).map_err(io_error)?;
        reject_untrusted_existing_lock(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&lock_path)
            .map_err(io_error)?;
        validate_lock_identity(&lock_path, &file)?;
        file.lock().map_err(io_error)?;
        validate_lock_identity(&lock_path, &file)?;
        Ok(file)
    }
}

#[derive(Debug)]
pub struct UpdateCoordinator {
    state: UpdateState,
    policy: UpdatePolicy,
    store: UpdateJournalStore,
    durability_uncertain: Option<String>,
}

impl UpdateCoordinator {
    pub fn open(store: UpdateJournalStore, policy: UpdatePolicy) -> Result<Self, UpdateError> {
        let _lock = store.acquire_exclusive()?;
        let state = store.load()?;
        validate_persisted_state(&state)?;
        Ok(Self {
            state,
            policy,
            store,
            durability_uncertain: None,
        })
    }

    #[must_use]
    pub fn state(&self) -> &UpdateState {
        &self.state
    }

    #[must_use]
    pub fn requires_recovery(&self) -> bool {
        self.durability_uncertain.is_some() || self.state.stage == UpdateStage::RecoveryRequired
    }

    pub fn transition(&mut self, next: UpdateStage) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        let mut candidate = self.state.clone();
        candidate.transition(next)?;
        self.commit(candidate)
    }

    pub fn record_snapshot(&mut self, snapshot_id: impl Into<String>) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::Snapshot {
            return Err(UpdateError::InvalidOperation(
                "snapshot evidence can only be recorded at Snapshot stage",
            ));
        }
        let mut candidate = self.state.clone();
        candidate.snapshot_id = Some(normalize_identifier("snapshot id", snapshot_id.into())?);
        self.commit(candidate)
    }

    /// Durably crosses the prepare boundary before any package transaction may
    /// be dispatched. A restart from Prepared may dispatch exactly that bound
    /// transaction; a restart after dispatch started must re-observe instead.
    pub fn prepare_package_transaction(
        &mut self,
        transaction_id: impl Into<String>,
    ) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::Snapshot {
            return Err(UpdateError::InvalidOperation(
                "package transaction may only be prepared after Snapshot stage",
            ));
        }
        if self.policy.require_snapshot_when_available && self.state.snapshot_id.is_none() {
            return Err(UpdateError::SnapshotRequired);
        }
        let mut candidate = self.state.clone();
        candidate.stage = UpdateStage::PackageTransaction;
        candidate.transaction_id = Some(normalize_identifier(
            "transaction id",
            transaction_id.into(),
        )?);
        candidate.external_effect = ExternalEffectState::Prepared;
        self.commit(candidate)
    }

    pub fn mark_dispatch_started(&mut self) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::PackageTransaction
            || self.state.external_effect != ExternalEffectState::Prepared
            || self.state.transaction_id.is_none()
        {
            return Err(UpdateError::InvalidOperation(
                "dispatch start requires an exact durably prepared package transaction",
            ));
        }
        let mut candidate = self.state.clone();
        candidate.external_effect = ExternalEffectState::DispatchStarted;
        self.commit(candidate)
    }

    pub fn mark_package_verified(&mut self) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::PackageTransaction
            || self.state.external_effect != ExternalEffectState::DispatchStarted
        {
            return Err(UpdateError::InvalidOperation(
                "package verification requires a previously dispatched transaction",
            ));
        }
        let mut candidate = self.state.clone();
        candidate.external_effect = ExternalEffectState::Verified;
        self.commit(candidate)
    }

    pub fn require_recovery(&mut self, reason: impl Into<String>) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        let mut candidate = self.state.clone();
        candidate.require_recovery(reason)?;
        self.commit(candidate)
    }

    #[must_use]
    pub fn resume_decision(&self) -> UpdateResumeDecision {
        if self.durability_uncertain.is_some() {
            return UpdateResumeDecision::ManualRecoveryRequired;
        }
        match (self.state.stage, self.state.external_effect) {
            (UpdateStage::Complete, _) => UpdateResumeDecision::Complete,
            (UpdateStage::RecoveryRequired, _) => UpdateResumeDecision::ManualRecoveryRequired,
            (UpdateStage::PackageTransaction, ExternalEffectState::Prepared) => {
                UpdateResumeDecision::SafeToDispatchPrepared
            }
            (UpdateStage::PackageTransaction, ExternalEffectState::DispatchStarted) => {
                UpdateResumeDecision::ReobserveBeforeContinuing
            }
            (UpdateStage::PackageTransaction, ExternalEffectState::Verified) => {
                UpdateResumeDecision::SafeToAdvanceAfterVerification
            }
            (UpdateStage::PackageTransaction, ExternalEffectState::None) => {
                UpdateResumeDecision::ManualRecoveryRequired
            }
            (stage, _) => UpdateResumeDecision::Continue(stage),
        }
    }

    fn ensure_usable(&self) -> Result<(), UpdateError> {
        if let Some(reason) = &self.durability_uncertain {
            return Err(UpdateError::RecoveryRequired(reason.clone()));
        }
        Ok(())
    }

    fn commit(&mut self, candidate: UpdateState) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        validate_persisted_state(&candidate)?;
        let _lock = self.store.acquire_exclusive()?;
        let durable = self.store.load()?;
        if durable != self.state {
            let reason = "durable update state changed through another coordinator; reopen and reconcile before continuing".to_owned();
            self.durability_uncertain = Some(reason);
            return Err(UpdateError::StaleCoordinator);
        }
        match self.store.persist(&candidate) {
            Ok(()) => {
                self.state = candidate;
                Ok(())
            }
            Err(error) => self.handle_persist_failure(error),
        }
    }

    fn handle_persist_failure<T>(&mut self, error: UpdateError) -> Result<T, UpdateError> {
        match error {
            UpdateError::DurabilityUncertain(reason) => {
                self.durability_uncertain = Some(reason.clone());
                Err(UpdateError::DurabilityUncertain(reason))
            }
            other => Err(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeUpgradeDecision {
    AllowLinuraCoordinator,
    AllowBreakGlass,
    DenyDirectUpgrade,
}

#[must_use]
pub fn direct_upgrade_decision(
    coordinator_owned: bool,
    break_glass: bool,
) -> NativeUpgradeDecision {
    if coordinator_owned {
        NativeUpgradeDecision::AllowLinuraCoordinator
    } else if break_glass {
        NativeUpgradeDecision::AllowBreakGlass
    } else {
        NativeUpgradeDecision::DenyDirectUpgrade
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateError {
    InvalidTransition { from: UpdateStage, to: UpdateStage },
    InvalidOperation(&'static str),
    InvalidField(&'static str),
    SnapshotRequired,
    ExternalEffectNotVerified,
    UntrustedJournalPath,
    UntrustedLockPath,
    StaleCoordinator,
    UnsupportedJournalVersion,
    CorruptJournal(String),
    DurabilityUncertain(String),
    RecoveryRequired(String),
    Io(String),
}

impl Display for UpdateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid update transition {from:?} -> {to:?}")
            }
            Self::InvalidOperation(message) => f.write_str(message),
            Self::InvalidField(label) => write!(f, "invalid {label}"),
            Self::SnapshotRequired => {
                f.write_str("a validated snapshot is required before package dispatch")
            }
            Self::ExternalEffectNotVerified => f.write_str(
                "package transaction cannot advance until independent verification succeeds",
            ),
            Self::UntrustedJournalPath => f.write_str(
                "update journal must be a regular non-symlink file without group/other write access",
            ),
            Self::UntrustedLockPath => f.write_str(
                "update lock must be a stable regular non-symlink file without group/other write access",
            ),
            Self::StaleCoordinator => f.write_str(
                "update coordinator observed stale durable state and must be reopened/reconciled",
            ),
            Self::UnsupportedJournalVersion => f.write_str("unsupported update journal version"),
            Self::CorruptJournal(reason) => write!(f, "corrupt update journal: {reason}"),
            Self::DurabilityUncertain(reason) => write!(
                f,
                "update journal rename may have committed but durable directory sync is uncertain: {reason}"
            ),
            Self::RecoveryRequired(reason) => write!(
                f,
                "update coordinator is poisoned by uncertain durable state and must be reopened/reconciled before continuing: {reason}"
            ),
            Self::Io(message) => write!(f, "update journal I/O failed: {message}"),
        }
    }
}

impl std::error::Error for UpdateError {}

fn normalize_identifier(label: &'static str, value: String) -> Result<String, UpdateError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(UpdateError::InvalidField(label));
    }
    Ok(value.to_owned())
}

fn normalize_text(
    label: &'static str,
    value: String,
    max_len: usize,
) -> Result<String, UpdateError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(UpdateError::InvalidField(label));
    }
    Ok(value.to_owned())
}

fn validate_persisted_state(state: &UpdateState) -> Result<(), UpdateError> {
    if let Some(value) = &state.snapshot_id {
        normalize_identifier("snapshot id", value.clone())?;
    }
    if let Some(value) = &state.transaction_id {
        normalize_identifier("transaction id", value.clone())?;
    }
    if let Some(value) = &state.recovery_reason {
        normalize_text("recovery reason", value.clone(), 4096)?;
    }

    if state.stage == UpdateStage::PackageTransaction {
        if state.external_effect == ExternalEffectState::None || state.transaction_id.is_none() {
            return Err(UpdateError::CorruptJournal(
                "package stage lacks exact prepared transaction identity/state".into(),
            ));
        }
    } else if state.external_effect != ExternalEffectState::None {
        return Err(UpdateError::CorruptJournal(
            "transient package external-effect state is only valid at package-transaction stage"
                .into(),
        ));
    }

    if matches!(
        state.stage,
        UpdateStage::AcquireLock
            | UpdateStage::Preflight
            | UpdateStage::DiskSpace
            | UpdateStage::Snapshot
    ) && state.transaction_id.is_some()
    {
        return Err(UpdateError::CorruptJournal(
            "pre-package stage retained a package transaction identity".into(),
        ));
    }

    if matches!(
        state.stage,
        UpdateStage::Migrations
            | UpdateStage::Reconcile
            | UpdateStage::RestartAssessment
            | UpdateStage::Verify
            | UpdateStage::Complete
    ) && state.transaction_id.is_none()
    {
        return Err(UpdateError::CorruptJournal(
            "post-package stage lacks retained package transaction identity".into(),
        ));
    }

    if state.stage == UpdateStage::RecoveryRequired {
        if state.recovery_reason.is_none() {
            return Err(UpdateError::CorruptJournal(
                "recovery-required state lacks a reason".into(),
            ));
        }
    } else if state.recovery_reason.is_some() {
        return Err(UpdateError::CorruptJournal(
            "non-recovery stage retained a recovery reason".into(),
        ));
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> UpdateError {
    UpdateError::Io(error.to_string())
}

fn sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, UpdateError> {
    let parent = path
        .parent()
        .ok_or_else(|| UpdateError::Io("update journal path has no parent".into()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| UpdateError::Io("invalid update journal file name".into()))?;
    Ok(parent.join(format!(".{file_name}.{suffix}")))
}

fn reject_untrusted_existing_lock(path: &Path) -> Result<(), UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.permissions().mode() & 0o022 != 0 =>
        {
            Err(UpdateError::UntrustedLockPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn validate_lock_identity(path: &Path, file: &fs::File) -> Result<(), UpdateError> {
    let path_metadata = fs::symlink_metadata(path).map_err(io_error)?;
    let opened_metadata = file.metadata().map_err(io_error)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.permissions().mode() & 0o022 != 0
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(UpdateError::UntrustedLockPath);
    }
    Ok(())
}

fn fnv1a_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn integrity_tag(bytes: &[u8]) -> u64 {
    fnv1a_update(FNV_OFFSET, bytes)
}

fn hex_encode(value: Option<&str>) -> String {
    match value {
        None => "-".into(),
        Some(value) => value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn hex_decode(value: &str) -> Result<Option<String>, UpdateError> {
    if value == "-" {
        return Ok(None);
    }
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdateError::CorruptJournal(
            "invalid hex-encoded journal field".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| UpdateError::CorruptJournal("invalid journal encoding".into()))?;
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| UpdateError::CorruptJournal("invalid journal encoding".into()))?,
        );
    }
    let decoded = String::from_utf8(bytes)
        .map_err(|_| UpdateError::CorruptJournal("journal field is not UTF-8".into()))?;
    Ok(Some(decoded))
}

fn serialize_journal(state: &UpdateState) -> Vec<u8> {
    let mut payload = format!(
        "{JOURNAL_MAGIC}\nstage={}\nsnapshot={}\ntransaction={}\neffect={}\nrecovery={}\n",
        state.stage.as_str(),
        hex_encode(state.snapshot_id.as_deref()),
        hex_encode(state.transaction_id.as_deref()),
        state.external_effect.as_str(),
        hex_encode(state.recovery_reason.as_deref()),
    );
    let tag = integrity_tag(payload.as_bytes());
    payload.push_str(&format!("integrity={tag:016x}\n"));
    payload.into_bytes()
}

fn parse_journal(bytes: &[u8]) -> Result<UpdateState, UpdateError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| UpdateError::CorruptJournal("journal is not UTF-8".into()))?;
    let integrity_start = text
        .rfind("integrity=")
        .ok_or_else(|| UpdateError::CorruptJournal("integrity record is missing".into()))?;
    let (payload, integrity_line) = text.split_at(integrity_start);
    let expected = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| UpdateError::CorruptJournal("invalid integrity record".into()))?;
    if expected.len() != 16 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdateError::CorruptJournal("invalid integrity tag".into()));
    }
    let expected = u64::from_str_radix(expected, 16)
        .map_err(|_| UpdateError::CorruptJournal("invalid integrity tag".into()))?;
    if integrity_tag(payload.as_bytes()) != expected {
        return Err(UpdateError::CorruptJournal("integrity tag mismatch".into()));
    }

    let mut lines = payload.lines();
    if lines.next() != Some(JOURNAL_MAGIC) {
        return Err(UpdateError::UnsupportedJournalVersion);
    }
    let stage = parse_field(lines.next(), "stage")?;
    let snapshot = parse_field(lines.next(), "snapshot")?;
    let transaction = parse_field(lines.next(), "transaction")?;
    let effect = parse_field(lines.next(), "effect")?;
    let recovery = parse_field(lines.next(), "recovery")?;
    if lines.next().is_some() {
        return Err(UpdateError::CorruptJournal(
            "unexpected journal field".into(),
        ));
    }
    let state = UpdateState {
        stage: UpdateStage::parse(stage)?,
        snapshot_id: hex_decode(snapshot)?,
        transaction_id: hex_decode(transaction)?,
        recovery_reason: hex_decode(recovery)?,
        external_effect: ExternalEffectState::parse(effect)?,
    };
    validate_persisted_state(&state)?;
    Ok(state)
}

fn parse_field<'a>(line: Option<&'a str>, name: &str) -> Result<&'a str, UpdateError> {
    let line = line.ok_or_else(|| UpdateError::CorruptJournal(format!("missing {name} field")))?;
    line.strip_prefix(&format!("{name}="))
        .ok_or_else(|| UpdateError::CorruptJournal(format!("invalid {name} field")))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), UpdateError> {
    let parent = path
        .parent()
        .ok_or_else(|| UpdateError::Io("update journal path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| UpdateError::Io(error.to_string()))?
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| UpdateError::Io("invalid update journal file name".into()))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
    let mut renamed = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::rename(&temporary, path).map_err(io_error)?;
        renamed = true;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                UpdateError::DurabilityUncertain(format!(
                    "journal rename completed but parent-directory fsync failed: {error}"
                ))
            })?;
        Ok(())
    })();
    if result.is_err() && !renamed {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[derive(Debug)]
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "linura-update-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap_or_else(|error| unreachable!("{error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn coordinator(label: &str) -> (TestDir, UpdateCoordinator) {
        let dir = TestDir::new(label);
        let store = UpdateJournalStore::new(dir.path().join("update.journal"));
        let coordinator = UpdateCoordinator::open(store, UpdatePolicy::default())
            .unwrap_or_else(|error| unreachable!("{error}"));
        (dir, coordinator)
    }

    #[test]
    fn update_happy_path_is_ordered() {
        let mut state = UpdateState::default();
        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            assert_eq!(state.transition(stage), Ok(()));
        }
        state.snapshot_id = Some("snapshot-1".into());
        state.transaction_id = Some("transaction-1".into());
        state.external_effect = ExternalEffectState::Prepared;
        assert_eq!(state.transition(UpdateStage::PackageTransaction), Ok(()));
        state.external_effect = ExternalEffectState::Verified;
        for stage in [
            UpdateStage::Migrations,
            UpdateStage::Reconcile,
            UpdateStage::RestartAssessment,
            UpdateStage::Verify,
            UpdateStage::Complete,
        ] {
            assert_eq!(state.transition(stage), Ok(()));
        }
        assert_eq!(state.stage, UpdateStage::Complete);
        assert_eq!(state.transaction_id.as_deref(), Some("transaction-1"));
    }

    #[test]
    fn prepared_transaction_is_durable_and_exactly_resumable_before_dispatch() {
        let (dir, mut coordinator) = coordinator("prepared");
        coordinator
            .transition(UpdateStage::Preflight)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .transition(UpdateStage::DiskSpace)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .transition(UpdateStage::Snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .record_snapshot("snapshot-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(coordinator);

        let reopened = UpdateCoordinator::open(
            UpdateJournalStore::new(dir.path().join("update.journal")),
            UpdatePolicy::default(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::SafeToDispatchPrepared
        );
        assert_eq!(
            reopened.state().transaction_id.as_deref(),
            Some("transaction-1")
        );
    }

    #[test]
    fn crash_after_dispatch_never_blindly_replays_package_transaction() {
        let (dir, mut coordinator) = coordinator("dispatch-started");
        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            coordinator
                .transition(stage)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        coordinator
            .record_snapshot("snapshot-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(coordinator);

        let reopened = UpdateCoordinator::open(
            UpdateJournalStore::new(dir.path().join("update.journal")),
            UpdatePolicy::default(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::ReobserveBeforeContinuing
        );
    }

    #[test]
    fn stale_coordinator_cannot_roll_back_newer_dispatch_state() {
        let dir = TestDir::new("stale-coordinator");
        let store = UpdateJournalStore::new(dir.path().join("update.journal"));
        let mut current = UpdateCoordinator::open(store.clone(), UpdatePolicy::default())
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut stale = UpdateCoordinator::open(store.clone(), UpdatePolicy::default())
            .unwrap_or_else(|error| unreachable!("{error}"));

        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            current
                .transition(stage)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        current
            .record_snapshot("snapshot-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        current
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        current
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(
            stale.transition(UpdateStage::Preflight),
            Err(UpdateError::StaleCoordinator)
        );
        assert!(stale.requires_recovery());
        assert_eq!(
            stale.resume_decision(),
            UpdateResumeDecision::ManualRecoveryRequired
        );

        let reopened = UpdateCoordinator::open(store, UpdatePolicy::default())
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::ReobserveBeforeContinuing
        );
    }

    #[test]
    fn migrations_are_blocked_until_dispatched_package_state_is_verified() {
        let (_dir, mut coordinator) = coordinator("verify-gate");
        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            coordinator
                .transition(stage)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        coordinator
            .record_snapshot("snapshot-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            coordinator.transition(UpdateStage::Migrations),
            Err(UpdateError::ExternalEffectNotVerified)
        );
        coordinator
            .mark_package_verified()
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(coordinator.transition(UpdateStage::Migrations), Ok(()));
    }

    #[test]
    fn post_package_stages_require_retained_transaction_identity() {
        let dir = TestDir::new("post-package-lineage");
        let journal = dir.path().join("update.journal");
        for stage in [
            UpdateStage::Migrations,
            UpdateStage::Reconcile,
            UpdateStage::RestartAssessment,
            UpdateStage::Verify,
            UpdateStage::Complete,
        ] {
            let invalid = UpdateState {
                stage,
                snapshot_id: None,
                transaction_id: None,
                recovery_reason: None,
                external_effect: ExternalEffectState::None,
            };
            fs::write(&journal, serialize_journal(&invalid))
                .unwrap_or_else(|error| unreachable!("{error}"));
            assert!(matches!(
                UpdateJournalStore::new(&journal).load(),
                Err(UpdateError::CorruptJournal(_))
            ));
        }
    }

    #[test]
    fn snapshot_policy_fails_closed_before_prepare() {
        let (_dir, mut coordinator) = coordinator("snapshot-required");
        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            coordinator
                .transition(stage)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        assert_eq!(
            coordinator.prepare_package_transaction("transaction-1"),
            Err(UpdateError::SnapshotRequired)
        );
    }

    #[test]
    fn dangling_journal_symlink_fails_closed() {
        let dir = TestDir::new("dangling-symlink");
        let journal = dir.path().join("update.journal");
        symlink(dir.path().join("missing-target"), &journal)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            UpdateJournalStore::new(journal).load(),
            Err(UpdateError::UntrustedJournalPath)
        );
    }

    #[test]
    fn lock_symlink_fails_closed_without_following_target() {
        let dir = TestDir::new("lock-symlink");
        let journal = dir.path().join("update.journal");
        let store = UpdateJournalStore::new(&journal);
        let target = dir.path().join("missing-lock-target");
        let lock = sidecar_path(&journal, "lock").unwrap_or_else(|error| unreachable!("{error}"));
        symlink(&target, lock).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            store.acquire_exclusive(),
            Err(UpdateError::UntrustedLockPath)
        ));
        assert!(!target.exists());
    }

    #[test]
    fn transient_dispatch_state_is_rejected_outside_package_stage() {
        let dir = TestDir::new("invalid-effect-stage");
        let journal = dir.path().join("update.journal");
        let invalid = UpdateState {
            stage: UpdateStage::Snapshot,
            snapshot_id: Some("snapshot-1".into()),
            transaction_id: Some("transaction-1".into()),
            recovery_reason: None,
            external_effect: ExternalEffectState::DispatchStarted,
        };
        fs::write(&journal, serialize_journal(&invalid))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            UpdateJournalStore::new(journal).load(),
            Err(UpdateError::CorruptJournal(_))
        ));
    }

    #[test]
    fn uncertain_post_rename_commit_poisons_coordinator_until_reopen() {
        let (_dir, mut coordinator) = coordinator("uncertain-commit");
        let result: Result<(), UpdateError> = coordinator.handle_persist_failure(
            UpdateError::DurabilityUncertain("injected parent fsync failure".into()),
        );
        assert!(matches!(result, Err(UpdateError::DurabilityUncertain(_))));
        assert!(coordinator.requires_recovery());
        assert_eq!(
            coordinator.resume_decision(),
            UpdateResumeDecision::ManualRecoveryRequired
        );
        assert!(matches!(
            coordinator.transition(UpdateStage::Preflight),
            Err(UpdateError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn journal_corruption_and_unknown_versions_fail_closed() {
        let (dir, mut coordinator) = coordinator("corruption");
        coordinator
            .transition(UpdateStage::Preflight)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let path = dir.path().join("update.journal");
        let mut bytes = fs::read(&path).unwrap_or_else(|error| unreachable!("{error}"));
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            UpdateJournalStore::new(&path).load(),
            Err(UpdateError::CorruptJournal(_))
        ));

        let payload = b"linura-update-journal-v2\nstage=preflight\nsnapshot=-\ntransaction=-\neffect=none\nrecovery=-\n";
        let tag = integrity_tag(payload);
        fs::write(
            &path,
            format!(
                "linura-update-journal-v2\nstage=preflight\nsnapshot=-\ntransaction=-\neffect=none\nrecovery=-\nintegrity={tag:016x}\n"
            ),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            UpdateJournalStore::new(&path).load(),
            Err(UpdateError::UnsupportedJournalVersion)
        );
    }

    #[test]
    fn direct_upgrade_is_fail_closed_without_explicit_context() {
        assert_eq!(
            direct_upgrade_decision(false, false),
            NativeUpgradeDecision::DenyDirectUpgrade
        );
        assert_eq!(
            direct_upgrade_decision(true, false),
            NativeUpgradeDecision::AllowLinuraCoordinator
        );
        assert_eq!(
            direct_upgrade_decision(false, true),
            NativeUpgradeDecision::AllowBreakGlass
        );
    }
}
