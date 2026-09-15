#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

pub const V09_UPDATE_EVIDENCE_ROOT: &str = "/var/lib/linura-update/v0.9";
pub const V09_UPDATE_EVIDENCE_PRODUCER_ID: &str = "linura-update-evidence-v09";
pub const V09_UPDATE_EVIDENCE_PRODUCER_UID: u32 = 0;

const JOURNAL_MAGIC: &str = "linura-update-journal-v2";
const EVIDENCE_MAGIC: &str = "linura-update-evidence-v3";
const EVIDENCE_AUTH_KEY_FILE: &str = "evidence-auth.key";
const EVIDENCE_AUTH_KEY_BYTES: usize = 32;
const HMAC_BLOCK_BYTES: usize = 64;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
const SNAPSHOT_EVIDENCE_MAX_AGE_MS: u64 = 15 * 60 * 1000;
const SNAPSHOT_EVIDENCE_FUTURE_SKEW_MS: u64 = 30 * 1000;
const PACKAGE_VERIFICATION_MAX_AGE_MS: u64 = 15 * 60 * 1000;
const PACKAGE_VERIFICATION_FUTURE_SKEW_MS: u64 = 30 * 1000;
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
    update_id: Option<String>,
    target_id: Option<String>,
    stage: UpdateStage,
    snapshot_id: Option<String>,
    snapshot_receipt_id: Option<String>,
    transaction_id: Option<String>,
    verification_receipt_id: Option<String>,
    recovery_reason: Option<String>,
    external_effect: ExternalEffectState,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            update_id: None,
            target_id: None,
            stage: UpdateStage::AcquireLock,
            snapshot_id: None,
            snapshot_receipt_id: None,
            transaction_id: None,
            verification_receipt_id: None,
            recovery_reason: None,
            external_effect: ExternalEffectState::None,
        }
    }
}

impl UpdateState {
    #[must_use]
    pub fn update_id(&self) -> Option<&str> {
        self.update_id.as_deref()
    }

    #[must_use]
    pub fn target_id(&self) -> Option<&str> {
        self.target_id.as_deref()
    }

    #[must_use]
    pub const fn stage(&self) -> UpdateStage {
        self.stage
    }

    #[must_use]
    pub fn snapshot_id(&self) -> Option<&str> {
        self.snapshot_id.as_deref()
    }

    #[must_use]
    pub fn snapshot_receipt_id(&self) -> Option<&str> {
        self.snapshot_receipt_id.as_deref()
    }

    #[must_use]
    pub fn transaction_id(&self) -> Option<&str> {
        self.transaction_id.as_deref()
    }

    #[must_use]
    pub fn verification_receipt_id(&self) -> Option<&str> {
        self.verification_receipt_id.as_deref()
    }

    #[must_use]
    pub fn recovery_reason(&self) -> Option<&str> {
        self.recovery_reason.as_deref()
    }

    #[must_use]
    pub const fn external_effect(&self) -> ExternalEffectState {
        self.external_effect
    }

    pub fn transition(&mut self, next: UpdateStage) -> Result<(), UpdateError> {
        if next == UpdateStage::RecoveryRequired {
            return Err(UpdateError::InvalidOperation(
                "use require_recovery to enter recovery-required state with an explicit reason",
            ));
        }
        if !valid_transition(self.stage, next) {
            return Err(UpdateError::InvalidTransition {
                from: self.stage,
                to: next,
            });
        }
        if self.stage == UpdateStage::PackageTransaction
            && next == UpdateStage::Migrations
            && (self.external_effect != ExternalEffectState::Verified
                || self.verification_receipt_id.is_none())
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
pub struct SnapshotReceipt {
    receipt_id: String,
    update_id: String,
    target_id: String,
    snapshot_id: String,
    proof_id: String,
    attempt_generation: String,
    issued_unix_ms: u64,
}

impl SnapshotReceipt {
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    #[must_use]
    pub fn attempt_generation(&self) -> &str {
        &self.attempt_generation
    }

    #[must_use]
    pub const fn issued_unix_ms(&self) -> u64 {
        self.issued_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageVerificationReceipt {
    receipt_id: String,
    update_id: String,
    target_id: String,
    transaction_id: String,
    observation_id: String,
    dispatch_generation: String,
    issued_unix_ms: u64,
}

impl PackageVerificationReceipt {
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    #[must_use]
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    #[must_use]
    pub fn dispatch_generation(&self) -> &str {
        &self.dispatch_generation
    }

    #[must_use]
    pub const fn issued_unix_ms(&self) -> u64 {
        self.issued_unix_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceKind {
    Snapshot,
    PackageVerification,
}

impl EvidenceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::PackageVerification => "package-verification",
        }
    }

    fn parse(value: &str) -> Result<Self, UpdateError> {
        match value {
            "snapshot" => Ok(Self::Snapshot),
            "package-verification" => Ok(Self::PackageVerification),
            _ => Err(UpdateError::CorruptEvidence("unknown evidence kind".into())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedEvidence {
    kind: EvidenceKind,
    update_id: String,
    target_id: String,
    subject_id: String,
    proof_id: String,
    dispatch_generation: Option<String>,
    issued_unix_ms: Option<u64>,
    source: String,
    result: String,
}

pub struct TrustedUpdateEvidenceVerifier {
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
    root_uid: u32,
    key: [u8; EVIDENCE_AUTH_KEY_BYTES],
}

impl std::fmt::Debug for TrustedUpdateEvidenceVerifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedUpdateEvidenceVerifier")
            .field("root", &self.root)
            .field("root_device", &self.root_device)
            .field("root_inode", &self.root_inode)
            .field("root_uid", &self.root_uid)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for TrustedUpdateEvidenceVerifier {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl TrustedUpdateEvidenceVerifier {
    pub fn open() -> Result<Self, UpdateError> {
        Self::open_at(
            Path::new(V09_UPDATE_EVIDENCE_ROOT),
            V09_UPDATE_EVIDENCE_PRODUCER_UID,
        )
    }

    #[cfg(test)]
    fn open_for_test(root: impl AsRef<Path>) -> Result<Self, UpdateError> {
        let metadata = fs::symlink_metadata(root.as_ref()).map_err(io_error)?;
        Self::open_at(root.as_ref(), metadata.uid())
    }

    fn open_at(root: &Path, expected_uid: u32) -> Result<Self, UpdateError> {
        let supplied_metadata = trusted_evidence_root_metadata(root, expected_uid)?;
        let canonical_root = root.canonicalize().map_err(io_error)?;
        let metadata = trusted_evidence_root_metadata(&canonical_root, expected_uid)?;
        if metadata.dev() != supplied_metadata.dev() || metadata.ino() != supplied_metadata.ino() {
            return Err(UpdateError::UntrustedEvidenceRoot);
        }
        let key = read_evidence_auth_key(&canonical_root, expected_uid)?;
        Ok(Self {
            root: canonical_root,
            root_device: metadata.dev(),
            root_inode: metadata.ino(),
            root_uid: expected_uid,
            key,
        })
    }

    pub fn verify_snapshot(
        &self,
        receipt_id: &str,
        expected_update_id: &str,
        expected_target_id: &str,
        expected_attempt_generation: &str,
        attempt_started_unix_ms: u64,
    ) -> Result<SnapshotReceipt, UpdateError> {
        let receipt_id = normalize_identifier("evidence receipt id", receipt_id.to_owned())?;
        let expected_update_id = normalize_identifier("update id", expected_update_id.to_owned())?;
        let expected_target_id =
            normalize_identifier("update target id", expected_target_id.to_owned())?;
        let expected_attempt_generation = normalize_identifier(
            "snapshot attempt generation",
            expected_attempt_generation.to_owned(),
        )?;
        let evidence = self.read_receipt(&receipt_id)?;
        let attempt_generation =
            evidence
                .dispatch_generation
                .as_deref()
                .ok_or(UpdateError::EvidenceBindingMismatch(
                    "snapshot receipt lacks update-attempt generation binding",
                ))?;
        let issued_unix_ms =
            evidence
                .issued_unix_ms
                .ok_or(UpdateError::EvidenceBindingMismatch(
                    "snapshot receipt lacks issuance freshness",
                ))?;
        if evidence.kind != EvidenceKind::Snapshot
            || evidence.update_id != expected_update_id
            || evidence.target_id != expected_target_id
            || attempt_generation != expected_attempt_generation
            || evidence.source != V09_UPDATE_EVIDENCE_PRODUCER_ID
            || evidence.result != "durable"
        {
            return Err(UpdateError::EvidenceBindingMismatch(
                "snapshot receipt is not durable trusted-producer evidence bound to this update, target and snapshot attempt",
            ));
        }
        validate_snapshot_evidence_freshness(issued_unix_ms, attempt_started_unix_ms)?;
        Ok(SnapshotReceipt {
            receipt_id,
            update_id: evidence.update_id,
            target_id: evidence.target_id,
            snapshot_id: normalize_identifier("snapshot id", evidence.subject_id)?,
            proof_id: normalize_identifier("snapshot proof id", evidence.proof_id)?,
            attempt_generation: expected_attempt_generation,
            issued_unix_ms,
        })
    }

    pub fn verify_package(
        &self,
        receipt_id: &str,
        expected_update_id: &str,
        expected_target_id: &str,
        expected_transaction_id: &str,
        expected_dispatch_generation: &str,
        dispatch_started_unix_ms: u64,
    ) -> Result<PackageVerificationReceipt, UpdateError> {
        let receipt_id = normalize_identifier("evidence receipt id", receipt_id.to_owned())?;
        let expected_update_id = normalize_identifier("update id", expected_update_id.to_owned())?;
        let expected_target_id =
            normalize_identifier("update target id", expected_target_id.to_owned())?;
        let expected_transaction_id =
            normalize_identifier("transaction id", expected_transaction_id.to_owned())?;
        let expected_dispatch_generation = normalize_identifier(
            "dispatch generation",
            expected_dispatch_generation.to_owned(),
        )?;
        let evidence = self.read_receipt(&receipt_id)?;
        let dispatch_generation =
            evidence
                .dispatch_generation
                .as_deref()
                .ok_or(UpdateError::EvidenceBindingMismatch(
                    "package verification receipt lacks dispatch-generation binding",
                ))?;
        let issued_unix_ms =
            evidence
                .issued_unix_ms
                .ok_or(UpdateError::EvidenceBindingMismatch(
                    "package verification receipt lacks issuance freshness",
                ))?;
        if evidence.kind != EvidenceKind::PackageVerification
            || evidence.update_id != expected_update_id
            || evidence.target_id != expected_target_id
            || evidence.subject_id != expected_transaction_id
            || dispatch_generation != expected_dispatch_generation
            || evidence.source != V09_UPDATE_EVIDENCE_PRODUCER_ID
            || evidence.result != "verified"
        {
            return Err(UpdateError::EvidenceBindingMismatch(
                "package verification receipt is not authoritative evidence bound to this update, target, transaction and dispatch instance",
            ));
        }
        validate_package_evidence_freshness(issued_unix_ms, dispatch_started_unix_ms)?;
        Ok(PackageVerificationReceipt {
            receipt_id,
            update_id: evidence.update_id,
            target_id: evidence.target_id,
            transaction_id: evidence.subject_id,
            observation_id: normalize_identifier("observation id", evidence.proof_id)?,
            dispatch_generation: expected_dispatch_generation,
            issued_unix_ms,
        })
    }

    fn read_receipt(&self, receipt_id: &str) -> Result<ParsedEvidence, UpdateError> {
        self.validate_root_identity()?;
        let path = self.root.join(format!("{receipt_id}.receipt"));
        let path_metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.file_type().is_file()
            || path_metadata.permissions().mode() & 0o022 != 0
            || path_metadata.uid() != self.root_uid
            || path_metadata.nlink() != 1
            || path_metadata.len() > MAX_EVIDENCE_BYTES
        {
            return Err(UpdateError::UntrustedEvidencePath);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)
            .map_err(io_error)?;
        let opened_metadata = file.metadata().map_err(io_error)?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
            || opened_metadata.uid() != self.root_uid
            || opened_metadata.nlink() != 1
        {
            return Err(UpdateError::UntrustedEvidencePath);
        }
        let mut bytes = Vec::with_capacity(path_metadata.len() as usize);
        file.read_to_end(&mut bytes).map_err(io_error)?;
        if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
            return Err(UpdateError::CorruptEvidence(
                "evidence receipt exceeds supported size bound".into(),
            ));
        }
        file.sync_all().map_err(io_error)?;
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        self.validate_root_identity()?;
        let after = fs::symlink_metadata(&path).map_err(io_error)?;
        if after.file_type().is_symlink()
            || !after.file_type().is_file()
            || after.dev() != opened_metadata.dev()
            || after.ino() != opened_metadata.ino()
            || after.uid() != self.root_uid
            || after.permissions().mode() & 0o022 != 0
            || after.nlink() != 1
        {
            return Err(UpdateError::UntrustedEvidencePath);
        }
        parse_evidence(&bytes, &self.key)
    }

    fn validate_root_identity(&self) -> Result<(), UpdateError> {
        let metadata = trusted_evidence_root_metadata(&self.root, self.root_uid)?;
        if metadata.dev() != self.root_device || metadata.ino() != self.root_inode {
            return Err(UpdateError::UntrustedEvidenceRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalGeneration {
    token: String,
    committed_unix_ms: u64,
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
        validate_journal_metadata(&metadata)?;
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(UpdateError::CorruptJournal(
                "update journal exceeds supported size bound".into(),
            ));
        }
        parse_journal(&fs::read(&self.path).map_err(io_error)?)
    }

    fn generation(&self) -> Result<JournalGeneration, UpdateError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(io_error)?;
        validate_journal_metadata(&metadata)?;
        let committed_unix_ms = system_time_to_unix_ms(metadata.modified().map_err(io_error)?)?;
        let token = normalize_identifier(
            "dispatch generation",
            format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.len()
            ),
        )?;
        Ok(JournalGeneration {
            token,
            committed_unix_ms,
        })
    }

    fn persist(&self, state: &UpdateState) -> Result<(), UpdateError> {
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
    update_id: String,
    target_id: String,
    journal_generation: JournalGeneration,
    durability_uncertain: Option<String>,
}

impl UpdateCoordinator {
    pub fn open(
        store: UpdateJournalStore,
        policy: UpdatePolicy,
        update_id: impl Into<String>,
        target_id: impl Into<String>,
    ) -> Result<Self, UpdateError> {
        let update_id = normalize_identifier("update id", update_id.into())?;
        let target_id = normalize_identifier("update target id", target_id.into())?;
        let _lock = store.acquire_exclusive()?;
        let mut state = store.load()?;
        if state.update_id.is_none() && state.target_id.is_none() {
            if state != UpdateState::default() {
                return Err(UpdateError::CorruptJournal(
                    "unbound journal contains non-default state".into(),
                ));
            }
            state.update_id = Some(update_id.clone());
            state.target_id = Some(target_id.clone());
            validate_persisted_state(&state)?;
            store.persist(&state)?;
        } else if state.update_id.as_deref() != Some(update_id.as_str())
            || state.target_id.as_deref() != Some(target_id.as_str())
        {
            return Err(UpdateError::JournalBindingMismatch);
        }
        validate_persisted_state(&state)?;
        let journal_generation = store.generation()?;
        Ok(Self {
            state,
            policy,
            store,
            update_id,
            target_id,
            journal_generation,
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

    #[must_use]
    pub fn snapshot_generation(&self) -> Option<&str> {
        (self.state.stage == UpdateStage::Snapshot)
            .then_some(self.journal_generation.token.as_str())
    }

    #[must_use]
    pub fn snapshot_started_unix_ms(&self) -> Option<u64> {
        (self.state.stage == UpdateStage::Snapshot)
            .then_some(self.journal_generation.committed_unix_ms)
    }

    #[must_use]
    pub fn dispatch_generation(&self) -> Option<&str> {
        (self.state.stage == UpdateStage::PackageTransaction
            && self.state.external_effect == ExternalEffectState::DispatchStarted)
            .then_some(self.journal_generation.token.as_str())
    }

    #[must_use]
    pub fn dispatch_started_unix_ms(&self) -> Option<u64> {
        (self.state.stage == UpdateStage::PackageTransaction
            && self.state.external_effect == ExternalEffectState::DispatchStarted)
            .then_some(self.journal_generation.committed_unix_ms)
    }

    pub fn transition(&mut self, next: UpdateStage) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        let mut candidate = self.state.clone();
        candidate.transition(next)?;
        self.commit(candidate)
    }

    pub fn record_snapshot(&mut self, receipt: &SnapshotReceipt) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::Snapshot {
            return Err(UpdateError::InvalidOperation(
                "snapshot evidence can only be recorded at Snapshot stage",
            ));
        }
        if receipt.update_id != self.update_id
            || receipt.target_id != self.target_id
            || receipt.attempt_generation != self.journal_generation.token
        {
            return Err(UpdateError::EvidenceBindingMismatch(
                "snapshot receipt belongs to another update, target or snapshot attempt",
            ));
        }
        validate_snapshot_evidence_freshness(
            receipt.issued_unix_ms,
            self.journal_generation.committed_unix_ms,
        )?;
        let mut candidate = self.state.clone();
        candidate.snapshot_id = Some(receipt.snapshot_id.clone());
        candidate.snapshot_receipt_id = Some(receipt.receipt_id.clone());
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
        self.ensure_snapshot_policy_satisfied()?;
        let mut candidate = self.state.clone();
        candidate.stage = UpdateStage::PackageTransaction;
        candidate.transaction_id = Some(normalize_identifier(
            "transaction id",
            transaction_id.into(),
        )?);
        candidate.verification_receipt_id = None;
        candidate.external_effect = ExternalEffectState::Prepared;
        self.commit(candidate)
    }

    pub fn mark_dispatch_started(&mut self) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::PackageTransaction
            || self.state.external_effect != ExternalEffectState::Prepared
            || self.state.transaction_id.is_none()
            || self.state.verification_receipt_id.is_some()
        {
            return Err(UpdateError::InvalidOperation(
                "dispatch start requires an exact durably prepared package transaction",
            ));
        }
        self.ensure_snapshot_policy_satisfied()?;
        let mut candidate = self.state.clone();
        candidate.external_effect = ExternalEffectState::DispatchStarted;
        self.commit(candidate)
    }

    pub fn mark_package_verified(
        &mut self,
        receipt: &PackageVerificationReceipt,
    ) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        if self.state.stage != UpdateStage::PackageTransaction
            || self.state.external_effect != ExternalEffectState::DispatchStarted
        {
            return Err(UpdateError::InvalidOperation(
                "package verification requires a previously dispatched transaction",
            ));
        }
        let transaction_id = self.state.transaction_id.as_deref().ok_or_else(|| {
            UpdateError::CorruptJournal(
                "dispatched package transaction lost its transaction identity".into(),
            )
        })?;
        if receipt.update_id != self.update_id
            || receipt.target_id != self.target_id
            || receipt.transaction_id != transaction_id
            || receipt.dispatch_generation != self.journal_generation.token
        {
            return Err(UpdateError::EvidenceBindingMismatch(
                "package verification receipt belongs to another update, target, transaction or dispatch instance",
            ));
        }
        validate_package_evidence_freshness(
            receipt.issued_unix_ms,
            self.journal_generation.committed_unix_ms,
        )?;
        let mut candidate = self.state.clone();
        candidate.verification_receipt_id = Some(receipt.receipt_id.clone());
        candidate.external_effect = ExternalEffectState::Verified;
        self.commit_with_package_freshness(candidate, receipt.issued_unix_ms)
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
                if self.snapshot_policy_satisfied() {
                    UpdateResumeDecision::SafeToDispatchPrepared
                } else {
                    UpdateResumeDecision::ManualRecoveryRequired
                }
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

    fn snapshot_policy_satisfied(&self) -> bool {
        !self.policy.require_snapshot_when_available
            || (self.state.snapshot_id.is_some() && self.state.snapshot_receipt_id.is_some())
    }

    fn ensure_snapshot_policy_satisfied(&self) -> Result<(), UpdateError> {
        if self.snapshot_policy_satisfied() {
            Ok(())
        } else {
            Err(UpdateError::SnapshotRequired)
        }
    }

    fn ensure_usable(&self) -> Result<(), UpdateError> {
        if let Some(reason) = &self.durability_uncertain {
            return Err(UpdateError::RecoveryRequired(reason.clone()));
        }
        Ok(())
    }

    fn commit(&mut self, candidate: UpdateState) -> Result<(), UpdateError> {
        self.commit_with_validation(candidate, None)
    }

    fn commit_with_package_freshness(
        &mut self,
        candidate: UpdateState,
        issued_unix_ms: u64,
    ) -> Result<(), UpdateError> {
        self.commit_with_validation(candidate, Some(issued_unix_ms))
    }

    fn commit_with_validation(
        &mut self,
        candidate: UpdateState,
        package_verification_issued_unix_ms: Option<u64>,
    ) -> Result<(), UpdateError> {
        self.ensure_usable()?;
        validate_persisted_state(&candidate)?;
        let _lock = self.store.acquire_exclusive()?;
        let durable = self.store.load()?;
        let durable_generation = self.store.generation()?;
        if durable != self.state || durable_generation != self.journal_generation {
            let reason = "durable update state/generation changed through another coordinator; reopen and reconcile before continuing".to_owned();
            self.durability_uncertain = Some(reason);
            return Err(UpdateError::StaleCoordinator);
        }
        if let Some(issued_unix_ms) = package_verification_issued_unix_ms {
            validate_package_evidence_freshness(
                issued_unix_ms,
                durable_generation.committed_unix_ms,
            )?;
        }
        match self.store.persist(&candidate) {
            Ok(()) => {
                let generation = match self.store.generation() {
                    Ok(generation) => generation,
                    Err(error) => {
                        return self.handle_persist_failure(UpdateError::DurabilityUncertain(
                            format!(
                                "journal commit succeeded but the new durable generation could not be re-observed: {error}"
                            ),
                        ));
                    }
                };
                self.state = candidate;
                self.journal_generation = generation;
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
    EvidenceBindingMismatch(&'static str),
    JournalBindingMismatch,
    UntrustedJournalPath,
    UntrustedLockPath,
    UntrustedEvidenceRoot,
    UntrustedEvidencePath,
    StaleCoordinator,
    UnsupportedJournalVersion,
    UnsupportedEvidenceVersion,
    CorruptJournal(String),
    CorruptEvidence(String),
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
            Self::SnapshotRequired => f.write_str(
                "the current update policy requires trusted snapshot evidence before package dispatch",
            ),
            Self::ExternalEffectNotVerified => f.write_str(
                "package transaction cannot advance until authoritative exact-bound verification evidence succeeds",
            ),
            Self::EvidenceBindingMismatch(message) => f.write_str(message),
            Self::JournalBindingMismatch => f.write_str(
                "update journal is bound to another update attempt or target and cannot be reused",
            ),
            Self::UntrustedJournalPath => f.write_str(
                "update journal must be a regular non-symlink file without group/other write access",
            ),
            Self::UntrustedLockPath => f.write_str(
                "update lock must be a stable regular non-symlink file without group/other write access",
            ),
            Self::UntrustedEvidenceRoot => write!(
                f,
                "update evidence root must be the fixed root-owned trusted producer path {V09_UPDATE_EVIDENCE_ROOT} without group/other write access"
            ),
            Self::UntrustedEvidencePath => f.write_str(
                "update evidence receipt must be a single-link regular non-symlink file owned by the trusted evidence producer without group/other write access",
            ),
            Self::StaleCoordinator => f.write_str(
                "update coordinator observed stale durable state/generation and must be reopened/reconciled",
            ),
            Self::UnsupportedJournalVersion => f.write_str("unsupported update journal version"),
            Self::UnsupportedEvidenceVersion => f.write_str("unsupported update evidence version"),
            Self::CorruptJournal(reason) => write!(f, "corrupt update journal: {reason}"),
            Self::CorruptEvidence(reason) => write!(f, "corrupt update evidence: {reason}"),
            Self::DurabilityUncertain(reason) => write!(
                f,
                "update journal rename may have committed but durable directory sync/generation is uncertain: {reason}"
            ),
            Self::RecoveryRequired(reason) => write!(
                f,
                "update coordinator is poisoned by uncertain durable state and must be reopened/reconciled before continuing: {reason}"
            ),
            Self::Io(message) => write!(f, "update persistence/evidence I/O failed: {message}"),
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
    let update_id = state
        .update_id
        .as_ref()
        .ok_or_else(|| UpdateError::CorruptJournal("journal lacks update binding".into()))?;
    let target_id = state
        .target_id
        .as_ref()
        .ok_or_else(|| UpdateError::CorruptJournal("journal lacks target binding".into()))?;
    normalize_identifier("update id", update_id.clone())?;
    normalize_identifier("update target id", target_id.clone())?;
    if let Some(value) = &state.snapshot_id {
        normalize_identifier("snapshot id", value.clone())?;
    }
    if let Some(value) = &state.snapshot_receipt_id {
        normalize_identifier("snapshot receipt id", value.clone())?;
    }
    if state.snapshot_id.is_some() != state.snapshot_receipt_id.is_some() {
        return Err(UpdateError::CorruptJournal(
            "snapshot identity and trusted receipt identity must be retained together".into(),
        ));
    }
    if let Some(value) = &state.transaction_id {
        normalize_identifier("transaction id", value.clone())?;
    }
    if let Some(value) = &state.verification_receipt_id {
        normalize_identifier("verification receipt id", value.clone())?;
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
        match state.external_effect {
            ExternalEffectState::Verified if state.verification_receipt_id.is_none() => {
                return Err(UpdateError::CorruptJournal(
                    "verified package state lacks authoritative verification receipt identity"
                        .into(),
                ));
            }
            ExternalEffectState::Prepared | ExternalEffectState::DispatchStarted
                if state.verification_receipt_id.is_some() =>
            {
                return Err(UpdateError::CorruptJournal(
                    "unverified package state retained a verification receipt".into(),
                ));
            }
            _ => {}
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
    ) && (state.transaction_id.is_some() || state.verification_receipt_id.is_some())
    {
        return Err(UpdateError::CorruptJournal(
            "pre-package stage retained package transaction/verification identity".into(),
        ));
    }

    if matches!(
        state.stage,
        UpdateStage::Migrations
            | UpdateStage::Reconcile
            | UpdateStage::RestartAssessment
            | UpdateStage::Verify
            | UpdateStage::Complete
    ) && (state.transaction_id.is_none() || state.verification_receipt_id.is_none())
    {
        return Err(UpdateError::CorruptJournal(
            "post-package stage lacks retained package transaction or authoritative verification receipt identity"
                .into(),
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

fn system_time_to_unix_ms(time: SystemTime) -> Result<u64, UpdateError> {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_err(|error| UpdateError::Io(error.to_string()))?
        .as_millis();
    u64::try_from(millis).map_err(|_| UpdateError::Io("timestamp exceeds u64 range".into()))
}

fn unix_now_ms() -> Result<u64, UpdateError> {
    system_time_to_unix_ms(SystemTime::now())
}

fn validate_snapshot_evidence_freshness(
    issued_unix_ms: u64,
    snapshot_started_unix_ms: u64,
) -> Result<(), UpdateError> {
    let now = unix_now_ms()?;
    if issued_unix_ms < snapshot_started_unix_ms
        || issued_unix_ms > now.saturating_add(SNAPSHOT_EVIDENCE_FUTURE_SKEW_MS)
        || now.saturating_sub(issued_unix_ms) > SNAPSHOT_EVIDENCE_MAX_AGE_MS
    {
        return Err(UpdateError::EvidenceBindingMismatch(
            "snapshot receipt is stale, predates this snapshot attempt, or is implausibly future-dated",
        ));
    }
    Ok(())
}

fn validate_package_evidence_freshness(
    issued_unix_ms: u64,
    dispatch_started_unix_ms: u64,
) -> Result<(), UpdateError> {
    let now = unix_now_ms()?;
    if issued_unix_ms < dispatch_started_unix_ms
        || issued_unix_ms > now.saturating_add(PACKAGE_VERIFICATION_FUTURE_SKEW_MS)
        || now.saturating_sub(issued_unix_ms) > PACKAGE_VERIFICATION_MAX_AGE_MS
    {
        return Err(UpdateError::EvidenceBindingMismatch(
            "package verification receipt is stale, predates this dispatch, or is implausibly future-dated",
        ));
    }
    Ok(())
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

fn validate_journal_metadata(metadata: &fs::Metadata) -> Result<(), UpdateError> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(UpdateError::UntrustedJournalPath);
    }
    Ok(())
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

fn trusted_evidence_root_metadata(
    path: &Path,
    expected_uid: u32,
) -> Result<fs::Metadata, UpdateError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != expected_uid
    {
        return Err(UpdateError::UntrustedEvidenceRoot);
    }
    Ok(metadata)
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
            "invalid hex-encoded field".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| UpdateError::CorruptJournal("invalid field encoding".into()))?;
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| UpdateError::CorruptJournal("invalid field encoding".into()))?,
        );
    }
    let decoded = String::from_utf8(bytes)
        .map_err(|_| UpdateError::CorruptJournal("field is not UTF-8".into()))?;
    Ok(Some(decoded))
}

fn required_hex(value: &str, label: &str) -> Result<String, UpdateError> {
    hex_decode(value)?.ok_or_else(|| UpdateError::CorruptEvidence(format!("missing {label}")))
}

fn optional_u64(value: &str, label: &str) -> Result<Option<u64>, UpdateError> {
    if value == "-" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| UpdateError::CorruptEvidence(format!("invalid {label}")))
}

fn serialize_journal(state: &UpdateState) -> Vec<u8> {
    let mut payload = format!(
        "{JOURNAL_MAGIC}\nupdate={}\ntarget={}\nstage={}\nsnapshot={}\nsnapshot_receipt={}\ntransaction={}\nverification_receipt={}\neffect={}\nrecovery={}\n",
        hex_encode(state.update_id.as_deref()),
        hex_encode(state.target_id.as_deref()),
        state.stage.as_str(),
        hex_encode(state.snapshot_id.as_deref()),
        hex_encode(state.snapshot_receipt_id.as_deref()),
        hex_encode(state.transaction_id.as_deref()),
        hex_encode(state.verification_receipt_id.as_deref()),
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
    let update = parse_field(lines.next(), "update")?;
    let target = parse_field(lines.next(), "target")?;
    let stage = parse_field(lines.next(), "stage")?;
    let snapshot = parse_field(lines.next(), "snapshot")?;
    let snapshot_receipt = parse_field(lines.next(), "snapshot_receipt")?;
    let transaction = parse_field(lines.next(), "transaction")?;
    let verification_receipt = parse_field(lines.next(), "verification_receipt")?;
    let effect = parse_field(lines.next(), "effect")?;
    let recovery = parse_field(lines.next(), "recovery")?;
    if lines.next().is_some() {
        return Err(UpdateError::CorruptJournal(
            "unexpected journal field".into(),
        ));
    }
    let state = UpdateState {
        update_id: hex_decode(update)?,
        target_id: hex_decode(target)?,
        stage: UpdateStage::parse(stage)?,
        snapshot_id: hex_decode(snapshot)?,
        snapshot_receipt_id: hex_decode(snapshot_receipt)?,
        transaction_id: hex_decode(transaction)?,
        verification_receipt_id: hex_decode(verification_receipt)?,
        recovery_reason: hex_decode(recovery)?,
        external_effect: ExternalEffectState::parse(effect)?,
    };
    validate_persisted_state(&state)?;
    Ok(state)
}

fn hmac_sha256(key: &[u8; EVIDENCE_AUTH_KEY_BYTES], payload: &[u8]) -> String {
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= *byte;
        outer_pad[index] ^= *byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(payload);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn read_evidence_auth_key(
    root: &Path,
    expected_uid: u32,
) -> Result<[u8; EVIDENCE_AUTH_KEY_BYTES], UpdateError> {
    let path = root.join(EVIDENCE_AUTH_KEY_FILE);
    let before = fs::symlink_metadata(&path).map_err(io_error)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != expected_uid
        || before.nlink() != 1
        || before.permissions().mode() & 0o077 != 0
        || before.len() != EVIDENCE_AUTH_KEY_BYTES as u64
    {
        return Err(UpdateError::UntrustedEvidencePath);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&path)
        .map_err(io_error)?;
    let opened = file.metadata().map_err(io_error)?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != expected_uid
        || opened.nlink() != 1
    {
        return Err(UpdateError::UntrustedEvidencePath);
    }
    let mut key = [0_u8; EVIDENCE_AUTH_KEY_BYTES];
    file.read_exact(&mut key).map_err(io_error)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(io_error)? != 0 || key.iter().all(|byte| *byte == 0) {
        key.fill(0);
        return Err(UpdateError::UntrustedEvidencePath);
    }
    Ok(key)
}

fn serialize_evidence(evidence: &ParsedEvidence, key: &[u8; EVIDENCE_AUTH_KEY_BYTES]) -> Vec<u8> {
    let issued = evidence
        .issued_unix_ms
        .map_or_else(|| "-".to_owned(), |value| value.to_string());
    let payload = format!(
        "{EVIDENCE_MAGIC}\nkind={}\nupdate={}\ntarget={}\nsubject={}\nproof={}\ndispatch_generation={}\nissued_unix_ms={}\nsource={}\nresult={}\n",
        evidence.kind.as_str(),
        hex_encode(Some(&evidence.update_id)),
        hex_encode(Some(&evidence.target_id)),
        hex_encode(Some(&evidence.subject_id)),
        hex_encode(Some(&evidence.proof_id)),
        hex_encode(evidence.dispatch_generation.as_deref()),
        issued,
        evidence.source,
        evidence.result,
    );
    let authentication = hmac_sha256(key, payload.as_bytes());
    format!("{payload}authentication={authentication}\n").into_bytes()
}

fn parse_evidence(
    bytes: &[u8],
    key: &[u8; EVIDENCE_AUTH_KEY_BYTES],
) -> Result<ParsedEvidence, UpdateError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| UpdateError::CorruptEvidence("evidence is not UTF-8".into()))?;
    let authentication_start = text
        .rfind("authentication=")
        .ok_or_else(|| UpdateError::CorruptEvidence("authentication record is missing".into()))?;
    let (payload, authentication_line) = text.split_at(authentication_start);
    let expected = authentication_line
        .strip_prefix("authentication=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| UpdateError::CorruptEvidence("invalid authentication record".into()))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdateError::CorruptEvidence(
            "invalid HMAC-SHA-256 authentication".into(),
        ));
    }
    let observed = hmac_sha256(key, payload.as_bytes());
    if !constant_time_hex_eq(&observed, expected) {
        return Err(UpdateError::CorruptEvidence(
            "evidence authentication mismatch".into(),
        ));
    }
    let mut lines = payload.lines();
    if lines.next() != Some(EVIDENCE_MAGIC) {
        return Err(UpdateError::UnsupportedEvidenceVersion);
    }
    let kind = EvidenceKind::parse(parse_field(lines.next(), "kind")?)?;
    let update_id = required_hex(parse_field(lines.next(), "update")?, "update field")?;
    let target_id = required_hex(parse_field(lines.next(), "target")?, "target field")?;
    let subject_id = required_hex(parse_field(lines.next(), "subject")?, "subject field")?;
    let proof_id = required_hex(parse_field(lines.next(), "proof")?, "proof field")?;
    let dispatch_generation = hex_decode(parse_field(lines.next(), "dispatch_generation")?)?;
    let issued_unix_ms = optional_u64(
        parse_field(lines.next(), "issued_unix_ms")?,
        "issued_unix_ms field",
    )?;
    let source = parse_field(lines.next(), "source")?.to_owned();
    let result = parse_field(lines.next(), "result")?.to_owned();
    if lines.next().is_some() {
        return Err(UpdateError::CorruptEvidence(
            "unexpected evidence field".into(),
        ));
    }
    normalize_identifier("update id", update_id.clone())?;
    normalize_identifier("update target id", target_id.clone())?;
    normalize_identifier("evidence subject id", subject_id.clone())?;
    normalize_identifier("evidence proof id", proof_id.clone())?;
    if let Some(value) = &dispatch_generation {
        normalize_identifier("dispatch generation", value.clone())?;
    }
    normalize_identifier("evidence source", source.clone())?;
    normalize_identifier("evidence result", result.clone())?;
    Ok(ParsedEvidence {
        kind,
        update_id,
        target_id,
        subject_id,
        proof_id,
        dispatch_generation,
        issued_unix_ms,
        source,
        result,
    })
}

#[cfg(feature = "qualification-harness")]
pub struct QualificationUpdateEvidenceIssuer {
    root: PathBuf,
    key: [u8; EVIDENCE_AUTH_KEY_BYTES],
}

#[cfg(feature = "qualification-harness")]
impl std::fmt::Debug for QualificationUpdateEvidenceIssuer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QualificationUpdateEvidenceIssuer")
            .field("root", &self.root)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "qualification-harness")]
impl Drop for QualificationUpdateEvidenceIssuer {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

#[cfg(feature = "qualification-harness")]
impl QualificationUpdateEvidenceIssuer {
    pub fn open_or_create() -> Result<Self, UpdateError> {
        let root = PathBuf::from(V09_UPDATE_EVIDENCE_ROOT);
        fs::create_dir_all(&root).map_err(io_error)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        trusted_evidence_root_metadata(&root, V09_UPDATE_EVIDENCE_PRODUCER_UID)?;
        let key_path = root.join(EVIDENCE_AUTH_KEY_FILE);
        if !key_path.exists() {
            let mut random = fs::File::open("/dev/urandom").map_err(io_error)?;
            let mut key = [0_u8; EVIDENCE_AUTH_KEY_BYTES];
            random.read_exact(&mut key).map_err(io_error)?;
            if key.iter().all(|byte| *byte == 0) {
                return Err(UpdateError::CorruptEvidence(
                    "OS random source returned an all-zero evidence key".into(),
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .map_err(io_error)?;
            file.write_all(&key).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            key.fill(0);
            fs::File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?;
        }
        let key = read_evidence_auth_key(&root, V09_UPDATE_EVIDENCE_PRODUCER_UID)?;
        Ok(Self { root, key })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_package_verification(
        &self,
        receipt_id: &str,
        update_id: &str,
        target_id: &str,
        transaction_id: &str,
        observation_id: &str,
        dispatch_generation: &str,
    ) -> Result<(), UpdateError> {
        let receipt_id = normalize_identifier("evidence receipt id", receipt_id.to_owned())?;
        let evidence = ParsedEvidence {
            kind: EvidenceKind::PackageVerification,
            update_id: normalize_identifier("update id", update_id.to_owned())?,
            target_id: normalize_identifier("update target id", target_id.to_owned())?,
            subject_id: normalize_identifier("transaction id", transaction_id.to_owned())?,
            proof_id: normalize_identifier("observation id", observation_id.to_owned())?,
            dispatch_generation: Some(normalize_identifier(
                "dispatch generation",
                dispatch_generation.to_owned(),
            )?),
            issued_unix_ms: Some(unix_now_ms()?),
            source: V09_UPDATE_EVIDENCE_PRODUCER_ID.into(),
            result: "verified".into(),
        };
        let bytes = serialize_evidence(&evidence, &self.key);
        let path = self.root.join(format!("{receipt_id}.receipt"));
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(io_error)?;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)
    }
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

    const UPDATE_ID: &str = "update-1";
    const TARGET_ID: &str = "system-root";

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
        coordinator_with_policy(label, UpdatePolicy::default())
    }

    fn coordinator_with_policy(label: &str, policy: UpdatePolicy) -> (TestDir, UpdateCoordinator) {
        let dir = TestDir::new(label);
        let store = UpdateJournalStore::new(dir.path().join("update.journal"));
        let coordinator = UpdateCoordinator::open(store, policy, UPDATE_ID, TARGET_ID)
            .unwrap_or_else(|error| unreachable!("{error}"));
        (dir, coordinator)
    }

    const TEST_EVIDENCE_KEY: [u8; EVIDENCE_AUTH_KEY_BYTES] = [0x6b; EVIDENCE_AUTH_KEY_BYTES];

    fn evidence_root(dir: &TestDir) -> PathBuf {
        let root = dir.path().join("trusted-evidence");
        fs::create_dir_all(&root).unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let key_path = root.join(EVIDENCE_AUTH_KEY_FILE);
        if !key_path.exists() {
            fs::write(&key_path, TEST_EVIDENCE_KEY).unwrap_or_else(|error| unreachable!("{error}"));
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        root
    }

    #[allow(clippy::too_many_arguments)]
    fn write_evidence(
        root: &Path,
        receipt_id: &str,
        kind: EvidenceKind,
        update_id: &str,
        target_id: &str,
        subject_id: &str,
        proof_id: &str,
        dispatch_generation: Option<&str>,
        issued_unix_ms: Option<u64>,
        source: &str,
        result: &str,
    ) {
        let evidence = ParsedEvidence {
            kind,
            update_id: update_id.into(),
            target_id: target_id.into(),
            subject_id: subject_id.into(),
            proof_id: proof_id.into(),
            dispatch_generation: dispatch_generation.map(str::to_owned),
            issued_unix_ms,
            source: source.into(),
            result: result.into(),
        };
        let path = root.join(format!("{receipt_id}.receipt"));
        fs::write(&path, serialize_evidence(&evidence, &TEST_EVIDENCE_KEY))
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| unreachable!("{error}"));
    }

    fn snapshot_receipt(
        dir: &TestDir,
        target_id: &str,
        coordinator: &UpdateCoordinator,
    ) -> SnapshotReceipt {
        let root = evidence_root(dir);
        let attempt_generation = coordinator
            .snapshot_generation()
            .unwrap_or_else(|| unreachable!("snapshot generation missing"));
        let snapshot_started_unix_ms = coordinator
            .snapshot_started_unix_ms()
            .unwrap_or_else(|| unreachable!("snapshot timestamp missing"));
        let issued_unix_ms = unix_now_ms().unwrap_or_else(|error| unreachable!("{error}"));
        write_evidence(
            &root,
            "snapshot-receipt-1",
            EvidenceKind::Snapshot,
            UPDATE_ID,
            target_id,
            "snapshot-1",
            "snapshot-proof-1",
            Some(attempt_generation),
            Some(issued_unix_ms),
            V09_UPDATE_EVIDENCE_PRODUCER_ID,
            "durable",
        );
        TrustedUpdateEvidenceVerifier::open_for_test(&root)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .verify_snapshot(
                "snapshot-receipt-1",
                UPDATE_ID,
                target_id,
                attempt_generation,
                snapshot_started_unix_ms,
            )
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn package_receipt(
        dir: &TestDir,
        target_id: &str,
        transaction_id: &str,
        coordinator: &UpdateCoordinator,
    ) -> PackageVerificationReceipt {
        let root = evidence_root(dir);
        let dispatch_generation = coordinator
            .dispatch_generation()
            .unwrap_or_else(|| unreachable!("dispatch generation missing"));
        let dispatch_started_unix_ms = coordinator
            .dispatch_started_unix_ms()
            .unwrap_or_else(|| unreachable!("dispatch timestamp missing"));
        let issued_unix_ms = unix_now_ms().unwrap_or_else(|error| unreachable!("{error}"));
        write_evidence(
            &root,
            "package-receipt-1",
            EvidenceKind::PackageVerification,
            UPDATE_ID,
            target_id,
            transaction_id,
            "observation-1",
            Some(dispatch_generation),
            Some(issued_unix_ms),
            V09_UPDATE_EVIDENCE_PRODUCER_ID,
            "verified",
        );
        TrustedUpdateEvidenceVerifier::open_for_test(&root)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .verify_package(
                "package-receipt-1",
                UPDATE_ID,
                target_id,
                transaction_id,
                dispatch_generation,
                dispatch_started_unix_ms,
            )
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn advance_to_snapshot(coordinator: &mut UpdateCoordinator) {
        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            coordinator
                .transition(stage)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
    }

    #[test]
    fn update_happy_path_is_ordered() {
        let mut state = UpdateState {
            update_id: Some(UPDATE_ID.into()),
            target_id: Some(TARGET_ID.into()),
            ..UpdateState::default()
        };
        for stage in [
            UpdateStage::Preflight,
            UpdateStage::DiskSpace,
            UpdateStage::Snapshot,
        ] {
            assert_eq!(state.transition(stage), Ok(()));
        }
        state.snapshot_id = Some("snapshot-1".into());
        state.snapshot_receipt_id = Some("snapshot-receipt-1".into());
        state.transaction_id = Some("transaction-1".into());
        state.external_effect = ExternalEffectState::Prepared;
        assert_eq!(state.transition(UpdateStage::PackageTransaction), Ok(()));
        state.external_effect = ExternalEffectState::Verified;
        state.verification_receipt_id = Some("package-receipt-1".into());
        for stage in [
            UpdateStage::Migrations,
            UpdateStage::Reconcile,
            UpdateStage::RestartAssessment,
            UpdateStage::Verify,
            UpdateStage::Complete,
        ] {
            assert_eq!(state.transition(stage), Ok(()));
        }
        assert_eq!(state.stage(), UpdateStage::Complete);
        assert_eq!(state.transaction_id(), Some("transaction-1"));
        assert_eq!(state.verification_receipt_id(), Some("package-receipt-1"));
    }

    #[test]
    fn prepared_transaction_is_durable_and_exactly_resumable_before_dispatch() {
        let (dir, mut coordinator) = coordinator("prepared");
        advance_to_snapshot(&mut coordinator);
        let snapshot = snapshot_receipt(&dir, TARGET_ID, &coordinator);
        coordinator
            .record_snapshot(&snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(coordinator);

        let reopened = UpdateCoordinator::open(
            UpdateJournalStore::new(dir.path().join("update.journal")),
            UpdatePolicy::default(),
            UPDATE_ID,
            TARGET_ID,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::SafeToDispatchPrepared
        );
        assert_eq!(reopened.state().transaction_id(), Some("transaction-1"));
        assert_eq!(
            reopened.state().snapshot_receipt_id(),
            Some("snapshot-receipt-1")
        );
    }

    #[test]
    fn prepared_transaction_revalidates_current_snapshot_policy_on_resume_and_dispatch() {
        let policy_without_snapshot = UpdatePolicy {
            require_snapshot_when_available: false,
            ..UpdatePolicy::default()
        };
        let (dir, mut coordinator) =
            coordinator_with_policy("policy-revalidation", policy_without_snapshot);
        advance_to_snapshot(&mut coordinator);
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(coordinator);

        let mut reopened = UpdateCoordinator::open(
            UpdateJournalStore::new(dir.path().join("update.journal")),
            UpdatePolicy::default(),
            UPDATE_ID,
            TARGET_ID,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::ManualRecoveryRequired
        );
        assert_eq!(
            reopened.mark_dispatch_started(),
            Err(UpdateError::SnapshotRequired)
        );
    }

    #[test]
    fn journal_binding_cannot_be_reused_for_another_update_or_target() {
        let (dir, coordinator) = coordinator("journal-binding");
        drop(coordinator);
        assert!(matches!(
            UpdateCoordinator::open(
                UpdateJournalStore::new(dir.path().join("update.journal")),
                UpdatePolicy::default(),
                "another-update",
                TARGET_ID,
            ),
            Err(UpdateError::JournalBindingMismatch)
        ));
        assert!(matches!(
            UpdateCoordinator::open(
                UpdateJournalStore::new(dir.path().join("update.journal")),
                UpdatePolicy::default(),
                UPDATE_ID,
                "another-target",
            ),
            Err(UpdateError::JournalBindingMismatch)
        ));
    }

    #[test]
    fn snapshot_receipt_must_be_trusted_and_exact_target_bound() {
        let (dir, mut coordinator) = coordinator("snapshot-binding");
        advance_to_snapshot(&mut coordinator);
        let wrong_target = snapshot_receipt(&dir, "other-target", &coordinator);
        assert!(matches!(
            coordinator.record_snapshot(&wrong_target),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
        assert!(coordinator.state().snapshot_id().is_none());

        let root = evidence_root(&dir);
        let generation = coordinator
            .snapshot_generation()
            .unwrap_or_else(|| unreachable!("snapshot generation missing"));
        let started = coordinator
            .snapshot_started_unix_ms()
            .unwrap_or_else(|| unreachable!("snapshot timestamp missing"));
        write_evidence(
            &root,
            "forged-snapshot",
            EvidenceKind::Snapshot,
            UPDATE_ID,
            TARGET_ID,
            "snapshot-forged",
            "proof-forged",
            Some(generation),
            Some(unix_now_ms().unwrap_or_else(|error| unreachable!("{error}"))),
            "caller-string",
            "durable",
        );
        let verifier = TrustedUpdateEvidenceVerifier::open_for_test(root)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            verifier.verify_snapshot("forged-snapshot", UPDATE_ID, TARGET_ID, generation, started,),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
    }

    #[test]
    fn snapshot_receipt_cannot_replay_across_update_attempt_generations() {
        let (first_dir, mut first) = coordinator("snapshot-replay-first");
        advance_to_snapshot(&mut first);
        let old_receipt = snapshot_receipt(&first_dir, TARGET_ID, &first);
        let old_generation = old_receipt.attempt_generation().to_owned();

        let (second_dir, mut second) = coordinator("snapshot-replay-second");
        advance_to_snapshot(&mut second);
        assert_ne!(second.snapshot_generation(), Some(old_generation.as_str()));
        assert!(matches!(
            second.record_snapshot(&old_receipt),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
        assert!(second.state().snapshot_id().is_none());
        drop(second_dir);
    }

    #[test]
    fn stale_snapshot_receipt_is_rejected() {
        let (dir, mut coordinator) = coordinator("stale-snapshot");
        advance_to_snapshot(&mut coordinator);
        let root = evidence_root(&dir);
        let generation = coordinator
            .snapshot_generation()
            .unwrap_or_else(|| unreachable!("snapshot generation missing"));
        let started = coordinator
            .snapshot_started_unix_ms()
            .unwrap_or_else(|| unreachable!("snapshot timestamp missing"));
        write_evidence(
            &root,
            "stale-snapshot-receipt",
            EvidenceKind::Snapshot,
            UPDATE_ID,
            TARGET_ID,
            "snapshot-stale",
            "snapshot-proof-stale",
            Some(generation),
            Some(started.saturating_sub(1)),
            V09_UPDATE_EVIDENCE_PRODUCER_ID,
            "durable",
        );
        let verifier = TrustedUpdateEvidenceVerifier::open_for_test(root)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            verifier.verify_snapshot(
                "stale-snapshot-receipt",
                UPDATE_ID,
                TARGET_ID,
                generation,
                started,
            ),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
    }

    #[test]
    fn production_evidence_anchor_is_fixed_and_root_owned() {
        assert_eq!(V09_UPDATE_EVIDENCE_ROOT, "/var/lib/linura-update/v0.9");
        assert_eq!(V09_UPDATE_EVIDENCE_PRODUCER_UID, 0);
        assert_eq!(
            V09_UPDATE_EVIDENCE_PRODUCER_ID,
            "linura-update-evidence-v09"
        );
    }

    #[test]
    fn crash_after_dispatch_never_blindly_replays_package_transaction() {
        let (dir, mut coordinator) = coordinator("dispatch-started");
        advance_to_snapshot(&mut coordinator);
        let snapshot = snapshot_receipt(&dir, TARGET_ID, &coordinator);
        coordinator
            .record_snapshot(&snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let generation = coordinator
            .dispatch_generation()
            .unwrap_or_else(|| unreachable!("dispatch generation missing"))
            .to_owned();
        drop(coordinator);

        let reopened = UpdateCoordinator::open(
            UpdateJournalStore::new(dir.path().join("update.journal")),
            UpdatePolicy::default(),
            UPDATE_ID,
            TARGET_ID,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::ReobserveBeforeContinuing
        );
        assert_eq!(reopened.dispatch_generation(), Some(generation.as_str()));
    }

    #[test]
    fn stale_coordinator_cannot_roll_back_newer_dispatch_state() {
        let dir = TestDir::new("stale-coordinator");
        let store = UpdateJournalStore::new(dir.path().join("update.journal"));
        let mut current =
            UpdateCoordinator::open(store.clone(), UpdatePolicy::default(), UPDATE_ID, TARGET_ID)
                .unwrap_or_else(|error| unreachable!("{error}"));
        let mut stale =
            UpdateCoordinator::open(store.clone(), UpdatePolicy::default(), UPDATE_ID, TARGET_ID)
                .unwrap_or_else(|error| unreachable!("{error}"));

        advance_to_snapshot(&mut current);
        let snapshot = snapshot_receipt(&dir, TARGET_ID, &current);
        current
            .record_snapshot(&snapshot)
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

        let reopened =
            UpdateCoordinator::open(store, UpdatePolicy::default(), UPDATE_ID, TARGET_ID)
                .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::ReobserveBeforeContinuing
        );
    }

    #[test]
    fn migrations_are_blocked_until_exact_authoritative_verification_receipt() {
        let (dir, mut coordinator) = coordinator("verify-gate");
        advance_to_snapshot(&mut coordinator);
        let snapshot = snapshot_receipt(&dir, TARGET_ID, &coordinator);
        coordinator
            .record_snapshot(&snapshot)
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

        let wrong = package_receipt(&dir, TARGET_ID, "transaction-2", &coordinator);
        assert!(matches!(
            coordinator.mark_package_verified(&wrong),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
        assert_eq!(
            coordinator.state().external_effect(),
            ExternalEffectState::DispatchStarted
        );

        let receipt = package_receipt(&dir, TARGET_ID, "transaction-1", &coordinator);
        coordinator
            .mark_package_verified(&receipt)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            coordinator.state().verification_receipt_id(),
            Some("package-receipt-1")
        );
        assert_eq!(coordinator.transition(UpdateStage::Migrations), Ok(()));
    }

    #[test]
    fn package_verification_receipt_cannot_replay_across_dispatch_generations() {
        let (first_dir, mut first) = coordinator("receipt-replay-first");
        advance_to_snapshot(&mut first);
        let first_snapshot = snapshot_receipt(&first_dir, TARGET_ID, &first);
        first
            .record_snapshot(&first_snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        first
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        first
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let old_receipt = package_receipt(&first_dir, TARGET_ID, "transaction-1", &first);
        let old_generation = old_receipt.dispatch_generation().to_owned();

        let (second_dir, mut second) = coordinator("receipt-replay-second");
        advance_to_snapshot(&mut second);
        let second_snapshot = snapshot_receipt(&second_dir, TARGET_ID, &second);
        second
            .record_snapshot(&second_snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        second
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        second
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_ne!(second.dispatch_generation(), Some(old_generation.as_str()));
        assert!(matches!(
            second.mark_package_verified(&old_receipt),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
    }

    #[test]
    fn stale_package_verification_receipt_is_rejected() {
        let (dir, mut coordinator) = coordinator("stale-receipt");
        advance_to_snapshot(&mut coordinator);
        let snapshot = snapshot_receipt(&dir, TARGET_ID, &coordinator);
        coordinator
            .record_snapshot(&snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));

        let root = evidence_root(&dir);
        let generation = coordinator
            .dispatch_generation()
            .unwrap_or_else(|| unreachable!("dispatch generation missing"));
        let started = coordinator
            .dispatch_started_unix_ms()
            .unwrap_or_else(|| unreachable!("dispatch timestamp missing"));
        write_evidence(
            &root,
            "stale-package-receipt",
            EvidenceKind::PackageVerification,
            UPDATE_ID,
            TARGET_ID,
            "transaction-1",
            "observation-stale",
            Some(generation),
            Some(started.saturating_sub(1)),
            V09_UPDATE_EVIDENCE_PRODUCER_ID,
            "verified",
        );
        let verifier = TrustedUpdateEvidenceVerifier::open_for_test(root)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            verifier.verify_package(
                "stale-package-receipt",
                UPDATE_ID,
                TARGET_ID,
                "transaction-1",
                generation,
                started,
            ),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
    }

    #[test]
    fn package_verification_freshness_is_rechecked_at_locked_commit_boundary() {
        let (dir, mut coordinator) = coordinator("locked-freshness");
        advance_to_snapshot(&mut coordinator);
        let snapshot = snapshot_receipt(&dir, TARGET_ID, &coordinator);
        coordinator
            .record_snapshot(&snapshot)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .prepare_package_transaction("transaction-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_dispatch_started()
            .unwrap_or_else(|error| unreachable!("{error}"));

        let mut candidate = coordinator.state.clone();
        candidate.verification_receipt_id = Some("package-receipt-locked".into());
        candidate.external_effect = ExternalEffectState::Verified;
        let stale_issued_unix_ms = coordinator
            .journal_generation
            .committed_unix_ms
            .saturating_sub(1);
        assert!(matches!(
            coordinator.commit_with_package_freshness(candidate, stale_issued_unix_ms),
            Err(UpdateError::EvidenceBindingMismatch(_))
        ));
        assert_eq!(
            coordinator.state().external_effect(),
            ExternalEffectState::DispatchStarted
        );
        assert!(coordinator.state().verification_receipt_id().is_none());
        drop(coordinator);

        let reopened = UpdateCoordinator::open(
            UpdateJournalStore::new(dir.path().join("update.journal")),
            UpdatePolicy::default(),
            UPDATE_ID,
            TARGET_ID,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            UpdateResumeDecision::ReobserveBeforeContinuing
        );
        assert!(reopened.state().verification_receipt_id().is_none());
    }

    #[test]
    fn post_package_stages_require_retained_transaction_and_verification_lineage() {
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
                update_id: Some(UPDATE_ID.into()),
                target_id: Some(TARGET_ID.into()),
                stage,
                snapshot_id: None,
                snapshot_receipt_id: None,
                transaction_id: Some("transaction-1".into()),
                verification_receipt_id: None,
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
        advance_to_snapshot(&mut coordinator);
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
    fn untrusted_evidence_symlink_fails_closed() {
        let dir = TestDir::new("evidence-symlink");
        let root = evidence_root(&dir);
        symlink(
            dir.path().join("missing-receipt"),
            root.join("snapshot-receipt-1.receipt"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let verifier = TrustedUpdateEvidenceVerifier::open_for_test(root)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            verifier.verify_snapshot(
                "snapshot-receipt-1",
                UPDATE_ID,
                TARGET_ID,
                "snapshot-generation",
                unix_now_ms().unwrap_or_else(|error| unreachable!("{error}")),
            ),
            Err(UpdateError::UntrustedEvidencePath)
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
            update_id: Some(UPDATE_ID.into()),
            target_id: Some(TARGET_ID.into()),
            stage: UpdateStage::Snapshot,
            snapshot_id: Some("snapshot-1".into()),
            snapshot_receipt_id: Some("snapshot-receipt-1".into()),
            transaction_id: Some("transaction-1".into()),
            verification_receipt_id: None,
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

        let payload = b"linura-update-journal-v3\nupdate=-\ntarget=-\nstage=preflight\nsnapshot=-\nsnapshot_receipt=-\ntransaction=-\nverification_receipt=-\neffect=none\nrecovery=-\n";
        let tag = integrity_tag(payload);
        fs::write(
            &path,
            format!(
                "linura-update-journal-v3\nupdate=-\ntarget=-\nstage=preflight\nsnapshot=-\nsnapshot_receipt=-\ntransaction=-\nverification_receipt=-\neffect=none\nrecovery=-\nintegrity={tag:016x}\n"
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
