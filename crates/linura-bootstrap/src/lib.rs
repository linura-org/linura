#![forbid(unsafe_code)]

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!(
    "linura-bootstrap test-support is for unit/integration tests only and must never be enabled in optimized release builds"
);

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const V09_NATIVE_RECOVERY_SHELL: &str = "/usr/bin/bash";
pub const V09_NATIVE_RECOVERY_PACKAGE_MANAGER: &str = "/usr/bin/apt";
pub const V09_NATIVE_RECOVERY_IDENTITY: &str = "ubuntu-native-shell+apt-v1";
pub const V09_RECOVERY_EVIDENCE_ROOT: &str = "/var/lib/linura-recovery/v0.9";
pub const V09_RECOVERY_PRODUCER_ID: &str = "linura-recovery-v09";
const V09_RECOVERY_RECEIPT_SCHEMA: &str = "1";

/// Future/full OS-installer stages. These remain relevant to concrete installer
/// PlatformProfiles such as the Arch/Hyprland development path, but they are
/// deliberately not the v0.9 Linura-on-existing-Linux readiness sequence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InstallerStage {
    Preflight,
    DiskLayout,
    Encryption,
    BaseSystem,
    PlatformPackages,
    Bootloader,
    SecurityBaseline,
    SnapshotBaseline,
    UserProvisioning,
    FirstBootReady,
}

impl InstallerStage {
    pub const ORDERED: [Self; 10] = [
        Self::Preflight,
        Self::DiskLayout,
        Self::Encryption,
        Self::BaseSystem,
        Self::PlatformPackages,
        Self::Bootloader,
        Self::SecurityBaseline,
        Self::SnapshotBaseline,
        Self::UserProvisioning,
        Self::FirstBootReady,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerMode {
    Interactive,
    NonInteractive,
    Recovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallSecurityPolicy {
    pub require_disk_encryption: bool,
    pub inbound_firewall_default_deny: bool,
    pub ssh_enabled_initially: bool,
    pub untrusted_package_sources_enabled: bool,
}

impl Default for InstallSecurityPolicy {
    fn default() -> Self {
        Self {
            require_disk_encryption: true,
            inbound_firewall_default_deny: true,
            ssh_enabled_initially: false,
            untrusted_package_sources_enabled: false,
        }
    }
}

/// v0.9 begins after an independently verified Linux base exists. These stages
/// describe installation/adoption of the Linura layer, not disk partitioning or
/// bootloader ownership.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BootstrapStage {
    BaseEnvironmentVerification,
    LinuraInstallation,
    PersistentStateInitialization,
    SecurityBaseline,
    ProvisioningModeSelection,
    BootstrapConnectivityResolution,
    HardwareDiscovery,
    SourceSelection,
    TargetObservation,
    FirstBootPlanning,
    RecoveryCheckpoint,
    OwnerEnrollmentResolution,
    FirstBootReady,
}

impl BootstrapStage {
    pub const ORDERED: [Self; 13] = [
        Self::BaseEnvironmentVerification,
        Self::LinuraInstallation,
        Self::PersistentStateInitialization,
        Self::SecurityBaseline,
        Self::ProvisioningModeSelection,
        Self::BootstrapConnectivityResolution,
        Self::HardwareDiscovery,
        Self::SourceSelection,
        Self::TargetObservation,
        Self::FirstBootPlanning,
        Self::RecoveryCheckpoint,
        Self::OwnerEnrollmentResolution,
        Self::FirstBootReady,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningMode {
    InteractiveOwner,
    PrepareForAnotherOwner,
    UnattendedLocal,
    Recovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapConnectivity {
    Offline,
    BoundedNetwork,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptionSecurityPolicy {
    pub inbound_firewall_default_deny: bool,
    pub ssh_enabled_initially: bool,
    pub untrusted_package_sources_enabled: bool,
}

impl Default for AdoptionSecurityPolicy {
    fn default() -> Self {
        Self {
            inbound_firewall_default_deny: true,
            ssh_enabled_initially: false,
            untrusted_package_sources_enabled: false,
        }
    }
}

impl AdoptionSecurityPolicy {
    pub fn validate(&self) -> Result<(), BootstrapError> {
        if !self.inbound_firewall_default_deny
            || self.ssh_enabled_initially
            || self.untrusted_package_sources_enabled
        {
            return Err(BootstrapError::UnsafeAdoptionSecurityPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootstrapLedger {
    completed: BTreeSet<BootstrapStage>,
}

impl BootstrapLedger {
    /// Reconstruct persisted state only from a canonical ordered prefix. This is
    /// the recovery/loading path; callers cannot mark arbitrary stages complete.
    pub fn from_completed_prefix(stages: &[BootstrapStage]) -> Result<Self, BootstrapError> {
        let mut ledger = Self::default();
        for &stage in stages {
            ledger.complete_next(stage)?;
        }
        Ok(ledger)
    }

    pub fn complete_next(&mut self, stage: BootstrapStage) -> Result<(), BootstrapError> {
        let expected = self.next_stage().ok_or(BootstrapError::AlreadyComplete)?;
        if expected != stage {
            return Err(BootstrapError::UnexpectedStage {
                expected,
                actual: stage,
            });
        }
        self.completed.insert(stage);
        Ok(())
    }

    #[must_use]
    pub fn is_completed(&self, stage: BootstrapStage) -> bool {
        self.completed.contains(&stage)
    }

    #[must_use]
    pub fn next_stage(&self) -> Option<BootstrapStage> {
        BootstrapStage::ORDERED
            .into_iter()
            .find(|stage| !self.completed.contains(stage))
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completed.len() == BootstrapStage::ORDERED.len()
    }

    pub fn validate_prefix(&self) -> Result<(), BootstrapError> {
        let canonical: Vec<_> = BootstrapStage::ORDERED
            .into_iter()
            .take(self.completed.len())
            .collect();
        let actual: Vec<_> = BootstrapStage::ORDERED
            .into_iter()
            .filter(|stage| self.completed.contains(stage))
            .collect();
        if actual == canonical {
            Ok(())
        } else {
            let offending = actual
                .into_iter()
                .zip(canonical)
                .find_map(|(actual, expected)| (actual != expected).then_some(actual))
                .or_else(|| {
                    BootstrapStage::ORDERED
                        .into_iter()
                        .find(|stage| self.completed.contains(stage))
                })
                .unwrap_or(BootstrapStage::BaseEnvironmentVerification);
            Err(BootstrapError::OutOfOrder(offending))
        }
    }
}

/// Recovery readiness that can only be produced by the repository-owned
/// verifier below. The fields are private so an unprivileged First Boot caller
/// cannot assert `restorable=true`, invent producer provenance, or manufacture
/// a native recovery path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCheckpointEvidence {
    session_id: String,
    plan_id: String,
    checkpoint_id: String,
    checkpoint_sha256: String,
    checkpoint_size: u64,
    restored_copy_sha256: String,
    producer_identity: &'static str,
    restore_receipt_sha256: String,
    native_recovery_identity: &'static str,
}

impl RecoveryCheckpointEvidence {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    #[must_use]
    pub fn checkpoint_id(&self) -> &str {
        &self.checkpoint_id
    }

    #[must_use]
    pub fn checkpoint_sha256(&self) -> &str {
        &self.checkpoint_sha256
    }

    #[must_use]
    pub const fn checkpoint_size(&self) -> u64 {
        self.checkpoint_size
    }

    #[must_use]
    pub fn restored_copy_sha256(&self) -> &str {
        &self.restored_copy_sha256
    }

    #[must_use]
    pub const fn producer_identity(&self) -> &'static str {
        self.producer_identity
    }

    #[must_use]
    pub fn restore_receipt_sha256(&self) -> &str {
        &self.restore_receipt_sha256
    }

    #[must_use]
    pub const fn native_recovery_identity(&self) -> &'static str {
        self.native_recovery_identity
    }

    pub fn validate_binding(&self, session_id: &str, plan_id: &str) -> Result<(), BootstrapError> {
        if self.session_id != session_id || self.plan_id != plan_id {
            return Err(BootstrapError::RecoveryBindingMismatch);
        }
        if self.producer_identity != V09_RECOVERY_PRODUCER_ID {
            return Err(BootstrapError::RecoveryProducerMismatch);
        }
        validate_sha256(&self.restore_receipt_sha256)?;
        if self.checkpoint_sha256 != self.restored_copy_sha256 || self.checkpoint_size == 0 {
            return Err(BootstrapError::RecoveryRestoreMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RecoveryCheckpointVerifier;

impl RecoveryCheckpointVerifier {
    /// Verify v0.9 recovery evidence for the bounded Ubuntu QualificationEnvironment.
    ///
    /// In production, caller-supplied paths and the digest are only redundant
    /// assertions: they must resolve to the fixed protected producer layout
    /// under `V09_RECOVERY_EVIDENCE_ROOT`, and the authoritative digest/session/
    /// plan/checkpoint binding comes from a protected restore receipt emitted by
    /// `V09_RECOVERY_PRODUCER_ID`. Equal caller-created files are therefore not
    /// sufficient to mint `RecoveryCheckpointEvidence`.
    ///
    /// The `test-support` feature permits the existing cross-crate unit fixtures
    /// to fall back to synthetic local files. Optimized builds refuse to compile
    /// when that feature is enabled, so the fallback cannot enter a release build.
    pub fn verify_v09(
        session_id: impl Into<String>,
        plan_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
        checkpoint_path: impl AsRef<Path>,
        restored_copy_path: impl AsRef<Path>,
        expected_sha256: &str,
    ) -> Result<RecoveryCheckpointEvidence, BootstrapError> {
        let session_id = session_id.into();
        let plan_id = plan_id.into();
        let checkpoint_id = checkpoint_id.into();
        let checkpoint_path = checkpoint_path.as_ref().to_path_buf();
        let restored_copy_path = restored_copy_path.as_ref().to_path_buf();
        let trusted = verify_v09_from_trusted_root(
            &session_id,
            &plan_id,
            &checkpoint_id,
            &checkpoint_path,
            &restored_copy_path,
            expected_sha256,
            RecoveryProducerRoot {
                path: Path::new(V09_RECOVERY_EVIDENCE_ROOT),
                require_root_owner: true,
            },
        );

        #[cfg(feature = "test-support")]
        {
            match trusted {
                Ok(evidence) => Ok(evidence),
                Err(_) => verify_v09_test_support(
                    &session_id,
                    &plan_id,
                    &checkpoint_id,
                    &checkpoint_path,
                    &restored_copy_path,
                    expected_sha256,
                ),
            }
        }

        #[cfg(not(feature = "test-support"))]
        {
            trusted
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RecoveryProducerRoot<'a> {
    path: &'a Path,
    require_root_owner: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct TrustedRestoreReceipt {
    session_id: String,
    plan_id: String,
    checkpoint_id: String,
    checkpoint_sha256: String,
    restored_sha256: String,
}

fn verify_v09_from_trusted_root(
    session_id: &str,
    plan_id: &str,
    checkpoint_id: &str,
    checkpoint_path: &Path,
    restored_copy_path: &Path,
    expected_sha256: &str,
    producer: RecoveryProducerRoot<'_>,
) -> Result<RecoveryCheckpointEvidence, BootstrapError> {
    let session_id = normalize_required("First Boot session id", session_id)?;
    let plan_id = normalize_required("plan id", plan_id)?;
    let checkpoint_id = normalize_checkpoint_id(checkpoint_id)?;
    validate_sha256(expected_sha256)?;

    verify_native_recovery_program(Path::new(V09_NATIVE_RECOVERY_SHELL))?;
    verify_native_recovery_program(Path::new(V09_NATIVE_RECOVERY_PACKAGE_MANAGER))?;

    let root = verified_trusted_directory(producer.path, producer.require_root_owner)?;
    let checkpoint_root =
        verified_trusted_child_directory(&root, "checkpoints", producer.require_root_owner)?;
    let restored_root =
        verified_trusted_child_directory(&root, "restored", producer.require_root_owner)?;
    let receipt_root =
        verified_trusted_child_directory(&root, "receipts", producer.require_root_owner)?;

    let expected_checkpoint = verified_trusted_regular_file(
        &checkpoint_root.join(format!("{checkpoint_id}.bin")),
        &checkpoint_root,
        producer.require_root_owner,
    )?;
    let expected_restored = verified_trusted_regular_file(
        &restored_root.join(format!("{checkpoint_id}.bin")),
        &restored_root,
        producer.require_root_owner,
    )?;
    let receipt_path = verified_trusted_regular_file(
        &receipt_root.join(format!("{checkpoint_id}.receipt")),
        &receipt_root,
        producer.require_root_owner,
    )?;

    require_exact_recovery_path("checkpoint", checkpoint_path, &expected_checkpoint)?;
    require_exact_recovery_path("restored copy", restored_copy_path, &expected_restored)?;

    let checkpoint_metadata = fs::metadata(&expected_checkpoint).map_err(BootstrapError::Io)?;
    let restored_metadata = fs::metadata(&expected_restored).map_err(BootstrapError::Io)?;
    if expected_checkpoint == expected_restored
        || (checkpoint_metadata.dev() == restored_metadata.dev()
            && checkpoint_metadata.ino() == restored_metadata.ino())
    {
        return Err(BootstrapError::RecoveryRestoreNotIndependent);
    }

    let receipt_bytes = fs::read(&receipt_path).map_err(BootstrapError::Io)?;
    let receipt = parse_restore_receipt(&receipt_bytes)?;
    if receipt.session_id != session_id
        || receipt.plan_id != plan_id
        || receipt.checkpoint_id != checkpoint_id
        || receipt.checkpoint_sha256 != expected_sha256
    {
        return Err(BootstrapError::RecoveryReceiptBindingMismatch);
    }

    let (checkpoint_sha256, checkpoint_size) = sha256_file(&expected_checkpoint)?;
    let (restored_copy_sha256, restored_size) = sha256_file(&expected_restored)?;
    if checkpoint_sha256 != receipt.checkpoint_sha256
        || restored_copy_sha256 != receipt.restored_sha256
        || restored_copy_sha256 != checkpoint_sha256
        || restored_size != checkpoint_size
        || checkpoint_size == 0
    {
        return Err(BootstrapError::RecoveryRestoreMismatch);
    }

    Ok(RecoveryCheckpointEvidence {
        session_id,
        plan_id,
        checkpoint_id,
        checkpoint_sha256,
        checkpoint_size,
        restored_copy_sha256,
        producer_identity: V09_RECOVERY_PRODUCER_ID,
        restore_receipt_sha256: sha256_bytes(&receipt_bytes),
        native_recovery_identity: V09_NATIVE_RECOVERY_IDENTITY,
    })
}

#[cfg(feature = "test-support")]
fn verify_v09_test_support(
    session_id: &str,
    plan_id: &str,
    checkpoint_id: &str,
    checkpoint_path: &Path,
    restored_copy_path: &Path,
    expected_sha256: &str,
) -> Result<RecoveryCheckpointEvidence, BootstrapError> {
    let session_id = normalize_required("First Boot session id", session_id)?;
    let plan_id = normalize_required("plan id", plan_id)?;
    let checkpoint_id = normalize_required("checkpoint id", checkpoint_id)?;
    validate_sha256(expected_sha256)?;

    verify_native_recovery_program(Path::new(V09_NATIVE_RECOVERY_SHELL))?;
    verify_native_recovery_program(Path::new(V09_NATIVE_RECOVERY_PACKAGE_MANAGER))?;

    let checkpoint = verified_regular_file(checkpoint_path)?;
    let restored = verified_regular_file(restored_copy_path)?;
    let checkpoint_metadata = fs::metadata(&checkpoint).map_err(BootstrapError::Io)?;
    let restored_metadata = fs::metadata(&restored).map_err(BootstrapError::Io)?;
    if checkpoint == restored
        || (checkpoint_metadata.dev() == restored_metadata.dev()
            && checkpoint_metadata.ino() == restored_metadata.ino())
    {
        return Err(BootstrapError::RecoveryRestoreNotIndependent);
    }
    let (checkpoint_sha256, checkpoint_size) = sha256_file(&checkpoint)?;
    let (restored_copy_sha256, restored_size) = sha256_file(&restored)?;
    if checkpoint_sha256 != expected_sha256
        || restored_copy_sha256 != checkpoint_sha256
        || restored_size != checkpoint_size
        || checkpoint_size == 0
    {
        return Err(BootstrapError::RecoveryRestoreMismatch);
    }

    let mut receipt_hasher = Sha256::new();
    for value in [
        "linura-recovery-test-support-v1",
        &session_id,
        &plan_id,
        &checkpoint_id,
        &checkpoint_sha256,
    ] {
        receipt_hasher.update((value.len() as u64).to_be_bytes());
        receipt_hasher.update(value.as_bytes());
    }

    Ok(RecoveryCheckpointEvidence {
        session_id,
        plan_id,
        checkpoint_id,
        checkpoint_sha256,
        checkpoint_size,
        restored_copy_sha256,
        producer_identity: V09_RECOVERY_PRODUCER_ID,
        restore_receipt_sha256: format!("{:x}", receipt_hasher.finalize()),
        native_recovery_identity: V09_NATIVE_RECOVERY_IDENTITY,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstBootReadiness {
    pub ledger: BootstrapLedger,
    pub security_policy: AdoptionSecurityPolicy,
    pub recovery: RecoveryCheckpointEvidence,
}

impl FirstBootReadiness {
    pub fn validate(&self, session_id: &str, plan_id: &str) -> Result<(), BootstrapError> {
        self.ledger.validate_prefix()?;
        for required in BootstrapStage::ORDERED {
            if required == BootstrapStage::FirstBootReady {
                break;
            }
            if !self.ledger.is_completed(required) {
                return Err(BootstrapError::MissingPrerequisite(required));
            }
        }
        self.security_policy.validate()?;
        self.recovery.validate_binding(session_id, plan_id)?;
        Ok(())
    }
}

fn normalize_required(label: &'static str, value: &str) -> Result<String, BootstrapError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) || trimmed.len() > 4096 {
        return Err(BootstrapError::InvalidField(label));
    }
    Ok(trimmed.to_owned())
}

fn normalize_checkpoint_id(value: &str) -> Result<String, BootstrapError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed.contains("..")
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(BootstrapError::InvalidCheckpointId);
    }
    Ok(trimmed.to_owned())
}

fn validate_sha256(value: &str) -> Result<(), BootstrapError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BootstrapError::InvalidCheckpointDigest);
    }
    Ok(())
}

fn verified_regular_file(path: &Path) -> Result<PathBuf, BootstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(BootstrapError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(BootstrapError::RecoveryArtifactNotRegular);
    }
    path.canonicalize().map_err(BootstrapError::Io)
}

fn verified_trusted_directory(
    path: &Path,
    require_root_owner: bool,
) -> Result<PathBuf, BootstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(BootstrapError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || (require_root_owner && metadata.uid() != 0)
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BootstrapError::RecoveryProducerPathUntrusted(
            path.display().to_string(),
        ));
    }
    path.canonicalize().map_err(BootstrapError::Io)
}

fn verified_trusted_child_directory(
    root: &Path,
    name: &str,
    require_root_owner: bool,
) -> Result<PathBuf, BootstrapError> {
    let child = verified_trusted_directory(&root.join(name), require_root_owner)?;
    if child.parent() != Some(root) {
        return Err(BootstrapError::RecoveryProducerPathUntrusted(
            child.display().to_string(),
        ));
    }
    Ok(child)
}

fn verified_trusted_regular_file(
    path: &Path,
    expected_parent: &Path,
    require_root_owner: bool,
) -> Result<PathBuf, BootstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(BootstrapError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || (require_root_owner && metadata.uid() != 0)
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(BootstrapError::RecoveryProducerPathUntrusted(
            path.display().to_string(),
        ));
    }
    let canonical = path.canonicalize().map_err(BootstrapError::Io)?;
    if canonical.parent() != Some(expected_parent) {
        return Err(BootstrapError::RecoveryProducerPathUntrusted(
            canonical.display().to_string(),
        ));
    }
    Ok(canonical)
}

fn require_exact_recovery_path(
    label: &'static str,
    supplied: &Path,
    expected: &Path,
) -> Result<(), BootstrapError> {
    let supplied = verified_regular_file(supplied)?;
    if supplied == expected {
        Ok(())
    } else {
        Err(BootstrapError::RecoveryArtifactPathMismatch(label))
    }
}

fn receipt_field(line: Option<&str>, key: &'static str) -> Result<String, BootstrapError> {
    let line = line.ok_or(BootstrapError::RecoveryReceiptInvalid)?;
    let prefix = format!("{key}=");
    let value = line
        .strip_prefix(&prefix)
        .ok_or(BootstrapError::RecoveryReceiptInvalid)?;
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(BootstrapError::RecoveryReceiptInvalid);
    }
    Ok(value.to_owned())
}

fn parse_restore_receipt(bytes: &[u8]) -> Result<TrustedRestoreReceipt, BootstrapError> {
    let text = std::str::from_utf8(bytes).map_err(|_| BootstrapError::RecoveryReceiptInvalid)?;
    let mut lines = text.lines();
    let schema = receipt_field(lines.next(), "schema")?;
    let producer = receipt_field(lines.next(), "producer")?;
    let session_id = receipt_field(lines.next(), "session_id")?;
    let plan_id = receipt_field(lines.next(), "plan_id")?;
    let checkpoint_id = receipt_field(lines.next(), "checkpoint_id")?;
    let checkpoint_sha256 = receipt_field(lines.next(), "checkpoint_sha256")?;
    let restored_sha256 = receipt_field(lines.next(), "restored_sha256")?;
    let result = receipt_field(lines.next(), "result")?;
    if lines.next().is_some()
        || schema != V09_RECOVERY_RECEIPT_SCHEMA
        || producer != V09_RECOVERY_PRODUCER_ID
        || result != "restored"
    {
        return Err(BootstrapError::RecoveryReceiptInvalid);
    }
    validate_sha256(&checkpoint_sha256)?;
    validate_sha256(&restored_sha256)?;
    Ok(TrustedRestoreReceipt {
        session_id,
        plan_id,
        checkpoint_id,
        checkpoint_sha256,
        restored_sha256,
    })
}

fn verify_native_recovery_program(path: &Path) -> Result<(), BootstrapError> {
    let metadata = fs::symlink_metadata(path).map_err(BootstrapError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(BootstrapError::NativeRecoveryUnavailable(
            path.display().to_string(),
        ));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn sha256_file(path: &Path) -> Result<(String, u64), BootstrapError> {
    let mut file = fs::File::open(path).map_err(BootstrapError::Io)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(BootstrapError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total
            .checked_add(read as u64)
            .ok_or(BootstrapError::RecoveryArtifactTooLarge)?;
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

#[derive(Debug)]
pub enum BootstrapError {
    OutOfOrder(BootstrapStage),
    UnexpectedStage {
        expected: BootstrapStage,
        actual: BootstrapStage,
    },
    AlreadyComplete,
    MissingPrerequisite(BootstrapStage),
    InvalidField(&'static str),
    InvalidCheckpointId,
    InvalidCheckpointDigest,
    UnsafeAdoptionSecurityPolicy,
    RecoveryBindingMismatch,
    RecoveryProducerMismatch,
    RecoveryRestoreMismatch,
    RecoveryRestoreNotIndependent,
    RecoveryArtifactNotRegular,
    RecoveryArtifactPathMismatch(&'static str),
    RecoveryProducerPathUntrusted(String),
    RecoveryReceiptInvalid,
    RecoveryReceiptBindingMismatch,
    RecoveryArtifactTooLarge,
    NativeRecoveryUnavailable(String),
    Io(std::io::Error),
}

impl PartialEq for BootstrapError {
    fn eq(&self, other: &Self) -> bool {
        use BootstrapError::*;
        match (self, other) {
            (OutOfOrder(a), OutOfOrder(b)) => a == b,
            (
                UnexpectedStage {
                    expected: ae,
                    actual: aa,
                },
                UnexpectedStage {
                    expected: be,
                    actual: ba,
                },
            ) => ae == be && aa == ba,
            (AlreadyComplete, AlreadyComplete)
            | (InvalidCheckpointId, InvalidCheckpointId)
            | (RecoveryBindingMismatch, RecoveryBindingMismatch)
            | (RecoveryProducerMismatch, RecoveryProducerMismatch)
            | (RecoveryRestoreMismatch, RecoveryRestoreMismatch)
            | (RecoveryRestoreNotIndependent, RecoveryRestoreNotIndependent)
            | (RecoveryArtifactNotRegular, RecoveryArtifactNotRegular)
            | (RecoveryReceiptInvalid, RecoveryReceiptInvalid)
            | (RecoveryReceiptBindingMismatch, RecoveryReceiptBindingMismatch)
            | (RecoveryArtifactTooLarge, RecoveryArtifactTooLarge)
            | (InvalidCheckpointDigest, InvalidCheckpointDigest)
            | (UnsafeAdoptionSecurityPolicy, UnsafeAdoptionSecurityPolicy) => true,
            (MissingPrerequisite(a), MissingPrerequisite(b)) => a == b,
            (InvalidField(a), InvalidField(b)) => a == b,
            (RecoveryArtifactPathMismatch(a), RecoveryArtifactPathMismatch(b)) => a == b,
            (RecoveryProducerPathUntrusted(a), RecoveryProducerPathUntrusted(b)) => a == b,
            (NativeRecoveryUnavailable(a), NativeRecoveryUnavailable(b)) => a == b,
            (Io(a), Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

impl Eq for BootstrapError {}

impl Display for BootstrapError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfOrder(stage) => write!(
                f,
                "bootstrap ledger contains out-of-order completed stage: {stage:?}"
            ),
            Self::UnexpectedStage { expected, actual } => write!(
                f,
                "bootstrap stage must advance monotonically: expected {expected:?}, got {actual:?}"
            ),
            Self::AlreadyComplete => f.write_str("bootstrap ledger is already complete"),
            Self::MissingPrerequisite(stage) => {
                write!(f, "First Boot prerequisite is incomplete: {stage:?}")
            }
            Self::InvalidField(label) => write!(f, "invalid {label}"),
            Self::InvalidCheckpointId => f.write_str(
                "recovery checkpoint id must be a bounded path-safe identifier",
            ),
            Self::InvalidCheckpointDigest => {
                f.write_str("recovery checkpoint digest must be 64-character SHA-256 hex")
            }
            Self::UnsafeAdoptionSecurityPolicy => f.write_str(
                "Linura adoption security policy is weaker than the v0.9 fail-closed baseline",
            ),
            Self::RecoveryBindingMismatch => {
                f.write_str("recovery evidence is not bound to the exact First Boot session/plan")
            }
            Self::RecoveryProducerMismatch => {
                f.write_str("recovery evidence did not originate from the qualified producer")
            }
            Self::RecoveryRestoreMismatch => f.write_str(
                "recovery checkpoint and trusted restored copy do not match the producer receipt",
            ),
            Self::RecoveryRestoreNotIndependent => f.write_str(
                "recovery verification requires a distinct restored artifact, not the checkpoint inode itself",
            ),
            Self::RecoveryArtifactNotRegular => {
                f.write_str("recovery evidence path must be a regular non-symlink file")
            }
            Self::RecoveryArtifactPathMismatch(label) => write!(
                f,
                "caller-supplied {label} path does not match the qualified recovery producer artifact"
            ),
            Self::RecoveryProducerPathUntrusted(path) => write!(
                f,
                "recovery producer path is not protected by the qualified ownership/permission contract: {path}"
            ),
            Self::RecoveryReceiptInvalid => {
                f.write_str("trusted recovery restore receipt is malformed or unsupported")
            }
            Self::RecoveryReceiptBindingMismatch => f.write_str(
                "trusted recovery restore receipt is not bound to the exact session/plan/checkpoint/digest",
            ),
            Self::RecoveryArtifactTooLarge => {
                f.write_str("recovery evidence size overflowed the supported bound")
            }
            Self::NativeRecoveryUnavailable(path) => {
                write!(f, "qualified native recovery program is unavailable or unsafe: {path}")
            }
            Self::Io(error) => write!(f, "recovery verification I/O failed: {error}"),
        }
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn stage_trusted_recovery_fixture(
        root: &Path,
        session: &str,
        plan: &str,
        checkpoint_id: &str,
        checkpoint_bytes: &[u8],
        restored_bytes: &[u8],
        receipt_plan: Option<&str>,
    ) -> (PathBuf, PathBuf, String) {
        let checkpoints = root.join("checkpoints");
        let restored_root = root.join("restored");
        let receipts = root.join("receipts");
        for directory in [&checkpoints, &restored_root, &receipts] {
            fs::create_dir_all(directory).unwrap_or_else(|error| unreachable!("{error}"));
        }
        let checkpoint = checkpoints.join(format!("{checkpoint_id}.bin"));
        let restored = restored_root.join(format!("{checkpoint_id}.bin"));
        fs::write(&checkpoint, checkpoint_bytes).unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&restored, restored_bytes).unwrap_or_else(|error| unreachable!("{error}"));
        let (checkpoint_digest, _) =
            sha256_file(&checkpoint).unwrap_or_else(|error| unreachable!("{error}"));
        let (restored_digest, _) =
            sha256_file(&restored).unwrap_or_else(|error| unreachable!("{error}"));
        let receipt = format!(
            "schema={V09_RECOVERY_RECEIPT_SCHEMA}\nproducer={V09_RECOVERY_PRODUCER_ID}\nsession_id={session}\nplan_id={}\ncheckpoint_id={checkpoint_id}\ncheckpoint_sha256={checkpoint_digest}\nrestored_sha256={restored_digest}\nresult=restored\n",
            receipt_plan.unwrap_or(plan),
        );
        fs::write(receipts.join(format!("{checkpoint_id}.receipt")), receipt)
            .unwrap_or_else(|error| unreachable!("{error}"));
        (checkpoint, restored, checkpoint_digest)
    }

    fn recovery_evidence(session: &str, plan: &str) -> RecoveryCheckpointEvidence {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint_id = "snapshot-1";
        let (checkpoint, restored, digest) = stage_trusted_recovery_fixture(
            dir.path(),
            session,
            plan,
            checkpoint_id,
            b"linura-v09-recovery-checkpoint",
            b"linura-v09-recovery-checkpoint",
            None,
        );
        verify_v09_from_trusted_root(
            session,
            plan,
            checkpoint_id,
            &checkpoint,
            &restored,
            &digest,
            RecoveryProducerRoot {
                path: dir.path(),
                require_root_owner: false,
            },
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn workstation_installer_policy_remains_fail_closed() {
        let policy = InstallSecurityPolicy::default();
        assert!(policy.require_disk_encryption);
        assert!(policy.inbound_firewall_default_deny);
        assert!(!policy.ssh_enabled_initially);
        assert!(!policy.untrusted_package_sources_enabled);
    }

    #[test]
    fn v09_adoption_policy_does_not_invent_disk_encryption_claims() {
        let policy = AdoptionSecurityPolicy::default();
        assert!(policy.inbound_firewall_default_deny);
        assert!(!policy.ssh_enabled_initially);
        assert!(!policy.untrusted_package_sources_enabled);
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn v09_ledger_starts_with_existing_base_verification_not_disk_layout() {
        let ledger = BootstrapLedger::default();
        assert_eq!(
            ledger.next_stage(),
            Some(BootstrapStage::BaseEnvironmentVerification)
        );
        assert!(
            !BootstrapStage::ORDERED
                .iter()
                .any(|stage| format!("{stage:?}") == "DiskLayout")
        );
    }

    #[test]
    fn persisted_ledger_accepts_only_an_ordered_prefix() {
        let prefix = [
            BootstrapStage::BaseEnvironmentVerification,
            BootstrapStage::LinuraInstallation,
        ];
        let ledger = BootstrapLedger::from_completed_prefix(&prefix)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            ledger.next_stage(),
            Some(BootstrapStage::PersistentStateInitialization)
        );
        assert_eq!(ledger.validate_prefix(), Ok(()));

        let invalid = [
            BootstrapStage::BaseEnvironmentVerification,
            BootstrapStage::SecurityBaseline,
        ];
        assert_eq!(
            BootstrapLedger::from_completed_prefix(&invalid),
            Err(BootstrapError::UnexpectedStage {
                expected: BootstrapStage::LinuraInstallation,
                actual: BootstrapStage::SecurityBaseline,
            })
        );
    }

    #[test]
    fn complete_next_rejects_skipped_stages() {
        let mut ledger = BootstrapLedger::default();
        assert_eq!(
            ledger.complete_next(BootstrapStage::LinuraInstallation),
            Err(BootstrapError::UnexpectedStage {
                expected: BootstrapStage::BaseEnvironmentVerification,
                actual: BootstrapStage::LinuraInstallation,
            })
        );
        assert_eq!(
            ledger.complete_next(BootstrapStage::BaseEnvironmentVerification),
            Ok(())
        );
    }

    #[test]
    fn adoption_policy_rejects_implicit_ssh() {
        let policy = AdoptionSecurityPolicy {
            inbound_firewall_default_deny: true,
            ssh_enabled_initially: true,
            untrusted_package_sources_enabled: false,
        };
        assert_eq!(
            policy.validate(),
            Err(BootstrapError::UnsafeAdoptionSecurityPolicy)
        );
    }

    #[test]
    fn recovery_verifier_binds_trusted_restore_receipt_and_native_recovery() {
        let evidence = recovery_evidence("session-1", "plan-1");
        assert_eq!(evidence.session_id(), "session-1");
        assert_eq!(evidence.plan_id(), "plan-1");
        assert_eq!(evidence.producer_identity(), V09_RECOVERY_PRODUCER_ID);
        assert_eq!(
            evidence.checkpoint_sha256(),
            evidence.restored_copy_sha256()
        );
        assert!(evidence.checkpoint_size() > 0);
        assert_eq!(evidence.restore_receipt_sha256().len(), 64);
        assert_eq!(
            evidence.native_recovery_identity(),
            V09_NATIVE_RECOVERY_IDENTITY
        );
        assert_eq!(evidence.validate_binding("session-1", "plan-1"), Ok(()));
        assert_eq!(
            evidence.validate_binding("session-2", "plan-1"),
            Err(BootstrapError::RecoveryBindingMismatch)
        );
    }

    #[test]
    fn recovery_verifier_rejects_caller_created_copies_outside_producer_root() {
        let producer = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let external = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint_id = "snapshot-path-bound";
        let (_, _, digest) = stage_trusted_recovery_fixture(
            producer.path(),
            "session",
            "plan",
            checkpoint_id,
            b"checkpoint",
            b"checkpoint",
            None,
        );
        let external_checkpoint = external.path().join("checkpoint.bin");
        let external_restored = external.path().join("restored.bin");
        fs::write(&external_checkpoint, b"checkpoint")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&external_restored, b"checkpoint")
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(
            verify_v09_from_trusted_root(
                "session",
                "plan",
                checkpoint_id,
                &external_checkpoint,
                &external_restored,
                &digest,
                RecoveryProducerRoot {
                    path: producer.path(),
                    require_root_owner: false,
                },
            ),
            Err(BootstrapError::RecoveryArtifactPathMismatch("checkpoint"))
        );
    }

    #[test]
    fn recovery_verifier_rejects_checkpoint_reused_as_restored_copy() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint_id = "snapshot-hard-link";
        let checkpoints = dir.path().join("checkpoints");
        let restored_root = dir.path().join("restored");
        let receipts = dir.path().join("receipts");
        for directory in [&checkpoints, &restored_root, &receipts] {
            fs::create_dir_all(directory).unwrap_or_else(|error| unreachable!("{error}"));
        }
        let checkpoint = checkpoints.join(format!("{checkpoint_id}.bin"));
        let restored = restored_root.join(format!("{checkpoint_id}.bin"));
        fs::write(&checkpoint, b"checkpoint").unwrap_or_else(|error| unreachable!("{error}"));
        fs::hard_link(&checkpoint, &restored).unwrap_or_else(|error| unreachable!("{error}"));
        let (digest, _) = sha256_file(&checkpoint).unwrap_or_else(|error| unreachable!("{error}"));
        let receipt = format!(
            "schema={V09_RECOVERY_RECEIPT_SCHEMA}\nproducer={V09_RECOVERY_PRODUCER_ID}\nsession_id=session\nplan_id=plan\ncheckpoint_id={checkpoint_id}\ncheckpoint_sha256={digest}\nrestored_sha256={digest}\nresult=restored\n"
        );
        fs::write(receipts.join(format!("{checkpoint_id}.receipt")), receipt)
            .unwrap_or_else(|error| unreachable!("{error}"));

        assert!(matches!(
            verify_v09_from_trusted_root(
                "session",
                "plan",
                checkpoint_id,
                &checkpoint,
                &restored,
                &digest,
                RecoveryProducerRoot {
                    path: dir.path(),
                    require_root_owner: false,
                },
            ),
            Err(BootstrapError::RecoveryRestoreNotIndependent)
        ));
    }

    #[test]
    fn recovery_verifier_rejects_substituted_restored_copy() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint_id = "snapshot-substituted";
        let (checkpoint, restored, digest) = stage_trusted_recovery_fixture(
            dir.path(),
            "session",
            "plan",
            checkpoint_id,
            b"checkpoint",
            b"different",
            None,
        );
        assert!(matches!(
            verify_v09_from_trusted_root(
                "session",
                "plan",
                checkpoint_id,
                &checkpoint,
                &restored,
                &digest,
                RecoveryProducerRoot {
                    path: dir.path(),
                    require_root_owner: false,
                },
            ),
            Err(BootstrapError::RecoveryRestoreMismatch)
        ));
    }

    #[test]
    fn recovery_verifier_rejects_receipt_bound_to_another_plan() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint_id = "snapshot-plan-bound";
        let (checkpoint, restored, digest) = stage_trusted_recovery_fixture(
            dir.path(),
            "session",
            "plan",
            checkpoint_id,
            b"checkpoint",
            b"checkpoint",
            Some("other-plan"),
        );
        assert_eq!(
            verify_v09_from_trusted_root(
                "session",
                "plan",
                checkpoint_id,
                &checkpoint,
                &restored,
                &digest,
                RecoveryProducerRoot {
                    path: dir.path(),
                    require_root_owner: false,
                },
            ),
            Err(BootstrapError::RecoveryReceiptBindingMismatch)
        );
    }

    #[test]
    fn recovery_verifier_rejects_checkpoint_path_traversal_identity() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            verify_v09_from_trusted_root(
                "session",
                "plan",
                "../snapshot",
                &dir.path().join("checkpoint"),
                &dir.path().join("restored"),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                RecoveryProducerRoot {
                    path: dir.path(),
                    require_root_owner: false,
                },
            ),
            Err(BootstrapError::InvalidCheckpointId)
        );
    }

    #[test]
    fn recovery_verifier_rejects_writable_producer_root() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            verified_trusted_directory(dir.path(), false),
            Err(BootstrapError::RecoveryProducerPathUntrusted(_))
        ));
    }

    #[test]
    fn first_boot_readiness_requires_ordered_prefix_security_and_bound_recovery() {
        let mut ledger = BootstrapLedger::default();
        for stage in BootstrapStage::ORDERED {
            if stage == BootstrapStage::FirstBootReady {
                break;
            }
            assert_eq!(ledger.complete_next(stage), Ok(()));
        }
        let readiness = FirstBootReadiness {
            ledger,
            security_policy: AdoptionSecurityPolicy::default(),
            recovery: recovery_evidence("session-1", "plan-1"),
        };
        assert_eq!(readiness.validate("session-1", "plan-1"), Ok(()));
        assert_eq!(
            readiness.validate("session-1", "other-plan"),
            Err(BootstrapError::RecoveryBindingMismatch)
        );
    }

    #[test]
    fn test_support_fixture_still_checks_byte_equality_when_enabled() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let checkpoint = dir.path().join("checkpoint.bin");
        let restored = dir.path().join("restored.bin");
        let mut file =
            fs::File::create(&checkpoint).unwrap_or_else(|error| unreachable!("{error}"));
        file.write_all(b"checkpoint")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&restored, b"different").unwrap_or_else(|error| unreachable!("{error}"));
        let (digest, _) = sha256_file(&checkpoint).unwrap_or_else(|error| unreachable!("{error}"));

        #[cfg(feature = "test-support")]
        assert!(matches!(
            RecoveryCheckpointVerifier::verify_v09(
                "session",
                "plan",
                "snapshot",
                &checkpoint,
                &restored,
                &digest,
            ),
            Err(BootstrapError::RecoveryRestoreMismatch)
        ));
    }
}
