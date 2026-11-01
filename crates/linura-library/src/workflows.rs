//! S26 read-only workstation workflows over the released local SQLite Library.
//! No review projection or imported artifact grants Control or executor authority.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use linura_core::{ProfileId, SetupId};
use linura_intent::{MachineProfile, Setup};
use sha2::{Digest, Sha256};

use crate::{
    AdoptionContext, AdoptionReport, LibraryError, LocalLibrary, StoredProfile, StoredSetup,
    decode_profile_bundle, decode_setup_bundle, encode_profile_bundle, encode_setup_bundle,
    validate_backup,
};

const MAX_BACKUP_INSPECTION_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn content_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

/// A checksum for an exact root and canonical portable closure, never a signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionInspection {
    pub id: String,
    pub revision: u32,
    pub closure_sha256: String,
    pub setup_count: usize,
    pub intent_count: usize,
}

/// Only static field labels, not untrusted content, are surfaced for comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionComparison {
    pub id: String,
    pub from_revision: u32,
    pub to_revision: u32,
    pub changed_fields: BTreeSet<&'static str>,
}

/// This candidate is not a write grant; the existing save API owns CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupEditorDraft {
    pub base_revision: u32,
    pub candidate: Setup,
}

/// This candidate is not a write grant; the existing save API owns CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileEditorDraft {
    pub base_revision: u32,
    pub next_revision: u32,
    pub candidate: MachineProfile,
}

/// In-memory portable bytes. Publication to a selected path is not enabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableExportPreview {
    pub root_id: String,
    pub root_revision: u32,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// Untrusted import preflight, never an executable plan or saved permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableImportReview {
    pub root_id: String,
    pub root_revision: u32,
    pub canonical_sha256: String,
    pub report: AdoptionReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineAdoptionDecision {
    Blocked,
    RequiresFreshControlPlan,
}

/// Even a successful local preflight always requires separate native planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineAdoptionReadiness {
    pub decision: MachineAdoptionDecision,
    pub blockers: BTreeSet<&'static str>,
    pub machine_verified: bool,
}

impl MachineAdoptionReadiness {
    #[must_use]
    pub fn from_report(report: &AdoptionReport) -> Self {
        let mut blockers = BTreeSet::new();
        if !report.collisions.is_empty() {
            blockers.insert("content-collision");
        }
        if report.machine_class_mismatch {
            blockers.insert("machine-class-mismatch");
        }
        if !report.missing_secret_refs.is_empty() {
            blockers.insert("missing-secret-reference");
        }
        if !report.unsupported_capabilities.is_empty() {
            blockers.insert("unsupported-capability");
        }
        let decision = if blockers.is_empty() {
            MachineAdoptionDecision::RequiresFreshControlPlan
        } else {
            MachineAdoptionDecision::Blocked
        };
        Self {
            decision,
            blockers,
            machine_verified: false,
        }
    }
}

/// Read-only inspection, never an inode pin or permission to restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupInspection {
    pub sha256: String,
    pub file_size: u64,
}

/// Validate and hash a bounded regular backup file; writers must be quiesced
/// and the backup revalidated independently before any future managed restore.
pub fn inspect_backup_read_only(path: impl AsRef<Path>) -> Result<BackupInspection, LibraryError> {
    let path = path.as_ref();
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.len() > MAX_BACKUP_INSPECTION_BYTES {
        return Err(LibraryError::Validation(
            "backup inspection requires a bounded regular file".into(),
        ));
    }
    validate_backup(path)?;
    let mut input = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut block = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut block)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(|_| {
                LibraryError::Validation("backup byte count overflow".into())
            })?)
            .ok_or_else(|| LibraryError::Validation("backup byte count overflow".into()))?;
        if length > MAX_BACKUP_INSPECTION_BYTES {
            return Err(LibraryError::Validation(
                "backup exceeds inspection bound".into(),
            ));
        }
        hasher.update(&block[..count]);
    }
    let after = fs::symlink_metadata(path)?;
    if !after.file_type().is_file()
        || before.len() != length
        || after.len() != length
        || before.modified()? != after.modified()?
    {
        return Err(LibraryError::Validation(
            "backup changed during inspection".into(),
        ));
    }
    Ok(BackupInspection {
        sha256: format!("{:x}", hasher.finalize()),
        file_size: length,
    })
}

impl LocalLibrary {
    pub fn inspect_setup_revision(
        &self,
        id: &SetupId,
        revision: u32,
    ) -> Result<RevisionInspection, LibraryError> {
        let bundle = self.export_setup(id, Some(revision))?;
        let bytes = encode_setup_bundle(&bundle)?;
        Ok(RevisionInspection {
            id: id.as_str().into(),
            revision,
            closure_sha256: content_digest(&bytes),
            setup_count: bundle.setups.len(),
            intent_count: bundle.intents.len(),
        })
    }

    pub fn inspect_profile_revision(
        &self,
        id: &ProfileId,
        revision: u32,
    ) -> Result<RevisionInspection, LibraryError> {
        let bundle = self.export_profile(id, Some(revision))?;
        let bytes = encode_profile_bundle(&bundle)?;
        Ok(RevisionInspection {
            id: id.as_str().into(),
            revision,
            closure_sha256: content_digest(&bytes),
            setup_count: bundle.setups.len(),
            intent_count: bundle.intents.len(),
        })
    }

    pub fn compare_setup_revisions(
        &self,
        id: &SetupId,
        from: u32,
        to: u32,
    ) -> Result<RevisionComparison, LibraryError> {
        let a: StoredSetup = self.setup_revision(id, from)?;
        let b: StoredSetup = self.setup_revision(id, to)?;
        let mut fields = BTreeSet::new();
        if a.setup.name != b.setup.name {
            fields.insert("name");
        }
        if a.setup.description != b.setup.description {
            fields.insert("description");
        }
        if a.setup.portable_constraints != b.setup.portable_constraints {
            fields.insert("portable_constraints");
        }
        if a.setup.required_secret_refs != b.setup.required_secret_refs {
            fields.insert("required_secret_refs");
        }
        if a.setup.hardware_hints != b.setup.hardware_hints {
            fields.insert("hardware_hints");
        }
        if a.intent_revisions != b.intent_revisions {
            fields.insert("intent_revisions");
        }
        if a.included_revisions != b.included_revisions {
            fields.insert("included_setup_revisions");
        }
        Ok(RevisionComparison {
            id: id.as_str().into(),
            from_revision: from,
            to_revision: to,
            changed_fields: fields,
        })
    }

    pub fn compare_profile_revisions(
        &self,
        id: &ProfileId,
        from: u32,
        to: u32,
    ) -> Result<RevisionComparison, LibraryError> {
        let a: StoredProfile = self.profile_revision(id, from)?;
        let b: StoredProfile = self.profile_revision(id, to)?;
        let mut fields = BTreeSet::new();
        if a.profile.name != b.profile.name {
            fields.insert("name");
        }
        if a.profile.machine_class != b.profile.machine_class {
            fields.insert("machine_class");
        }
        if a.profile.portable_constraints != b.profile.portable_constraints {
            fields.insert("portable_constraints");
        }
        if a.profile.hardware_hints != b.profile.hardware_hints {
            fields.insert("hardware_hints");
        }
        if a.intent_revisions != b.intent_revisions {
            fields.insert("intent_revisions");
        }
        if a.setup_revisions != b.setup_revisions {
            fields.insert("setup_revisions");
        }
        Ok(RevisionComparison {
            id: id.as_str().into(),
            from_revision: from,
            to_revision: to,
            changed_fields: fields,
        })
    }

    /// Pure draft preparation; exact CAS is rechecked by released save_setup.
    pub fn prepare_setup_edit(
        &self,
        id: &SetupId,
        expected: u32,
        mut candidate: Setup,
    ) -> Result<SetupEditorDraft, LibraryError> {
        let current = self.setup(id)?;
        if current.setup.revision != expected {
            return Err(LibraryError::RevisionConflict {
                expected: u64::from(expected),
                actual: u64::from(current.setup.revision),
            });
        }
        if candidate.id != *id {
            return Err(LibraryError::Validation(
                "Setup identity cannot change during edit".into(),
            ));
        }
        candidate.revision = expected
            .checked_add(1)
            .ok_or_else(|| LibraryError::Validation("Setup revision exhausted".into()))?;
        candidate.validate().map_err(|error| {
            LibraryError::Validation(format!("invalid Setup draft: {error:?}"))
        })?;
        Ok(SetupEditorDraft {
            base_revision: expected,
            candidate,
        })
    }

    /// Pure draft preparation; exact CAS is rechecked by released save_profile.
    pub fn prepare_profile_edit(
        &self,
        id: &ProfileId,
        expected: u32,
        candidate: MachineProfile,
    ) -> Result<ProfileEditorDraft, LibraryError> {
        let current = self.profile(id)?;
        if current.revision != expected {
            return Err(LibraryError::RevisionConflict {
                expected: u64::from(expected),
                actual: u64::from(current.revision),
            });
        }
        if candidate.id != *id || candidate.name.trim().is_empty() {
            return Err(LibraryError::Validation(
                "profile editor requires exact identity and nonempty name".into(),
            ));
        }
        let next_revision = expected
            .checked_add(1)
            .ok_or_else(|| LibraryError::Validation("Profile revision exhausted".into()))?;
        Ok(ProfileEditorDraft {
            base_revision: expected,
            next_revision,
            candidate,
        })
    }

    pub fn preview_setup_export(
        &self,
        id: &SetupId,
        revision: u32,
    ) -> Result<PortableExportPreview, LibraryError> {
        let bytes = encode_setup_bundle(&self.export_setup(id, Some(revision))?)?;
        Ok(PortableExportPreview {
            root_id: id.as_str().into(),
            root_revision: revision,
            sha256: content_digest(&bytes),
            bytes,
        })
    }

    pub fn preview_profile_export(
        &self,
        id: &ProfileId,
        revision: u32,
    ) -> Result<PortableExportPreview, LibraryError> {
        let bytes = encode_profile_bundle(&self.export_profile(id, Some(revision))?)?;
        Ok(PortableExportPreview {
            root_id: id.as_str().into(),
            root_revision: revision,
            sha256: content_digest(&bytes),
            bytes,
        })
    }

    pub fn review_setup_import(
        &self,
        untrusted: &[u8],
        context: &AdoptionContext,
    ) -> Result<PortableImportReview, LibraryError> {
        let bundle = decode_setup_bundle(untrusted)?;
        let bytes = encode_setup_bundle(&bundle)?;
        let report = self.preflight_setup_adoption(&bundle, context)?;
        Ok(PortableImportReview {
            root_id: bundle.root.id.as_str().into(),
            root_revision: bundle.root.revision,
            canonical_sha256: content_digest(&bytes),
            report,
        })
    }

    pub fn review_profile_import(
        &self,
        untrusted: &[u8],
        context: &AdoptionContext,
    ) -> Result<PortableImportReview, LibraryError> {
        let bundle = decode_profile_bundle(untrusted)?;
        let bytes = encode_profile_bundle(&bundle)?;
        let report = self.preflight_profile_adoption(&bundle, context)?;
        Ok(PortableImportReview {
            root_id: bundle.profile.profile.id.as_str().into(),
            root_revision: bundle.profile.revision,
            canonical_sha256: content_digest(&bytes),
            report,
        })
    }
}
