#![forbid(unsafe_code)]

//! Durable, local-first storage for Linura declarative intent and Library state.
//!
//! This crate is intentionally non-privileged. Persisted Library data is
//! declarative input to fresh local planning/authorization; it never stores or
//! reconstructs executor authority, approval authority, or privileged tokens.

mod adoption;
mod portable;
mod schema;
mod store;

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::path::Path;

use linura_core::{CapabilityId, IntentId, ProfileId, ProviderId, RequestId, ResourceId, SetupId};
use linura_intent::{Intent, MachineProfile, Setup};

pub use adoption::AdoptionContext;
pub use portable::{
    PORTABLE_FORMAT_VERSION, PortableProfileBundle, PortableSetupBundle, decode_profile_bundle,
    decode_setup_bundle, encode_profile_bundle, encode_setup_bundle,
};
pub use schema::LIBRARY_SCHEMA_VERSION;
pub use store::{LibrarySettings, LocalLibrary};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentTransition {
    Activate,
    Suspend,
    Retire,
}

impl IntentTransition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Suspend => "suspend",
            Self::Retire => "retire",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredIntent {
    pub intent: Intent,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentRevisionRef {
    pub id: IntentId,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRevisionRef {
    pub id: SetupId,
    pub revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSetup {
    pub setup: Setup,
    pub intent_revisions: Vec<IntentRevisionRef>,
    pub included_revisions: Vec<SetupRevisionRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredProfile {
    pub profile: MachineProfile,
    pub revision: u32,
    pub intent_revisions: Vec<IntentRevisionRef>,
    pub setup_revisions: Vec<SetupRevisionRef>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ManagedResourceIdentity {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub capability: CapabilityId,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemovalImpactReport {
    pub removable: BTreeSet<ManagedResourceIdentity>,
    pub retained_shared: BTreeSet<ManagedResourceIdentity>,
    pub indeterminate: BTreeSet<ManagedResourceIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRecordKind {
    DesiredState,
    Provenance,
    ApprovalReference,
    AuditReference,
    Reconciliation,
}

impl LifecycleRecordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DesiredState => "desired-state",
            Self::Provenance => "provenance",
            Self::ApprovalReference => "approval-reference",
            Self::AuditReference => "audit-reference",
            Self::Reconciliation => "reconciliation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRecord {
    pub sequence: u64,
    pub kind: LifecycleRecordKind,
    pub entity_id: String,
    pub content_digest: String,
    pub payload: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdoptionReport {
    pub create_intents: BTreeSet<IntentId>,
    pub reuse_intents: BTreeSet<IntentId>,
    pub create_setups: BTreeSet<SetupId>,
    pub reuse_setups: BTreeSet<SetupId>,
    pub create_profiles: BTreeSet<ProfileId>,
    pub reuse_profiles: BTreeSet<ProfileId>,
    pub proposed_intents: BTreeSet<IntentId>,
    pub active_intents: BTreeSet<IntentId>,
    pub unsupported_capabilities: BTreeSet<CapabilityId>,
    pub collisions: Vec<String>,
    pub missing_secret_refs: BTreeSet<String>,
    pub warnings: Vec<String>,
    pub requires_plan: bool,
    pub machine_class_mismatch: bool,
}

impl AdoptionReport {
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        !self.collisions.is_empty() || self.machine_class_mismatch
    }
}

#[derive(Debug)]
pub enum LibraryError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Validation(String),
    NotFound { kind: &'static str, id: String },
    AlreadyExists { kind: &'static str, id: String },
    RevisionConflict { expected: u64, actual: u64 },
    InvalidTransition { from: String, operation: String },
    IdempotencyConflict(RequestId),
    Corrupt(String),
    UnsupportedSchema { found: u32, supported: u32 },
    UnsupportedPortableFormat { found: u16, supported: u16 },
    PortableDigestMismatch,
    PortableFormat(String),
}

impl Display for LibraryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "SQLite Library error: {error}"),
            Self::Io(error) => write!(f, "Library filesystem error: {error}"),
            Self::Validation(reason) => write!(f, "invalid Library state: {reason}"),
            Self::NotFound { kind, id } => write!(f, "{kind} not found: {id}"),
            Self::AlreadyExists { kind, id } => write!(f, "{kind} already exists: {id}"),
            Self::RevisionConflict { expected, actual } => write!(
                f,
                "Library revision conflict: expected {expected}, current revision is {actual}"
            ),
            Self::InvalidTransition { from, operation } => {
                write!(f, "intent transition {operation} is not legal from {from}")
            }
            Self::IdempotencyConflict(request) => write!(
                f,
                "operation id {} was already used for different Library semantics",
                request.as_str()
            ),
            Self::Corrupt(reason) => write!(f, "Library integrity validation failed: {reason}"),
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "Library schema version {found} is newer than supported version {supported}"
            ),
            Self::UnsupportedPortableFormat { found, supported } => write!(
                f,
                "portable Library format {found} is newer than supported version {supported}"
            ),
            Self::PortableDigestMismatch => {
                f.write_str("portable Library artifact digest mismatch")
            }
            Self::PortableFormat(reason) => {
                write!(f, "invalid portable Library artifact: {reason}")
            }
        }
    }
}

impl std::error::Error for LibraryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for LibraryError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for LibraryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn validate_backup(path: impl AsRef<Path>) -> Result<(), LibraryError> {
    store::validate_database_file(path.as_ref())
}

pub fn restore_backup(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<(), LibraryError> {
    store::restore_database_file(backup.as_ref(), destination.as_ref())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileIdentity {
    pub id: ProfileId,
    pub revision: u32,
}
