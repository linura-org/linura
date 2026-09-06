use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;

use linura_control::{
    MANAGED_SYSTEMD_CAPABILITY, MANAGED_SYSTEMD_INTENT_ORIGIN, MANAGED_SYSTEMD_PROVIDER,
    ManagedLifecycleControl, PlanPreviewControl, managed_request_id,
};
use linura_core::{CapabilityId, IntentId, ProviderId, RequestId, SemanticReason};
use linura_dbus::{Authority1Context, Authority1Handler, Authority1ManagedRequest};
use linura_executor_systemd::{ManagedActiveState, ManagedUnitName};
use linura_linux_observation::SystemdObserver;
use linura_observation_control::ObservationCoordinator;
use linura_persistence_sqlite::{
    SqliteIntegrityKey, SqliteTransactionStore, is_physical_storage_exhaustion,
};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    AbortRequest, TransactionAuthorityKey, TransactionState, TransactionStore,
    TransactionStoreError, digest_parts,
};

use crate::systemd_adapter::{FreshSystemdVerifier, SystemdExecutorClient};

const DEFAULT_STATE_DIR: &str = "/var/lib/linura-authority";
const STATE_DIR_ENV: &str = "LINURA_AUTHORITY_STATE_DIR";
const AUTHORITY_KEY_FILE: &str = "transaction-authority.key";
const INTEGRITY_KEY_FILE: &str = "sqlite-integrity.key";
const DATABASE_FILE: &str = "authority.sqlite3";
const SECRET_BYTES: usize = 32;
const MAX_REASON_BYTES: usize = 1024;
const SECRET_INSTALL_ATTEMPTS: u32 = 32;

#[derive(Debug)]
pub(crate) struct ManagedRuntime {
    control: ManagedLifecycleControl<SqliteTransactionStore>,
    executor: SystemdExecutorClient,
    verifier: FreshSystemdVerifier,
}

impl ManagedRuntime {
    pub(crate) fn open(state_dir: &Path) -> Result<Self, String> {
        prepare_state_dir(state_dir)?;
        let authority_bytes = load_or_create_secret(&state_dir.join(AUTHORITY_KEY_FILE))?;
        let integrity_bytes = load_or_create_secret(&state_dir.join(INTEGRITY_KEY_FILE))?;

        let authority_key = TransactionAuthorityKey::new(authority_bytes.clone())
            .map_err(|error| format!("invalid transaction authority key: {error}"))?;
        let (authority_signer, _unused_verifier) = authority_key.split();
        let store = open_authority_store(
            &state_dir.join(DATABASE_FILE),
            &authority_bytes,
            &integrity_bytes,
        )?;

        let control_observer = SystemdObserver::connect()
            .map_err(|error| format!("cannot connect authoritative systemd observer: {error}"))?;
        let mut coordinator = ObservationCoordinator::new();
        coordinator
            .register_observer(Box::new(control_observer))
            .map_err(|error| format!("cannot register authoritative systemd observer: {error}"))?;
        let previews = PlanPreviewControl::new(coordinator);
        let control = ManagedLifecycleControl::new(previews, store, authority_signer)
            .map_err(|error| error.to_string())?;

        Ok(Self {
            control,
            executor: SystemdExecutorClient::connect()?,
            verifier: FreshSystemdVerifier::connect()?,
        })
    }
}

impl Authority1Handler for ManagedRuntime {
    fn converge_systemd_active_state(
        &mut self,
        context: Authority1Context,
        request: Authority1ManagedRequest,
    ) -> Result<linura_control::ManagedMutationReceipt, String> {
        let request = managed_request(&request)?;
        let Self {
            control,
            executor,
            verifier,
        } = self;
        control
            .converge_systemd_active_state(
                context.principal,
                context.actor,
                request,
                context.approval.as_ref(),
                executor,
                verifier,
            )
            .map_err(|error| error.to_string())
    }
}

fn managed_request(wire: &Authority1ManagedRequest) -> Result<PlanDesiredStateRequest, String> {
    if wire.reason.is_empty()
        || wire.reason.len() > MAX_REASON_BYTES
        || wire.reason.chars().any(char::is_control)
    {
        return Err("reason must be 1..1024 bytes without control characters".into());
    }
    let unit = ManagedUnitName::parse(&wire.unit).map_err(|error| error.to_string())?;
    let state = ManagedActiveState::parse(&wire.desired_active_state).map_err(str::to_owned)?;
    let resource = unit.resource_id().map_err(|error| error.to_string())?;
    let mut request = PlanDesiredStateRequest {
        request_id: RequestId::new("request:v06:pending").map_err(|error| error.to_string())?,
        provider: ProviderId::new(MANAGED_SYSTEMD_PROVIDER).map_err(|error| error.to_string())?,
        resource,
        observation_capability: CapabilityId::new(MANAGED_SYSTEMD_CAPABILITY)
            .map_err(|error| error.to_string())?,
        reason: SemanticReason {
            summary: wire.reason.clone(),
            intent_ids: vec![
                IntentId::new(MANAGED_SYSTEMD_INTENT_ORIGIN).map_err(|error| error.to_string())?,
            ],
            requirement_ids: vec![],
            capability_ids: vec![],
        },
        desired_state: BTreeMap::from([("active_state".to_owned(), state.as_str().to_owned())]),
    };
    request.request_id =
        managed_request_id(&wire.operation_id, &request).map_err(|error| error.to_string())?;
    Ok(request)
}

fn open_authority_store(
    database: &Path,
    authority_bytes: &[u8],
    integrity_bytes: &[u8],
) -> Result<SqliteTransactionStore, String> {
    match open_store_once(database, authority_bytes, integrity_bytes, false) {
        Ok(store) => Ok(store),
        Err(error) if is_physical_storage_exhaustion(database, &error) => {
            let mut recovery = open_store_once(database, authority_bytes, integrity_bytes, true)
                .map_err(|recovery_error| {
                    format!(
                        "cannot open durable authority store after ENOSPC recovery headroom release: {recovery_error}"
                    )
                })?;
            retire_prepared_after_restart(&mut recovery)?;
            drop(recovery);
            open_store_once(database, authority_bytes, integrity_bytes, false).map_err(|error| {
                format!("cannot reopen durable authority store after terminal recovery: {error}")
            })
        }
        Err(error) => Err(format!("cannot open durable authority store: {error}")),
    }
}

fn open_store_once(
    database: &Path,
    authority_bytes: &[u8],
    integrity_bytes: &[u8],
    terminal_recovery: bool,
) -> Result<SqliteTransactionStore, TransactionStoreError> {
    let authority_key = TransactionAuthorityKey::new(authority_bytes.to_vec())
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
    let (_unused_signer, authority_verifier) = authority_key.split();
    let integrity_key = SqliteIntegrityKey::new(integrity_bytes.to_vec())?;
    if terminal_recovery {
        SqliteTransactionStore::open_for_terminal_recovery(
            database,
            authority_verifier,
            integrity_key,
        )
    } else {
        SqliteTransactionStore::open(database, authority_verifier, integrity_key)
    }
}

fn retire_prepared_after_restart(store: &mut SqliteTransactionStore) -> Result<(), String> {
    let prepared = store
        .list_state(TransactionState::Prepared)
        .map_err(|error| {
            format!("cannot enumerate Prepared authority during ENOSPC recovery: {error}")
        })?;
    let reason = digest_parts(
        "linura.control.restart-prepared-abort.v1",
        [b"process-local mutable authority state was lost at restart".as_slice()],
    );
    for snapshot in prepared {
        store
            .abort_prepared(&AbortRequest {
                transaction_id: snapshot.transaction_id.clone(),
                expected_generation: snapshot.current_generation,
                expected_state_version: snapshot.state_version,
                reason_digest: reason.clone(),
            })
            .map_err(|error| {
                format!(
                    "cannot retire Prepared authority {} during ENOSPC recovery: {error}",
                    snapshot.transaction_id.as_str()
                )
            })?;
    }
    Ok(())
}

fn prepare_state_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create authority state dir: {error}"))?;
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("authority state path is not a directory".into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot harden authority state directory: {error}"))?;
    }
    Ok(())
}

fn load_or_create_secret(path: &Path) -> Result<Vec<u8>, String> {
    match fs::read(path) {
        Ok(bytes) => {
            validate_secret_file(path, &bytes)?;
            Ok(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_secret(path),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn validate_secret_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != SECRET_BYTES || bytes.iter().all(|byte| *byte == 0) {
        return Err(format!(
            "{} is not a non-zero 256-bit secret",
            path.display()
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err(format!("{} is not a regular secret file", path.display()));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{} permissions are broader than 0600",
            path.display()
        ));
    }
    Ok(())
}

fn create_secret(path: &Path) -> Result<Vec<u8>, String> {
    let mut random = File::open("/dev/urandom")
        .map_err(|error| format!("cannot open kernel random source: {error}"))?;
    let mut bytes = vec![0_u8; SECRET_BYTES];
    random
        .read_exact(&mut bytes)
        .map_err(|error| format!("cannot read kernel random source: {error}"))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("kernel random source returned an invalid all-zero secret".into());
    }
    install_secret_atomically(path, &bytes)
}

fn install_secret_atomically(path: &Path, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() != SECRET_BYTES || bytes.iter().all(|byte| *byte == 0) {
        return Err("refusing to provision an invalid authority secret".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("{} has no canonical UTF-8 file name", path.display()))?;

    for attempt in 0..SECRET_INSTALL_ATTEMPTS {
        let temporary = parent.join(format!(".{name}.tmp-{}-{attempt}", process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create temporary secret {}: {error}",
                    temporary.display()
                ));
            }
        };

        let provision = (|| -> Result<Vec<u8>, String> {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| {
                    format!("cannot durably write {}: {error}", temporary.display())
                })?;
            drop(file);

            match fs::hard_link(&temporary, path) {
                Ok(()) => {
                    fs::remove_file(&temporary).map_err(|error| {
                        format!(
                            "cannot remove temporary secret {}: {error}",
                            temporary.display()
                        )
                    })?;
                    File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| {
                            format!("cannot durably publish {}: {error}", path.display())
                        })?;
                    validate_secret_file(path, bytes)?;
                    Ok(bytes.to_vec())
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary).map_err(|remove_error| {
                        format!(
                            "cannot clean temporary secret {} after concurrent creation: {remove_error}",
                            temporary.display()
                        )
                    })?;
                    let existing = fs::read(path).map_err(|read_error| {
                        format!("cannot read {}: {read_error}", path.display())
                    })?;
                    validate_secret_file(path, &existing)?;
                    Ok(existing)
                }
                Err(error) => Err(format!(
                    "cannot atomically publish {}: {error}",
                    path.display()
                )),
            }
        })();

        if provision.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return provision;
    }

    Err(format!(
        "cannot allocate a unique temporary secret beside {}",
        path.display()
    ))
}

pub(crate) fn state_dir() -> PathBuf {
    env::var_os(STATE_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn wire(unit: &str, state: &str) -> Authority1ManagedRequest {
        Authority1ManagedRequest {
            operation_id: "qualification-operation".into(),
            unit: unit.into(),
            desired_active_state: state.into(),
            reason: "qualify exact managed request".into(),
        }
    }

    fn scratch(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        env::temp_dir().join(format!(
            "linura-authorityd-{label}-{}-{nonce}",
            process::id()
        ))
    }

    #[test]
    fn request_builder_retains_exact_v06_boundary_and_origin() {
        let request = managed_request(&wire("linura-managed-example.service", "active"))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(request.provider.as_str(), MANAGED_SYSTEMD_PROVIDER);
        assert_eq!(
            request.observation_capability.as_str(),
            MANAGED_SYSTEMD_CAPABILITY
        );
        assert_eq!(
            request.resource.as_str(),
            "systemd:unit:linura-managed-example.service"
        );
        assert_eq!(
            request
                .desired_state
                .get("active_state")
                .map(String::as_str),
            Some("active")
        );
        assert_eq!(request.reason.intent_ids.len(), 1);
        assert_eq!(
            request.reason.intent_ids[0].as_str(),
            MANAGED_SYSTEMD_INTENT_ORIGIN
        );
    }

    #[test]
    fn request_builder_rejects_scope_widening() {
        assert!(managed_request(&wire("sshd.service", "active")).is_err());
        assert!(managed_request(&wire("linura-managed-example.service", "failed")).is_err());
    }

    #[test]
    fn atomic_secret_install_never_replaces_existing_secret() {
        let root = scratch("secret-race");
        fs::create_dir_all(&root).unwrap_or_else(|error| unreachable!("{error}"));
        let path = root.join("authority.key");
        let original = vec![0x11; SECRET_BYTES];
        let competing = vec![0x22; SECRET_BYTES];
        fs::write(&path, &original).unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| unreachable!("{error}"));

        let installed = install_secret_atomically(&path, &competing)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(installed, original);
        assert_eq!(fs::read(&path).unwrap_or_default(), original);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn partial_final_secret_fails_closed_instead_of_being_overwritten() {
        let root = scratch("partial-secret");
        fs::create_dir_all(&root).unwrap_or_else(|error| unreachable!("{error}"));
        let path = root.join("authority.key");
        fs::write(&path, [1_u8, 2, 3]).unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| unreachable!("{error}"));

        let error = match load_or_create_secret(&path) {
            Ok(_) => unreachable!("partial final key must fail closed"),
            Err(error) => error,
        };
        assert!(error.contains("not a non-zero 256-bit secret"));
        assert_eq!(fs::read(&path).unwrap_or_default(), vec![1_u8, 2, 3]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn filesystem_full_detection_is_narrow() {
        let root = scratch("capacity-probe");
        fs::create_dir_all(&root).unwrap_or_else(|error| unreachable!("{error}"));
        let database = root.join("authority.sqlite3");
        assert!(is_physical_storage_exhaustion(
            &database,
            &TransactionStoreError::Storage("database or disk is full".into())
        ));
        assert!(is_physical_storage_exhaustion(
            &database,
            &TransactionStoreError::Storage("No space left on device".into())
        ));
        assert!(!is_physical_storage_exhaustion(
            &database,
            &TransactionStoreError::Corruption("bad tag".into())
        ));
        assert!(!is_physical_storage_exhaustion(
            &database,
            &TransactionStoreError::CapacityExceeded
        ));
        let _ = fs::remove_dir_all(root);
    }
}
