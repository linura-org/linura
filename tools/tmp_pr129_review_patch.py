from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    source = target.read_text()
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    target.write_text(source.replace(old, new, 1))


# P1: evidence assembly must use the filename that was actually validated.
replace_once(
    ".github/workflows/v09-qualification.yml",
    "shutil.copy2(adversarial_transcript, qualification_root / adversarial_transcript_name)",
    "shutil.copy2(adversarial_transcript, qualification_root / transcript_name)",
)

# P1/Q8: perform a delayed handoff from stock Ubuntu SSH to the qualification-only
# daemon so the command scheduling the handoff can return before port 22 moves.
replace_once(
    "scripts/qualification/v09-adversarial-guest.sh",
    """remote 'sudo -n systemctl daemon-reload && sudo -n systemctl enable linura-qualification-transport.service >/dev/null'
remote 'for unit in ssh.service sshd.service ssh.socket sshd.socket; do sudo -n systemctl disable "$unit" >/dev/null 2>&1 || true; done'
""",
    """remote 'sudo -n systemctl daemon-reload && sudo -n systemctl enable linura-qualification-transport.service >/dev/null'
remote 'set -e; for unit in ssh.service sshd.service ssh.socket sshd.socket; do sudo -n systemctl disable "$unit" >/dev/null 2>&1 || true; done; sudo -n systemd-run --unit=linura-v09-qualification-transport-switch --on-active=1s /bin/sh -c "systemctl stop ssh.socket sshd.socket ssh.service sshd.service >/dev/null 2>&1 || true; systemctl start linura-qualification-transport.service" >/dev/null'
transport_switched=0
for _ in $(seq 1 60); do
  if remote 'systemctl is-active --quiet linura-qualification-transport.service && ! systemctl is-active --quiet ssh.service && ! systemctl is-active --quiet sshd.service && ! systemctl is-active --quiet ssh.socket && ! systemctl is-active --quiet sshd.socket' >/dev/null 2>&1; then
    transport_switched=1
    break
  fi
  sleep 1
done
if [[ "$transport_switched" != 1 ]]; then
  echo 'failed to hand qualification transport from stock Ubuntu SSH' >&2
  exit 1
fi
""",
)

# A disabled alias/indirect unit is still useful as a discovery candidate, but
# alias/indirect/link state does not itself mean SSH will be started at boot.
replace_once(
    "crates/linura-bootstrap/src/durable/verification.rs",
    '''        ) || matches!(
            line.strip_prefix("UnitFileState="),
            Some("enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias" | "indirect")
        )
''',
    '''        ) || matches!(
            line.strip_prefix("UnitFileState="),
            Some("enabled" | "enabled-runtime")
        )
''',
)

# P2: retain TCP/22 detection for renamed servers, but additionally correlate
# every LISTEN socket inode with sshd/dropbear server processes on any port.
replace_once(
    "crates/linura-bootstrap/src/durable/verification.rs",
    '''fn tcp22_listening(path: &Path) -> Result<bool, DurableBootstrapError> {
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
''',
    '''fn tcp_listener_inodes(
    path: &Path,
) -> Result<(bool, std::collections::BTreeSet<u64>), DurableBootstrapError> {
    let text = fs::read_to_string(path).map_err(DurableBootstrapError::Io)?;
    let mut port22 = false;
    let mut inodes = std::collections::BTreeSet::new();
    for line in text.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || fields[3] != "0A" {
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
        port22 |= port == 22;
        let inode = fields[9].parse::<u64>().map_err(|_| {
            DurableBootstrapError::InvalidVerificationEvidence(
                "kernel TCP listener inode is malformed",
            )
        })?;
        if inode != 0 {
            inodes.insert(inode);
        }
    }
    Ok((port22, inodes))
}

fn ssh_process(pid: &Path) -> Result<bool, DurableBootstrapError> {
    let comm = match fs::read_to_string(pid.join("comm")) {
        Ok(value) => value.trim().to_ascii_lowercase(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(DurableBootstrapError::Io(error)),
    };
    if matches!(comm.as_str(), "sshd" | "dropbear") {
        return Ok(true);
    }
    let cmdline = match fs::read(pid.join("cmdline")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(DurableBootstrapError::Io(error)),
    };
    let executable = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
    let executable = std::str::from_utf8(executable).unwrap_or_default();
    let basename = Path::new(executable)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    Ok(matches!(basename.as_str(), "sshd" | "dropbear"))
}

fn socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_string_lossy();
    text.strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok())
}

fn ssh_server_owns_listener(
    listener_inodes: &std::collections::BTreeSet<u64>,
) -> Result<bool, DurableBootstrapError> {
    if listener_inodes.is_empty() {
        return Ok(false);
    }
    for entry in fs::read_dir("/proc").map_err(DurableBootstrapError::Io)? {
        let entry = entry.map_err(DurableBootstrapError::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue; };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let pid = entry.path();
        if !ssh_process(&pid)? {
            continue;
        }
        let fds = match fs::read_dir(pid.join("fd")) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(DurableBootstrapError::Io(error)),
        };
        for fd in fds {
            let fd = fd.map_err(DurableBootstrapError::Io)?;
            let target = match fs::read_link(fd.path()) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(DurableBootstrapError::Io(error)),
            };
            if socket_inode(&target).is_some_and(|inode| listener_inodes.contains(&inode)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
''',
)
replace_once(
    "crates/linura-bootstrap/src/durable/verification.rs",
    '''    Ok(tcp22_listening(Path::new("/proc/net/tcp"))?
        || tcp22_listening(Path::new("/proc/net/tcp6"))?)
''',
    '''    let (tcp22_v4, mut listeners) = tcp_listener_inodes(Path::new("/proc/net/tcp"))?;
    let (tcp22_v6, listeners_v6) = tcp_listener_inodes(Path::new("/proc/net/tcp6"))?;
    listeners.extend(listeners_v6);
    Ok(tcp22_v4 || tcp22_v6 || ssh_server_owns_listener(&listeners)?)
''',
)

# Read-only snapshots are declarative inputs: First Boot must not migrate or
# otherwise mutate them while resolving manifest selections.
replace_once(
    "crates/linura-library/src/store.rs",
    '''    pub fn open(path: impl AsRef<Path>) -> Result<Self, LibraryError> {
        Self::open_with_settings(path, LibrarySettings::default())
    }

''',
    '''    pub fn open(path: impl AsRef<Path>) -> Result<Self, LibraryError> {
        Self::open_with_settings(path, LibrarySettings::default())
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, LibraryError> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_millis(
            LibrarySettings::default().busy_timeout_ms,
        ))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        integrity_check_connection(&connection)?;
        let found = schema::read_schema_version(&connection)?;
        if found != LIBRARY_SCHEMA_VERSION {
            if found > LIBRARY_SCHEMA_VERSION {
                return Err(LibraryError::UnsupportedSchema {
                    found,
                    supported: LIBRARY_SCHEMA_VERSION,
                });
            }
            return Err(LibraryError::Validation(format!(
                "read-only Library schema {found} must equal current schema {LIBRARY_SCHEMA_VERSION}"
            )));
        }
        Ok(Self {
            connection,
            path: Some(path),
        })
    }

''',
)

# P1/P1: observe the full candidate environment and actually consume the
# persisted Provisioning Manifest selections in downstream First Boot stages.
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''    OwnerEnrollmentAuthorityVerifier, OwnerEnrollmentState,
    TrustedPreparerAuthorityRevocationReceipt,
};
use linura_bootstrap::{BootstrapStage, ProvisioningMode};
''',
    '''    OwnerEnrollmentAuthorityVerifier, OwnerEnrollmentState, ProvisioningManifest,
    TrustedPreparerAuthorityRevocationReceipt,
};
use linura_bootstrap::{BootstrapStage, ProvisioningMode};
use linura_core::{ProfileId, SetupId};
''',
)
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''use linura_hardware::{QualificationEnvironment, V09_QUALIFICATION_ENVIRONMENT_ID};
use sha2::{Digest, Sha256};
''',
    '''use linura_hardware::{
    InteractionMode, MachineClass, ObservedEnvironment, QualificationEnvironment,
    V09_QUALIFICATION_ENVIRONMENT_ID, VirtualizationKind,
};
use linura_library::{LocalLibrary, encode_profile_bundle, encode_setup_bundle};
use sha2::{Digest, Sha256};
''',
)
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''use std::path::{Path, PathBuf};
use std::process::ExitCode;
''',
    '''use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
''',
)
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''const PREPARER_REVOCATION_RECEIPT: &str = "authority/preparer-revocation.receipt";
const O_NOFOLLOW: i32 = 0o400000;
''',
    '''const PREPARER_REVOCATION_RECEIPT: &str = "authority/preparer-revocation.receipt";
const PROVISIONING_MANIFEST_FILE: &str = "provisioning.manifest";
const PROVISIONING_LIBRARY_FILE: &str = "provisioning-library.db";
const PROVISIONING_SOURCE_BINDING_FILE: &str = "provisioning-source.binding";
const O_NOFOLLOW: i32 = 0o400000;
''',
)
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''    if !stage_has_effect(stage) {
        return execute_non_effect_stage(coordinator, stage, operation_id);
    }
''',
    '''    if !stage_has_effect(stage) {
        return execute_non_effect_stage(root, coordinator, stage, operation_id);
    }
    if matches!(
        stage,
        BootstrapStage::RecoveryCheckpoint | BootstrapStage::OwnerEnrollmentResolution
    ) {
        verify_unattended_selection_binding(root, coordinator)?;
    }
''',
)
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''fn execute_non_effect_stage(
    coordinator: &mut DurableBootstrapCoordinator,
    stage: BootstrapStage,
    operation_id: &str,
) -> Result<(), String> {
    match stage {
        BootstrapStage::BaseEnvironmentVerification => verify_candidate_environment()?,
        BootstrapStage::ProvisioningModeSelection => {
            if coordinator.state().provisioning().mode().is_none() {
                coordinator
                    .select_provisioning(ProvisioningMode::PrepareForAnotherOwner, None)
                    .map_err(display_string)?;
            }
        }
        BootstrapStage::HardwareDiscovery
        | BootstrapStage::SourceSelection
        | BootstrapStage::TargetObservation
        | BootstrapStage::FirstBootPlanning => verify_candidate_environment()?,
        BootstrapStage::FirstBootReady => {
            if coordinator.state().provisioning().owner_enrollment()
                == OwnerEnrollmentState::Unresolved
            {
                return Err("First Boot readiness requires resolved owner state".into());
            }
        }
        _ => return Err(format!("unexpected non-effect stage: {stage:?}")),
    }
    coordinator
        .complete_verified(operation_id)
        .map_err(display_string)
}
''',
    '''fn execute_non_effect_stage(
    root: &Path,
    coordinator: &mut DurableBootstrapCoordinator,
    stage: BootstrapStage,
    operation_id: &str,
) -> Result<(), String> {
    match stage {
        BootstrapStage::BaseEnvironmentVerification => verify_candidate_environment()?,
        BootstrapStage::ProvisioningModeSelection => {
            select_provisioning_from_manifest_or_default(root, coordinator)?;
        }
        BootstrapStage::HardwareDiscovery => {
            verify_candidate_environment()?;
            verify_manifest_host_identity(coordinator)?;
        }
        BootstrapStage::SourceSelection => {
            verify_candidate_environment()?;
            persist_unattended_selection_binding(root, coordinator)?;
        }
        BootstrapStage::TargetObservation | BootstrapStage::FirstBootPlanning => {
            verify_candidate_environment()?;
            verify_manifest_host_identity(coordinator)?;
            verify_unattended_selection_binding(root, coordinator)?;
        }
        BootstrapStage::FirstBootReady => {
            verify_unattended_selection_binding(root, coordinator)?;
            if coordinator.state().provisioning().owner_enrollment()
                == OwnerEnrollmentState::Unresolved
            {
                return Err("First Boot readiness requires resolved owner state".into());
            }
        }
        _ => return Err(format!("unexpected non-effect stage: {stage:?}")),
    }
    coordinator
        .complete_verified(operation_id)
        .map_err(display_string)
}
''',
)
replace_once(
    "apps/linura-firstboot/src/main.rs",
    '''fn verify_candidate_environment() -> Result<(), String> {
    QualificationEnvironment::v09_candidate()
        .validate_contract()
        .map_err(|error| format!("qualification environment contract failed: {error:?}"))?;
    let os_release = fs::read_to_string("/etc/os-release").map_err(io_string)?;
    if !os_release.lines().any(|line| line == "ID=ubuntu")
        || !os_release
            .lines()
            .any(|line| line == "VERSION_ID=\"24.04\"")
    {
        return Err("running system is not the bounded Ubuntu 24.04 v0.9 environment".into());
    }
    if std::env::consts::ARCH != "x86_64" {
        return Err("running system is not x86_64".into());
    }
    Ok(())
}
''',
    '''fn verify_candidate_environment() -> Result<(), String> {
    let expected = QualificationEnvironment::v09_candidate();
    expected
        .validate_contract()
        .map_err(|error| format!("qualification environment contract failed: {error:?}"))?;
    let observed = observe_candidate_environment()?;
    let mismatches = expected.assess(&observed);
    if !mismatches.is_empty() {
        let fields = mismatches
            .iter()
            .map(|mismatch| mismatch.field)
            .collect::<Vec<_>>()
            .join(",");
        return Err(format!(
            "running system does not match the bounded v0.9 QualificationEnvironment: {fields}"
        ));
    }
    Ok(())
}

fn observe_candidate_environment() -> Result<ObservedEnvironment, String> {
    let os_release = fs::read_to_string("/etc/os-release").map_err(io_string)?;
    let distribution_id = os_release_value(&os_release, "ID")
        .ok_or_else(|| "running system has no /etc/os-release ID".to_owned())?;
    let distribution_version = os_release_value(&os_release, "VERSION_ID")
        .ok_or_else(|| "running system has no /etc/os-release VERSION_ID".to_owned())?;
    let init_system = fs::read_to_string("/proc/1/comm")
        .map_err(io_string)?
        .trim()
        .to_owned();

    let default_target = Command::new("systemctl")
        .arg("get-default")
        .output()
        .map_err(io_string)?;
    if !default_target.status.success() {
        return Err("could not observe systemd default target".into());
    }
    let default_target = String::from_utf8_lossy(&default_target.stdout)
        .trim()
        .to_owned();
    let display_manager_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "display-manager.service"])
        .status()
        .map_err(io_string)?
        .success();
    let interaction = if display_manager_active || default_target == "graphical.target" {
        InteractionMode::Interactive
    } else {
        InteractionMode::Headless
    };
    let machine_class = match interaction {
        InteractionMode::Headless => MachineClass::Server,
        InteractionMode::Interactive => MachineClass::Workstation,
    };

    let virtualization = Command::new("systemd-detect-virt")
        .arg("--vm")
        .output()
        .map_err(io_string)?;
    let virtualization_name = String::from_utf8_lossy(&virtualization.stdout);
    let virtualization = match virtualization_name.trim() {
        "qemu" => VirtualizationKind::QemuTcg,
        "kvm" => VirtualizationKind::QemuKvm,
        "none" => VirtualizationKind::BareMetal,
        _ => VirtualizationKind::Other,
    };

    Ok(ObservedEnvironment {
        machine_class,
        distribution_id,
        distribution_version,
        architecture: std::env::consts::ARCH.to_owned(),
        interaction,
        virtualization,
        init_system,
    })
}

fn os_release_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        if candidate != key {
            return None;
        }
        let value = value.trim();
        Some(
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(value)
                .to_owned(),
        )
    })
}

fn select_provisioning_from_manifest_or_default(
    root: &Path,
    coordinator: &mut DurableBootstrapCoordinator,
) -> Result<(), String> {
    if coordinator.state().provisioning().mode().is_some() {
        return Ok(());
    }
    let manifest_path = root.join(PROVISIONING_MANIFEST_FILE);
    match fs::symlink_metadata(&manifest_path) {
        Ok(_) => {
            let raw = read_protected_identity_file(
                &manifest_path,
                16 * 1024,
                "Provisioning Manifest",
            )?;
            let manifest = ProvisioningManifest::parse(raw.as_bytes()).map_err(display_string)?;
            coordinator
                .select_provisioning(manifest.mode(), Some(&manifest))
                .map_err(display_string)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => coordinator
            .select_provisioning(ProvisioningMode::PrepareForAnotherOwner, None)
            .map_err(display_string),
        Err(error) => Err(io_string(error)),
    }
}

fn verify_manifest_host_identity(
    coordinator: &DurableBootstrapCoordinator,
) -> Result<(), String> {
    if coordinator.state().provisioning().mode() != Some(ProvisioningMode::UnattendedLocal) {
        return Ok(());
    }
    let expected = coordinator
        .state()
        .provisioning()
        .manifest_host_identity()
        .ok_or_else(|| "unattended-local manifest requires host_identity".to_owned())?;
    let expected = expected
        .strip_prefix("host:")
        .ok_or_else(|| "manifest host_identity must use host:<hostname>".to_owned())?;
    let observed = fs::read_to_string("/etc/hostname").map_err(io_string)?;
    if observed.trim() != expected {
        return Err("manifest host_identity does not match the observed host".into());
    }
    Ok(())
}

fn parse_library_revision_ref(value: &str, label: &str) -> Result<(String, u32), String> {
    let (id, revision) = value
        .rsplit_once(":v")
        .ok_or_else(|| format!("{label} must use <id>:v<revision>"))?;
    if id.is_empty() {
        return Err(format!("{label} has an empty id"));
    }
    let revision = revision
        .parse::<u32>()
        .map_err(|_| format!("{label} revision is not a positive u32"))?;
    if revision == 0 {
        return Err(format!("{label} revision must be nonzero"));
    }
    Ok((id.to_owned(), revision))
}

fn verify_protected_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(io_string)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!("{label} is not a protected root-owned regular file"));
    }
    Ok(())
}

fn hash_binding_field(hasher: &mut Sha256, label: &str, bytes: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn resolve_unattended_selection_binding(
    root: &Path,
    coordinator: &DurableBootstrapCoordinator,
) -> Result<Option<String>, String> {
    if coordinator.state().provisioning().mode() != Some(ProvisioningMode::UnattendedLocal) {
        return Ok(None);
    }
    verify_manifest_host_identity(coordinator)?;
    let provisioning = coordinator.state().provisioning();
    if provisioning.manifest_source_ref() != Some("local:library") {
        return Err("unattended-local source_ref must be local:library".into());
    }
    let library_path = root.join(PROVISIONING_LIBRARY_FILE);
    verify_protected_regular_file(&library_path, "provisioning Library snapshot")?;
    let library = LocalLibrary::open_read_only(&library_path).map_err(display_string)?;
    let mut hasher = Sha256::new();
    hash_binding_field(
        &mut hasher,
        "domain",
        b"linura-firstboot-unattended-selection-v1",
    );
    hash_binding_field(
        &mut hasher,
        "manifest",
        provisioning
            .manifest_identity()
            .ok_or_else(|| "unattended-local manifest identity is missing".to_owned())?
            .as_bytes(),
    );
    hash_binding_field(&mut hasher, "source", b"local:library");

    let mut selected_objects = 0_u32;
    let mut typed_intents = 0_usize;
    if let Some(reference) = provisioning.manifest_setup_ref() {
        let (id, revision) = parse_library_revision_ref(reference, "setup_ref")?;
        let id = SetupId::new(id).map_err(display_string)?;
        let bundle = library
            .export_setup(&id, Some(revision))
            .map_err(display_string)?;
        typed_intents = typed_intents.saturating_add(bundle.intents.len());
        let encoded = encode_setup_bundle(&bundle).map_err(display_string)?;
        hash_binding_field(&mut hasher, "setup_ref", reference.as_bytes());
        hash_binding_field(&mut hasher, "setup_bundle", &encoded);
        selected_objects += 1;
    }
    if let Some(reference) = provisioning.manifest_machine_profile_ref() {
        let (id, revision) = parse_library_revision_ref(reference, "machine_profile_ref")?;
        let id = ProfileId::new(id).map_err(display_string)?;
        let bundle = library
            .export_profile(&id, Some(revision))
            .map_err(display_string)?;
        typed_intents = typed_intents.saturating_add(bundle.intents.len());
        let encoded = encode_profile_bundle(&bundle).map_err(display_string)?;
        hash_binding_field(&mut hasher, "machine_profile_ref", reference.as_bytes());
        hash_binding_field(&mut hasher, "machine_profile_bundle", &encoded);
        selected_objects += 1;
    }
    if selected_objects == 0 {
        return Err("unattended-local manifest selects neither Setup nor MachineProfile".into());
    }
    if typed_intents == 0 {
        return Err("unattended-local selections resolve to no typed intents".into());
    }
    hash_binding_field(
        &mut hasher,
        "host_identity",
        provisioning
            .manifest_host_identity()
            .ok_or_else(|| "unattended-local host_identity is missing".to_owned())?
            .as_bytes(),
    );
    Ok(Some(format!("{:x}", hasher.finalize())))
}

fn persist_unattended_selection_binding(
    root: &Path,
    coordinator: &DurableBootstrapCoordinator,
) -> Result<(), String> {
    let Some(binding) = resolve_unattended_selection_binding(root, coordinator)? else {
        return Ok(());
    };
    durable_write(
        &root.join(PROVISIONING_SOURCE_BINDING_FILE),
        format!("{binding}\n").as_bytes(),
        0o600,
    )
}

fn verify_unattended_selection_binding(
    root: &Path,
    coordinator: &DurableBootstrapCoordinator,
) -> Result<(), String> {
    let Some(expected) = resolve_unattended_selection_binding(root, coordinator)? else {
        return Ok(());
    };
    let actual = read_protected_identity_file(
        &root.join(PROVISIONING_SOURCE_BINDING_FILE),
        128,
        "unattended source binding",
    )?;
    if actual.trim() != expected {
        return Err("unattended source selection changed after durable binding".into());
    }
    Ok(())
}
''',
)

Path("tests/tooling/test_v09_final_review_contract.py").write_text('''from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class V09FinalReviewContract(unittest.TestCase):
    def test_transcript_copy_uses_validated_name(self) -> None:
        source = (ROOT / ".github/workflows/v09-qualification.yml").read_text()
        self.assertIn("qualification_root / transcript_name", source)
        self.assertNotIn("qualification_root / adversarial_transcript_name", source)

    def test_stock_ssh_is_stopped_before_qualification_transport_takes_over(self) -> None:
        source = (ROOT / "scripts/qualification/v09-adversarial-guest.sh").read_text()
        self.assertIn("systemd-run --unit=linura-v09-qualification-transport-switch", source)
        self.assertIn("systemctl stop ssh.socket sshd.socket ssh.service sshd.service", source)
        self.assertIn("transport_switched=1", source)

    def test_firstboot_observes_full_environment_and_consumes_manifest_selections(self) -> None:
        source = (ROOT / "apps/linura-firstboot/src/main.rs").read_text()
        for token in [
            "observe_candidate_environment",
            "systemd-detect-virt",
            "expected.assess(&observed)",
            "manifest_source_ref",
            "manifest_setup_ref",
            "manifest_machine_profile_ref",
            "manifest_host_identity",
            "export_setup",
            "export_profile",
            "verify_unattended_selection_binding",
        ]:
            self.assertIn(token, source)

    def test_nonstandard_ssh_listener_is_correlated_to_server_process(self) -> None:
        source = (ROOT / "crates/linura-bootstrap/src/durable/verification.rs").read_text()
        self.assertIn("tcp_listener_inodes", source)
        self.assertIn("ssh_server_owns_listener", source)
        self.assertIn("socket:[", source)
        self.assertIn("dropbear", source)

if __name__ == "__main__":
    unittest.main()
''')
