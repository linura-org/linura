#![forbid(unsafe_code)]

use linura_bootstrap::durable::{
    BootstrapResumeDecision, BootstrapStateStore, DurableBootstrapCoordinator, OwnerEnrollmentState,
};
use linura_bootstrap::{BootstrapStage, ProvisioningMode};
use linura_firstboot::{
    CANDIDATE_BASE_IMAGE_SHA256, CANDIDATE_BASE_IMAGE_URL, FIRST_BOOT_CONTRACT_VERSION,
};
use linura_hardware::{QualificationEnvironment, V09_QUALIFICATION_ENVIRONMENT_ID};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BOOTSTRAP_SESSION_FILE: &str = ".linura-bootstrap-session";
const MACHINE_ID_DOMAIN: &[u8] = b"linura-bootstrap-machine-v2\0";
const DMI_PRODUCT_UUID: &str = "/sys/class/dmi/id/product_uuid";
const MANAGED_FIRSTBOOT_PATH: &str = "/opt/linura/bin/linura-firstboot";
const CHECKPOINT_DIRECTORY: &str = "recovery-checkpoint";
const CHECKPOINT_MANIFEST: &str = "checkpoint.manifest";
const O_NOFOLLOW: i32 = 0o400000;
const MAX_BOOTSTRAP_TRANSITIONS: usize = 64;

fn print_help() {
    println!("linura-firstboot — Linura v0.9 First Boot client");
    println!();
    println!("Usage:");
    println!("  linura-firstboot");
    println!("  linura-firstboot --qualification-environment");
    println!("  linura-firstboot --self-check");
    println!(
        "  linura-firstboot --durable-bootstrap-init <absolute-state-root> <expected-self-sha256>"
    );
    println!(
        "  linura-firstboot --durable-bootstrap-start <absolute-state-root> <expected-self-sha256>"
    );
    println!(
        "  linura-firstboot --durable-bootstrap-step <absolute-state-root> <expected-self-sha256>"
    );
    println!(
        "  linura-firstboot --durable-bootstrap-resume <absolute-state-root> <expected-self-sha256>"
    );
    println!("  linura-firstboot --help");
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {
            println!("What do you want this computer to become?");
            println!();
            println!("First Boot contract v{FIRST_BOOT_CONTRACT_VERSION}");
            println!("Qualification environment: {V09_QUALIFICATION_ENVIRONMENT_ID}");
            println!(
                "First Boot prepares a typed, non-authorizing submission to Linura Control; review and execution authority remain Control-owned."
            );
            ExitCode::SUCCESS
        }
        Some("--qualification-environment") => {
            println!("id={V09_QUALIFICATION_ENVIRONMENT_ID}");
            println!("base_image={CANDIDATE_BASE_IMAGE_URL}");
            println!("base_image_sha256={CANDIDATE_BASE_IMAGE_SHA256}");
            println!("kind=qualification-environment");
            println!("status=candidate-not-yet-release-supported");
            ExitCode::SUCCESS
        }
        Some("--self-check") => {
            let environment = QualificationEnvironment::v09_candidate();
            match environment.validate_contract() {
                Ok(()) => {
                    println!("contract_version={FIRST_BOOT_CONTRACT_VERSION}");
                    println!("qualification_environment={V09_QUALIFICATION_ENVIRONMENT_ID}");
                    println!("preauthority_submission=opaque");
                    println!("policy_review=control-owned");
                    println!("execution_authority=absent");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("First Boot self-check failed: {error:?}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("--durable-bootstrap-init") => {
            let result = parse_root_and_digest(&mut args)
                .and_then(|(root, digest)| durable_bootstrap_init(&root, &digest));
            finish_durable_command(result)
        }
        Some("--durable-bootstrap-start") => {
            let result = parse_root_and_digest(&mut args)
                .and_then(|(root, digest)| durable_bootstrap_start(&root, &digest));
            finish_durable_command(result)
        }
        Some("--durable-bootstrap-step") => {
            let result = parse_root_and_digest(&mut args)
                .and_then(|(root, digest)| durable_bootstrap_step(&root, &digest));
            finish_durable_command(result)
        }
        Some("--durable-bootstrap-resume") => {
            let result = parse_root_and_digest(&mut args)
                .and_then(|(root, digest)| durable_bootstrap_resume(&root, &digest));
            finish_durable_command(result)
        }
        Some("--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown argument: {other}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn finish_durable_command(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("durable First Boot failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_root_and_digest(
    args: &mut impl Iterator<Item = String>,
) -> Result<(PathBuf, String), String> {
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing absolute durable bootstrap state root".to_owned())?,
    );
    let digest = args
        .next()
        .ok_or_else(|| "missing expected linura-firstboot SHA-256".to_owned())?;
    if args.next().is_some() || !root.is_absolute() {
        return Err(
            "durable bootstrap requires exactly one absolute state root and one SHA-256".to_owned(),
        );
    }
    validate_sha256(&digest)?;
    Ok((root, digest))
}

fn durable_bootstrap_init(root: &Path, expected_self_sha256: &str) -> Result<(), String> {
    fs::create_dir_all(root).map_err(io_string)?;
    verify_protected_root(root)?;
    verify_exact_running_binary(expected_self_sha256)?;
    let (_, coordinator) = open_coordinator(root, true)?;
    if coordinator.resume_decision()
        != BootstrapResumeDecision::ContinueAt(BootstrapStage::BaseEnvironmentVerification)
    {
        return Err("durable bootstrap init requires a fresh canonical ledger".into());
    }
    println!("bootstrap_initialized=durable");
    println!("bootstrap_generation={}", coordinator.state().generation());
    Ok(())
}

fn durable_bootstrap_start(root: &Path, expected_self_sha256: &str) -> Result<(), String> {
    fs::create_dir_all(root).map_err(io_string)?;
    verify_protected_root(root)?;
    verify_exact_running_binary(expected_self_sha256)?;
    let (store, mut coordinator) = open_coordinator(root, true)?;
    if coordinator.resume_decision()
        != BootstrapResumeDecision::ContinueAt(BootstrapStage::BaseEnvironmentVerification)
    {
        return Err("durable bootstrap start requires a fresh canonical ledger".into());
    }

    // Start performs two complete canonical stages, including a real atomic
    // managed installation. All later states are handled by the same generic
    // driver used after arbitrary restarts.
    drive_one_stage(&store, root, expected_self_sha256, &mut coordinator)?;
    drive_one_stage(&store, root, expected_self_sha256, &mut coordinator)?;
    println!("bootstrap_effect_started=durable");
    println!("bootstrap_effect=linura-installation");
    println!("bootstrap_installation=managed-atomic-copy");
    println!("bootstrap_producer=linura-firstboot");
    Ok(())
}

fn durable_bootstrap_step(root: &Path, expected_self_sha256: &str) -> Result<(), String> {
    verify_protected_root(root)?;
    verify_exact_running_binary(expected_self_sha256)?;
    let (store, mut coordinator) = open_coordinator(root, false)?;
    let advanced = drive_one_stage(&store, root, expected_self_sha256, &mut coordinator)?;
    println!("bootstrap_step_advanced={advanced}");
    println!("bootstrap_generation={}", coordinator.state().generation());
    Ok(())
}

fn durable_bootstrap_resume(root: &Path, expected_self_sha256: &str) -> Result<(), String> {
    verify_protected_root(root)?;
    verify_exact_running_binary(expected_self_sha256)?;
    let (store, mut coordinator) = open_coordinator(root, false)?;
    for _ in 0..MAX_BOOTSTRAP_TRANSITIONS {
        if coordinator.resume_decision() == BootstrapResumeDecision::Complete {
            println!("bootstrap_restart=reobserved");
            println!("bootstrap_restart_source=production-firstboot");
            println!("bootstrap_sequence=canonical-13-stage-prefix");
            println!("owner_enrollment=owner-enrollment-pending");
            println!("preparer_authority_inherited=false");
            return Ok(());
        }
        if !drive_one_stage(&store, root, expected_self_sha256, &mut coordinator)? {
            break;
        }
    }
    Err(format!(
        "production First Boot did not converge to Complete; last decision: {:?}",
        coordinator.resume_decision()
    ))
}

fn open_coordinator(
    root: &Path,
    create_session: bool,
) -> Result<(BootstrapStateStore, DurableBootstrapCoordinator), String> {
    let machine_id = trusted_machine_id()?;
    let session_id = if create_session {
        load_or_create_bootstrap_session_id(root)?
    } else {
        load_bootstrap_session_id(root)?
    };
    let store = BootstrapStateStore::new(root.join("bootstrap.state"));
    let coordinator = DurableBootstrapCoordinator::open(store.clone(), session_id, machine_id)
        .map_err(display_string)?;
    Ok((store, coordinator))
}

#[derive(Debug)]
enum OwnedResumeDecision {
    ContinueAt(BootstrapStage),
    ExecutePrepared(BootstrapStage, String),
    Reobserve(BootstrapStage, String),
    Complete,
    RecoveryRequired,
}

fn owned_resume_decision(coordinator: &DurableBootstrapCoordinator) -> OwnedResumeDecision {
    match coordinator.resume_decision() {
        BootstrapResumeDecision::ContinueAt(stage) => OwnedResumeDecision::ContinueAt(stage),
        BootstrapResumeDecision::ExecutePrepared {
            stage,
            operation_id,
        } => OwnedResumeDecision::ExecutePrepared(stage, operation_id.to_owned()),
        BootstrapResumeDecision::ReobserveBeforeContinuing {
            stage,
            operation_id,
        } => OwnedResumeDecision::Reobserve(stage, operation_id.to_owned()),
        BootstrapResumeDecision::Complete => OwnedResumeDecision::Complete,
        BootstrapResumeDecision::RecoveryRequired => OwnedResumeDecision::RecoveryRequired,
    }
}

fn drive_one_stage(
    store: &BootstrapStateStore,
    root: &Path,
    expected_self_sha256: &str,
    coordinator: &mut DurableBootstrapCoordinator,
) -> Result<bool, String> {
    match owned_resume_decision(coordinator) {
        OwnedResumeDecision::Complete => Ok(false),
        OwnedResumeDecision::RecoveryRequired => {
            Err("durable coordinator requires explicit recovery before continuing".into())
        }
        OwnedResumeDecision::ContinueAt(stage) => {
            let operation_id = operation_id(stage);
            coordinator
                .prepare_stage(stage, operation_id)
                .map_err(display_string)?;
            execute_prepared_stage(
                store,
                root,
                expected_self_sha256,
                coordinator,
                stage,
                operation_id,
            )?;
            Ok(true)
        }
        OwnedResumeDecision::ExecutePrepared(stage, operation_id) => {
            if operation_id != operation_id_for(stage) {
                return Err(format!(
                    "prepared stage operation binding is not canonical: {stage:?}/{operation_id}"
                ));
            }
            execute_prepared_stage(
                store,
                root,
                expected_self_sha256,
                coordinator,
                stage,
                &operation_id,
            )?;
            Ok(true)
        }
        OwnedResumeDecision::Reobserve(stage, operation_id) => {
            if operation_id != operation_id_for(stage) {
                return Err(format!(
                    "started stage operation binding is not canonical: {stage:?}/{operation_id}"
                ));
            }
            reconcile_started_effect(store, root, expected_self_sha256, coordinator, stage)?;
            Ok(true)
        }
    }
}

fn operation_id(stage: BootstrapStage) -> &'static str {
    operation_id_for(stage)
}

fn operation_id_for(stage: BootstrapStage) -> &'static str {
    match stage {
        BootstrapStage::BaseEnvironmentVerification => "firstboot-base-environment",
        BootstrapStage::LinuraInstallation => "firstboot-linura-installation",
        BootstrapStage::PersistentStateInitialization => "firstboot-persistent-state",
        BootstrapStage::SecurityBaseline => "firstboot-security-baseline",
        BootstrapStage::ProvisioningModeSelection => "firstboot-provisioning-mode",
        BootstrapStage::BootstrapConnectivityResolution => "firstboot-connectivity",
        BootstrapStage::HardwareDiscovery => "firstboot-hardware",
        BootstrapStage::SourceSelection => "firstboot-source",
        BootstrapStage::TargetObservation => "firstboot-target-observation",
        BootstrapStage::FirstBootPlanning => "firstboot-plan",
        BootstrapStage::RecoveryCheckpoint => "firstboot-recovery-checkpoint",
        BootstrapStage::OwnerEnrollmentResolution => "firstboot-owner-resolution",
        BootstrapStage::FirstBootReady => "firstboot-ready",
    }
}

fn stage_has_effect(stage: BootstrapStage) -> bool {
    matches!(
        stage,
        BootstrapStage::LinuraInstallation
            | BootstrapStage::PersistentStateInitialization
            | BootstrapStage::SecurityBaseline
            | BootstrapStage::BootstrapConnectivityResolution
            | BootstrapStage::RecoveryCheckpoint
            | BootstrapStage::OwnerEnrollmentResolution
    )
}

fn execute_prepared_stage(
    store: &BootstrapStateStore,
    root: &Path,
    expected_self_sha256: &str,
    coordinator: &mut DurableBootstrapCoordinator,
    stage: BootstrapStage,
    operation_id: &str,
) -> Result<(), String> {
    if !stage_has_effect(stage) {
        return execute_non_effect_stage(coordinator, stage, operation_id);
    }
    coordinator
        .mark_effect_started(operation_id)
        .map_err(display_string)?;
    match stage {
        BootstrapStage::LinuraInstallation => {
            perform_managed_installation(expected_self_sha256)?;
        }
        BootstrapStage::PersistentStateInitialization => {
            verify_protected_root(root)?;
        }
        BootstrapStage::SecurityBaseline => {}
        BootstrapStage::BootstrapConnectivityResolution => {}
        BootstrapStage::RecoveryCheckpoint => {
            create_checkpoint_bundle(store, root, coordinator)?;
        }
        BootstrapStage::OwnerEnrollmentResolution => {
            resolve_owner_stage(coordinator)?;
        }
        _ => return Err(format!("unexpected effectful stage: {stage:?}")),
    }
    reconcile_started_effect(store, root, expected_self_sha256, coordinator, stage)
}

fn execute_non_effect_stage(
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

fn reconcile_started_effect(
    store: &BootstrapStateStore,
    root: &Path,
    expected_self_sha256: &str,
    coordinator: &mut DurableBootstrapCoordinator,
    stage: BootstrapStage,
) -> Result<(), String> {
    match stage {
        BootstrapStage::LinuraInstallation => {
            // Re-observe first. If the exact managed target is absent or does
            // not match, the operation is a deterministic atomic file install,
            // so it may be reconciled by repeating the exact-source copy only
            // after observing the post-state; this is not blind replay.
            let target = Path::new(MANAGED_FIRSTBOOT_PATH);
            let matches = target.exists()
                && file_sha256(target)
                    .map(|digest| digest == expected_self_sha256)
                    .unwrap_or(false);
            if !matches {
                perform_managed_installation(expected_self_sha256)?;
            }
            coordinator
                .verify_linura_installation(expected_self_sha256)
                .map_err(display_string)
        }
        BootstrapStage::PersistentStateInitialization => coordinator
            .verify_persistent_state_root(root)
            .map_err(display_string),
        BootstrapStage::SecurityBaseline => coordinator
            .verify_security_baseline()
            .map_err(display_string),
        BootstrapStage::BootstrapConnectivityResolution => coordinator
            .verify_connectivity_observation()
            .map_err(display_string),
        BootstrapStage::RecoveryCheckpoint => {
            let manifest = root.join(CHECKPOINT_DIRECTORY).join(CHECKPOINT_MANIFEST);
            if !manifest.is_file() {
                create_checkpoint_bundle(store, root, coordinator)?;
            }
            coordinator
                .verify_recovery_checkpoint_manifest(&manifest)
                .map_err(display_string)
        }
        BootstrapStage::OwnerEnrollmentResolution => {
            if coordinator.state().provisioning().owner_enrollment()
                == OwnerEnrollmentState::Unresolved
            {
                resolve_owner_stage(coordinator)?;
            }
            coordinator
                .verify_owner_resolution()
                .map_err(display_string)
        }
        _ => Err(format!("unexpected started effect stage: {stage:?}")),
    }
}

fn resolve_owner_stage(coordinator: &mut DurableBootstrapCoordinator) -> Result<(), String> {
    match coordinator.state().provisioning().mode() {
        Some(ProvisioningMode::PrepareForAnotherOwner | ProvisioningMode::UnattendedLocal) => {
            coordinator
                .enter_owner_enrollment_pending()
                .map_err(display_string)
        }
        Some(ProvisioningMode::Recovery) => coordinator
            .enter_recovery_owner_resolution()
            .map_err(display_string),
        Some(ProvisioningMode::InteractiveOwner) => Err(
            "interactive owner mode requires a Control-produced owner enrollment receipt".into(),
        ),
        None => Err("owner resolution reached before provisioning mode selection".into()),
    }
}

fn perform_managed_installation(expected_self_sha256: &str) -> Result<(), String> {
    verify_exact_running_binary(expected_self_sha256)?;
    let source = fs::canonicalize("/proc/self/exe").map_err(io_string)?;
    let target = Path::new(MANAGED_FIRSTBOOT_PATH);
    let parent = target
        .parent()
        .ok_or_else(|| "managed First Boot path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(io_string)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).map_err(io_string)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(io_string)?;
    if parent_metadata.uid() != 0
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("managed Linura installation directory is not protected/root-owned".into());
    }
    if target.exists() {
        let metadata = fs::symlink_metadata(target).map_err(io_string)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("existing managed First Boot target is untrusted".into());
        }
        if file_sha256(target)? == expected_self_sha256 {
            return Ok(());
        }
    }

    let temporary = parent.join(format!(".linura-firstboot.install-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let mut input = fs::File::open(&source).map_err(io_string)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(O_NOFOLLOW)
        .open(&temporary)
        .map_err(io_string)?;
    std::io::copy(&mut input, &mut output).map_err(io_string)?;
    output.sync_all().map_err(io_string)?;
    fs::rename(&temporary, target).map_err(io_string)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_string)?;
    if file_sha256(target)? != expected_self_sha256 {
        return Err("managed First Boot installation failed exact-source verification".into());
    }
    Ok(())
}

fn create_checkpoint_bundle(
    store: &BootstrapStateStore,
    root: &Path,
    coordinator: &DurableBootstrapCoordinator,
) -> Result<(), String> {
    let directory = root.join(CHECKPOINT_DIRECTORY);
    fs::create_dir_all(&directory).map_err(io_string)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(io_string)?;
    let state_copy = directory.join("bootstrap.state");
    let session_copy = directory.join(BOOTSTRAP_SESSION_FILE);
    let anchor_copy = directory.join("generation.anchor");
    durable_copy(store.path(), &state_copy)?;
    durable_copy(&root.join(BOOTSTRAP_SESSION_FILE), &session_copy)?;
    let anchor_path = store.recovery_anchor_path().map_err(display_string)?;
    durable_copy(&anchor_path, &anchor_copy)?;

    let state_sha = file_sha256(&state_copy)?;
    let session_sha = file_sha256(&session_copy)?;
    let anchor_sha = file_sha256(&anchor_copy)?;
    // Deliberately omit raw machine/session identifiers from evidence-like
    // recovery artifacts. Exact artifact digests retain restore binding without
    // exposing stable identity material in logs or uploaded evidence.
    let payload = format!(
        "linura-bootstrap-recovery-checkpoint-v3\nstate_generation={}\nstate_sha256={}\nsession_sha256={}\nanchor_sha256={}\nresume_stage=recovery-checkpoint\n",
        coordinator.state().generation(),
        state_sha,
        session_sha,
        anchor_sha,
    );
    let integrity = sha256_hex(payload.as_bytes());
    durable_write(
        &directory.join(CHECKPOINT_MANIFEST),
        format!("{payload}integrity={integrity}\n").as_bytes(),
        0o600,
    )?;
    fs::File::open(&directory)
        .and_then(|dir| dir.sync_all())
        .map_err(io_string)?;
    Ok(())
}

fn durable_copy(source: &Path, target: &Path) -> Result<(), String> {
    let bytes = fs::read(source).map_err(io_string)?;
    durable_write(target, &bytes, 0o600)
}

fn durable_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "durable target has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(io_string)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "invalid durable target file name".to_owned())?,
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(&temporary)
        .map_err(io_string)?;
    file.write_all(bytes).map_err(io_string)?;
    file.sync_all().map_err(io_string)?;
    fs::rename(&temporary, path).map_err(io_string)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_string)
}

fn trusted_machine_id() -> Result<String, String> {
    let machine_raw =
        read_protected_identity_file(Path::new("/etc/machine-id"), 128, "machine-id")?;
    let machine_id = machine_raw.trim();
    if machine_id.len() != 32
        || machine_id.bytes().all(|byte| byte == b'0')
        || !machine_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("trusted /etc/machine-id is not a nonzero 128-bit machine identity".into());
    }
    let hardware_raw =
        read_protected_identity_file(Path::new(DMI_PRODUCT_UUID), 128, "DMI product UUID")?;
    let hardware_id = hardware_raw.trim().to_ascii_lowercase();
    if hardware_id.len() != 36
        || hardware_id.bytes().all(|byte| matches!(byte, b'0' | b'-'))
        || !hardware_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err("trusted DMI product UUID is not a nonzero canonical hardware identity".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(MACHINE_ID_DOMAIN);
    hasher.update(machine_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(hardware_id.as_bytes());
    Ok(format!("linura-machine-{:x}", hasher.finalize()))
}

fn load_or_create_bootstrap_session_id(root: &Path) -> Result<String, String> {
    let path = root.join(BOOTSTRAP_SESSION_FILE);
    match load_session_id(&path) {
        Ok(session_id) => Ok(session_id),
        Err(error) if error.starts_with("missing bootstrap session identity:") => {
            let uuid = fs::read_to_string("/proc/sys/kernel/random/uuid").map_err(io_string)?;
            let uuid = uuid.trim();
            if uuid.len() != 36
                || !uuid
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            {
                return Err("kernel did not provide a canonical bootstrap session UUID".into());
            }
            let session_id = format!("linura-bootstrap-session-{uuid}");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(O_NOFOLLOW)
                .open(&path)
                .map_err(io_string)?;
            file.write_all(format!("{session_id}\n").as_bytes())
                .map_err(io_string)?;
            file.sync_all().map_err(io_string)?;
            fs::File::open(root)
                .and_then(|directory| directory.sync_all())
                .map_err(io_string)?;
            load_session_id(&path)
        }
        Err(error) => Err(error),
    }
}

fn load_bootstrap_session_id(root: &Path) -> Result<String, String> {
    load_session_id(&root.join(BOOTSTRAP_SESSION_FILE))
}

fn load_session_id(path: &Path) -> Result<String, String> {
    let raw = match read_protected_identity_file(path, 512, "bootstrap session identity") {
        Ok(raw) => raw,
        Err(error) if error.contains("No such file or directory") => {
            return Err(format!("missing bootstrap session identity: {error}"));
        }
        Err(error) => return Err(error),
    };
    let value = raw.trim();
    if !value.starts_with("linura-bootstrap-session-")
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err("invalid durable bootstrap session identity".into());
    }
    Ok(value.to_owned())
}

fn read_protected_identity_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<String, String> {
    let before = fs::symlink_metadata(path).map_err(io_string)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
        || before.len() > max_bytes
    {
        return Err(format!(
            "{label} is not a protected root-owned regular file"
        ));
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(io_string)?;
    let opened = file.metadata().map_err(io_string)?;
    if opened.uid() != 0
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o022 != 0
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
        || opened.len() > max_bytes
    {
        return Err(format!("{label} changed or is not trusted while open"));
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw).map_err(io_string)?;
    let after = fs::symlink_metadata(path).map_err(io_string)?;
    if after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != opened.len()
        || after.uid() != 0
        || after.permissions().mode() & 0o022 != 0
    {
        return Err(format!("{label} changed during observation"));
    }
    Ok(raw)
}

fn verify_candidate_environment() -> Result<(), String> {
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

fn verify_protected_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root).map_err(io_string)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("durable First Boot root must be a root-owned protected directory".into());
    }
    Ok(())
}

fn verify_exact_running_binary(expected_self_sha256: &str) -> Result<(), String> {
    let actual = current_executable_sha256()?;
    if actual != expected_self_sha256 {
        return Err("running First Boot binary does not match exact-source SHA-256".into());
    }
    Ok(())
}

fn current_executable_sha256() -> Result<String, String> {
    let executable = fs::canonicalize("/proc/self/exe").map_err(io_string)?;
    file_sha256(&executable)
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(io_string)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_string)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected First Boot digest must be 64-character SHA-256 hex".into());
    }
    Ok(())
}

fn io_string(error: std::io::Error) -> String {
    error.to_string()
}

fn display_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}
