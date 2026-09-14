#![forbid(unsafe_code)]

use linura_bootstrap::durable::{
    BootstrapResumeDecision, BootstrapStateStore, BootstrapVerificationEvidence,
    DurableBootstrapCoordinator, DurableBootstrapError, OwnerEnrollmentState, ProvisioningManifest,
    TrustedOwnerEnrollmentReceipt,
};
use linura_bootstrap::{BootstrapStage, ProvisioningMode};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bootstrap qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| "missing qualification command".to_owned())?;
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing qualification state root".to_owned())?,
    );
    if args.next().is_some() || !root.is_absolute() {
        return Err("qualification requires exactly one absolute state root".into());
    }
    if command != "untrusted-parent" {
        fs::create_dir_all(&root).map_err(io_string)?;
    }
    match command.as_str() {
        "bootstrap-start" => bootstrap_start(&root),
        "bootstrap-resume" => bootstrap_resume(&root),
        "owner-enroll" => owner_enroll(&root),
        "interactive-owner" => interactive_owner(&root),
        "unattended-manifest" => unattended_manifest(&root),
        "recovery-mode" => recovery_mode(&root),
        "untrusted-parent" => untrusted_parent(&root),
        _ => Err(format!("unknown qualification command: {command}")),
    }
}

fn store(root: &Path) -> BootstrapStateStore {
    BootstrapStateStore::new(root.join("bootstrap.state"))
}

fn stage_has_external_effect(stage: BootstrapStage) -> bool {
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

fn complete_active_effect(
    coordinator: &mut DurableBootstrapCoordinator,
    stage: BootstrapStage,
    operation_id: &str,
) -> Result<(), String> {
    let evidence = BootstrapVerificationEvidence::qualification_observation(
        stage,
        operation_id,
        coordinator.state().session_id(),
        coordinator.state().machine_id(),
        format!("qualification-observation-{operation_id}"),
        format!("stage={stage:?};operation={operation_id};result=qualification-fixture").as_bytes(),
    )
    .map_err(display_string)?;
    coordinator
        .complete_effect_verified(&evidence)
        .map_err(display_string)
}

fn complete_stage(
    coordinator: &mut DurableBootstrapCoordinator,
    stage: BootstrapStage,
    operation_id: &str,
) -> Result<(), String> {
    coordinator
        .prepare_stage(stage, operation_id)
        .map_err(display_string)?;
    if stage_has_external_effect(stage) {
        coordinator
            .mark_effect_started(operation_id)
            .map_err(display_string)?;
        complete_active_effect(coordinator, stage, operation_id)
    } else {
        coordinator
            .complete_verified(operation_id)
            .map_err(display_string)
    }
}

fn advance_to_provisioning_stage(
    coordinator: &mut DurableBootstrapCoordinator,
    prefix: &str,
) -> Result<(), String> {
    for (stage, suffix) in [
        (BootstrapStage::BaseEnvironmentVerification, "base"),
        (BootstrapStage::LinuraInstallation, "install"),
        (BootstrapStage::PersistentStateInitialization, "persistence"),
        (BootstrapStage::SecurityBaseline, "security"),
    ] {
        complete_stage(coordinator, stage, &format!("{prefix}-{suffix}"))?;
    }
    coordinator
        .prepare_stage(
            BootstrapStage::ProvisioningModeSelection,
            format!("{prefix}-provisioning-mode"),
        )
        .map_err(display_string)
}

fn complete_provisioning_mode(
    coordinator: &mut DurableBootstrapCoordinator,
    prefix: &str,
    mode: ProvisioningMode,
    manifest: Option<&ProvisioningManifest>,
) -> Result<(), String> {
    coordinator
        .select_provisioning(mode, manifest)
        .map_err(display_string)?;
    coordinator
        .complete_verified(&format!("{prefix}-provisioning-mode"))
        .map_err(display_string)
}

fn advance_to_owner_resolution(
    coordinator: &mut DurableBootstrapCoordinator,
    prefix: &str,
) -> Result<(), String> {
    for (stage, suffix) in [
        (
            BootstrapStage::BootstrapConnectivityResolution,
            "connectivity",
        ),
        (BootstrapStage::HardwareDiscovery, "hardware"),
        (BootstrapStage::SourceSelection, "source"),
        (BootstrapStage::TargetObservation, "observation"),
        (BootstrapStage::FirstBootPlanning, "plan"),
        (BootstrapStage::RecoveryCheckpoint, "recovery"),
    ] {
        complete_stage(coordinator, stage, &format!("{prefix}-{suffix}"))?;
    }
    let operation_id = format!("{prefix}-owner-resolution");
    coordinator
        .prepare_stage(BootstrapStage::OwnerEnrollmentResolution, &operation_id)
        .map_err(display_string)?;
    coordinator
        .mark_effect_started(&operation_id)
        .map_err(display_string)
}

fn bootstrap_start(root: &Path) -> Result<(), String> {
    let mut coordinator =
        DurableBootstrapCoordinator::open(store(root), "qe-bootstrap-session", "qe-machine")
            .map_err(display_string)?;
    complete_stage(
        &mut coordinator,
        BootstrapStage::BaseEnvironmentVerification,
        "qe-base",
    )?;
    coordinator
        .prepare_stage(BootstrapStage::LinuraInstallation, "qe-install")
        .map_err(display_string)?;
    coordinator
        .mark_effect_started("qe-install")
        .map_err(display_string)?;
    if coordinator.resume_decision()
        != (BootstrapResumeDecision::ReobserveBeforeContinuing {
            stage: BootstrapStage::LinuraInstallation,
            operation_id: "qe-install",
        })
    {
        return Err("started bootstrap effect did not require re-observation".into());
    }
    println!("bootstrap_effect_started=durable");
    println!("bootstrap_replay_authority=absent");
    Ok(())
}

fn bootstrap_resume(root: &Path) -> Result<(), String> {
    let mut coordinator =
        DurableBootstrapCoordinator::open(store(root), "qe-bootstrap-session", "qe-machine")
            .map_err(display_string)?;
    if coordinator.resume_decision()
        != (BootstrapResumeDecision::ReobserveBeforeContinuing {
            stage: BootstrapStage::LinuraInstallation,
            operation_id: "qe-install",
        })
    {
        return Err("restart lost the re-observation boundary".into());
    }
    complete_active_effect(
        &mut coordinator,
        BootstrapStage::LinuraInstallation,
        "qe-install",
    )?;
    complete_stage(
        &mut coordinator,
        BootstrapStage::PersistentStateInitialization,
        "qe-persistence",
    )?;
    complete_stage(
        &mut coordinator,
        BootstrapStage::SecurityBaseline,
        "qe-security",
    )?;
    coordinator
        .prepare_stage(
            BootstrapStage::ProvisioningModeSelection,
            "qe-provisioning-mode",
        )
        .map_err(display_string)?;
    coordinator
        .select_provisioning(ProvisioningMode::PrepareForAnotherOwner, None)
        .map_err(display_string)?;
    coordinator
        .complete_verified("qe-provisioning-mode")
        .map_err(display_string)?;
    advance_to_owner_resolution(&mut coordinator, "qe")?;
    coordinator
        .enter_owner_enrollment_pending()
        .map_err(display_string)?;
    complete_active_effect(
        &mut coordinator,
        BootstrapStage::OwnerEnrollmentResolution,
        "qe-owner-resolution",
    )?;
    if coordinator.state().provisioning().owner_enrollment() != OwnerEnrollmentState::Pending
        || !coordinator
            .state()
            .provisioning()
            .preparer_authority_retired()
        || coordinator.resume_decision()
            != BootstrapResumeDecision::ContinueAt(BootstrapStage::FirstBootReady)
    {
        return Err("owner handoff did not stop at stable pending state".into());
    }
    println!("bootstrap_restart=reobserved");
    println!("bootstrap_sequence=canonical-13-stage-prefix");
    println!("owner_enrollment=owner-enrollment-pending");
    println!("preparer_authority=retired");
    Ok(())
}

fn write_enrollment_receipt(
    root: &Path,
    session_id: &str,
    machine_id: &str,
    owner_id: &str,
    enrollment_id: &str,
) -> Result<PathBuf, String> {
    let directory = root.join("authority");
    fs::create_dir_all(&directory).map_err(io_string)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(io_string)?;
    let issued_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    let payload = format!(
        "linura-owner-enrollment-receipt-v1\nproducer=linura-control-owner-enrollment-v1\nsession_id={session_id}\nmachine_id={machine_id}\nowner_id={owner_id}\nenrollment_id={enrollment_id}\nissued_unix_ms={issued_unix_ms}\n"
    );
    let digest = sha256_hex(payload.as_bytes());
    let path = directory.join(format!("{enrollment_id}.receipt"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(io_string)?;
    file.write_all(format!("{payload}integrity={digest}\n").as_bytes())
        .map_err(io_string)?;
    file.sync_all().map_err(io_string)?;
    fs::File::open(&directory)
        .and_then(|dir| dir.sync_all())
        .map_err(io_string)?;
    Ok(path)
}

fn owner_enroll(root: &Path) -> Result<(), String> {
    let mut coordinator =
        DurableBootstrapCoordinator::open(store(root), "qe-bootstrap-session", "qe-machine")
            .map_err(display_string)?;
    if coordinator.state().provisioning().owner_enrollment() != OwnerEnrollmentState::Pending
        || coordinator.state().active().is_some()
    {
        return Err("restart lost stable owner-enrollment-pending".into());
    }
    let receipt_path = write_enrollment_receipt(
        root,
        coordinator.state().session_id(),
        coordinator.state().machine_id(),
        "qe-owner",
        "qe-owner-enrollment-fresh",
    )?;
    let receipt = TrustedOwnerEnrollmentReceipt::load(
        &receipt_path,
        coordinator.state().session_id(),
        coordinator.state().machine_id(),
    )
    .map_err(display_string)?;
    coordinator
        .enroll_pending_owner_from_receipt(&receipt)
        .map_err(display_string)?;
    let provisioning = coordinator.state().provisioning();
    let authority = provisioning
        .owner_authority()
        .ok_or_else(|| "owner authority evidence was not minted".to_owned())?;
    if authority.owner_id() != "qe-owner"
        || authority.enrollment_id() != "qe-owner-enrollment-fresh"
        || authority.generation() != 1
        || provisioning.authority_generation() != 1
        || !provisioning.preparer_authority_retired()
    {
        return Err("owner authority evidence generation is not fresh/separated".into());
    }
    if coordinator.resume_decision()
        == BootstrapResumeDecision::ContinueAt(BootstrapStage::FirstBootReady)
    {
        complete_stage(
            &mut coordinator,
            BootstrapStage::FirstBootReady,
            "qe-firstboot-ready",
        )?;
    }
    println!("owner_authority_generation=1");
    println!("owner_enrollment_receipt=protected-control-boundary");
    println!("preparer_authority_inherited=false");
    Ok(())
}

fn interactive_owner(root: &Path) -> Result<(), String> {
    let interactive_store = BootstrapStateStore::new(root.join("interactive.state"));
    let mut coordinator = DurableBootstrapCoordinator::open(
        interactive_store.clone(),
        "qe-interactive-session",
        "qe-machine-interactive",
    )
    .map_err(display_string)?;
    advance_to_provisioning_stage(&mut coordinator, "interactive")?;
    complete_provisioning_mode(
        &mut coordinator,
        "interactive",
        ProvisioningMode::InteractiveOwner,
        None,
    )?;
    advance_to_owner_resolution(&mut coordinator, "interactive")?;
    let receipt_path = write_enrollment_receipt(
        root,
        coordinator.state().session_id(),
        coordinator.state().machine_id(),
        "qe-interactive-owner",
        "qe-interactive-enrollment",
    )?;
    let receipt = TrustedOwnerEnrollmentReceipt::load(
        &receipt_path,
        coordinator.state().session_id(),
        coordinator.state().machine_id(),
    )
    .map_err(display_string)?;
    coordinator
        .enroll_interactive_owner_from_receipt(&receipt)
        .map_err(display_string)?;
    complete_active_effect(
        &mut coordinator,
        BootstrapStage::OwnerEnrollmentResolution,
        "interactive-owner-resolution",
    )?;
    drop(coordinator);
    let reopened = DurableBootstrapCoordinator::open(
        interactive_store,
        "qe-interactive-session",
        "qe-machine-interactive",
    )
    .map_err(display_string)?;
    if reopened.state().provisioning().owner_enrollment() != OwnerEnrollmentState::Enrolled
        || reopened
            .state()
            .provisioning()
            .owner_authority()
            .map(|record| record.generation())
            != Some(1)
    {
        return Err("interactive owner enrollment did not survive restart".into());
    }
    println!("interactive_owner_restart=enrolled-generation-1");
    Ok(())
}

fn unattended_manifest(root: &Path) -> Result<(), String> {
    let bytes = manifest_bytes(
        "qe-manifest",
        "qe-unattended-session",
        "qe-machine-unattended",
        "unattended-local",
        true,
    );
    let manifest = ProvisioningManifest::parse(&bytes).map_err(display_string)?;
    manifest
        .validate_binding(
            "qe-unattended-session",
            "qe-machine-unattended",
            ProvisioningMode::UnattendedLocal,
        )
        .map_err(display_string)?;
    if !matches!(
        manifest.validate_binding(
            "qe-unattended-session",
            "other-machine",
            ProvisioningMode::UnattendedLocal,
        ),
        Err(DurableBootstrapError::ManifestBindingMismatch)
    ) {
        return Err("cross-machine manifest replay was not rejected".into());
    }
    let unattended_store = BootstrapStateStore::new(root.join("unattended.state"));
    let mut coordinator = DurableBootstrapCoordinator::open(
        unattended_store.clone(),
        "qe-unattended-session",
        "qe-machine-unattended",
    )
    .map_err(display_string)?;
    advance_to_provisioning_stage(&mut coordinator, "unattended")?;
    complete_provisioning_mode(
        &mut coordinator,
        "unattended",
        ProvisioningMode::UnattendedLocal,
        Some(&manifest),
    )?;
    advance_to_owner_resolution(&mut coordinator, "unattended")?;
    coordinator
        .enter_owner_enrollment_pending()
        .map_err(display_string)?;
    complete_active_effect(
        &mut coordinator,
        BootstrapStage::OwnerEnrollmentResolution,
        "unattended-owner-resolution",
    )?;
    drop(coordinator);
    let reopened = DurableBootstrapCoordinator::open(
        unattended_store,
        "qe-unattended-session",
        "qe-machine-unattended",
    )
    .map_err(display_string)?;
    if reopened.state().provisioning().owner_enrollment() != OwnerEnrollmentState::Pending
        || reopened.state().provisioning().manifest_identity() != Some(manifest.identity())
    {
        return Err("manifest/state binding did not survive stable pending restart".into());
    }
    println!("manifest_identity={}", manifest.identity());
    println!("manifest_replay=cross-machine-rejected");
    println!("manifest_command_field=rejected");
    println!("unattended_restart=owner-enrollment-pending");
    Ok(())
}

fn recovery_mode(root: &Path) -> Result<(), String> {
    let recovery_store = BootstrapStateStore::new(root.join("recovery.state"));
    let mut coordinator = DurableBootstrapCoordinator::open(
        recovery_store.clone(),
        "qe-recovery-session",
        "qe-machine-recovery",
    )
    .map_err(display_string)?;
    advance_to_provisioning_stage(&mut coordinator, "recovery")?;
    complete_provisioning_mode(
        &mut coordinator,
        "recovery",
        ProvisioningMode::Recovery,
        None,
    )?;
    advance_to_owner_resolution(&mut coordinator, "recovery")?;
    coordinator
        .enter_recovery_owner_resolution()
        .map_err(display_string)?;
    complete_active_effect(
        &mut coordinator,
        BootstrapStage::OwnerEnrollmentResolution,
        "recovery-owner-resolution",
    )?;
    drop(coordinator);
    let reopened = DurableBootstrapCoordinator::open(
        recovery_store,
        "qe-recovery-session",
        "qe-machine-recovery",
    )
    .map_err(display_string)?;
    if reopened.state().provisioning().owner_enrollment() != OwnerEnrollmentState::RecoveryResolved
        || reopened.state().provisioning().owner_authority().is_some()
    {
        return Err("recovery mode did not retain non-authorizing owner resolution".into());
    }
    println!("recovery_owner_resolution=non-authorizing");
    Ok(())
}

fn untrusted_parent(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root).map_err(io_string)?;
    let original = fs::metadata(root).map_err(io_string)?.permissions();
    let mut unsafe_permissions = original.clone();
    unsafe_permissions.set_mode(0o777);
    fs::set_permissions(root, unsafe_permissions).map_err(io_string)?;
    let result = DurableBootstrapCoordinator::open(
        BootstrapStateStore::new(root.join("bootstrap.state")),
        "qe-untrusted-parent",
        "qe-untrusted-machine",
    );
    fs::set_permissions(root, original).map_err(io_string)?;
    if !matches!(result, Err(DurableBootstrapError::UntrustedStatePath)) {
        return Err("untrusted writable state parent was not rejected".into());
    }
    println!("untrusted_parent=rejected");
    Ok(())
}

fn manifest_bytes(
    manifest_id: &str,
    session_id: &str,
    machine_id: &str,
    mode: &str,
    defer_owner: bool,
) -> Vec<u8> {
    let payload = format!(
        "linura-provisioning-manifest-v1\nmanifest_id={manifest_id}\nsession_id={session_id}\nmachine_id={machine_id}\nmode={mode}\nconnectivity=offline\ndefer_owner_enrollment={defer_owner}\nsource_ref=local:library\nsetup_ref=setup:v1\nmachine_profile_ref=profile:v1\nhost_identity=host:qe\n"
    );
    let digest = sha256_hex(payload.as_bytes());
    format!("{payload}integrity={digest}\n").into_bytes()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn io_string(error: std::io::Error) -> String {
    error.to_string()
}

fn display_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}
