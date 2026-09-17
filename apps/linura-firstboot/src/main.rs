#![forbid(unsafe_code)]

mod bootstrap_runtime;
mod sudo_policy;

use linura_bootstrap::durable::{
    BootstrapResumeDecision, BootstrapStateStore, DurableBootstrapCoordinator,
    OwnerEnrollmentAuthorityVerifier, OwnerEnrollmentState, PreparerRevocationAuthoritySigner,
    TrustedPreparerAuthorityRevocationReceipt,
};
use linura_bootstrap::{BootstrapStage, ProvisioningMode};
use linura_firstboot::{
    CANDIDATE_BASE_IMAGE_SHA256, CANDIDATE_BASE_IMAGE_URL, FIRST_BOOT_CONTRACT_VERSION,
};
use linura_hardware::{QualificationEnvironment, V09_QUALIFICATION_ENVIRONMENT_ID};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

const BOOTSTRAP_SESSION_FILE: &str = ".linura-bootstrap-session";
const MACHINE_ID_DOMAIN: &[u8] = b"linura-bootstrap-machine-v2\0";
const DMI_PRODUCT_UUID: &str = "/sys/class/dmi/id/product_uuid";
const MANAGED_FIRSTBOOT_PATH: &str = "/opt/linura/bin/linura-firstboot";
const CHECKPOINT_DIRECTORY: &str = "recovery-checkpoint";
const CHECKPOINT_MANIFEST: &str = "checkpoint.manifest";
const CONTROL_RECEIPT_AUTH_KEY: &str = "authority/control-receipt-auth.key";
const PREPARER_REVOCATION_RECEIPT: &str = "authority/preparer-revocation.receipt";
const PREPARER_USER: &str = "linura-preparer";
const PREPARER_SUDOERS: &str = "/etc/sudoers.d/99-linura-preparer";
const SSHD_POLICY_RUNTIME_DIRECTORY: &str = "/run/sshd";
const CONTROL_RECEIPT_AUTH_KEY_BYTES: usize = 32;
const O_NOFOLLOW: i32 = 0o400000;
const O_DIRECTORY: i32 = 0o200000;
const MAX_BOOTSTRAP_TRANSITIONS: usize = 64;

fn print_help() {
    println!("linura-firstboot — Linura v0.9 First Boot client");
    println!();
    println!("Usage:");
    println!("  linura-firstboot");
    println!("  linura-firstboot --qualification-environment");
    println!("  linura-firstboot --self-check");
    println!("  linura-firstboot --bootstrap <absolute-state-root>");
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
            println!("status={}", qualification_environment_status());
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
        Some("--bootstrap") => {
            let result =
                parse_bootstrap_root(&mut args).and_then(|root| durable_bootstrap_converge(&root));
            finish_durable_command(result)
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
            let failure_class = match error.as_str() {
                value if value.contains("Q8 security baseline rejected SSH exposure") => {
                    "security-baseline/ssh-exposure"
                }
                value if value.contains("Q8 security baseline could not observe SSH exposure") => {
                    "security-baseline/ssh-observation"
                }
                value
                    if value.contains(
                        "Q8 security baseline requires inbound default-deny firewall",
                    ) =>
                {
                    "security-baseline/firewall-policy"
                }
                value
                    if value.contains("Q8 security baseline could not observe firewall policy") =>
                {
                    "security-baseline/firewall-observation"
                }
                value
                    if value
                        .contains("Q8 security baseline rejected insecure APT source override") =>
                {
                    "security-baseline/apt-policy"
                }
                value
                    if value
                        .contains("Q8 security baseline could not observe APT source policy") =>
                {
                    "security-baseline/apt-observation"
                }
                _ => "protected",
            };
            eprintln!(
                "durable First Boot failed (class={failure_class}; protected diagnostic details withheld)"
            );
            ExitCode::FAILURE
        }
    }
}

fn qualification_environment_status() -> &'static str {
    if env!("CARGO_PKG_VERSION") == "0.9.0" {
        "release-qualified-experimental"
    } else {
        "candidate-not-yet-release-supported"
    }
}

fn parse_bootstrap_root(args: &mut impl Iterator<Item = String>) -> Result<PathBuf, String> {
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing absolute durable bootstrap state root".to_owned())?,
    );
    if args.next().is_some() || !root.is_absolute() {
        return Err("bootstrap requires exactly one absolute state root".into());
    }
    Ok(root)
}

fn durable_bootstrap_converge(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root).map_err(io_string)?;
    verify_protected_root(root)?;
    let expected_self_sha256 = current_executable_sha256()?;
    let create_session = !root.join(BOOTSTRAP_SESSION_FILE).exists();
    let (store, mut coordinator) = open_coordinator(root, create_session)?;

    for _ in 0..MAX_BOOTSTRAP_TRANSITIONS {
        if coordinator.resume_decision() == BootstrapResumeDecision::Complete {
            if coordinator.state().provisioning().mode()
                != Some(ProvisioningMode::PrepareForAnotherOwner)
                || coordinator.state().provisioning().owner_enrollment()
                    != OwnerEnrollmentState::Pending
                || !coordinator
                    .state()
                    .provisioning()
                    .preparer_authority_retired()
            {
                return Err("production v0.9 bootstrap completed outside the deferred-owner handoff boundary".into());
            }
            require_effective_root()?;
            observe_preparer_os_authority_absent()?;
            println!("bootstrap_mode=prepare-for-another-owner");
            println!("owner_enrollment=owner-enrollment-pending");
            println!("preparer_authority_inherited=false");
            return Ok(());
        }
        if !drive_one_stage(&store, root, &expected_self_sha256, &mut coordinator)? {
            break;
        }
    }
    Err("production v0.9 bootstrap did not converge within the bounded transition budget".into())
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
        return execute_non_effect_stage(root, coordinator, stage, operation_id);
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
            resolve_owner_stage(root, coordinator)?;
        }
        _ => return Err(format!("unexpected effectful stage: {stage:?}")),
    }
    reconcile_started_effect(store, root, expected_self_sha256, coordinator, stage)
}

fn execute_non_effect_stage(
    root: &Path,
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
        BootstrapStage::HardwareDiscovery => verify_candidate_environment()?,
        BootstrapStage::SourceSelection => {
            verify_candidate_environment()?;
            bootstrap_runtime::verify_manifest_source_selection(root, coordinator)?;
        }
        BootstrapStage::TargetObservation => {
            verify_candidate_environment()?;
            bootstrap_runtime::verify_manifest_target_binding(coordinator)?;
        }
        BootstrapStage::FirstBootPlanning => {
            verify_candidate_environment()?;
            bootstrap_runtime::derive_and_bind_first_boot_plan(root, coordinator)?;
        }
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
                resolve_owner_stage(root, coordinator)?;
            }
            coordinator
                .verify_owner_resolution()
                .map_err(display_string)
        }
        _ => Err(format!("unexpected started effect stage: {stage:?}")),
    }
}

fn resolve_owner_stage(
    root: &Path,
    coordinator: &mut DurableBootstrapCoordinator,
) -> Result<(), String> {
    match coordinator.state().provisioning().mode() {
        Some(ProvisioningMode::PrepareForAnotherOwner | ProvisioningMode::UnattendedLocal) => {
            let revocation = trusted_or_produced_preparer_revocation(root, coordinator)?;
            coordinator
                .enter_owner_enrollment_pending(&revocation)
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

fn trusted_or_produced_preparer_revocation(
    root: &Path,
    coordinator: &DurableBootstrapCoordinator,
) -> Result<TrustedPreparerAuthorityRevocationReceipt, String> {
    require_effective_root()?;
    let receipt_path = root.join(PREPARER_REVOCATION_RECEIPT);

    // No key or receipt that existed while the preparer still had sudo is
    // authoritative. Revoke and independently re-observe the fixed OS identity
    // first, then rotate the authentication key and issue fresh evidence.
    let postcondition_sha256 = revoke_and_verify_preparer_os_authority()?;
    remove_path_if_present(&receipt_path)?;
    let key_path = rotate_control_receipt_auth_key(root)?;
    let signer = PreparerRevocationAuthoritySigner::open(&key_path).map_err(display_string)?;
    let receipt = signer
        .preparer_revocation_receipt_bytes(coordinator.state(), &postcondition_sha256)
        .map_err(display_string)?;
    durable_write(&receipt_path, &receipt, 0o600)?;

    let verifier = OwnerEnrollmentAuthorityVerifier::open(&key_path).map_err(display_string)?;
    TrustedPreparerAuthorityRevocationReceipt::load(&receipt_path, coordinator.state(), &verifier)
        .map_err(display_string)
}

fn require_effective_root() -> Result<(), String> {
    let status = fs::read_to_string("/proc/self/status").map_err(io_string)?;
    let uid_line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(|| "cannot observe process effective uid".to_owned())?;
    let mut values = uid_line.split_whitespace();
    let _real = values.next();
    let effective = values
        .next()
        .ok_or_else(|| "cannot parse process effective uid".to_owned())?;
    if effective != "0" {
        return Err("production bootstrap owner handoff requires effective uid 0".into());
    }
    Ok(())
}

fn revoke_and_verify_preparer_os_authority() -> Result<String, String> {
    let identity = preparer_os_identity()?.ok_or_else(|| {
        "expected linura-preparer identity is absent before authority retirement".to_owned()
    })?;
    terminate_preparer_processes(&identity.uid)?;
    run_fixed("/usr/sbin/usermod", &["-G", "", PREPARER_USER])?;
    run_fixed("/usr/bin/passwd", &["-l", PREPARER_USER])?;
    remove_preparer_ssh_authority(&identity)?;
    remove_path_if_present(Path::new(PREPARER_SUDOERS))?;
    run_fixed("/usr/bin/sync", &[])?;
    observe_preparer_os_authority_absent()
}

fn observe_preparer_os_authority_absent() -> Result<String, String> {
    let identity = preparer_os_identity()?.ok_or_else(|| {
        "expected linura-preparer identity is absent during authority observation".to_owned()
    })?;
    if preparer_has_processes(&identity.uid)? {
        return Err("preparer process authority survived revocation".into());
    }
    if preparer_has_supplementary_group()? {
        return Err("preparer supplementary group authority survived revocation".into());
    }
    if !preparer_password_is_locked()? {
        return Err("preparer password authority survived revocation".into());
    }
    if preparer_has_ssh_authority(&identity)? {
        return Err("preparer SSH authority survived revocation".into());
    }
    run_fixed("/usr/sbin/visudo", &["-cf", "/etc/sudoers"])?;
    if sudoers_mentions_preparer(Path::new("/etc/sudoers"), Some(&identity))?
        || sudoers_directory_mentions_preparer(Path::new("/etc/sudoers.d"), Some(&identity))?
        || preparer_has_effective_sudo_authority()?
    {
        return Err("preparer sudo authority survived revocation".into());
    }

    let postcondition = format!(
        "linura-preparer-revocation-postcondition-v4\naccount_present=true\nuid={}\nprimary_gid={}\nprimary_group={}\nprocesses=absent\nsupplementary_groups=absent\npassword=locked\nssh_authority=absent\nsudo_authority=absent\nsudoers=valid\n",
        identity.uid, identity.gid, identity.primary_group,
    );
    Ok(sha256_hex(postcondition.as_bytes()))
}

fn preparer_has_effective_sudo_authority() -> Result<bool, String> {
    let output = Command::new("/usr/bin/sudo")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(["-n", "-l", "-U", PREPARER_USER])
        .output()
        .map_err(io_string)?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "sudo policy query returned non-UTF-8 stdout".to_owned())?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| "sudo policy query returned non-UTF-8 stderr".to_owned())?;
    let observed = format!("{stdout}\n{stderr}");
    sudo_policy::listing_grants_authority(&observed, PREPARER_USER)
        .map_err(|_| "cannot authoritatively evaluate preparer effective sudo policy".to_owned())
}

fn run_fixed(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(io_string)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("bounded bootstrap operation failed: {program}"))
    }
}

fn terminate_preparer_processes(uid: &str) -> Result<(), String> {
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("preparer numeric uid is not canonical".into());
    }
    for selector in ["-u", "-U"] {
        let status = Command::new("/usr/bin/pkill")
            .args(["-KILL", selector, uid])
            .status()
            .map_err(io_string)?;
        if !matches!(status.code(), Some(0 | 1)) {
            return Err(format!(
                "failed to terminate preparer processes for identity selector {selector}"
            ));
        }
    }
    Ok(())
}

fn preparer_has_processes(uid: &str) -> Result<bool, String> {
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("preparer numeric uid is not canonical".into());
    }
    for selector in ["-u", "-U"] {
        let status = Command::new("/usr/bin/pgrep")
            .args([selector, uid])
            .status()
            .map_err(io_string)?;
        match status.code() {
            Some(0) => return Ok(true),
            Some(1) => {}
            _ => {
                return Err(format!(
                    "cannot verify preparer process revocation for identity selector {selector}"
                ));
            }
        }
    }
    Ok(false)
}

fn preparer_has_supplementary_group() -> Result<bool, String> {
    let groups = fs::read_to_string("/etc/group").map_err(io_string)?;
    Ok(groups.lines().any(|line| {
        let mut fields = line.split(':');
        let _name = fields.next();
        let _password = fields.next();
        let _gid = fields.next();
        fields
            .next()
            .is_some_and(|members| members.split(',').any(|member| member == PREPARER_USER))
    }))
}

fn preparer_password_is_locked() -> Result<bool, String> {
    let shadow = fs::read_to_string("/etc/shadow").map_err(io_string)?;
    let password = shadow
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == PREPARER_USER)
                .then(|| fields.next())
                .flatten()
        })
        .ok_or_else(|| "preparer shadow record is missing".to_owned())?;
    Ok(password.starts_with('!') || password.starts_with('*'))
}

fn remove_path_if_present(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_string(error)),
    };
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).map_err(io_string)
    } else {
        fs::remove_file(path).map_err(io_string)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparerOsIdentity {
    uid: String,
    gid: String,
    primary_group: String,
    home: PathBuf,
}

fn preparer_os_identity() -> Result<Option<PreparerOsIdentity>, String> {
    let passwd = fs::read_to_string("/etc/passwd").map_err(io_string)?;
    let Some((uid, gid, home)) = passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let uid = fields.next()?;
        let gid = fields.next()?;
        let _gecos = fields.next()?;
        let home = fields.next()?;
        (name == PREPARER_USER).then(|| (uid.to_owned(), gid.to_owned(), PathBuf::from(home)))
    }) else {
        return Ok(None);
    };
    if uid.is_empty()
        || gid.is_empty()
        || !uid.bytes().all(|byte| byte.is_ascii_digit())
        || !gid.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("preparer account has a non-canonical numeric uid/gid".into());
    }
    validate_preparer_home(&home, &uid)?;
    let groups = fs::read_to_string("/etc/group").map_err(io_string)?;
    let primary_group = groups
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let candidate_gid = fields.next()?;
            (candidate_gid == gid).then(|| name.to_owned())
        })
        .ok_or_else(|| "preparer primary group cannot be resolved".to_owned())?;
    Ok(Some(PreparerOsIdentity {
        uid,
        gid,
        primary_group,
        home,
    }))
}

fn validate_preparer_home(home: &Path, uid: &str) -> Result<(), String> {
    if !home.is_absolute()
        || home == Path::new("/")
        || home
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("preparer home is not a bounded absolute directory".into());
    }
    let expected_uid = uid
        .parse::<u32>()
        .map_err(|_| "preparer numeric uid is not canonical".to_owned())?;
    let metadata = fs::symlink_metadata(home).map_err(io_string)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
    {
        return Err("preparer home is not a dedicated preparer-owned directory".into());
    }
    Ok(())
}

fn preparer_effective_ssh_credential_roots(
    identity: &PreparerOsIdentity,
) -> Result<Vec<PathBuf>, String> {
    // `sshd -T` on Ubuntu requires its privilege-separation runtime directory
    // even when no SSH daemon is running. Q8 deliberately disables SSH, so
    // establish only the protected query prerequisite; this does not start or
    // enable an SSH service.
    let _policy_runtime =
        open_or_create_protected_directory(Path::new(SSHD_POLICY_RUNTIME_DIRECTORY), 0o755)
            .map_err(|error| {
                format!("cannot establish protected OpenSSH policy-query runtime: {error}")
            })?;

    let output = Command::new("/usr/sbin/sshd")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args([
            "-T",
            "-C",
            "user=linura-preparer,host=localhost,addr=127.0.0.1",
        ])
        .output()
        .map_err(io_string)?;
    if !output.status.success() {
        return Err("cannot evaluate effective sshd policy for preparer".into());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "effective sshd policy returned non-UTF-8 output".to_owned())?;
    ssh_credential_roots_from_effective_config(&stdout, identity)
}

fn ssh_credential_roots_from_effective_config(
    config: &str,
    identity: &PreparerOsIdentity,
) -> Result<Vec<PathBuf>, String> {
    let authorized_keys_files = config
        .lines()
        .find_map(|line| line.strip_prefix("authorizedkeysfile "))
        .ok_or_else(|| "effective sshd policy omitted AuthorizedKeysFile".to_owned())?;
    let authorized_keys_command = config
        .lines()
        .find_map(|line| line.strip_prefix("authorizedkeyscommand "))
        .ok_or_else(|| "effective sshd policy omitted AuthorizedKeysCommand".to_owned())?;
    if authorized_keys_command.trim() != "none" {
        return Err(
            "effective sshd AuthorizedKeysCommand is outside the bounded v0.9 retirement policy"
                .into(),
        );
    }
    if authorized_keys_files.trim() == "none" {
        return Ok(Vec::new());
    }

    let mut roots = Vec::new();
    for template in authorized_keys_files.split_whitespace() {
        if template == "none" {
            return Err("effective sshd AuthorizedKeysFile policy mixes none with paths".into());
        }
        let resolved = expand_authorized_keys_file(template, identity)?;
        let relative = resolved.strip_prefix(&identity.home).map_err(|_| {
            "effective sshd AuthorizedKeysFile escapes the dedicated preparer home".to_owned()
        })?;
        let mut components = relative.components();
        let first = match components.next() {
            Some(Component::Normal(component)) => component,
            _ => {
                return Err(
                    "effective sshd AuthorizedKeysFile is not a bounded home-relative path".into(),
                );
            }
        };
        if components.any(|component| !matches!(component, Component::Normal(_))) {
            return Err("effective sshd AuthorizedKeysFile contains unsafe path components".into());
        }
        roots.push(identity.home.join(first));
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

fn expand_authorized_keys_file(
    template: &str,
    identity: &PreparerOsIdentity,
) -> Result<PathBuf, String> {
    let home = identity
        .home
        .to_str()
        .ok_or_else(|| "preparer home is not valid UTF-8".to_owned())?;
    let mut expanded = String::new();
    let mut chars = template.chars();
    while let Some(character) = chars.next() {
        if character != '%' {
            expanded.push(character);
            continue;
        }
        let token = chars
            .next()
            .ok_or_else(|| "unterminated AuthorizedKeysFile token".to_owned())?;
        match token {
            '%' => expanded.push('%'),
            'h' => expanded.push_str(home),
            'u' => expanded.push_str(PREPARER_USER),
            'U' => expanded.push_str(&identity.uid),
            _ => {
                return Err(format!(
                    "unsupported AuthorizedKeysFile token %{token} for bounded retirement"
                ));
            }
        }
    }
    let path = PathBuf::from(expanded);
    Ok(if path.is_absolute() {
        path
    } else {
        identity.home.join(path)
    })
}

fn remove_preparer_ssh_authority(identity: &PreparerOsIdentity) -> Result<(), String> {
    for path in preparer_effective_ssh_credential_roots(identity)? {
        remove_path_if_present(&path)?;
    }
    Ok(())
}

fn preparer_has_ssh_authority(identity: &PreparerOsIdentity) -> Result<bool, String> {
    for path in preparer_effective_ssh_credential_roots(identity)? {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_string(error)),
        }
    }
    Ok(false)
}

fn sudoers_code_prefix(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'#'
            && bytes
                .get(index + 1)
                .is_none_or(|next| !next.is_ascii_digit())
        {
            return &line[..index];
        }
    }
    line
}

fn sudoers_text_mentions_preparer(text: &str, identity: Option<&PreparerOsIdentity>) -> bool {
    let named_group = identity.map(|value| format!("%{}", value.primary_group));
    let numeric_user = identity.map(|value| format!("#{}", value.uid));
    let numeric_group = identity.map(|value| format!("%#{}", value.gid));
    text.lines().any(|line| {
        sudoers_code_prefix(line)
            .split(|character: char| {
                character.is_whitespace() || matches!(character, ',' | '=' | ':' | '(' | ')')
            })
            .any(|token| {
                token == PREPARER_USER
                    || token == "%linura-preparer"
                    || named_group.as_deref() == Some(token)
                    || numeric_user.as_deref() == Some(token)
                    || numeric_group.as_deref() == Some(token)
            })
    })
}

fn sudoers_mentions_preparer(
    path: &Path,
    identity: Option<&PreparerOsIdentity>,
) -> Result<bool, String> {
    let text = fs::read_to_string(path).map_err(io_string)?;
    Ok(sudoers_text_mentions_preparer(&text, identity))
}

fn sudoers_directory_mentions_preparer(
    path: &Path,
    identity: Option<&PreparerOsIdentity>,
) -> Result<bool, String> {
    for entry in fs::read_dir(path).map_err(io_string)? {
        let entry = entry.map_err(io_string)?;
        let metadata = entry.metadata().map_err(io_string)?;
        if metadata.is_file() && sudoers_mentions_preparer(&entry.path(), identity)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_or_create_protected_directory(path: &Path, mode: u32) -> Result<fs::File, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "protected directory has no parent".to_owned())?;
    verify_protected_root(parent)?;

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(
                    "existing authority directory is not a protected root-owned directory".into(),
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode).create(path).map_err(io_string)?;
        }
        Err(error) => return Err(io_string(error)),
    }

    let observed = fs::symlink_metadata(path).map_err(io_string)?;
    if observed.file_type().is_symlink()
        || !observed.file_type().is_dir()
        || observed.uid() != 0
        || observed.permissions().mode() & 0o022 != 0
    {
        return Err("authority directory failed pre-open protection checks".into());
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(path)
        .map_err(io_string)?;
    let opened = directory.metadata().map_err(io_string)?;
    if !opened.file_type().is_dir()
        || opened.uid() != 0
        || opened.permissions().mode() & 0o022 != 0
        || opened.dev() != observed.dev()
        || opened.ino() != observed.ino()
    {
        return Err("authority directory changed or is untrusted while open".into());
    }

    directory
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(io_string)?;
    let hardened = directory.metadata().map_err(io_string)?;
    if hardened.uid() != 0
        || !hardened.file_type().is_dir()
        || hardened.permissions().mode() & 0o777 != mode
    {
        return Err("authority directory could not be hardened on the opened inode".into());
    }
    directory.sync_all().map_err(io_string)?;
    fs::File::open(parent)
        .and_then(|parent| parent.sync_all())
        .map_err(io_string)?;
    Ok(directory)
}

fn rotate_control_receipt_auth_key(root: &Path) -> Result<PathBuf, String> {
    let directory = root.join("authority");
    let directory_handle = open_or_create_protected_directory(&directory, 0o700)?;
    let path = root.join(CONTROL_RECEIPT_AUTH_KEY);

    // The preparer previously held sudo, so an existing root-owned/mode-0600
    // file has no trusted provenance. Remove it only after OS authority has been
    // retired, then require exclusive creation of fresh kernel-random material.
    remove_path_if_present(&path)?;
    directory_handle.sync_all().map_err(io_string)?;

    let mut random = fs::File::open("/dev/urandom").map_err(io_string)?;
    let mut key = [0_u8; CONTROL_RECEIPT_AUTH_KEY_BYTES];
    random.read_exact(&mut key).map_err(io_string)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err("kernel random source returned an invalid all-zero receipt key".into());
    }
    let create_result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&path);
    let mut file = match create_result {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            key.fill(0);
            return Err("receipt key unexpectedly appeared during post-revocation rotation".into());
        }
        Err(error) => {
            key.fill(0);
            return Err(io_string(error));
        }
    };
    if let Err(error) = file.write_all(&key).and_then(|_| file.sync_all()) {
        key.fill(0);
        return Err(io_string(error));
    }
    key.fill(0);
    directory_handle.sync_all().map_err(io_string)?;
    validate_control_receipt_auth_key(&path)?;
    Ok(path)
}

fn validate_control_receipt_auth_key(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(io_string)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != CONTROL_RECEIPT_AUTH_KEY_BYTES as u64
    {
        return Err("preparer revocation key is not a protected root-owned 256-bit file".into());
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(io_string)?;
    let mut key = [0_u8; CONTROL_RECEIPT_AUTH_KEY_BYTES];
    file.read_exact(&mut key).map_err(io_string)?;
    let mut trailing = [0_u8; 1];
    let invalid =
        file.read(&mut trailing).map_err(io_string)? != 0 || key.iter().all(|byte| *byte == 0);
    key.fill(0);
    if invalid {
        return Err("preparer revocation key failed exact protected-key validation".into());
    }
    Ok(())
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
    if max_bytes == 0 {
        return Err(format!("{label} read bound must be nonzero"));
    }
    let before = fs::symlink_metadata(path).map_err(io_string)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
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
    if !opened.file_type().is_file()
        || opened.uid() != 0
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o022 != 0
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Err(format!("{label} changed or is not trusted while open"));
    }

    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{label} read bound overflow"))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(io_string)?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{label} exceeds the supported byte bound"));
    }
    let raw = String::from_utf8(bytes).map_err(|_| format!("{label} is not valid UTF-8"))?;

    let after = fs::symlink_metadata(path).map_err(io_string)?;
    if after.file_type().is_symlink()
        || !after.file_type().is_file()
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.uid() != 0
        || after.nlink() != 1
        || after.permissions().mode() & 0o022 != 0
    {
        return Err(format!("{label} changed during observation"));
    }
    Ok(raw)
}

fn verify_candidate_environment() -> Result<(), String> {
    bootstrap_runtime::verify_candidate_environment()
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

#[cfg(test)]
mod authority_retirement_tests {
    use super::*;

    fn identity() -> PreparerOsIdentity {
        PreparerOsIdentity {
            uid: "1234".into(),
            gid: "4321".into(),
            primary_group: "machine-preparers".into(),
            home: PathBuf::from("/home/linura-preparer"),
        }
    }

    #[test]
    fn ssh_policy_collapses_default_keys_to_account_scoped_root() {
        let roots = ssh_credential_roots_from_effective_config(
            "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
authorizedkeyscommand none
",
            &identity(),
        );
        assert_eq!(roots, Ok(vec![PathBuf::from("/home/linura-preparer/.ssh")]));
    }

    #[test]
    fn ssh_policy_fails_closed_on_external_or_command_key_sources() {
        let identity = identity();
        assert!(
            ssh_credential_roots_from_effective_config(
                "authorizedkeysfile /etc/ssh/authorized_keys/%u
authorizedkeyscommand none
",
                &identity,
            )
            .is_err()
        );
        assert!(
            ssh_credential_roots_from_effective_config(
                "authorizedkeysfile .ssh/authorized_keys
authorizedkeyscommand /usr/local/bin/key-source
",
                &identity,
            )
            .is_err()
        );
    }

    #[test]
    fn sudoers_parser_rejects_named_and_numeric_preparer_grants() {
        let identity = identity();
        assert!(sudoers_text_mentions_preparer(
            "linura-preparer ALL=(ALL) ALL\n",
            Some(&identity),
        ));
        assert!(sudoers_text_mentions_preparer(
            "%linura-preparer ALL=(ALL) ALL\n",
            Some(&identity),
        ));
        assert!(sudoers_text_mentions_preparer(
            "%machine-preparers ALL=(ALL) NOPASSWD:ALL\n",
            Some(&identity),
        ));
        assert!(sudoers_text_mentions_preparer(
            "#1234 ALL=(ALL) NOPASSWD:ALL\n",
            Some(&identity),
        ));
        assert!(sudoers_text_mentions_preparer(
            "%#4321 ALL=(ALL) NOPASSWD:ALL\n",
            Some(&identity),
        ));
        assert!(!sudoers_text_mentions_preparer(
            "%sudo ALL=(ALL) ALL # ordinary comment\n",
            Some(&identity),
        ));
        assert!(!sudoers_text_mentions_preparer(
            "# ordinary comment about linura-preparer\n",
            Some(&identity),
        ));
    }
}
