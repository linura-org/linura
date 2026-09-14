#![forbid(unsafe_code)]

use linura_bootstrap::BootstrapStage;
use linura_bootstrap::durable::{
    BootstrapResumeDecision, BootstrapStateStore, DurableBootstrapCoordinator,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bootstrap transition qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| "missing transition qualification command".to_owned())?;
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing production bootstrap state root".to_owned())?,
    );
    if args.next().is_some() || !root.is_absolute() {
        return Err(
            "transition qualification requires exactly one absolute production state root".into(),
        );
    }

    match command.as_str() {
        "prepare" => prepare_only(&root),
        "effect-start" => effect_start_only(&root),
        other => Err(format!("unknown transition qualification command: {other}")),
    }
}

fn store(root: &Path) -> BootstrapStateStore {
    BootstrapStateStore::new(root.join("bootstrap.state"))
}

fn open_from_durable_identity(root: &Path) -> Result<DurableBootstrapCoordinator, String> {
    let store = store(root);
    let durable = store
        .load()
        .map_err(display_string)?
        .ok_or_else(|| "production bootstrap state is missing".to_owned())?;
    let session_id = durable.session_id().to_owned();
    let machine_id = durable.machine_id().to_owned();
    DurableBootstrapCoordinator::open(store, session_id, machine_id).map_err(display_string)
}

fn prepare_only(root: &Path) -> Result<(), String> {
    let mut coordinator = open_from_durable_identity(root)?;
    let stage = match coordinator.resume_decision() {
        BootstrapResumeDecision::ContinueAt(stage) => stage,
        decision => {
            return Err(format!(
                "prepare qualification requires ContinueAt, got {decision:?}"
            ));
        }
    };
    let operation_id = operation_id_for(stage);
    coordinator
        .prepare_stage(stage, operation_id)
        .map_err(display_string)?;
    println!("qualification_transition=prepared");
    println!("qualification_stage={stage:?}");
    println!("qualification_operation={operation_id}");
    Ok(())
}

fn effect_start_only(root: &Path) -> Result<(), String> {
    let mut coordinator = open_from_durable_identity(root)?;
    let (stage, operation_id) = match coordinator.resume_decision() {
        BootstrapResumeDecision::ExecutePrepared {
            stage,
            operation_id,
        } => (stage, operation_id.to_owned()),
        decision => {
            return Err(format!(
                "effect-start qualification requires ExecutePrepared, got {decision:?}"
            ));
        }
    };
    if !stage_has_external_effect(stage) {
        return Err(format!(
            "stage {stage:?} has no external-effect start boundary"
        ));
    }
    if operation_id != operation_id_for(stage) {
        return Err(format!(
            "prepared production operation is not canonical: {stage:?}/{operation_id}"
        ));
    }
    coordinator
        .mark_effect_started(&operation_id)
        .map_err(display_string)?;
    println!("qualification_transition=effect-started");
    println!("qualification_stage={stage:?}");
    println!("qualification_operation={operation_id}");
    Ok(())
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

fn display_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}
