#![forbid(unsafe_code)]

use linura_bootstrap::durable::DurableBootstrapCoordinator;
use linura_core::{ActorKind, ProfileId, RequestId, SetupId};
use linura_firstboot::FirstBootObservationSource;
use linura_hardware::{
    InteractionMode, MachineClass, ObservedEnvironment, QualificationEnvironment,
    VirtualizationKind,
};
use linura_library::{LocalLibrary, StoredIntent};
use linura_observation::ObservationAuthority;
use linura_planner::{
    DeterministicPlanner, PlanningFreshness, PlanningObservation, ReconciliationPlan,
};
use linura_protocol::ObservationRequest;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PROVISIONING_LIBRARY_FILE: &str = "provisioning-library.db";
const LOCAL_LIBRARY_SOURCE_REF: &str = "local:library";

pub(crate) fn verify_candidate_environment() -> Result<(), String> {
    let contract = QualificationEnvironment::v09_candidate();
    contract
        .validate_contract()
        .map_err(|error| format!("qualification environment contract failed: {error:?}"))?;

    let observed = observe_candidate_environment()?;
    let mismatches = contract.assess(&observed);
    if !mismatches.is_empty() {
        return Err(format!(
            "running system does not match the bounded v0.9 QualificationEnvironment: {mismatches:?}"
        ));
    }
    Ok(())
}

pub(crate) fn verify_manifest_source_selection(
    root: &Path,
    coordinator: &DurableBootstrapCoordinator,
) -> Result<(), String> {
    let provisioning = coordinator.state().provisioning();
    let source_ref = provisioning.manifest_source_ref();
    let setup_ref = provisioning.manifest_setup_ref();
    let profile_ref = provisioning.manifest_machine_profile_ref();

    if source_ref.is_none() && setup_ref.is_none() && profile_ref.is_none() {
        return Ok(());
    }
    if source_ref != Some(LOCAL_LIBRARY_SOURCE_REF) {
        return Err(
            "Provisioning Manifest object references require source_ref=local:library in v0.9"
                .into(),
        );
    }
    if setup_ref.is_none() && profile_ref.is_none() {
        return Err(
            "local:library Provisioning Manifest source requires an exact setup_ref or machine_profile_ref"
                .into(),
        );
    }

    let path = root.join(PROVISIONING_LIBRARY_FILE);
    verify_protected_library_file(&path)?;
    let library = LocalLibrary::open(&path)
        .map_err(|error| format!("failed to open protected provisioning Library: {error}"))?;

    if let Some(reference) = setup_ref {
        let (id, revision) = parse_revision_reference(reference, "setup:")?;
        let id = SetupId::new(id.to_owned())
            .map_err(|error| format!("invalid setup_ref object id: {error}"))?;
        library.setup_revision(&id, revision).map_err(|error| {
            format!("Provisioning Manifest setup_ref does not resolve exactly: {error}")
        })?;
    }

    if let Some(reference) = profile_ref {
        let (id, revision) = parse_revision_reference(reference, "profile:")?;
        let id = ProfileId::new(id.to_owned())
            .map_err(|error| format!("invalid machine_profile_ref object id: {error}"))?;
        library.profile_revision(&id, revision).map_err(|error| {
            format!("Provisioning Manifest machine_profile_ref does not resolve exactly: {error}")
        })?;
    }

    Ok(())
}

pub(crate) fn derive_and_bind_first_boot_plan(
    root: &Path,
    coordinator: &mut DurableBootstrapCoordinator,
) -> Result<(), String> {
    if coordinator
        .state()
        .provisioning()
        .first_boot_plan_sha256()
        .is_some()
    {
        return Ok(());
    }
    verify_manifest_source_selection(root, coordinator)?;
    verify_manifest_target_binding(coordinator)?;

    let (manifest_identity, manifest_source_ref, setup_ref, profile_ref, manifest_host_identity) = {
        let provisioning = coordinator.state().provisioning();
        (
            provisioning.manifest_identity().map(str::to_owned),
            provisioning.manifest_source_ref().map(str::to_owned),
            provisioning.manifest_setup_ref().map(str::to_owned),
            provisioning
                .manifest_machine_profile_ref()
                .map(str::to_owned),
            provisioning.manifest_host_identity().map(str::to_owned),
        )
    };
    let mut plan_hasher = Sha256::new();
    hash_plan_field(&mut plan_hasher, "linura-firstboot-durable-plan-bundle-v1");
    hash_plan_field(&mut plan_hasher, coordinator.state().session_id());
    hash_plan_field(&mut plan_hasher, coordinator.state().machine_id());
    hash_plan_field(
        &mut plan_hasher,
        manifest_identity.as_deref().unwrap_or("-"),
    );
    hash_plan_field(
        &mut plan_hasher,
        manifest_source_ref.as_deref().unwrap_or("-"),
    );
    hash_plan_field(&mut plan_hasher, setup_ref.as_deref().unwrap_or("-"));
    hash_plan_field(&mut plan_hasher, profile_ref.as_deref().unwrap_or("-"));
    hash_plan_field(
        &mut plan_hasher,
        manifest_host_identity.as_deref().unwrap_or("-"),
    );

    if setup_ref.is_none() && profile_ref.is_none() {
        hash_plan_field(&mut plan_hasher, "no-declarative-resource-selected");
        return coordinator
            .bind_first_boot_plan(format!("{:x}", plan_hasher.finalize()), 0)
            .map_err(|error| error.to_string());
    }

    let path = root.join(PROVISIONING_LIBRARY_FILE);
    verify_protected_library_file(&path)?;
    let library = LocalLibrary::open(&path)
        .map_err(|error| format!("failed to open protected provisioning Library: {error}"))?;
    let mut intents = BTreeMap::<String, StoredIntent>::new();
    if let Some(reference) = setup_ref.as_deref() {
        let (id, revision) = parse_revision_reference(reference, "setup:")?;
        let id = SetupId::new(id.to_owned())
            .map_err(|error| format!("invalid setup_ref object id: {error}"))?;
        let bundle = library
            .export_setup(&id, Some(revision))
            .map_err(|error| format!("failed to resolve exact Setup planning closure: {error}"))?;
        collect_exact_planning_intents(&mut intents, bundle.intents)?;
    }
    if let Some(reference) = profile_ref.as_deref() {
        let (id, revision) = parse_revision_reference(reference, "profile:")?;
        let id = ProfileId::new(id.to_owned())
            .map_err(|error| format!("invalid machine_profile_ref object id: {error}"))?;
        let bundle = library
            .export_profile(&id, Some(revision))
            .map_err(|error| {
                format!("failed to resolve exact MachineProfile planning closure: {error}")
            })?;
        collect_exact_planning_intents(&mut intents, bundle.intents)?;
    }
    if intents.is_empty() {
        return Err("selected Library source contains no exact intent revisions to plan".into());
    }

    let plan_request_context = DurablePlanRequestContext {
        session_id: coordinator.state().session_id().to_owned(),
        machine_id: coordinator.state().machine_id().to_owned(),
        manifest_identity: manifest_identity.clone(),
        setup_ref: setup_ref.clone(),
        profile_ref: profile_ref.clone(),
    };
    let mut observer =
        FirstBootObservationSource::connect_reference_environment().map_err(|error| {
            format!("failed to connect authoritative First Boot observation source: {error}")
        })?;
    let mut plans = Vec::new();
    for stored in intents.into_values() {
        let desired_state = library
            .desired_state_for_intent_revision(&stored.intent.id, stored.revision)
            .map_err(|error| {
                format!("failed to load exact desired state for First Boot planning: {error}")
            })?;
        for desired in desired_state.resources {
            let request = ObservationRequest {
                provider: desired.provider.clone(),
                resource: desired.resource.clone(),
                capability: desired.observation_capability.clone(),
            };
            let observation = observer
                .observe(&request)
                .map_err(|error| format!("authoritative First Boot observation failed: {error}"))?;
            observation
                .validate(&request.provider, &request.resource, &request.capability)
                .map_err(|error| {
                    format!("First Boot observation identity validation failed: {error}")
                })?;
            observation
                .require_current(current_unix_ms()?)
                .map_err(|error| {
                    format!("First Boot planning observation is not current: {error}")
                })?;
            if observation.authority == ObservationAuthority::SyntheticTest {
                return Err(
                    "synthetic observation cannot satisfy durable First Boot planning".into(),
                );
            }
            let evidence_id = observation.evidence_id();
            let request_id = canonical_durable_plan_request_id(
                &plan_request_context,
                stored.intent.id.as_str(),
                stored.revision,
                &desired,
                &evidence_id,
            )?;
            let planning_observation = PlanningObservation {
                provider: observation.provider.clone(),
                resource: observation.resource.clone(),
                observation_capability: observation.capability.clone(),
                authority: observation.authority.as_str().to_owned(),
                evidence_id,
                freshness: PlanningFreshness::Current,
                attributes: observation
                    .attributes
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_string()))
                    .collect(),
            };
            let plan = DeterministicPlanner
                .plan_resource(
                    request_id,
                    stored.intent.actor.clone(),
                    desired,
                    &planning_observation,
                )
                .map_err(|error| format!("canonical First Boot planning failed: {error}"))?;
            if plan.execution_authorized() || plan.has_blockers() {
                return Err(
                    "canonical First Boot plan is blocked or unexpectedly authorizing".into(),
                );
            }
            plans.push(plan);
        }
    }
    plans.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    if plans.is_empty() {
        return Err("selected Library source produced no canonical First Boot plans".into());
    }
    for plan in &plans {
        hash_reconciliation_plan(&mut plan_hasher, plan);
    }
    let plan_count =
        u32::try_from(plans.len()).map_err(|_| "First Boot plan count exceeds u32".to_owned())?;
    coordinator
        .bind_first_boot_plan(format!("{:x}", plan_hasher.finalize()), plan_count)
        .map_err(|error| error.to_string())
}

fn collect_exact_planning_intents(
    intents: &mut BTreeMap<String, StoredIntent>,
    candidates: Vec<StoredIntent>,
) -> Result<(), String> {
    for stored in candidates {
        let id = stored.intent.id.as_str().to_owned();
        if let Some(existing) = intents.get(&id) {
            if existing.revision != stored.revision {
                return Err(format!(
                    "selected Library closure contains conflicting exact revisions for intent {id}: {} and {}",
                    existing.revision, stored.revision
                ));
            }
            continue;
        }
        intents.insert(id, stored);
    }
    Ok(())
}

struct DurablePlanRequestContext {
    session_id: String,
    machine_id: String,
    manifest_identity: Option<String>,
    setup_ref: Option<String>,
    profile_ref: Option<String>,
}

fn canonical_durable_plan_request_id(
    context: &DurablePlanRequestContext,
    intent_id: &str,
    intent_revision: u64,
    desired: &linura_planner::DesiredResource,
    evidence_id: &str,
) -> Result<RequestId, String> {
    let intent_revision = intent_revision.to_string();
    let mut hasher = Sha256::new();
    for field in [
        "linura-v09-firstboot-plan-request-v1",
        context.session_id.as_str(),
        context.machine_id.as_str(),
        context.manifest_identity.as_deref().unwrap_or("-"),
        context.setup_ref.as_deref().unwrap_or("-"),
        context.profile_ref.as_deref().unwrap_or("-"),
        intent_id,
        intent_revision.as_str(),
        desired.provider.as_str(),
        desired.resource.as_str(),
        desired.observation_capability.as_str(),
        evidence_id,
    ] {
        hash_plan_field(&mut hasher, field);
    }
    RequestId::new(format!("request:v09:firstboot:{:x}", hasher.finalize()))
        .map_err(|error| format!("invalid canonical First Boot request id: {error}"))
}

fn hash_reconciliation_plan(hasher: &mut Sha256, plan: &ReconciliationPlan) {
    for field in [
        plan.id.as_str(),
        plan.request_id.as_str(),
        plan.actor.id.as_str(),
        actor_kind_str(plan.actor.kind),
        plan.provider.as_str(),
        plan.resource.as_str(),
        plan.observation_capability.as_str(),
        plan.observed_evidence_id.as_str(),
        plan.status.as_str(),
    ] {
        hash_plan_field(hasher, field);
    }
    for change in &plan.changes {
        hash_plan_field(hasher, &change.key);
        hash_plan_field(hasher, change.current.as_deref().unwrap_or("-"));
        hash_plan_field(hasher, &change.desired);
    }
    for finding in &plan.findings {
        hash_plan_field(hasher, &finding.code);
        hash_plan_field(hasher, finding.level.as_str());
        hash_plan_field(hasher, &finding.message);
    }
}

fn actor_kind_str(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

fn hash_plan_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn current_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "current time exceeds u64 milliseconds".into())
}

pub(crate) fn verify_manifest_target_binding(
    coordinator: &DurableBootstrapCoordinator,
) -> Result<(), String> {
    let Some(host_identity) = coordinator.state().provisioning().manifest_host_identity() else {
        return Ok(());
    };
    let expected = format!("host:{}", coordinator.state().machine_id());
    if host_identity != expected {
        return Err(
            "Provisioning Manifest host_identity is not bound to the observed durable machine identity"
                .into(),
        );
    }
    Ok(())
}

fn observe_candidate_environment() -> Result<ObservedEnvironment, String> {
    let os_release = fs::read_to_string("/etc/os-release").map_err(io_string)?;
    let distribution_id = os_release_value(&os_release, "ID")
        .ok_or_else(|| "/etc/os-release does not contain ID".to_owned())?;
    let distribution_version = os_release_value(&os_release, "VERSION_ID")
        .ok_or_else(|| "/etc/os-release does not contain VERSION_ID".to_owned())?;

    let init_system = fs::read_to_string("/proc/1/comm")
        .map_err(io_string)?
        .trim()
        .to_owned();
    if init_system.is_empty() {
        return Err("PID 1 process identity is empty".into());
    }

    let virtualization = observe_virtualization()?;
    let interaction = observe_interaction(&init_system)?;
    let machine_class = match interaction {
        InteractionMode::Headless => MachineClass::Server,
        InteractionMode::Interactive => MachineClass::Workstation,
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

fn observe_virtualization() -> Result<VirtualizationKind, String> {
    let output = Command::new("systemd-detect-virt")
        .arg("--vm")
        .output()
        .map_err(|error| format!("failed to execute systemd-detect-virt: {error}"))?;
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "systemd-detect-virt returned non-UTF-8 output".to_owned())?;
    let value = value.trim();

    if output.status.success() {
        return Ok(virtualization_from_name(value));
    }
    if value.is_empty() || value == "none" {
        return Ok(VirtualizationKind::BareMetal);
    }
    Err(format!(
        "systemd-detect-virt failed while reporting virtualization kind: {value}"
    ))
}

fn virtualization_from_name(value: &str) -> VirtualizationKind {
    match value {
        "qemu" => VirtualizationKind::QemuTcg,
        "kvm" => VirtualizationKind::QemuKvm,
        "none" | "" => VirtualizationKind::BareMetal,
        _ => VirtualizationKind::Other,
    }
}

fn observe_interaction(init_system: &str) -> Result<InteractionMode, String> {
    if init_system != "systemd" {
        return Ok(InteractionMode::Headless);
    }

    let status = Command::new("systemctl")
        .args(["is-active", "--quiet", "display-manager.service"])
        .status()
        .map_err(|error| format!("failed to query display-manager state: {error}"))?;
    if status.success() {
        Ok(InteractionMode::Interactive)
    } else {
        Ok(InteractionMode::Headless)
    }
}

fn os_release_value(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    text.lines().find_map(|line| {
        let value = line.strip_prefix(&prefix)?.trim();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            Some(value[1..value.len() - 1].to_owned())
        } else {
            Some(value.to_owned())
        }
    })
}

fn parse_revision_reference<'a>(value: &'a str, prefix: &str) -> Result<(&'a str, u32), String> {
    let value = value
        .strip_prefix(prefix)
        .ok_or_else(|| format!("manifest reference must begin with {prefix}"))?;
    let (id, revision) = value
        .rsplit_once('@')
        .ok_or_else(|| "manifest Library reference must include an exact @revision".to_owned())?;
    if id.is_empty() {
        return Err("manifest Library reference object id is empty".into());
    }
    let revision = revision
        .parse::<u32>()
        .map_err(|_| "manifest Library reference revision is not a u32".to_owned())?;
    if revision == 0 {
        return Err("manifest Library reference revision must be greater than zero".into());
    }
    Ok((id, revision))
}

fn verify_protected_library_file(path: &PathBuf) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "protected provisioning Library {} is unavailable: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(
            "provisioning Library must be a protected root-owned single-link regular file".into(),
        );
    }
    Ok(())
}

fn io_string(error: std::io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_parser_accepts_quoted_and_unquoted_values() {
        let text = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(os_release_value(text, "ID").as_deref(), Some("ubuntu"));
        assert_eq!(
            os_release_value(text, "VERSION_ID").as_deref(),
            Some("24.04")
        );
    }

    #[test]
    fn library_references_require_exact_nonzero_revisions() {
        assert_eq!(
            parse_revision_reference("setup:desktop@7", "setup:")
                .unwrap_or_else(|error| unreachable!("{error}")),
            ("desktop", 7)
        );
        assert!(parse_revision_reference("setup:desktop", "setup:").is_err());
        assert!(parse_revision_reference("setup:desktop@0", "setup:").is_err());
        assert!(parse_revision_reference("profile:desktop@1", "setup:").is_err());
    }

    #[test]
    fn qemu_tcg_and_kvm_are_not_conflated() {
        assert_eq!(
            virtualization_from_name("qemu"),
            VirtualizationKind::QemuTcg
        );
        assert_eq!(virtualization_from_name("kvm"), VirtualizationKind::QemuKvm);
        assert_eq!(
            virtualization_from_name("none"),
            VirtualizationKind::BareMetal
        );
        assert_eq!(
            virtualization_from_name("vmware"),
            VirtualizationKind::Other
        );
    }
}
