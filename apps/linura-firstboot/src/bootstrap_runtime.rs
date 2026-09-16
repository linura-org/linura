#![forbid(unsafe_code)]

use linura_bootstrap::durable::DurableBootstrapCoordinator;
use linura_core::{ProfileId, SetupId};
use linura_hardware::{
    InteractionMode, MachineClass, ObservedEnvironment, QualificationEnvironment,
    VirtualizationKind,
};
use linura_library::LocalLibrary;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

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
