#![forbid(unsafe_code)]

use linura_update::{
    TrustedUpdateEvidenceVerifier, UpdateCoordinator, UpdateJournalStore, UpdatePolicy,
    UpdateResumeDecision, UpdateStage,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const UPDATE_ID: &str = "qe-update";
const TARGET_ID: &str = "qe-system-root";
const TRANSACTION_ID: &str = "qe-package-transaction";
const PACKAGE_NAME: &str = "linura-qualification-update";
const PACKAGE_VERSION: &str = "1.0.0";
const RECEIPT_ID: &str = "qe-package-verification";
const PACKAGE_MARKER: &str = "/usr/share/linura-qualification/update-marker";
const POSTINST_STARTED: &str = "/run/linura-qualification-postinst-started";
const POSTINST_CONTINUE: &str = "/run/linura-qualification-postinst-continue";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("update qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let root = single_absolute_root()?;
    fs::create_dir_all(&root).map_err(io_string)?;
    cleanup_runtime_markers()?;
    if package_is_installed()? {
        return Err("qualification package unexpectedly exists before bounded transaction".into());
    }
    let package = build_qualification_package(&root)?;

    let store = UpdateJournalStore::new(root.join("update.journal"));
    let policy = UpdatePolicy {
        require_snapshot_when_available: false,
        ..UpdatePolicy::default()
    };

    let mut update = UpdateCoordinator::open(store.clone(), policy.clone(), UPDATE_ID, TARGET_ID)
        .map_err(display_string)?;
    for stage in [
        UpdateStage::Preflight,
        UpdateStage::DiskSpace,
        UpdateStage::Snapshot,
    ] {
        update.transition(stage).map_err(display_string)?;
    }
    update
        .prepare_package_transaction(TRANSACTION_ID)
        .map_err(display_string)?;
    drop(update);

    let mut update = UpdateCoordinator::open(store.clone(), policy.clone(), UPDATE_ID, TARGET_ID)
        .map_err(display_string)?;
    if update.resume_decision() != UpdateResumeDecision::SafeToDispatchPrepared {
        return Err("prepared update was not exactly restart-resumable".into());
    }
    update.mark_dispatch_started().map_err(display_string)?;
    let dispatch_generation = update
        .dispatch_generation()
        .ok_or_else(|| "dispatched update lost generation binding".to_owned())?
        .to_owned();
    let dispatch_started_unix_ms = update
        .dispatch_started_unix_ms()
        .ok_or_else(|| "dispatched update lost start-time binding".to_owned())?;

    // Cross the real package-manager effect boundary and then kill dpkg while
    // its postinst is intentionally blocked. This leaves authoritative dpkg
    // state changed but not successfully configured.
    let mut dpkg = start_interruptible_local_package(&package)?;
    wait_for_path(
        Path::new(POSTINST_STARTED),
        Duration::from_secs(20),
        &mut dpkg,
    )?;
    let interrupted_state = observe_package_status()?;
    if interrupted_state == "install ok installed" {
        terminate_process_group(&mut dpkg)?;
        return Err("dpkg reached installed state before qualification interruption".into());
    }
    terminate_process_group(&mut dpkg)?;
    drop(update);

    let mut update = UpdateCoordinator::open(store.clone(), policy.clone(), UPDATE_ID, TARGET_ID)
        .map_err(display_string)?;
    if update.resume_decision() != UpdateResumeDecision::ReobserveBeforeContinuing {
        return Err("interrupted dispatched update did not require re-observation".into());
    }
    let post_crash_state = observe_package_status()?;
    if post_crash_state == "install ok installed" || post_crash_state.is_empty() {
        return Err(format!(
            "interrupted dpkg transaction did not leave an authoritative partial state: {post_crash_state:?}"
        ));
    }
    let reopened_generation = update
        .dispatch_generation()
        .ok_or_else(|| "reopened update lost dispatch generation".to_owned())?;
    let reopened_started_unix_ms = update
        .dispatch_started_unix_ms()
        .ok_or_else(|| "reopened update lost dispatch timestamp".to_owned())?;
    if reopened_generation != dispatch_generation
        || reopened_started_unix_ms != dispatch_started_unix_ms
    {
        return Err("reopened update changed its durable dispatch identity".into());
    }

    reconcile_interrupted_package()?;
    verify_installed_package()?;
    let verifier_output =
        Command::new("/usr/local/bin/linura-update-evidence-verifier-qualification")
            .arg(&dispatch_generation)
            .output()
            .map_err(io_string)?;
    if !verifier_output.status.success() {
        return Err(
            "independent update evidence verifier rejected the reconciled package state".into(),
        );
    }
    let verifier_stdout = String::from_utf8(verifier_output.stdout)
        .map_err(|error| format!("independent verifier output is not UTF-8: {error}"))?;
    if !verifier_stdout.contains("q11_package_verifier=independent-authenticated-producer") {
        return Err("independent verifier did not emit its authenticated-producer marker".into());
    }
    print!("{verifier_stdout}");
    let verifier = TrustedUpdateEvidenceVerifier::open().map_err(display_string)?;
    let receipt = verifier
        .verify_package(
            RECEIPT_ID,
            UPDATE_ID,
            TARGET_ID,
            TRANSACTION_ID,
            &dispatch_generation,
            dispatch_started_unix_ms,
        )
        .map_err(display_string)?;
    update
        .mark_package_verified(&receipt)
        .map_err(display_string)?;
    if update.resume_decision() != UpdateResumeDecision::SafeToAdvanceAfterVerification {
        return Err("authoritatively re-observed package transaction could not advance".into());
    }
    for stage in [
        UpdateStage::Migrations,
        UpdateStage::Reconcile,
        UpdateStage::RestartAssessment,
        UpdateStage::Verify,
        UpdateStage::Complete,
    ] {
        update.transition(stage).map_err(display_string)?;
    }
    drop(update);

    let update = UpdateCoordinator::open(store, policy.clone(), UPDATE_ID, TARGET_ID)
        .map_err(display_string)?;
    if update.resume_decision() != UpdateResumeDecision::Complete {
        return Err("verified package transaction was not durably complete after reopen".into());
    }

    qualify_indeterminate_recovery(&root, policy)?;
    cleanup_runtime_markers()?;

    println!("q11_update_restart=reobserve-no-blind-replay");
    println!("q11_package_transaction=dpkg-killed-mid-postinst");
    println!("q11_package_intermediate_state={post_crash_state}");
    println!("q11_package_reconcile=dpkg-configure-authoritative");
    println!("q11_package_poststate=authoritatively-verified");
    println!("q11_indeterminate=recovery-required");
    Ok(())
}

fn qualify_indeterminate_recovery(root: &Path, policy: UpdatePolicy) -> Result<(), String> {
    let indeterminate_root = root.join("indeterminate");
    fs::create_dir_all(&indeterminate_root).map_err(io_string)?;
    let store = UpdateJournalStore::new(indeterminate_root.join("update.journal"));
    let update_id = "qe-update-indeterminate";
    let target_id = "qe-system-root-indeterminate";
    let mut update = UpdateCoordinator::open(store.clone(), policy.clone(), update_id, target_id)
        .map_err(display_string)?;
    for stage in [
        UpdateStage::Preflight,
        UpdateStage::DiskSpace,
        UpdateStage::Snapshot,
    ] {
        update.transition(stage).map_err(display_string)?;
    }
    update
        .prepare_package_transaction("qe-indeterminate-package-transaction")
        .map_err(display_string)?;
    update.mark_dispatch_started().map_err(display_string)?;
    drop(update);

    let mut update = UpdateCoordinator::open(store.clone(), policy.clone(), update_id, target_id)
        .map_err(display_string)?;
    if update.resume_decision() != UpdateResumeDecision::ReobserveBeforeContinuing {
        return Err("indeterminate dispatched update did not require re-observation".into());
    }
    update
        .require_recovery("qualification-indeterminate-package-effect")
        .map_err(display_string)?;
    drop(update);

    let update =
        UpdateCoordinator::open(store, policy, update_id, target_id).map_err(display_string)?;
    if update.resume_decision() != UpdateResumeDecision::ManualRecoveryRequired {
        return Err("indeterminate update did not remain recovery-required".into());
    }
    Ok(())
}

fn build_qualification_package(root: &Path) -> Result<PathBuf, String> {
    let package_root = root.join("package-root");
    if package_root.exists() {
        fs::remove_dir_all(&package_root).map_err(io_string)?;
    }
    fs::create_dir_all(package_root.join("DEBIAN")).map_err(io_string)?;
    fs::create_dir_all(package_root.join("usr/share/linura-qualification")).map_err(io_string)?;
    fs::write(
        package_root.join("DEBIAN/control"),
        format!(
            "Package: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\nSection: misc\nPriority: optional\nArchitecture: all\nMaintainer: Linura Qualification <qualification@linura.org>\nDescription: bounded local package for Linura update qualification\n"
        ),
    )
    .map_err(io_string)?;
    fs::write(
        package_root.join("DEBIAN/postinst"),
        format!(
            "#!/bin/sh\nset -eu\nprintf 'started\\n' > {POSTINST_STARTED}\nwhile [ ! -e {POSTINST_CONTINUE} ]; do sleep 0.1; done\nexit 0\n"
        ),
    )
    .map_err(io_string)?;
    fs::set_permissions(
        package_root.join("DEBIAN/postinst"),
        fs::Permissions::from_mode(0o755),
    )
    .map_err(io_string)?;
    fs::write(
        package_root.join("usr/share/linura-qualification/update-marker"),
        format!("transaction={TRANSACTION_ID}\nversion={PACKAGE_VERSION}\n"),
    )
    .map_err(io_string)?;
    let package = root.join(format!("{PACKAGE_NAME}_{PACKAGE_VERSION}_all.deb"));
    let status = Command::new("dpkg-deb")
        .arg("--build")
        .arg("--root-owner-group")
        .arg(&package_root)
        .arg(&package)
        .status()
        .map_err(io_string)?;
    if !status.success() {
        return Err("dpkg-deb failed to build bounded qualification package".into());
    }
    Ok(package)
}

fn start_interruptible_local_package(package: &Path) -> Result<Child, String> {
    Command::new("setsid")
        .arg("dpkg")
        .arg("--install")
        .arg(package)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(io_string)
}

fn wait_for_path(path: &Path, timeout: Duration, child: &mut Child) -> Result<(), String> {
    let started = Instant::now();
    loop {
        if path.is_file() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(io_string)? {
            return Err(format!(
                "dpkg exited before the interruption barrier: {status}"
            ));
        }
        if started.elapsed() >= timeout {
            terminate_process_group(child)?;
            return Err("timed out waiting for dpkg postinst interruption barrier".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn terminate_process_group(child: &mut Child) -> Result<(), String> {
    let group = format!("-{}", child.id());
    let status = Command::new("kill")
        .args(["-KILL", "--", &group])
        .status()
        .map_err(io_string)?;
    if !status.success() {
        return Err("failed to terminate interrupted dpkg process group".into());
    }
    let _ = child.wait().map_err(io_string)?;
    Ok(())
}

fn reconcile_interrupted_package() -> Result<(), String> {
    fs::write(POSTINST_CONTINUE, b"continue\n").map_err(io_string)?;
    let status = Command::new("dpkg")
        .args(["--configure", PACKAGE_NAME])
        .status()
        .map_err(io_string)?;
    if !status.success() {
        return Err("dpkg failed to reconcile the interrupted package transaction".into());
    }
    Ok(())
}

fn observe_package_status() -> Result<String, String> {
    let output = Command::new("dpkg-query")
        .args(["--show", "--showformat=${Status}", PACKAGE_NAME])
        .output()
        .map_err(io_string)?;
    if !output.status.success() {
        return Ok(String::new());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("dpkg-query output is not UTF-8: {error}"))
}

fn package_is_installed() -> Result<bool, String> {
    Ok(observe_package_status()? == "install ok installed")
}

fn verify_installed_package() -> Result<(), String> {
    let output = Command::new("dpkg-query")
        .args([
            "--show",
            "--showformat=${Status}\n${Version}\n",
            PACKAGE_NAME,
        ])
        .output()
        .map_err(io_string)?;
    if !output.status.success() {
        return Err("package re-observation could not query dpkg state".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("dpkg-query output is not UTF-8: {error}"))?;
    let expected = format!("install ok installed\n{PACKAGE_VERSION}\n");
    if text != expected {
        return Err(format!("package post-state mismatch: {text:?}"));
    }
    let marker = fs::read_to_string(PACKAGE_MARKER).map_err(io_string)?;
    let expected_marker = format!("transaction={TRANSACTION_ID}\nversion={PACKAGE_VERSION}\n");
    if marker != expected_marker {
        return Err("installed package marker does not match the exact transaction".into());
    }
    Ok(())
}

fn cleanup_runtime_markers() -> Result<(), String> {
    for path in [POSTINST_STARTED, POSTINST_CONTINUE] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_string(error)),
        }
    }
    Ok(())
}

fn single_absolute_root() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing qualification state root".to_owned())?,
    );
    if args.next().is_some() || !root.is_absolute() {
        return Err("qualification requires exactly one absolute state root".into());
    }
    Ok(root)
}

fn io_string(error: std::io::Error) -> String {
    error.to_string()
}

fn display_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}
