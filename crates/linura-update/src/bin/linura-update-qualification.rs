#![forbid(unsafe_code)]

use linura_update::{
    TrustedUpdateEvidenceVerifier, UpdateCoordinator, UpdateJournalStore, UpdatePolicy,
    UpdateResumeDecision, UpdateStage, V09_UPDATE_EVIDENCE_PRODUCER_ID, V09_UPDATE_EVIDENCE_ROOT,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const UPDATE_ID: &str = "qe-update";
const TARGET_ID: &str = "qe-system-root";
const TRANSACTION_ID: &str = "qe-package-transaction";
const PACKAGE_NAME: &str = "linura-qualification-update";
const PACKAGE_VERSION: &str = "1.0.0";
const RECEIPT_ID: &str = "qe-package-verification";
const OBSERVATION_ID: &str = "dpkg-installed-after-interrupted-reconcile-v1";
const PACKAGE_MARKER: &str = "/usr/share/linura-qualification/update-marker";
const POSTINST_STARTED: &str = "/run/linura-qualification-postinst-started";
const POSTINST_CONTINUE: &str = "/run/linura-qualification-postinst-continue";
const EVIDENCE_MAGIC: &str = "linura-update-evidence-v2";
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

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
    write_package_verification_receipt(&dispatch_generation)?;
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

fn write_package_verification_receipt(dispatch_generation: &str) -> Result<(), String> {
    let root = Path::new(V09_UPDATE_EVIDENCE_ROOT);
    fs::create_dir_all(root).map_err(io_string)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(io_string)?;
    let metadata = fs::symlink_metadata(root).map_err(io_string)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("trusted update evidence root is not root-owned and protected".into());
    }

    let issued_unix_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "qualification timestamp exceeds u64".to_owned())?;
    let mut payload = format!(
        "{EVIDENCE_MAGIC}\nkind=package-verification\nupdate={}\ntarget={}\nsubject={}\nproof={}\ndispatch_generation={}\nissued_unix_ms={issued_unix_ms}\nsource={V09_UPDATE_EVIDENCE_PRODUCER_ID}\nresult=verified\n",
        hex_encode(UPDATE_ID),
        hex_encode(TARGET_ID),
        hex_encode(TRANSACTION_ID),
        hex_encode(OBSERVATION_ID),
        hex_encode(dispatch_generation),
    );
    let tag = integrity_tag(payload.as_bytes());
    payload.push_str(&format!("integrity={tag:016x}\n"));

    let receipt_path = root.join(format!("{RECEIPT_ID}.receipt"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&receipt_path)
        .map_err(io_string)?;
    file.write_all(payload.as_bytes()).map_err(io_string)?;
    file.sync_all().map_err(io_string)?;
    fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(io_string)?;
    Ok(())
}

fn integrity_tag(bytes: &[u8]) -> u64 {
    let mut state = FNV_OFFSET;
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn hex_encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
