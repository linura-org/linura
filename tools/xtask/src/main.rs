#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsStr;
use std::process::{Command, ExitCode, Stdio};

const SCOPED_OUTPUT_ENVIRONMENT: &str = "LINURA_XTASK_CARGO_ENVIRONMENT";

fn child_command(program: &str, args: &[&str], cargo_target: Option<&OsStr>) -> Command {
    let mut command = Command::new(program);
    // A nested/detached workspace must select its own outputs. Never forward
    // this xtask-specific selector or set Cargo's inherited target overrides.
    command.env_remove(SCOPED_OUTPUT_ENVIRONMENT);
    if let Some(target) = cargo_target {
        command
            .args(&args[..1])
            .arg("--target-dir")
            .arg(target)
            .args(&args[1..]);
    } else {
        command.args(args);
    }
    command
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let target = if program == "cargo" && matches!(args.first(), Some(&"clippy" | &"test")) {
        if let Some(environment) = env::var_os(SCOPED_OUTPUT_ENVIRONMENT) {
            let target = env::var_os("LINURA_CARGO_TARGET")
                .ok_or("scoped xtask output requires LINURA_CARGO_TARGET")?;
            let status = Command::new("python3")
                .args(["tools/development_storage.py", "--environment"])
                .arg(environment)
                .args(["check", "--role", "cargo", "--path"])
                .arg(&target)
                .env_remove(SCOPED_OUTPUT_ENVIRONMENT)
                .stdout(Stdio::null())
                .status()
                .map_err(|error| format!("cannot validate scoped Cargo output: {error}"))?;
            if !status.success() {
                return Err("guarded Cargo output rejected; no root/shared fallback".into());
            }
            Some(target)
        } else {
            None
        }
    } else {
        None
    };
    let status = child_command(program, args, target.as_deref())
        .status()
        .map_err(|error| format!("failed to start {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} exited with {status}", args.join(" ")))
    }
}

fn parse_ruff_validator_output(output: &[u8]) -> Result<&str, String> {
    let value = std::str::from_utf8(output)
        .map_err(|error| format!("toolchain validator emitted non-UTF-8: {error}"))?;
    let version = value
        .strip_suffix('\n')
        .ok_or("toolchain validator did not emit a terminated Ruff version")?;
    if version.is_empty() || version.contains('\n') || version.contains('\r') {
        return Err("toolchain validator emitted malformed Ruff version".into());
    }
    Ok(version)
}

fn pinned_ruff_version() -> Result<String, String> {
    let output = Command::new("python3")
        .args(["-I", "-S", "tools/check_toolchain_env.py", "--ruff-version"])
        .output()
        .map_err(|error| format!("failed to run isolated toolchain validator: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "pinned toolchain validator rejected Ruff version: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_ruff_validator_output(&output.stdout)?.to_owned())
}

fn verify_ruff_version() -> Result<(), String> {
    let expected = pinned_ruff_version()?;
    let output = Command::new("ruff")
        .arg("--version")
        .output()
        .map_err(|error| format!("failed to start ruff --version: {error}"))?;
    if !output.status.success() {
        return Err(format!("ruff --version exited with {}", output.status));
    }
    let observed = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("ruff --version returned invalid UTF-8: {error}"))?
        .trim();
    let required = format!("ruff {expected}");
    if observed != required {
        return Err(format!(
            "Ruff version mismatch: expected {required}, got {observed:?}; install the pinned development toolchain"
        ));
    }
    Ok(())
}

fn release_contracts() -> Result<(), String> {
    run(
        "python3",
        &[
            "tools/release_contract.py",
            "validate-tree",
            "--releases-dir",
            "docs/releases",
        ],
    )
}

fn authority_foundation() -> Result<(), String> {
    run("python3", &["tools/check_authority_foundation.py"])
}

fn component_maturity() -> Result<(), String> {
    run("python3", &["tools/check_component_maturity.py"])
}

fn desktop_identity() -> Result<(), String> {
    run("python3", &["tools/check_desktop_identity.py"])
}

fn check() -> Result<(), String> {
    run("cargo", &["fmt", "--all", "--check"])?;
    run("python3", &["tools/check_source_formatting.py"])?;
    verify_ruff_version()?;
    run("ruff", &["check", "."])?;
    run("ruff", &["format", "--check", "."])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        "cargo",
        &["test", "--workspace", "--all-features", "--locked"],
    )?;
    run("python3", &["scripts/check_repository.py"])?;
    component_maturity()?;
    authority_foundation()?;
    run("python3", &["scripts/validate_assets.py"])?;
    desktop_identity()?;
    release_contracts()?;
    run("python3", &["tools/run_tooling_tests.py"])?;
    Ok(())
}

fn repo() -> Result<(), String> {
    run("python3", &["scripts/check_repository.py"])?;
    component_maturity()?;
    authority_foundation()?;
    run("python3", &["scripts/validate_assets.py"])?;
    desktop_identity()?;
    release_contracts()
}

fn print_help() {
    println!("Linura development orchestrator");
    println!("\nUSAGE:\n  cargo xtask <command>");
    println!("\nCOMMANDS:");
    println!("  check              canonical local/CI validation");
    println!("  repo               repository, asset and release-contract validation");
    println!("  acceptance-list    list disposable-machine acceptance scenarios");
    println!("  vm-plan            print QEMU command for a qcow2 image");
    println!("  image-plan         print Arch image build stages");
    println!("  slices-ready       list v0.10 slices whose dependencies are complete");
    println!("  slices-waves       print deterministic v0.10 dependency waves");
}

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "help".into());
    let result = match command.as_str() {
        "check" => check(),
        "repo" => repo(),
        "acceptance-list" => run("python3", &["tools/acceptance.py", "list"]),
        "vm-plan" => run("python3", &["tools/vm.py", "plan"]),
        "image-plan" => run("python3", &["tools/image.py", "plan"]),
        "slices-ready" => run("python3", &["tools/v010_slice_graph.py", "ready"]),
        "slices-waves" => run("python3", &["tools/v010_slice_graph.py", "waves"]),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown xtask command: {other}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SCOPED_OUTPUT_ENVIRONMENT, child_command, parse_ruff_validator_output};
    use std::ffi::OsStr;

    #[test]
    fn scoped_output_preserves_all_clippy_assertions_and_stays_out_of_child_environment() {
        let command = child_command(
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
            Some(OsStr::new("/checked/task/cargo")),
        );
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args,
            [
                "clippy",
                "--target-dir",
                "/checked/task/cargo",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == SCOPED_OUTPUT_ENVIRONMENT && value.is_none())
        );
        assert!(
            !command
                .get_envs()
                .any(|(key, _)| key == "CARGO_TARGET_DIR" || key == "CARGO_BUILD_TARGET_DIR")
        );
        let python = child_command("python3", &["scripts/check_repository.py"], None);
        assert_eq!(
            python.get_args().collect::<Vec<_>>(),
            ["scripts/check_repository.py"]
        );
    }

    #[test]
    fn isolated_ruff_validator_output_is_one_utf8_line() {
        assert_eq!(parse_ruff_validator_output(b"0.16.10\n"), Ok("0.16.10"));
        for invalid in ["", "0.16.10", "0.16.10\nextra\n", "0.16.10\r\n", "\n"] {
            assert!(
                parse_ruff_validator_output(invalid.as_bytes()).is_err(),
                "{invalid:?}"
            );
        }
        assert!(parse_ruff_validator_output(&[0xff, b'\n']).is_err());
    }
}
