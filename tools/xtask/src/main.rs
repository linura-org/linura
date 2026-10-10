#![forbid(unsafe_code)]

use std::env;
use std::process::{Command, ExitCode};

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("failed to start {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} exited with {status}", args.join(" ")))
    }
}

fn pinned_ruff_version(contract: &str) -> Result<&str, String> {
    let mut matches = contract
        .lines()
        .filter_map(|line| line.strip_prefix("RUFF_VERSION="));
    let version = matches
        .next()
        .ok_or("RUFF_VERSION missing from toolchain contract")?;
    if matches.next().is_some()
        || version.split('.').count() != 3
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err("RUFF_VERSION must be a single pinned major.minor.patch".into());
    }
    Ok(version)
}

fn verify_ruff_version() -> Result<(), String> {
    let contract = std::fs::read_to_string("tools/codex/versions.env")
        .map_err(|error| format!("failed to read pinned Ruff toolchain: {error}"))?;
    let expected = pinned_ruff_version(&contract)?;
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
    verify_ruff_version()?;
    run("ruff", &["check", "."])?;
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
    run(
        "python3",
        &[
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/tooling",
            "-p",
            "test_*.py",
        ],
    )?;
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
    use super::pinned_ruff_version;

    #[test]
    fn ruff_pin_requires_one_exact_semver_assignment() {
        assert_eq!(
            pinned_ruff_version("RUST_VERSION=1.98.0\nRUFF_VERSION=0.16.10\n"),
            Ok("0.16.10")
        );
        for invalid in [
            "RUST_VERSION=1.98.0\n",
            "RUFF_VERSION=\n",
            "RUFF_VERSION=0.16\n",
            "RUFF_VERSION=0.16.10\nRUFF_VERSION=0.15.12\n",
            "RUFF_VERSION=0.16.10 --untrusted\n",
        ] {
            assert!(pinned_ruff_version(invalid).is_err(), "{invalid}");
        }
    }
}
