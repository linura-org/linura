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

fn check() -> Result<(), String> {
    run("cargo", &["fmt", "--all", "--check"])?;
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
}

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "help".into());
    let result = match command.as_str() {
        "check" => check(),
        "repo" => repo(),
        "acceptance-list" => run("python3", &["tools/acceptance.py", "list"]),
        "vm-plan" => run("python3", &["tools/vm.py", "plan"]),
        "image-plan" => run("python3", &["tools/image.py", "plan"]),
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
