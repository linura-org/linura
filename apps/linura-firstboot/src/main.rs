#![forbid(unsafe_code)]

use linura_firstboot::{
    CANDIDATE_BASE_IMAGE_SHA256, CANDIDATE_BASE_IMAGE_URL, FIRST_BOOT_CONTRACT_VERSION,
};
use linura_hardware::{QualificationEnvironment, V09_QUALIFICATION_ENVIRONMENT_ID};
use std::process::ExitCode;

fn print_help() {
    println!("linura-firstboot — Linura v0.9 First Boot client");
    println!();
    println!("Usage:");
    println!("  linura-firstboot");
    println!("  linura-firstboot --qualification-environment");
    println!("  linura-firstboot --self-check");
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
            println!("status=candidate-not-yet-release-supported");
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
