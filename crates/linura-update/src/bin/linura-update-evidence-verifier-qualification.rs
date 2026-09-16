#![forbid(unsafe_code)]

use linura_update::QualificationUpdateEvidenceIssuer;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode};

const UPDATE_ID: &str = "qe-update";
const TARGET_ID: &str = "qe-system-root";
const TRANSACTION_ID: &str = "qe-package-transaction";
const PACKAGE_NAME: &str = "linura-qualification-update";
const PACKAGE_VERSION: &str = "1.0.0";
const RECEIPT_ID: &str = "qe-package-verification";
const OBSERVATION_ID: &str = "dpkg-installed-after-interrupted-reconcile-v1";
const PACKAGE_MARKER: &str = "/usr/share/linura-qualification/update-marker";

fn expected_package_state() -> String {
    format!("install ok installed\n{PACKAGE_VERSION}\n")
}

fn expected_package_marker() -> String {
    format!("transaction={TRANSACTION_ID}\nversion={PACKAGE_VERSION}\n")
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("update evidence verifier qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let dispatch_generation = args
        .next()
        .ok_or_else(|| "missing dispatch generation".to_owned())?;
    if args.next().is_some() {
        return Err("verifier requires exactly one dispatch generation".into());
    }

    let output = Command::new("dpkg-query")
        .args([
            "--show",
            "--showformat=${Status}\\n${Version}\\n",
            PACKAGE_NAME,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("independent verifier could not query dpkg state".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("dpkg-query output is not UTF-8: {error}"))?;
    let expected = expected_package_state();
    if text != expected {
        return Err(format!(
            "independent package post-state mismatch: expected {expected:?}, observed {text:?}"
        ));
    }
    let marker =
        fs::read_to_string(Path::new(PACKAGE_MARKER)).map_err(|error| error.to_string())?;
    let expected_marker = expected_package_marker();
    if marker != expected_marker {
        return Err(format!(
            "independent verifier observed a mismatched package marker: expected {expected_marker:?}, observed {marker:?}"
        ));
    }

    QualificationUpdateEvidenceIssuer::open_or_create()
        .map_err(|error| error.to_string())?
        .issue_package_verification(
            RECEIPT_ID,
            UPDATE_ID,
            TARGET_ID,
            TRANSACTION_ID,
            OBSERVATION_ID,
            &dispatch_generation,
        )
        .map_err(|error| error.to_string())?;
    println!("q11_package_verifier=independent-authenticated-producer");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_dpkg_state_uses_real_line_boundaries() {
        let expected = expected_package_state();
        assert_eq!(expected, "install ok installed\n1.0.0\n");
        assert!(!expected.contains("\\n"));
    }

    #[test]
    fn expected_package_marker_uses_real_line_boundaries() {
        let expected = expected_package_marker();
        assert_eq!(
            expected,
            "transaction=qe-package-transaction\nversion=1.0.0\n"
        );
        assert!(!expected.contains("\\n"));
    }
}
