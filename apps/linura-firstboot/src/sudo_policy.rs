#![forbid(unsafe_code)]

/// Interpret `sudo -n -l -U <user>` output produced under `LC_ALL=C`.
///
/// `sudo -l` reports whether the policy query itself completed; its process exit
/// status is not, by itself, an authority decision. Production must therefore
/// classify the policy listing that sudo actually evaluated.
pub(crate) fn listing_grants_authority(listing: &str, user: &str) -> Result<bool, &'static str> {
    let denied_prefix = format!("User {user} is not allowed to run sudo on ");
    if listing
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with(&denied_prefix))
    {
        return Ok(false);
    }

    let allowed_prefix = format!("User {user} may run the following commands on ");
    let mut lines = listing.lines();
    while let Some(line) = lines.next() {
        if !line.trim().starts_with(&allowed_prefix) {
            continue;
        }

        // A successful policy header without a command specification is not
        // sufficient evidence either way. Sudo command specifications are
        // rendered as indented non-empty records after this header.
        if lines.any(|candidate| {
            !candidate.trim().is_empty()
                && candidate.chars().next().is_some_and(char::is_whitespace)
        }) {
            return Ok(true);
        }
        return Err("sudo policy listing contained an authority header without a command record");
    }

    Err("sudo policy listing did not contain an authoritative allow/deny result")
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "linura-preparer";

    #[test]
    fn classifies_explicit_no_authority_independent_of_exit_status_semantics() {
        let listing = "Matching Defaults entries for linura-preparer on host:\n    env_reset\n\nUser linura-preparer is not allowed to run sudo on host.\n";
        assert_eq!(listing_grants_authority(listing, USER), Ok(false));
    }

    #[test]
    fn classifies_wildcard_command_authority() {
        let listing = "User linura-preparer may run the following commands on host:\n    (ALL : ALL) NOPASSWD: ALL\n";
        assert_eq!(listing_grants_authority(listing, USER), Ok(true));
    }

    #[test]
    fn classifies_bounded_command_authority() {
        let listing = "Matching Defaults entries for linura-preparer on host:\n    env_reset\n\nUser linura-preparer may run the following commands on host:\n    (root) /usr/bin/systemctl status linurad.service\n";
        assert_eq!(listing_grants_authority(listing, USER), Ok(true));
    }

    #[test]
    fn fails_closed_for_ambiguous_output() {
        assert!(listing_grants_authority("sudo: policy plugin failed\n", USER).is_err());
    }

    #[test]
    fn fails_closed_for_empty_authority_header() {
        let listing = "User linura-preparer may run the following commands on host:\n";
        assert!(listing_grants_authority(listing, USER).is_err());
    }
}
