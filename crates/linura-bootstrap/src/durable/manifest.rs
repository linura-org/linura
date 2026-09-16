#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningManifest {
    manifest_id: String,
    session_id: String,
    machine_id: String,
    mode: ProvisioningMode,
    connectivity: BootstrapConnectivity,
    defer_owner_enrollment: bool,
    source_ref: Option<String>,
    setup_ref: Option<String>,
    machine_profile_ref: Option<String>,
    host_identity: Option<String>,
    identity: String,
}

impl ProvisioningManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, DurableBootstrapError> {
        if bytes.is_empty() || bytes.len() > MAX_PROVISIONING_MANIFEST_BYTES {
            return Err(DurableBootstrapError::ManifestSizeExceeded);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| DurableBootstrapError::InvalidManifest("manifest must be UTF-8"))?;
        if text.bytes().any(|byte| byte == 0 || (byte < 0x20 && byte != b'\n')) {
            return Err(DurableBootstrapError::InvalidManifest(
                "manifest contains forbidden control characters",
            ));
        }
        let integrity_index = text
            .rfind("\nintegrity=")
            .map(|index| index + 1)
            .ok_or(DurableBootstrapError::InvalidManifest(
                "manifest integrity record is missing",
            ))?;
        let (payload, integrity_line) = text.split_at(integrity_index);
        let expected = integrity_line
            .strip_prefix("integrity=")
            .and_then(|value| value.strip_suffix('\n'))
            .ok_or(DurableBootstrapError::InvalidManifest(
                "manifest integrity record is malformed",
            ))?;
        validate_sha256(expected)?;
        let identity = sha256(payload.as_bytes());
        if !constant_time_ascii_eq(identity.as_bytes(), expected.as_bytes()) {
            return Err(DurableBootstrapError::ManifestIntegrityMismatch);
        }

        let mut lines = payload.lines();
        if lines.next() != Some(PROVISIONING_MANIFEST_SCHEMA) {
            return Err(DurableBootstrapError::UnsupportedManifestVersion);
        }
        let manifest_id = parse_identifier_field(lines.next(), "manifest_id")?;
        let session_id = parse_identifier_field(lines.next(), "session_id")?;
        let machine_id = parse_identifier_field(lines.next(), "machine_id")?;
        let mode = parse_mode(parse_exact_field(lines.next(), "mode")?)?;
        if mode == ProvisioningMode::Recovery {
            return Err(DurableBootstrapError::InvalidManifest(
                "recovery is not selectable through Provisioning Manifest",
            ));
        }
        let connectivity = parse_connectivity(parse_exact_field(lines.next(), "connectivity")?)?;
        let defer_owner_enrollment = match parse_exact_field(lines.next(), "defer_owner_enrollment")? {
            "true" => true,
            "false" => false,
            _ => {
                return Err(DurableBootstrapError::InvalidManifest(
                    "defer_owner_enrollment must be true or false",
                ));
            }
        };
        let source_ref = parse_optional_reference(lines.next(), "source_ref")?;
        let setup_ref = parse_optional_reference(lines.next(), "setup_ref")?;
        let machine_profile_ref = parse_optional_reference(lines.next(), "machine_profile_ref")?;
        let host_identity = parse_optional_reference(lines.next(), "host_identity")?;
        if lines.next().is_some() {
            return Err(DurableBootstrapError::InvalidManifest(
                "manifest contains unknown or duplicate fields",
            ));
        }
        if matches!(
            mode,
            ProvisioningMode::PrepareForAnotherOwner | ProvisioningMode::UnattendedLocal
        ) && !defer_owner_enrollment
        {
            return Err(DurableBootstrapError::InvalidManifest(
                "non-interactive ownership handoff must defer owner enrollment",
            ));
        }
        if mode == ProvisioningMode::InteractiveOwner && defer_owner_enrollment {
            return Err(DurableBootstrapError::InvalidManifest(
                "interactive-owner cannot request deferred owner enrollment",
            ));
        }

        Ok(Self {
            manifest_id,
            session_id,
            machine_id,
            mode,
            connectivity,
            defer_owner_enrollment,
            source_ref,
            setup_ref,
            machine_profile_ref,
            host_identity,
            identity,
        })
    }

    #[must_use]
    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    #[must_use]
    pub const fn mode(&self) -> ProvisioningMode {
        self.mode
    }

    #[must_use]
    pub const fn connectivity(&self) -> BootstrapConnectivity {
        self.connectivity
    }

    #[must_use]
    pub const fn defer_owner_enrollment(&self) -> bool {
        self.defer_owner_enrollment
    }

    #[must_use]
    pub fn source_ref(&self) -> Option<&str> {
        self.source_ref.as_deref()
    }

    #[must_use]
    pub fn setup_ref(&self) -> Option<&str> {
        self.setup_ref.as_deref()
    }

    #[must_use]
    pub fn machine_profile_ref(&self) -> Option<&str> {
        self.machine_profile_ref.as_deref()
    }

    #[must_use]
    pub fn host_identity(&self) -> Option<&str> {
        self.host_identity.as_deref()
    }

    pub fn validate_binding(
        &self,
        session_id: &str,
        machine_id: &str,
        mode: ProvisioningMode,
    ) -> Result<(), DurableBootstrapError> {
        if self.session_id != session_id || self.machine_id != machine_id || self.mode != mode {
            return Err(DurableBootstrapError::ManifestBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreGeneration {
    state_generation: u64,
    device: u64,
    inode: u64,
    ctime: i64,
    ctime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
    len: u64,
}
