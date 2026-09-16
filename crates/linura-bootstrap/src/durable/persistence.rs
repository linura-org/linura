fn parse_state(bytes: &[u8]) -> Result<DurableBootstrapState, DurableBootstrapError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| DurableBootstrapError::CorruptState("state is not UTF-8".into()))?;
    let integrity_index = text
        .rfind("\nintegrity=")
        .map(|index| index + 1)
        .ok_or_else(|| {
            DurableBootstrapError::CorruptState("state integrity record is missing".into())
        })?;
    let (payload, integrity_line) = text.split_at(integrity_index);
    let expected = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| DurableBootstrapError::CorruptState("invalid integrity record".into()))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DurableBootstrapError::CorruptState(
            "invalid state integrity digest".into(),
        ));
    }
    if !constant_time_ascii_eq(sha256(payload.as_bytes()).as_bytes(), expected.as_bytes()) {
        return Err(DurableBootstrapError::StateIntegrityMismatch);
    }

    let mut lines = payload.lines();
    if lines.next() != Some(BOOTSTRAP_STATE_SCHEMA) {
        return Err(DurableBootstrapError::UnsupportedStateVersion);
    }
    let generation = state_field(lines.next(), "generation")?
        .parse::<u64>()
        .map_err(|_| DurableBootstrapError::CorruptState("invalid generation".into()))?;
    let session_id = normalize_identifier(
        "bootstrap session id",
        state_field(lines.next(), "session_id")?,
    )?;
    let machine_id = normalize_identifier("machine id", state_field(lines.next(), "machine_id")?)?;
    let completed_raw = state_field(lines.next(), "completed")?;
    let completed = if completed_raw == "-" {
        Vec::new()
    } else {
        let parsed = completed_raw
            .split(',')
            .map(parse_stage)
            .collect::<Result<Vec<_>, _>>()?;
        if parsed.len() > BootstrapStage::ORDERED.len() {
            return Err(DurableBootstrapError::CorruptState(
                "too many completed bootstrap stages".into(),
            ));
        }
        parsed
    };
    let effect_verifications_raw = state_field(lines.next(), "effect_verifications")?;
    let effect_verifications = if effect_verifications_raw == "-" {
        Vec::new()
    } else {
        effect_verifications_raw
            .split(',')
            .map(|encoded| {
                let mut fields = encoded.split('|');
                let stage = parse_stage(fields.next().ok_or_else(|| {
                    DurableBootstrapError::CorruptState(
                        "effect verification lacks stage".into(),
                    )
                })?)?;
                let operation_id = normalize_identifier(
                    "verified bootstrap operation id",
                    fields.next().ok_or_else(|| {
                        DurableBootstrapError::CorruptState(
                            "effect verification lacks operation id".into(),
                        )
                    })?,
                )?;
                let verifier_id = normalize_identifier(
                    "bootstrap verifier id",
                    fields.next().ok_or_else(|| {
                        DurableBootstrapError::CorruptState(
                            "effect verification lacks verifier id".into(),
                        )
                    })?,
                )?;
                let observation_id = normalize_identifier(
                    "bootstrap observation id",
                    fields.next().ok_or_else(|| {
                        DurableBootstrapError::CorruptState(
                            "effect verification lacks observation id".into(),
                        )
                    })?,
                )?;
                let postcondition_sha256 = fields
                    .next()
                    .ok_or_else(|| {
                        DurableBootstrapError::CorruptState(
                            "effect verification lacks postcondition digest".into(),
                        )
                    })?
                    .to_owned();
                let observed_unix_ms = fields
                    .next()
                    .ok_or_else(|| {
                        DurableBootstrapError::CorruptState(
                            "effect verification lacks observation timestamp".into(),
                        )
                    })?
                    .parse::<u64>()
                    .map_err(|_| {
                        DurableBootstrapError::CorruptState(
                            "effect verification timestamp is invalid".into(),
                        )
                    })?;
                if fields.next().is_some() {
                    return Err(DurableBootstrapError::CorruptState(
                        "effect verification contains unexpected fields".into(),
                    ));
                }
                let verification = CompletedEffectVerification {
                    stage,
                    operation_id,
                    verifier_id,
                    observation_id,
                    postcondition_sha256,
                    observed_unix_ms,
                };
                verification.validate()?;
                Ok(verification)
            })
            .collect::<Result<Vec<_>, DurableBootstrapError>>()?
    };
    let active_stage_raw = state_field(lines.next(), "active_stage")?;
    let active_operation_raw = state_field(lines.next(), "active_operation")?;
    let active_effect_raw = state_field(lines.next(), "active_effect")?;
    let active = match (active_stage_raw, active_operation_raw, active_effect_raw) {
        ("-", "-", "-") => None,
        (stage, operation, effect) if stage != "-" && operation != "-" && effect != "-" => {
            Some(ActiveBootstrapStage {
                stage: parse_stage(stage)?,
                operation_id: normalize_identifier("bootstrap operation id", operation)?,
                effect_state: BootstrapEffectState::parse(effect)?,
            })
        }
        _ => {
            return Err(DurableBootstrapError::CorruptState(
                "active bootstrap stage fields must be present together".into(),
            ));
        }
    };
    let mode_raw = state_field(lines.next(), "provisioning_mode")?;
    let mode = if mode_raw == "-" {
        None
    } else {
        Some(match mode_raw {
            "interactive-owner" => ProvisioningMode::InteractiveOwner,
            "prepare-for-another-owner" => ProvisioningMode::PrepareForAnotherOwner,
            "unattended-local" => ProvisioningMode::UnattendedLocal,
            "recovery" => ProvisioningMode::Recovery,
            _ => {
                return Err(DurableBootstrapError::CorruptState(
                    "unknown provisioning mode".into(),
                ));
            }
        })
    };
    let manifest_raw = state_field(lines.next(), "manifest_identity")?;
    let manifest_identity = if manifest_raw == "-" {
        None
    } else {
        if manifest_raw.len() != 64 || !manifest_raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(DurableBootstrapError::CorruptState(
                "manifest identity is not SHA-256".into(),
            ));
        }
        Some(manifest_raw.to_owned())
    };
    let manifest_id_raw = state_field(lines.next(), "manifest_id")?;
    let manifest_id = if manifest_id_raw == "-" {
        None
    } else {
        Some(normalize_identifier("manifest_id", manifest_id_raw)?)
    };
    let manifest_connectivity_raw = state_field(lines.next(), "manifest_connectivity")?;
    let manifest_connectivity = match manifest_connectivity_raw {
        "-" => None,
        "offline" => Some(BootstrapConnectivity::Offline),
        "bounded-network" => Some(BootstrapConnectivity::BoundedNetwork),
        _ => {
            return Err(DurableBootstrapError::CorruptState(
                "unknown persisted manifest connectivity".into(),
            ));
        }
    };
    let manifest_defer_owner_enrollment =
        match state_field(lines.next(), "manifest_defer_owner_enrollment")? {
            "-" => None,
            "true" => Some(true),
            "false" => Some(false),
            _ => {
                return Err(DurableBootstrapError::CorruptState(
                    "invalid persisted manifest owner-defer selection".into(),
                ));
            }
        };
    fn persisted_manifest_reference(
        value: &str,
        label: &'static str,
    ) -> Result<Option<String>, DurableBootstrapError> {
        if value == "-" {
            Ok(None)
        } else {
            normalize_identifier(label, value).map(Some)
        }
    }
    let manifest_source_ref = persisted_manifest_reference(
        state_field(lines.next(), "manifest_source_ref")?,
        "manifest source_ref",
    )?;
    let manifest_setup_ref = persisted_manifest_reference(
        state_field(lines.next(), "manifest_setup_ref")?,
        "manifest setup_ref",
    )?;
    let manifest_machine_profile_ref = persisted_manifest_reference(
        state_field(lines.next(), "manifest_machine_profile_ref")?,
        "manifest machine_profile_ref",
    )?;
    let manifest_host_identity = persisted_manifest_reference(
        state_field(lines.next(), "manifest_host_identity")?,
        "manifest host_identity",
    )?;
    let owner_enrollment =
        OwnerEnrollmentState::parse(state_field(lines.next(), "owner_enrollment")?)?;
    let owner_id_raw = state_field(lines.next(), "owner_id")?;
    let enrollment_id_raw = state_field(lines.next(), "owner_enrollment_id")?;
    let authority_generation = state_field(lines.next(), "authority_generation")?
        .parse::<u64>()
        .map_err(|_| DurableBootstrapError::CorruptState("invalid authority generation".into()))?;
    let owner_authority_generation = state_field(lines.next(), "owner_authority_generation")?
        .parse::<u64>()
        .map_err(|_| {
            DurableBootstrapError::CorruptState("invalid owner authority generation".into())
        })?;
    let preparer_authority_retired = match state_field(lines.next(), "preparer_authority_retired")? {
        "true" => true,
        "false" => false,
        _ => {
            return Err(DurableBootstrapError::CorruptState(
                "invalid preparer-authority-retired flag".into(),
            ));
        }
    };
    if lines.next().is_some() {
        return Err(DurableBootstrapError::CorruptState(
            "unexpected durable bootstrap state field".into(),
        ));
    }
    let owner_authority = match (owner_id_raw, enrollment_id_raw, owner_authority_generation) {
        ("-", "-", 0) => None,
        (owner, enrollment, generation) if owner != "-" && enrollment != "-" && generation > 0 => {
            Some(OwnerAuthorityRecord {
                owner_id: normalize_identifier("owner id", owner)?,
                enrollment_id: normalize_identifier("owner enrollment id", enrollment)?,
                generation,
            })
        }
        _ => {
            return Err(DurableBootstrapError::CorruptState(
                "owner authority fields must be present together".into(),
            ));
        }
    };
    let state = DurableBootstrapState {
        generation,
        session_id,
        machine_id,
        completed,
        effect_verifications,
        active,
        provisioning: ProvisioningState {
            mode,
            manifest_identity,
            manifest_id,
            manifest_connectivity,
            manifest_defer_owner_enrollment,
            manifest_source_ref,
            manifest_setup_ref,
            manifest_machine_profile_ref,
            manifest_host_identity,
            owner_enrollment,
            owner_authority,
            authority_generation,
            preparer_authority_retired,
        },
    };
    state.validate()?;
    Ok(state)
}

fn current_effective_uid() -> Result<u32, DurableBootstrapError> {
    let status = fs::read_to_string("/proc/self/status").map_err(DurableBootstrapError::Io)?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| {
            DurableBootstrapError::Io(std::io::Error::other(
                "cannot determine bootstrap process effective uid",
            ))
        })?;
    let mut fields = uid_line.split_whitespace();
    if fields.next() != Some("Uid:") {
        return Err(DurableBootstrapError::Io(std::io::Error::other(
            "invalid /proc/self/status Uid record",
        )));
    }
    let _real = fields.next().ok_or_else(|| {
        DurableBootstrapError::Io(std::io::Error::other(
            "missing real uid in /proc/self/status",
        ))
    })?;
    fields
        .next()
        .ok_or_else(|| {
            DurableBootstrapError::Io(std::io::Error::other(
                "missing effective uid in /proc/self/status",
            ))
        })?
        .parse::<u32>()
        .map_err(|error| {
            DurableBootstrapError::Io(std::io::Error::other(format!(
                "invalid effective uid in /proc/self/status: {error}"
            )))
        })
}

fn validate_state_parent(path: &Path) -> Result<(), DurableBootstrapError> {
    if !path.is_absolute() {
        return Err(DurableBootstrapError::UntrustedStatePath);
    }
    let parent = path.parent().ok_or_else(|| {
        DurableBootstrapError::Io(std::io::Error::other(
            "bootstrap state path has no parent directory",
        ))
    })?;
    let expected_uid = current_effective_uid()?;
    let mut current = PathBuf::from("/");
    for component in parent.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(value) => current.push(value),
            _ => return Err(DurableBootstrapError::UntrustedStatePath),
        }
        let metadata = fs::symlink_metadata(&current).map_err(DurableBootstrapError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(DurableBootstrapError::UntrustedStatePath);
        }
        if current != parent {
            let mode = metadata.permissions().mode();
            let trusted_owner = metadata.uid() == 0 || metadata.uid() == expected_uid;
            let root_sticky_shared = metadata.uid() == 0 && mode & 0o1000 != 0;
            if !trusted_owner || (mode & 0o022 != 0 && !root_sticky_shared) {
                return Err(DurableBootstrapError::UntrustedStatePath);
            }
        }
    }
    let metadata = fs::symlink_metadata(parent).map_err(DurableBootstrapError::Io)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(DurableBootstrapError::UntrustedStatePath);
    }
    Ok(())
}

fn validate_state_metadata(metadata: &fs::Metadata) -> Result<(), DurableBootstrapError> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.uid() != current_effective_uid()?
    {
        return Err(DurableBootstrapError::UntrustedStatePath);
    }
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, DurableBootstrapError> {
    let parent = path.parent().ok_or_else(|| {
        DurableBootstrapError::Io(std::io::Error::other(
            "bootstrap state path has no parent directory",
        ))
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            DurableBootstrapError::Io(std::io::Error::other(
                "invalid bootstrap state file name",
            ))
        })?;
    Ok(parent.join(format!(".{file_name}.{suffix}")))
}

fn reject_untrusted_existing_control_file(path: &Path) -> Result<(), DurableBootstrapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.nlink() != 1
                || metadata.uid() != current_effective_uid()? =>
        {
            Err(DurableBootstrapError::UntrustedControlPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DurableBootstrapError::Io(error)),
    }
}

fn validate_control_identity(path: &Path, file: &File) -> Result<(), DurableBootstrapError> {
    let expected_uid = current_effective_uid()?;
    let path_metadata = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
    let opened = file.metadata().map_err(DurableBootstrapError::Io)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.permissions().mode() & 0o022 != 0
        || path_metadata.nlink() != 1
        || path_metadata.uid() != expected_uid
        || opened.uid() != expected_uid
        || opened.nlink() != 1
        || opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), DurableBootstrapError> {
    if bytes.len() as u64 > MAX_BOOTSTRAP_STATE_BYTES {
        return Err(DurableBootstrapError::StateSizeExceeded);
    }
    let parent = path.parent().ok_or_else(|| {
        DurableBootstrapError::Io(std::io::Error::other(
            "bootstrap state path has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent).map_err(DurableBootstrapError::Io)?;
    validate_state_parent(path)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DurableBootstrapError::Io(std::io::Error::other(error.to_string())))?
        .as_nanos();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            DurableBootstrapError::Io(std::io::Error::other(
                "invalid bootstrap state file name",
            ))
        })?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
    let mut renamed = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(DurableBootstrapError::Io)?;
        file.write_all(bytes).map_err(DurableBootstrapError::Io)?;
        file.sync_all().map_err(DurableBootstrapError::Io)?;
        fs::rename(&temporary, path).map_err(DurableBootstrapError::Io)?;
        renamed = true;
        validate_state_parent(path)?;
        let committed = fs::symlink_metadata(path).map_err(DurableBootstrapError::Io)?;
        validate_state_metadata(&committed)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                DurableBootstrapError::DurabilityUncertain(format!(
                    "bootstrap state/control rename completed but parent-directory fsync failed: {error}"
                ))
            })?;
        Ok(())
    })();
    if result.is_err() && !renamed {
        let _ = fs::remove_file(&temporary);
    }
    result
}
