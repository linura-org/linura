const GENERATION_ANCHOR_MAGIC: &str = "linura-bootstrap-generation-anchor-v2";
const MAX_GENERATION_ANCHOR_BYTES: u64 = 4096;
const ROOT_ANCHOR_DIRECTORY: &str = "/var/lib/linura/bootstrap-anchors";

#[derive(Clone, Debug, Eq, PartialEq)]
struct GenerationAnchor {
    committed_generation: u64,
    committed_state_sha256: String,
    pending_generation: Option<u64>,
    pending_state_sha256: Option<String>,
}

impl GenerationAnchor {
    fn committed(state: &DurableBootstrapState) -> Self {
        Self {
            committed_generation: state.generation,
            committed_state_sha256: bootstrap_state_digest(state),
            pending_generation: None,
            pending_state_sha256: None,
        }
    }

    fn with_pending(
        current: &DurableBootstrapState,
        candidate: &DurableBootstrapState,
    ) -> Result<Self, DurableBootstrapError> {
        if candidate.generation != current.generation.saturating_add(1) {
            return Err(DurableBootstrapError::CorruptGenerationAnchor(
                "pending anchor transition is not the next ledger generation".into(),
            ));
        }
        Ok(Self {
            committed_generation: current.generation,
            committed_state_sha256: bootstrap_state_digest(current),
            pending_generation: Some(candidate.generation),
            pending_state_sha256: Some(bootstrap_state_digest(candidate)),
        })
    }

    fn validate(&self) -> Result<(), DurableBootstrapError> {
        validate_anchor_sha256(&self.committed_state_sha256)?;
        match (self.pending_generation, self.pending_state_sha256.as_deref()) {
            (None, None) => Ok(()),
            (Some(generation), Some(digest)) => {
                if generation != self.committed_generation.saturating_add(1) {
                    return Err(DurableBootstrapError::CorruptGenerationAnchor(
                        "pending generation does not immediately follow committed generation".into(),
                    ));
                }
                validate_anchor_sha256(digest)
            }
            _ => Err(DurableBootstrapError::CorruptGenerationAnchor(
                "pending generation/digest must be present together".into(),
            )),
        }
    }
}

fn validate_anchor_sha256(value: &str) -> Result<(), DurableBootstrapError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DurableBootstrapError::CorruptGenerationAnchor(
            "generation anchor contains an invalid state SHA-256".into(),
        ));
    }
    Ok(())
}

fn bootstrap_state_digest(state: &DurableBootstrapState) -> String {
    sha256(&serialize_state(state))
}

fn serialize_generation_anchor(anchor: &GenerationAnchor) -> Vec<u8> {
    let pending_generation = anchor
        .pending_generation
        .map_or_else(|| "-".to_owned(), |value| value.to_string());
    let pending_digest = anchor.pending_state_sha256.as_deref().unwrap_or("-");
    let mut payload = format!(
        "{GENERATION_ANCHOR_MAGIC}\ncommitted_generation={}\ncommitted_state_sha256={}\npending_generation={}\npending_state_sha256={}\n",
        anchor.committed_generation,
        anchor.committed_state_sha256,
        pending_generation,
        pending_digest,
    );
    let digest = sha256(payload.as_bytes());
    payload.push_str(&format!("integrity={digest}\n"));
    payload.into_bytes()
}

fn parse_generation_anchor(bytes: &[u8]) -> Result<GenerationAnchor, DurableBootstrapError> {
    if bytes.len() as u64 > MAX_GENERATION_ANCHOR_BYTES {
        return Err(DurableBootstrapError::CorruptGenerationAnchor(
            "generation anchor exceeds the supported byte bound".into(),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        DurableBootstrapError::CorruptGenerationAnchor("generation anchor is not UTF-8".into())
    })?;
    let integrity_index = text.rfind("\nintegrity=").map(|index| index + 1).ok_or_else(|| {
        DurableBootstrapError::CorruptGenerationAnchor(
            "generation anchor integrity record is missing".into(),
        )
    })?;
    let (payload, integrity_line) = text.split_at(integrity_index);
    let expected = integrity_line
        .strip_prefix("integrity=")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor integrity record is malformed".into(),
            )
        })?;
    validate_anchor_sha256(expected)?;
    if !constant_time_ascii_eq(sha256(payload.as_bytes()).as_bytes(), expected.as_bytes()) {
        return Err(DurableBootstrapError::GenerationAnchorIntegrityMismatch);
    }

    let mut lines = payload.lines();
    if lines.next() != Some(GENERATION_ANCHOR_MAGIC) {
        return Err(DurableBootstrapError::UnsupportedGenerationAnchorVersion);
    }
    let committed_generation = lines
        .next()
        .and_then(|line| line.strip_prefix("committed_generation="))
        .ok_or_else(|| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor lacks committed generation".into(),
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor contains an invalid committed generation".into(),
            )
        })?;
    let committed_state_sha256 = lines
        .next()
        .and_then(|line| line.strip_prefix("committed_state_sha256="))
        .ok_or_else(|| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor lacks committed state digest".into(),
            )
        })?
        .to_owned();
    let pending_generation_raw = lines
        .next()
        .and_then(|line| line.strip_prefix("pending_generation="))
        .ok_or_else(|| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor lacks pending generation".into(),
            )
        })?;
    let pending_state_sha256_raw = lines
        .next()
        .and_then(|line| line.strip_prefix("pending_state_sha256="))
        .ok_or_else(|| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor lacks pending state digest".into(),
            )
        })?;
    if lines.next().is_some() {
        return Err(DurableBootstrapError::CorruptGenerationAnchor(
            "generation anchor contains unexpected fields".into(),
        ));
    }
    let pending_generation = if pending_generation_raw == "-" {
        None
    } else {
        Some(pending_generation_raw.parse::<u64>().map_err(|_| {
            DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor contains an invalid pending generation".into(),
            )
        })?)
    };
    let pending_state_sha256 = if pending_state_sha256_raw == "-" {
        None
    } else {
        Some(pending_state_sha256_raw.to_owned())
    };
    let anchor = GenerationAnchor {
        committed_generation,
        committed_state_sha256,
        pending_generation,
        pending_state_sha256,
    };
    anchor.validate()?;
    Ok(anchor)
}

fn machine_anchor_scope() -> Result<String, DurableBootstrapError> {
    if current_effective_uid()? != 0 {
        return Ok("nonroot-test-scope".to_owned());
    }
    let machine = fs::read_to_string("/etc/machine-id").map_err(DurableBootstrapError::Io)?;
    let hardware = fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .map_err(DurableBootstrapError::Io)?;
    let machine = machine.trim();
    let hardware = hardware.trim();
    if machine.is_empty()
        || hardware.is_empty()
        || hardware.bytes().all(|byte| matches!(byte, b'0' | b'-'))
    {
        return Err(DurableBootstrapError::UntrustedControlPath);
    }
    Ok(sha256(format!("{machine}\0{hardware}").as_bytes()))
}

impl BootstrapStateStore {
    fn generation_anchor_path(&self) -> Result<PathBuf, DurableBootstrapError> {
        if current_effective_uid()? == 0 {
            let scope = machine_anchor_scope()?;
            let state_identity = sha256(self.path.to_string_lossy().as_bytes());
            Ok(PathBuf::from(ROOT_ANCHOR_DIRECTORY)
                .join(scope)
                .join(format!("{state_identity}.generation")))
        } else {
            // Unit tests run unprivileged and deliberately keep their whole
            // fixture in one temporary directory. Production/root execution
            // always uses the machine-scoped external anchor directory above.
            sidecar_path(&self.path, "generation")
        }
    }

    fn load_generation_anchor(&self) -> Result<Option<GenerationAnchor>, DurableBootstrapError> {
        let path = self.generation_anchor_path()?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(DurableBootstrapError::Io(error)),
        };
        if metadata.len() > MAX_GENERATION_ANCHOR_BYTES {
            return Err(DurableBootstrapError::CorruptGenerationAnchor(
                "generation anchor exceeds the supported byte bound".into(),
            ));
        }
        reject_untrusted_existing_control_file(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)
            .map_err(DurableBootstrapError::Io)?;
        validate_control_identity(&path, &file)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(DurableBootstrapError::Io)?;
        validate_control_identity(&path, &file)?;
        parse_generation_anchor(&bytes).map(Some)
    }

    fn persist_generation_anchor_record(
        &self,
        anchor: &GenerationAnchor,
    ) -> Result<(), DurableBootstrapError> {
        anchor.validate()?;
        let path = self.generation_anchor_path()?;
        atomic_write(&path, &serialize_generation_anchor(anchor))
    }

    fn reconcile_generation_anchor(
        &self,
        state: &DurableBootstrapState,
    ) -> Result<(), DurableBootstrapError> {
        let state_digest = bootstrap_state_digest(state);
        let Some(anchor) = self.load_generation_anchor()? else {
            if state.generation == 0 {
                return self.persist_generation_anchor_record(&GenerationAnchor::committed(state));
            }
            return Err(DurableBootstrapError::GenerationAnchorMissing);
        };

        if anchor.committed_generation == state.generation
            && constant_time_ascii_eq(
                anchor.committed_state_sha256.as_bytes(),
                state_digest.as_bytes(),
            )
        {
            // A pending next generation with the old committed ledger means the
            // process crashed after staging the external anchor but before the
            // atomic ledger rename. Clearing it is safe and deterministic.
            if anchor.pending_generation.is_some() {
                self.persist_generation_anchor_record(&GenerationAnchor::committed(state))?;
            }
            return Ok(());
        }

        if anchor.pending_generation == Some(state.generation)
            && anchor
                .pending_state_sha256
                .as_deref()
                .is_some_and(|digest| constant_time_ascii_eq(digest.as_bytes(), state_digest.as_bytes()))
            && state.generation == anchor.committed_generation.saturating_add(1)
        {
            // The ledger rename was durable and power was lost before the
            // external anchor finalization. Finalize exactly the precommitted
            // generation/digest; no caller-authored reconciliation is accepted.
            return self.persist_generation_anchor_record(&GenerationAnchor::committed(state));
        }

        Err(DurableBootstrapError::GenerationRollbackDetected {
            state_generation: state.generation,
            anchor_generation: anchor.committed_generation,
        })
    }

    fn stage_generation_anchor(
        &self,
        current: &DurableBootstrapState,
        candidate: &DurableBootstrapState,
    ) -> Result<(), DurableBootstrapError> {
        self.reconcile_generation_anchor(current)?;
        self.persist_generation_anchor_record(&GenerationAnchor::with_pending(current, candidate)?)
    }

    fn finalize_generation_anchor(
        &self,
        candidate: &DurableBootstrapState,
    ) -> Result<(), DurableBootstrapError> {
        let anchor = self
            .load_generation_anchor()?
            .ok_or(DurableBootstrapError::GenerationAnchorMissing)?;
        let digest = bootstrap_state_digest(candidate);
        if anchor.pending_generation != Some(candidate.generation)
            || !anchor
                .pending_state_sha256
                .as_deref()
                .is_some_and(|value| constant_time_ascii_eq(value.as_bytes(), digest.as_bytes()))
        {
            return Err(DurableBootstrapError::CorruptGenerationAnchor(
                "finalization does not match the precommitted ledger generation/digest".into(),
            ));
        }
        self.persist_generation_anchor_record(&GenerationAnchor::committed(candidate))
    }

}
