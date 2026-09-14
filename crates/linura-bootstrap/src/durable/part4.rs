#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn manifest_bytes(
        manifest_id: &str,
        session_id: &str,
        machine_id: &str,
        mode: &str,
        defer: bool,
    ) -> Vec<u8> {
        let mut payload = format!(
            "{PROVISIONING_MANIFEST_SCHEMA}\nmanifest_id={manifest_id}\nsession_id={session_id}\nmachine_id={machine_id}\nmode={mode}\nconnectivity=offline\ndefer_owner_enrollment={defer}\nsource_ref=local:library\nsetup_ref=setup:v1\nmachine_profile_ref=profile:v1\nhost_identity=host:test\n"
        );
        let digest = sha256(payload.as_bytes());
        payload.push_str(&format!("integrity={digest}\n"));
        payload.into_bytes()
    }

    fn verification_evidence(
        coordinator: &DurableBootstrapCoordinator,
        stage: BootstrapStage,
        operation_id: &str,
    ) -> BootstrapVerificationEvidence {
        BootstrapVerificationEvidence::qualification_observation(
            stage,
            operation_id,
            coordinator.state().session_id(),
            coordinator.state().machine_id(),
            format!("observation-{operation_id}"),
            format!("stage={stage:?};operation={operation_id};result=verified").as_bytes(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn trusted_owner_receipt(
        path: &Path,
        session_id: &str,
        machine_id: &str,
        owner_id: &str,
        enrollment_id: &str,
    ) -> TrustedOwnerEnrollmentReceipt {
        let issued_unix_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .as_millis()
            .try_into()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut payload = format!(
            "{OWNER_ENROLLMENT_RECEIPT_SCHEMA}\nproducer={OWNER_ENROLLMENT_PRODUCER}\nsession_id={session_id}\nmachine_id={machine_id}\nowner_id={owner_id}\nenrollment_id={enrollment_id}\nissued_unix_ms={issued_unix_ms}\n"
        );
        let digest = sha256(payload.as_bytes());
        payload.push_str(&format!("integrity={digest}\n"));
        fs::write(path, payload).unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| unreachable!("{error}"));
        TrustedOwnerEnrollmentReceipt::load(path, session_id, machine_id)
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn complete_stage(
        coordinator: &mut DurableBootstrapCoordinator,
        stage: BootstrapStage,
        operation_id: &str,
    ) {
        coordinator
            .prepare_stage(stage, operation_id)
            .unwrap_or_else(|error| unreachable!("{error}"));
        if stage_requires_effect_boundary(stage) {
            coordinator
                .mark_effect_started(operation_id)
                .unwrap_or_else(|error| unreachable!("{error}"));
            let evidence = verification_evidence(coordinator, stage, operation_id);
            coordinator
                .complete_effect_verified(&evidence)
                .unwrap_or_else(|error| unreachable!("{error}"));
        } else {
            coordinator
                .complete_verified(operation_id)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
    }

    fn advance_to_provisioning_stage(coordinator: &mut DurableBootstrapCoordinator) {
        for (stage, operation_id) in [
            (BootstrapStage::BaseEnvironmentVerification, "op-base"),
            (BootstrapStage::LinuraInstallation, "op-install"),
            (
                BootstrapStage::PersistentStateInitialization,
                "op-persistence",
            ),
            (BootstrapStage::SecurityBaseline, "op-security"),
        ] {
            complete_stage(coordinator, stage, operation_id);
        }
        coordinator
            .prepare_stage(
                BootstrapStage::ProvisioningModeSelection,
                "op-provisioning-mode",
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
    }

    fn complete_provisioning_mode(
        coordinator: &mut DurableBootstrapCoordinator,
        mode: ProvisioningMode,
        manifest: Option<&ProvisioningManifest>,
    ) {
        coordinator
            .select_provisioning(mode, manifest)
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .complete_verified("op-provisioning-mode")
            .unwrap_or_else(|error| unreachable!("{error}"));
    }

    fn advance_to_owner_resolution(coordinator: &mut DurableBootstrapCoordinator) {
        for (stage, operation_id) in [
            (
                BootstrapStage::BootstrapConnectivityResolution,
                "op-connectivity",
            ),
            (BootstrapStage::HardwareDiscovery, "op-hardware"),
            (BootstrapStage::SourceSelection, "op-source"),
            (BootstrapStage::TargetObservation, "op-observation"),
            (BootstrapStage::FirstBootPlanning, "op-plan"),
            (BootstrapStage::RecoveryCheckpoint, "op-recovery"),
        ] {
            complete_stage(coordinator, stage, operation_id);
        }
        coordinator
            .prepare_stage(
                BootstrapStage::OwnerEnrollmentResolution,
                "op-owner-resolution",
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_effect_started("op-owner-resolution")
            .unwrap_or_else(|error| unreachable!("{error}"));
    }

    fn complete_owner_resolution(coordinator: &mut DurableBootstrapCoordinator) {
        let evidence = verification_evidence(
            coordinator,
            BootstrapStage::OwnerEnrollmentResolution,
            "op-owner-resolution",
        );
        coordinator
            .complete_effect_verified(&evidence)
            .unwrap_or_else(|error| unreachable!("{error}"));
    }

    #[test]
    fn manifest_is_strict_bounded_and_integrity_bound() {
        let bytes = manifest_bytes(
            "manifest-1",
            "session-1",
            "machine-1",
            "unattended-local",
            true,
        );
        let manifest = ProvisioningManifest::parse(&bytes)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(manifest.manifest_id(), "manifest-1");
        assert_eq!(manifest.identity().len(), 64);
        assert_eq!(manifest.mode(), ProvisioningMode::UnattendedLocal);
        assert!(manifest.defer_owner_enrollment());

        let mut tampered = bytes.clone();
        let index = tampered
            .iter()
            .position(|byte| *byte == b'm')
            .unwrap_or_else(|| unreachable!("manifest bytes missing"));
        tampered[index] = b'n';
        assert!(matches!(
            ProvisioningManifest::parse(&tampered),
            Err(DurableBootstrapError::ManifestIntegrityMismatch)
        ));
    }

    #[test]
    fn manifest_rejects_unknown_command_fields_even_with_valid_digest() {
        let mut payload = format!(
            "{PROVISIONING_MANIFEST_SCHEMA}\nmanifest_id=manifest-1\nsession_id=session-1\nmachine_id=machine-1\nmode=unattended-local\nconnectivity=offline\ndefer_owner_enrollment=true\nsource_ref=local:library\nsetup_ref=setup:v1\nmachine_profile_ref=profile:v1\nhost_identity=host:test\ncommand=sudo-rm-rf\n"
        );
        let digest = sha256(payload.as_bytes());
        payload.push_str(&format!("integrity={digest}\n"));
        assert!(matches!(
            ProvisioningManifest::parse(payload.as_bytes()),
            Err(DurableBootstrapError::InvalidManifest(_))
        ));
    }

    #[test]
    fn unattended_manifest_requires_deferred_owner_enrollment() {
        assert!(matches!(
            ProvisioningManifest::parse(&manifest_bytes(
                "manifest-1",
                "session-1",
                "machine-1",
                "unattended-local",
                false,
            )),
            Err(DurableBootstrapError::InvalidManifest(_))
        ));
    }

    #[test]
    fn manifest_cannot_replay_across_machine_or_session() {
        let bytes = manifest_bytes(
            "manifest-1",
            "session-1",
            "machine-1",
            "unattended-local",
            true,
        );
        let manifest = ProvisioningManifest::parse(&bytes)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            manifest.validate_binding(
                "session-2",
                "machine-1",
                ProvisioningMode::UnattendedLocal,
            ),
            Err(DurableBootstrapError::ManifestBindingMismatch)
        ));
        assert!(matches!(
            manifest.validate_binding(
                "session-1",
                "machine-2",
                ProvisioningMode::UnattendedLocal,
            ),
            Err(DurableBootstrapError::ManifestBindingMismatch)
        ));
    }

    #[test]
    fn identifiers_are_canonical_and_do_not_silently_trim() {
        assert!(matches!(
            DurableBootstrapState::new(" session-1", "machine-1"),
            Err(DurableBootstrapError::InvalidIdentifier("bootstrap session id"))
        ));
        assert!(matches!(
            DurableBootstrapState::new("session-1", "/machine-1"),
            Err(DurableBootstrapError::InvalidIdentifier("machine id"))
        ));
    }

    #[test]
    fn durable_stage_restart_never_blindly_replays_started_effect() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        complete_stage(
            &mut coordinator,
            BootstrapStage::BaseEnvironmentVerification,
            "op-base",
        );
        coordinator
            .prepare_stage(BootstrapStage::LinuraInstallation, "op-install")
            .unwrap_or_else(|error| unreachable!("{error}"));
        coordinator
            .mark_effect_started("op-install")
            .unwrap_or_else(|error| unreachable!("{error}"));
        drop(coordinator);

        let reopened = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            BootstrapResumeDecision::ReobserveBeforeContinuing {
                stage: BootstrapStage::LinuraInstallation,
                operation_id: "op-install",
            }
        );
    }

    #[test]
    fn effectful_stage_requires_started_boundary_and_fresh_evidence() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator =
            DurableBootstrapCoordinator::open(store.clone(), "session-1", "machine-1")
                .unwrap_or_else(|error| unreachable!("{error}"));
        complete_stage(
            &mut coordinator,
            BootstrapStage::BaseEnvironmentVerification,
            "op-base",
        );
        coordinator
            .prepare_stage(BootstrapStage::LinuraInstallation, "op-install")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = verification_evidence(
            &coordinator,
            BootstrapStage::LinuraInstallation,
            "op-install",
        );
        assert!(matches!(
            coordinator.complete_effect_verified(&evidence),
            Err(DurableBootstrapError::EffectNotStarted(
                BootstrapStage::LinuraInstallation
            ))
        ));
        coordinator
            .mark_effect_started("op-install")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            coordinator.complete_verified("op-install"),
            Err(DurableBootstrapError::VerificationEvidenceRequired(
                BootstrapStage::LinuraInstallation
            ))
        ));
        let wrong_machine = BootstrapVerificationEvidence::qualification_observation(
            BootstrapStage::LinuraInstallation,
            "op-install",
            "session-1",
            "machine-2",
            "wrong-machine-observation",
            b"installed=true",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            coordinator.complete_effect_verified(&wrong_machine),
            Err(DurableBootstrapError::VerificationEvidenceBindingMismatch)
        ));
        let evidence = verification_evidence(
            &coordinator,
            BootstrapStage::LinuraInstallation,
            "op-install",
        );
        coordinator
            .complete_effect_verified(&evidence)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let lineage = coordinator.state().effect_verifications().to_vec();
        assert_eq!(lineage.len(), 1);
        assert_eq!(lineage[0].stage(), BootstrapStage::LinuraInstallation);
        assert_eq!(lineage[0].operation_id(), "op-install");
        assert_eq!(lineage[0].verifier_id(), "linura-bootstrap-qualification-fixture-v1");
        assert_eq!(lineage[0].observation_id(), "observation-op-install");
        assert_eq!(lineage[0].postcondition_sha256().len(), 64);
        assert!(lineage[0].observed_unix_ms() > 0);
        drop(coordinator);

        let reopened = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(reopened.state().effect_verifications(), lineage.as_slice());
    }

    #[test]
    fn verified_stage_resumes_at_first_incomplete_stage() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        complete_stage(
            &mut coordinator,
            BootstrapStage::BaseEnvironmentVerification,
            "op-base",
        );
        drop(coordinator);

        let reopened = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.resume_decision(),
            BootstrapResumeDecision::ContinueAt(BootstrapStage::LinuraInstallation)
        );
    }

    #[test]
    fn stale_coordinator_cannot_rollback_durable_progress() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut current = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let mut stale = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        current
            .prepare_stage(BootstrapStage::BaseEnvironmentVerification, "op-current")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            stale.prepare_stage(BootstrapStage::BaseEnvironmentVerification, "op-stale"),
            Err(DurableBootstrapError::StaleCoordinator)
        ));
        assert!(stale.requires_recovery());
    }

    #[test]
    fn reopening_rejects_a_previous_valid_ledger_generation() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let old_state = fs::read(store.path()).unwrap_or_else(|error| unreachable!("{error}"));
        complete_stage(
            &mut coordinator,
            BootstrapStage::BaseEnvironmentVerification,
            "op-base",
        );
        drop(coordinator);
        fs::write(store.path(), old_state).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            DurableBootstrapCoordinator::open(store, "session-1", "machine-1"),
            Err(DurableBootstrapError::GenerationRollbackDetected { .. })
        ));
    }

    #[test]
    fn provisioning_selection_is_bound_to_its_canonical_stage() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            coordinator.select_provisioning(ProvisioningMode::PrepareForAnotherOwner, None),
            Err(DurableBootstrapError::StageContextRequired(
                BootstrapStage::ProvisioningModeSelection
            ))
        ));
    }

    #[test]
    fn prepare_for_another_owner_persists_stable_pending_then_mints_fresh_owner_evidence() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        advance_to_provisioning_stage(&mut coordinator);
        complete_provisioning_mode(
            &mut coordinator,
            ProvisioningMode::PrepareForAnotherOwner,
            None,
        );
        advance_to_owner_resolution(&mut coordinator);
        coordinator
            .enter_owner_enrollment_pending()
            .unwrap_or_else(|error| unreachable!("{error}"));
        complete_owner_resolution(&mut coordinator);
        assert_eq!(
            coordinator.state().provisioning().owner_enrollment(),
            OwnerEnrollmentState::Pending
        );
        assert!(coordinator
            .state()
            .provisioning()
            .preparer_authority_retired());
        assert_eq!(
            coordinator.resume_decision(),
            BootstrapResumeDecision::ContinueAt(BootstrapStage::FirstBootReady)
        );
        drop(coordinator);

        let mut reopened = DurableBootstrapCoordinator::open(store.clone(), "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.state().provisioning().owner_enrollment(),
            OwnerEnrollmentState::Pending
        );
        let receipt = trusted_owner_receipt(
            &dir.path().join("pending-owner.receipt"),
            "session-1",
            "machine-1",
            "owner-1",
            "fresh-enrollment-1",
        );
        reopened
            .enroll_pending_owner_from_receipt(&receipt)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let authority = reopened
            .state()
            .provisioning()
            .owner_authority()
            .unwrap_or_else(|| unreachable!("owner authority evidence missing"));
        assert_eq!(authority.owner_id(), "owner-1");
        assert_eq!(authority.enrollment_id(), "fresh-enrollment-1");
        assert_eq!(authority.generation(), 1);
        let second_receipt = trusted_owner_receipt(
            &dir.path().join("second-owner.receipt"),
            "session-1",
            "machine-1",
            "owner-2",
            "fresh-enrollment-2",
        );
        assert!(matches!(
            reopened.enroll_pending_owner_from_receipt(&second_receipt),
            Err(DurableBootstrapError::FreshOwnerEnrollmentRequired)
        ));

        let serialized = fs::read_to_string(store.path())
            .unwrap_or_else(|error| unreachable!("{error}"));
        for forbidden in [
            "password=",
            "private_key=",
            "approval=",
            "permit=",
            "session_token=",
            "executor=",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn interactive_owner_is_enrolled_only_inside_owner_resolution_stage() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        advance_to_provisioning_stage(&mut coordinator);
        complete_provisioning_mode(&mut coordinator, ProvisioningMode::InteractiveOwner, None);
        let receipt = trusted_owner_receipt(
            &dir.path().join("interactive-owner.receipt"),
            "session-1",
            "machine-1",
            "owner-1",
            "enrollment-1",
        );
        assert!(matches!(
            coordinator.enroll_interactive_owner_from_receipt(&receipt),
            Err(DurableBootstrapError::StageContextRequired(
                BootstrapStage::OwnerEnrollmentResolution
            ))
        ));
        advance_to_owner_resolution(&mut coordinator);
        coordinator
            .enroll_interactive_owner_from_receipt(&receipt)
            .unwrap_or_else(|error| unreachable!("{error}"));
        complete_owner_resolution(&mut coordinator);
        assert_eq!(
            coordinator.state().provisioning().owner_enrollment(),
            OwnerEnrollmentState::Enrolled
        );
    }

    #[test]
    fn recovery_mode_resolves_owner_stage_without_inventing_authority() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        advance_to_provisioning_stage(&mut coordinator);
        complete_provisioning_mode(&mut coordinator, ProvisioningMode::Recovery, None);
        advance_to_owner_resolution(&mut coordinator);
        coordinator
            .enter_recovery_owner_resolution()
            .unwrap_or_else(|error| unreachable!("{error}"));
        complete_owner_resolution(&mut coordinator);
        assert_eq!(
            coordinator.state().provisioning().owner_enrollment(),
            OwnerEnrollmentState::RecoveryResolved
        );
        assert!(coordinator.state().provisioning().owner_authority().is_none());
        assert_eq!(coordinator.state().provisioning().authority_generation(), 0);
        assert!(!coordinator
            .state()
            .provisioning()
            .preparer_authority_retired());
        complete_stage(
            &mut coordinator,
            BootstrapStage::FirstBootReady,
            "op-ready",
        );
        assert_eq!(coordinator.resume_decision(), BootstrapResumeDecision::Complete);
    }

    #[test]
    fn unattended_local_requires_exact_bound_manifest_and_stable_pending() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(dir.path().join("bootstrap.state"));
        let mut coordinator = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        advance_to_provisioning_stage(&mut coordinator);
        assert!(matches!(
            coordinator.select_provisioning(ProvisioningMode::UnattendedLocal, None),
            Err(DurableBootstrapError::ManifestRequired)
        ));
        let manifest = ProvisioningManifest::parse(&manifest_bytes(
            "manifest-1",
            "session-1",
            "machine-1",
            "unattended-local",
            true,
        ))
        .unwrap_or_else(|error| unreachable!("{error}"));
        complete_provisioning_mode(
            &mut coordinator,
            ProvisioningMode::UnattendedLocal,
            Some(&manifest),
        );
        assert_eq!(
            coordinator.state().provisioning().manifest_identity(),
            Some(manifest.identity())
        );
        advance_to_owner_resolution(&mut coordinator);
        coordinator
            .enter_owner_enrollment_pending()
            .unwrap_or_else(|error| unreachable!("{error}"));
        complete_owner_resolution(&mut coordinator);
        drop(coordinator);

        let reopened = DurableBootstrapCoordinator::open(store, "session-1", "machine-1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reopened.state().provisioning().owner_enrollment(),
            OwnerEnrollmentState::Pending
        );
        assert_eq!(
            reopened.state().provisioning().manifest_identity(),
            Some(manifest.identity())
        );
    }

    #[test]
    fn group_writable_state_parent_fails_closed() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let parent = dir.path().join("untrusted");
        fs::create_dir(&parent).unwrap_or_else(|error| unreachable!("{error}"));
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let store = BootstrapStateStore::new(parent.join("bootstrap.state"));
        assert!(matches!(
            DurableBootstrapCoordinator::open(store, "session-1", "machine-1"),
            Err(DurableBootstrapError::UntrustedStatePath)
        ));
    }

    #[test]
    fn state_corruption_and_newer_schema_fail_closed() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let path = dir.path().join("bootstrap.state");
        let store = BootstrapStateStore::new(&path);
        let coordinator = DurableBootstrapCoordinator::open(
            store.clone(),
            "session-1",
            "machine-1",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        drop(coordinator);
        let mut bytes = fs::read(&path).unwrap_or_else(|error| unreachable!("{error}"));
        bytes[0] ^= 1;
        fs::write(&path, bytes).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            store.load(),
            Err(DurableBootstrapError::StateIntegrityMismatch)
                | Err(DurableBootstrapError::UnsupportedStateVersion)
        ));

        let payload = b"linura-bootstrap-state-v2\ngeneration=0\n";
        let digest = sha256(payload);
        fs::write(
            &path,
            format!("linura-bootstrap-state-v2\ngeneration=0\nintegrity={digest}\n"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            store.load(),
            Err(DurableBootstrapError::UnsupportedStateVersion)
        ));
    }

    #[test]
    fn symlink_state_path_fails_closed() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let target = dir.path().join("target");
        let state = dir.path().join("bootstrap.state");
        fs::write(&target, b"not-state").unwrap_or_else(|error| unreachable!("{error}"));
        symlink(&target, &state).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            BootstrapStateStore::new(state).load(),
            Err(DurableBootstrapError::UntrustedStatePath)
        ));
    }
}
