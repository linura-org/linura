use super::*;

fn discovery_identity(name: &str) -> NativeOwnerIdentity {
    NativeOwnerIdentity {
        unique_name: name.into(),
        uid: 1000,
        pid: 51,
        invocation: lock().security_owner_invocation().clone(),
    }
}

#[test]
fn endpoint_reply_rejects_wrong_wire_type_and_oversized_replies_before_selection() {
    let call = value(
        value(zbus::Message::method_call(
            "/org/linura/SecurityOwner1",
            "Introspect",
        ))
        .build(&()),
    );
    for (xml, expected) in [
        (
            "<node><interface name=\"org.linura.SecurityOwner1\"></interface></node>",
            true,
        ),
        (
            "<node><interface name=\"org.freedesktop.DBus.Introspectable\"></interface></node>",
            false,
        ),
    ] {
        let reply = value(value(zbus::Message::method_return(&call.header())).build(&(xml,)));
        assert!(matches!(owner_endpoint_reply(&reply),Ok(found) if found==expected));
    }
    for length in [16 * 1024 + 1, crate::bus::MAX_REPLY_BYTES + 1] {
        let reply = value(
            value(zbus::Message::method_return(&call.header())).build(&("x".repeat(length),)),
        );
        assert!(matches!(
            owner_endpoint_reply(&reply),
            Err(NativeCallError::Failure(_))
        ));
    }
    let reply = value(value(zbus::Message::method_return(&call.header())).build(&(42_u64,)));
    assert!(matches!(
        owner_endpoint_reply(&reply),
        Err(NativeCallError::Failure(_))
    ));
}

#[test]
fn owner_disappearance_discards_every_partial_candidate_and_restarts_one_complete_snapshot() {
    let initial = discovery_identity(":1.10");
    let expected = (initial.pid, initial.invocation.clone());
    let mut attempts = 0;
    let result = value(complete_owner_discovery(
        1000,
        &expected,
        || Duration::ZERO,
        |remaining| {
            attempts += 1;
            let names = if attempts == 1 {
                vec![":1.10".into(), ":1.11".into()]
            } else {
                vec![":1.12".into(), ":1.13".into()]
            };
            let selected = select_owner_connection(
                &names,
                (1000, 51),
                remaining,
                |name| {
                    if name == ":1.11" {
                        Err(NativeCallError::CredentialPeerVanished)
                    } else {
                        Ok((1000, 51))
                    }
                },
                |name| Ok(name != ":1.13"),
            )?;
            Ok(selected.map(|name| discovery_identity(&name)))
        },
    ));
    assert_eq!(attempts, 2);
    assert_eq!(result.unique_name, ":1.12");
    let mut remaining = MAX_DISCOVERY_NAMES;
    assert_eq!(
        value(select_owner_connection(
            &[":1.10".into(), ":1.11".into()],
            (1000, 51),
            &mut remaining,
            |_| Ok((1000, 51)),
            |name| if name == ":1.11" {
                Err(NativeCallError::EndpointPeerVanished)
            } else {
                Ok(true)
            },
        )),
        None
    );
}

#[test]
fn owner_discovery_refuses_ambiguity_unknown_failures_missing_endpoint_and_persistent_churn() {
    for mode in 0..5 {
        let mut remaining = MAX_DISCOVERY_NAMES;
        let result = select_owner_connection(
            &[":1.10".into(), ":1.11".into()],
            (1000, 51),
            &mut remaining,
            |_| {
                if mode == 1 {
                    Err(NativeCallError::Failure("credential denial".into()))
                } else {
                    Ok((1000, 51))
                }
            },
            |_| match mode {
                0 => Ok(true),
                2 => Err(NativeCallError::Failure("inspection unavailable".into())),
                3 => Err(NativeCallError::EndpointAbsent),
                _ => Ok(false),
            },
        );
        assert!(result.is_err());
    }
    let identity = discovery_identity(":1.10");
    let expected = (identity.pid, identity.invocation.clone());
    let mut attempts = 0;
    assert!(
        complete_owner_discovery(
            1000,
            &expected,
            || Duration::ZERO,
            |_| {
                attempts += 1;
                Ok(None)
            }
        )
        .is_err()
    );
    assert_eq!(attempts, 2);
    attempts = 0;
    assert!(
        complete_owner_discovery(
            1000,
            &expected,
            || Duration::ZERO,
            |_| {
                attempts += 1;
                Err("unavailable".into())
            }
        )
        .is_err()
    );
    assert_eq!(attempts, 1);
    let mut remaining = MAX_DISCOVERY_NAMES;
    assert_eq!(
        value(select_owner_connection(
            &[":1.10".into(), ":1.11".into()],
            (1000, 51),
            &mut remaining,
            |name| Ok(if name == ":1.10" {
                (1000, 51)
            } else {
                (1001, 51)
            }),
            |_| Ok(true)
        )),
        Some(":1.10".into())
    );
}

#[test]
fn owner_discovery_keeps_aggregate_names_original_deadline_and_supervisor_epoch() {
    let identity = discovery_identity(":1.10");
    let expected = (identity.pid, identity.invocation.clone());
    for change in ["uid", "pid", "invocation", "name"] {
        let mut changed = identity.clone();
        match change {
            "uid" => changed.uid += 1,
            "pid" => changed.pid += 1,
            "invocation" => {
                changed.invocation = value(SecurityOwnerInvocationId::new(
                    "abcdef12-1234-4567-89ab-0123456789ab",
                ))
            }
            _ => changed.unique_name = "org.linura.Preclaimed".into(),
        }
        assert!(
            complete_owner_discovery(
                1000,
                &expected,
                || Duration::ZERO,
                |_| Ok(Some(changed.clone()))
            )
            .is_err(),
            "{change}"
        );
    }
    let mut calls = 0;
    assert!(
        complete_owner_discovery(
            1000,
            &expected,
            || crate::bus::PROBE_BUDGET,
            |_| {
                calls += 1;
                Ok(Some(identity.clone()))
            }
        )
        .is_err()
    );
    assert_eq!(calls, 0);
    let mut times = [Duration::ZERO, crate::bus::PROBE_BUDGET].into_iter();
    assert!(
        complete_owner_discovery(
            1000,
            &expected,
            || times.next().unwrap_or(Duration::MAX),
            |_| Ok(Some(identity.clone()))
        )
        .is_err()
    );
    let mut remaining = MAX_DISCOVERY_NAMES;
    let names = vec![":1.10".into(); MAX_DISCOVERY_NAMES - 1];
    assert_eq!(
        value(select_owner_connection(
            &names,
            (1000, 51),
            &mut remaining,
            |_| Err(NativeCallError::CredentialPeerVanished),
            |_| Ok(true)
        )),
        None
    );
    assert_eq!(remaining, 1);
    assert!(
        select_owner_connection(
            &[":1.12".into(), ":1.13".into()],
            (1000, 51),
            &mut remaining,
            |_| Ok((1000, 51)),
            |_| Ok(true)
        )
        .is_err()
    );
    assert_eq!(crate::bus::CALL_BUDGET, Duration::from_millis(500));
    assert_eq!(crate::bus::PROBE_BUDGET, Duration::from_secs(2));
}

#[test]
fn compound_owner_observation_and_approval_share_only_the_original_probe_remainder() {
    for elapsed in [
        Duration::ZERO,
        Duration::from_millis(499),
        Duration::from_millis(500),
        Duration::from_millis(750),
        Duration::from_millis(1_500),
        Duration::from_millis(1_999),
    ] {
        let remaining = value(owner_reply_budget(elapsed));
        assert_eq!(elapsed + remaining, Duration::from_secs(2));
    }
    assert_eq!(
        value(owner_reply_budget(Duration::from_millis(750))),
        Duration::from_millis(1_250)
    );
    assert!(value(owner_reply_budget(Duration::from_millis(750))) > crate::bus::CALL_BUDGET);
    for expired in [
        Duration::from_secs(2),
        Duration::from_millis(2_001),
        Duration::MAX,
    ] {
        assert!(owner_reply_budget(expired).is_err());
    }
    assert_eq!(crate::bus::CALL_BUDGET, Duration::from_millis(500));
}

#[test]
fn each_authentication_purpose_has_its_own_fixed_non_lock_action() {
    for (purpose, action) in [
        (
            NativeApprovalPurpose::Unlock,
            "org.linura.authority.unlock-session",
        ),
        (
            NativeApprovalPurpose::Suspend,
            "org.linura.authority.suspend-session",
        ),
        (
            NativeApprovalPurpose::Logout,
            "org.linura.authority.logout-session",
        ),
        (
            NativeApprovalPurpose::Reboot,
            "org.linura.authority.reboot-session",
        ),
        (
            NativeApprovalPurpose::PowerOff,
            "org.linura.authority.power-off-session",
        ),
        (
            NativeApprovalPurpose::EnableProtectiveLock,
            "org.linura.authority.enable-protective-lock",
        ),
        (
            NativeApprovalPurpose::RevokeProtectiveLock,
            "org.linura.authority.revoke-protective-lock",
        ),
    ] {
        assert_eq!(authentication_action(purpose), Ok(action));
    }
    assert!(authentication_action(NativeApprovalPurpose::Lock).is_err());
}

#[test]
fn protective_setting_wire_scope_cannot_be_reused_for_unlock_or_power() {
    for (purpose, wire_purpose) in [
        (NativeApprovalPurpose::EnableProtectiveLock, 6),
        (NativeApprovalPurpose::RevokeProtectiveLock, 7),
    ] {
        let mut request = NativeApprovalRequest {
            lock: lock(),
            transition: None,
            principal: value(PrincipalId::new("unix:uid:1000")),
            request: value(RequestId::new("request:v010:protective-lock-setting:test")),
            plan: value(PlanId::new("request:v010:protective-lock-setting:test")),
            request_digest: ComponentDigest::from_bytes([1; 32]),
            observation_digest: ComponentDigest::from_bytes([2; 32]),
            review_digest: ComponentDigest::from_bytes([3; 32]),
            purpose,
        };
        assert_eq!(value(request.wire()).7, wire_purpose);
        request.purpose = NativeApprovalPurpose::Unlock;
        assert!(request.wire().is_err());
        request.purpose = purpose;
        request.transition = Some(value(SessionTransitionId::new(
            request.lock.clone(),
            SessionTransition::Reboot,
        )));
        assert!(request.wire().is_err());
        request.transition = None;
        request.request = value(RequestId::new("request:v010:session-lock:test"));
        request.plan = value(PlanId::new(request.request.as_str()));
        assert!(request.wire().is_err());
    }
}
use linura_core::{ResourceId, SessionEpoch};
use zbus::zvariant::Value;

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture failed: {error:?}"))
}

fn identity() -> NativeOwnerIdentity {
    NativeOwnerIdentity {
        unique_name: ":1.42".into(),
        uid: 1000,
        pid: 42,
        invocation: value(SecurityOwnerInvocationId::new(
            "98765432-1234-4567-89ab-0123456789ab",
        )),
    }
}

fn lock() -> SessionLockId {
    value(SessionLockId::new(
        value(SessionEpoch::new(
            value(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            1000,
            "c2",
            42,
        )),
        identity().invocation,
        7,
    ))
}

#[test]
fn power_permission_requires_exact_transition_scope_and_preserves_native_sample_age() {
    let transition = value(SessionTransitionId::new(lock(), SessionTransition::Reboot));
    let resource = value(transition.resource_id());
    for availability in ["yes", "challenge", "no"] {
        let observed = value(power_permission_observation(
            &transition,
            resource.as_str(),
            availability,
            100,
            150,
            1_000,
            1,
        ));
        assert_eq!(observed.observed_at_unix_ms, 950);
        assert_eq!(observed.valid_for_ms, 1_999);
        assert_eq!(observed.provider.as_str(), "polkit");
        assert_eq!(
            observed.attributes.get("permission_query_principal"),
            Some(&ObservedValue::Text("unix:uid:1000".into()))
        );
    }
    assert!(
        power_permission_observation(&transition, resource.as_str(), "yes", 100, 2_099, 4_000, 1)
            .is_ok()
    );
    for (received, availability, sample, now, wall, sequence) in [
        (resource.as_str(), "yes", 100, 2_100, 4_000, 1),
        (resource.as_str(), "yes", 101, 100, 4_000, 1),
        (resource.as_str(), "yes", 0, 100, 4_000, 1),
        (resource.as_str(), "yes", 100, 150, 50, 1),
        (resource.as_str(), "yes", 100, 150, 1_000, 0),
        (resource.as_str(), "authorized", 100, 150, 1_000, 1),
        (
            "session:transition:power-off:0:substituted",
            "yes",
            100,
            150,
            1_000,
            1,
        ),
    ] {
        assert!(
            power_permission_observation(
                &transition,
                received,
                availability,
                sample,
                now,
                wall,
                sequence
            )
            .is_err()
        );
    }
    let logout = value(SessionTransitionId::new(lock(), SessionTransition::Logout));
    assert!(
        power_permission_observation(
            &logout,
            value(logout.resource_id()).as_str(),
            "yes",
            100,
            150,
            1_000,
            1
        )
        .is_err()
    );
}

fn properties() -> (Properties, Properties) {
    let invocation = vec![
        0x98_u8, 0x76, 0x54, 0x32, 0x12, 0x34, 0x45, 0x67, 0x89, 0xab, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab,
    ];
    let launch: ExecStart = (
        IMAGE.into(),
        vec![IMAGE.into()],
        false,
        10,
        10,
        0,
        0,
        42,
        0,
        0,
    );
    let unit = Properties::from([
        (
            "InvocationID".into(),
            value(OwnedValue::try_from(Value::from(invocation))),
        ),
        (
            "DropInPaths".into(),
            value(OwnedValue::try_from(Value::from(Vec::<String>::new()))),
        ),
        (
            "FragmentPath".into(),
            value(OwnedValue::try_from(Value::from(FRAGMENT))),
        ),
        (
            "ActiveState".into(),
            value(OwnedValue::try_from(Value::from("active"))),
        ),
        (
            "SubState".into(),
            value(OwnedValue::try_from(Value::from("running"))),
        ),
    ]);
    let service = Properties::from([
        ("MainPID".into(), OwnedValue::from(42_u32)),
        (
            "User".into(),
            value(OwnedValue::try_from(Value::from("1000"))),
        ),
        (
            "ExecStart".into(),
            value(OwnedValue::try_from(Value::from(vec![launch]))),
        ),
    ]);
    (unit, service)
}

#[test]
fn attestation_requires_exact_supervised_image_user_invocation_and_launch() {
    let (unit, service) = properties();
    assert_eq!(
        value(bind_supervised(1000, &unit, &service, true, true)),
        (42, identity().invocation)
    );
    for (key, wrong) in [
        ("MainPID", OwnedValue::from(0_u32)),
        ("MainPID", OwnedValue::from(42_u64)),
        ("User", value(OwnedValue::try_from(Value::from("root")))),
        ("User", value(OwnedValue::try_from(Value::from("01000")))),
        (
            "ExecStart",
            value(OwnedValue::try_from(Value::from(Vec::<ExecStart>::new()))),
        ),
    ] {
        let (_, mut service) = properties();
        service.insert(key.into(), wrong);
        assert!(
            bind_supervised(1000, &unit, &service, true, true).is_err(),
            "{key}"
        );
    }
    for (key, wrong) in [
        (
            "InvocationID",
            value(OwnedValue::try_from(Value::from(vec![0_u8; 16]))),
        ),
        (
            "InvocationID",
            value(OwnedValue::try_from(Value::from(vec![1_u8; 15]))),
        ),
        (
            "DropInPaths",
            value(OwnedValue::try_from(Value::from(vec![
                "/etc/override.conf".to_owned(),
            ]))),
        ),
        (
            "FragmentPath",
            value(OwnedValue::try_from(Value::from(
                "/etc/systemd/system/override.service",
            ))),
        ),
        (
            "ActiveState",
            value(OwnedValue::try_from(Value::from("activating"))),
        ),
        (
            "SubState",
            value(OwnedValue::try_from(Value::from("exited"))),
        ),
    ] {
        let (mut unit, service) = properties();
        unit.insert(key.into(), wrong);
        assert!(
            bind_supervised(1000, &unit, &service, true, true).is_err(),
            "{key}"
        );
    }
    assert!(bind_supervised(0, &unit, &service, true, true).is_err());
    assert!(bind_supervised(1000, &unit, &service, false, true).is_err());
    assert!(bind_supervised(1000, &unit, &service, true, false).is_err());
}

#[test]
fn supervision_refusals_report_only_closed_stages() {
    for stage in [
        "process",
        "user",
        "unit",
        "state",
        "invocation",
        "launch",
        "assets",
    ] {
        let (mut unit, mut service) = properties();
        let mut uid = 1000;
        let mut immutable_image = true;
        match stage {
            "process" => uid = 0,
            "user" => {
                service.insert(
                    "User".into(),
                    value(OwnedValue::try_from(Value::from("private-wire-marker"))),
                );
            }
            "unit" => {
                unit.insert(
                    "FragmentPath".into(),
                    value(OwnedValue::try_from(Value::from("private-wire-marker"))),
                );
            }
            "state" => {
                unit.insert(
                    "ActiveState".into(),
                    value(OwnedValue::try_from(Value::from("private-wire-marker"))),
                );
            }
            "invocation" => {
                unit.insert(
                    "InvocationID".into(),
                    value(OwnedValue::try_from(Value::from(vec![0_u8; 16]))),
                );
            }
            "launch" => {
                service.insert(
                    "ExecStart".into(),
                    value(OwnedValue::try_from(Value::from(Vec::<ExecStart>::new()))),
                );
            }
            _ => immutable_image = false,
        }
        assert_eq!(
            bind_supervised(uid, &unit, &service, true, immutable_image).err(),
            Some(format!(
                "native owner is not the exact immutable supervised invocation: supervision={stage}"
            ))
        );
    }
}

#[test]
fn exec_start_history_arguments_and_pid_cannot_replace_exact_live_launch() {
    let launches: [ExecStart; 6] = [
        (
            IMAGE.into(),
            vec![IMAGE.into(), "--untrusted".into()],
            false,
            10,
            10,
            0,
            0,
            42,
            0,
            0,
        ),
        (
            IMAGE.into(),
            vec![IMAGE.into()],
            true,
            10,
            10,
            0,
            0,
            42,
            0,
            0,
        ),
        (
            IMAGE.into(),
            vec![IMAGE.into()],
            false,
            0,
            10,
            0,
            0,
            42,
            0,
            0,
        ),
        (
            IMAGE.into(),
            vec![IMAGE.into()],
            false,
            10,
            0,
            0,
            0,
            42,
            0,
            0,
        ),
        (
            IMAGE.into(),
            vec![IMAGE.into()],
            false,
            10,
            10,
            11,
            0,
            42,
            0,
            0,
        ),
        (
            IMAGE.into(),
            vec![IMAGE.into()],
            false,
            10,
            10,
            0,
            0,
            43,
            0,
            0,
        ),
    ];
    for launch in launches {
        let (unit, mut service) = properties();
        service.insert(
            "ExecStart".into(),
            value(OwnedValue::try_from(Value::from(vec![launch]))),
        );
        assert!(bind_supervised(1000, &unit, &service, true, true).is_err());
    }
}

#[test]
fn native_freshness_is_preserved_at_exclusive_two_second_boundary() {
    let lock = lock();
    let resource = value(lock.resource_id());
    let envelope = value(observation(
        &identity(),
        lock.epoch().boot(),
        resource.as_str(),
        true,
        10_000,
        11_999,
        100_000,
        1,
    ));
    assert_eq!(envelope.observed_at_unix_ms, 98_001);
    assert_eq!(envelope.valid_for_ms, 1_999);
    assert!(envelope.require_current(100_000).is_ok());
    assert!(envelope.require_current(100_001).is_err());
    for (sample, now, wall) in [
        (10_000, 12_000, 100_000),
        (12_000, 10_000, 100_000),
        (0, 1, 100_000),
        (10_000, 11_000, 1_000),
    ] {
        assert!(
            observation(
                &identity(),
                lock.epoch().boot(),
                resource.as_str(),
                true,
                sample,
                now,
                wall,
                1
            )
            .is_err()
        );
    }
}

#[test]
fn changed_native_identity_and_noncanonical_resource_are_rejected() {
    let lock = lock();
    let resource = value(lock.resource_id());
    let mut other = identity();
    other.uid = 1001;
    assert!(
        observation(
            &other,
            lock.epoch().boot(),
            resource.as_str(),
            true,
            100,
            100,
            1000,
            1
        )
        .is_err()
    );
    other = identity();
    other.invocation = value(SecurityOwnerInvocationId::new(
        "12345678-1234-4567-89ab-0123456789ab",
    ));
    assert!(
        observation(
            &other,
            lock.epoch().boot(),
            resource.as_str(),
            true,
            100,
            100,
            1000,
            1
        )
        .is_err()
    );
    assert!(
        observation(
            &identity(),
            lock.epoch().boot(),
            "session:lock:bad",
            true,
            100,
            100,
            1000,
            1
        )
        .is_err()
    );
    assert!(
        SessionLockId::from_resource(&value(ResourceId::new(
            resource.as_str().replace(":1000:", ":01000:")
        )))
        .is_err()
    );
}

#[test]
fn approval_scope_is_exact_and_purpose_bound() {
    let mut request = NativeApprovalRequest {
        transition: None,
        lock: lock(),
        principal: value(PrincipalId::new("unix:uid:1000")),
        request: value(RequestId::new("request:v010:session-lock:lock-now")),
        plan: value(PlanId::new("request:v010:session-lock:lock-now")),
        request_digest: ComponentDigest::from_bytes([1; 32]),
        observation_digest: ComponentDigest::from_bytes([2; 32]),
        review_digest: ComponentDigest::from_bytes([3; 32]),
        purpose: NativeApprovalPurpose::Lock,
    };
    assert_eq!(value(request.wire()).7, 0);
    request.purpose = NativeApprovalPurpose::Unlock;
    assert_eq!(value(request.wire()).7, 1);
    request.principal = value(PrincipalId::new("unix:uid:0"));
    assert!(request.wire().is_err());
    request.principal = value(PrincipalId::new("unix:uid:1000"));
    for slug in ["", "-x", "x-", "x--y", "Upper", "a/b"] {
        request.request = value(RequestId::new(format!("request:v010:session-lock:{slug}")));
        request.plan = value(PlanId::new(request.request.as_str()));
        assert!(request.wire().is_err());
    }
}

#[test]
fn power_approval_wire_cannot_alias_unlock_or_another_transition() {
    let actions = [
        (
            NativeApprovalPurpose::Suspend,
            SessionTransition::Suspend {
                successful_cycles_before: 12,
            },
            2,
        ),
        (NativeApprovalPurpose::Logout, SessionTransition::Logout, 3),
        (NativeApprovalPurpose::Reboot, SessionTransition::Reboot, 4),
        (
            NativeApprovalPurpose::PowerOff,
            SessionTransition::PowerOff,
            5,
        ),
    ];
    for (purpose, action, wire_purpose) in actions {
        let transition = value(SessionTransitionId::new(lock(), action));
        let mut request = NativeApprovalRequest {
            lock: lock(),
            transition: Some(transition.clone()),
            principal: value(PrincipalId::new("unix:uid:1000")),
            request: value(RequestId::new("request:v010:session-transition:power-test")),
            plan: value(PlanId::new("request:v010:session-transition:power-test")),
            request_digest: ComponentDigest::from_bytes([1; 32]),
            observation_digest: ComponentDigest::from_bytes([2; 32]),
            review_digest: ComponentDigest::from_bytes([3; 32]),
            purpose,
        };
        let wire = value(request.wire());
        assert_eq!(wire.0, value(transition.resource_id()).as_str());
        assert_eq!(wire.7, wire_purpose);
        for (other, _, _) in actions {
            request.purpose = other;
            assert_eq!(request.wire().is_ok(), other == purpose);
        }
        request.purpose = NativeApprovalPurpose::Unlock;
        assert!(request.wire().is_err());
        request.purpose = purpose;
        request.transition = None;
        assert!(request.wire().is_err());
        request.transition = Some(transition);
        request.request = value(RequestId::new("request:v010:session-lock:power-test"));
        request.plan = value(PlanId::new(request.request.as_str()));
        assert!(request.wire().is_err());
    }
}

#[test]
fn private_wire_signatures_preserve_one_struct_argument_not_flat_fields() {
    let call = value(value(zbus::Message::method_call(ENDPOINT, "ObserveLock")).build(&()));
    let reply = value(
        value(zbus::Message::method_return(&call.header())).build(&((
            "session:lock:example",
            true,
            42_u64,
        ),)),
    );
    assert_eq!(reply.body().signature().to_string(), "(sbt)");
    let ((resource, secure, sample),): ((String, bool, u64),) = value(reply.body().deserialize());
    assert_eq!(
        (resource.as_str(), secure, sample),
        ("session:lock:example", true, 42)
    );
    assert!(require_observation_signature(&reply).is_ok());
    // The parsed Signature normalizes top-level grouping; verify the actual
    // serialized header as well, rather than drawing conclusions from Display.
    assert!(
        reply
            .data()
            .bytes()
            .windows(6)
            .any(|bytes| bytes == b"(sbt)\0")
    );
    let wrong_type = value(
        value(zbus::Message::method_return(&call.header())).build(&((
            "session:lock:example",
            true,
            42_u32,
        ),)),
    );
    assert!(require_observation_signature(&wrong_type).is_err());
}

#[test]
fn unique_bus_name_parser_rejects_preclaimable_and_malformed_names() {
    assert!(unique_name(":1.42"));
    for name in [
        "org.linura.Fake",
        ":1",
        ":1.",
        ":.1",
        ":1..2",
        ":1.a",
        ":1.2\n",
    ] {
        assert!(!unique_name(name));
    }
}

#[test]
fn authentication_requires_exact_active_local_wayland_leader_and_epoch() {
    fn session() -> Properties {
        Properties::from([
            (
                "User".into(),
                value(OwnedValue::try_from(Value::from((
                    1000_u32,
                    value(OwnedObjectPath::try_from(
                        "/org/freedesktop/login1/user/_1000",
                    )),
                )))),
            ),
            ("Id".into(), value(OwnedValue::try_from(Value::from("c2")))),
            ("TimestampMonotonic".into(), OwnedValue::from(42_u64)),
            ("Leader".into(), OwnedValue::from(51_u32)),
            (
                "Type".into(),
                value(OwnedValue::try_from(Value::from("wayland"))),
            ),
            (
                "Class".into(),
                value(OwnedValue::try_from(Value::from("user"))),
            ),
            (
                "State".into(),
                value(OwnedValue::try_from(Value::from("active"))),
            ),
            ("Active".into(), OwnedValue::from(true)),
            ("Remote".into(), OwnedValue::from(false)),
        ])
    }
    assert_eq!(value(authentication_leader(&lock(), &session())), 51);
    for (key, wrong) in [
        ("Id", value(OwnedValue::try_from(Value::from("c3")))),
        ("TimestampMonotonic", OwnedValue::from(43_u64)),
        ("TimestampMonotonic", OwnedValue::from(42_u32)),
        ("Leader", OwnedValue::from(0_u32)),
        ("Leader", OwnedValue::from(u32::MAX)),
        ("Type", value(OwnedValue::try_from(Value::from("tty")))),
        ("Class", value(OwnedValue::try_from(Value::from("manager")))),
        ("State", value(OwnedValue::try_from(Value::from("closing")))),
        ("Active", OwnedValue::from(false)),
        ("Remote", OwnedValue::from(true)),
        (
            "User",
            value(OwnedValue::try_from(Value::from((
                1001_u32,
                value(OwnedObjectPath::try_from(
                    "/org/freedesktop/login1/user/_1001",
                )),
            )))),
        ),
    ] {
        let mut facts = session();
        facts.insert(key.into(), wrong);
        assert!(authentication_leader(&lock(), &facts).is_err(), "{key}");
    }
    for key in session().keys() {
        let mut facts = session();
        facts.remove(key);
        assert!(
            authentication_leader(&lock(), &facts).is_err(),
            "missing {key}"
        );
    }
}

#[test]
fn process_start_parser_handles_parentheses_but_rejects_wrong_or_unknown_generation() {
    let fields = std::iter::once("S")
        .chain(std::iter::repeat_n("1", 18))
        .chain(["1234", "0"])
        .collect::<Vec<_>>()
        .join(" ");
    let stat = format!("51 (compositor ) name) {fields}\n");
    assert_eq!(parse_process_start(51, &stat), Ok(1234));
    assert!(parse_process_start(52, &stat).is_err());
    assert!(parse_process_start(51, "51 (missing) S 1").is_err());
    assert!(parse_process_start(51, &stat.replace("1234", "0")).is_err());
    assert!(parse_process_start(51, &stat.replace("1234", "invalid")).is_err());
    assert!(parse_process_start(51, &stat.replace("1234", "18446744073709551616")).is_err());
}
