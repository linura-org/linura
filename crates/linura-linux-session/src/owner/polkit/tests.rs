use super::*;
use zbus::zvariant::Value;

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture failed: {error:?}"))
}

fn owned<T: Into<Value<'static>>>(data: T) -> OwnedValue {
    value(OwnedValue::try_from(data.into()))
}

fn launch() -> ExecStart {
    (
        POLKIT_IMAGE.into(),
        vec![
            POLKIT_IMAGE.into(),
            "--no-debug".into(),
            "--log-level=notice".into(),
        ],
        false,
        10,
        10,
        0,
        0,
        42,
        0,
        0,
    )
}

fn facts() -> (Properties, Properties) {
    (
        HashMap::from([
            ("Id".into(), owned(POLKIT_UNIT)),
            ("FragmentPath".into(), owned(POLKIT_FRAGMENT)),
            ("ActiveState".into(), owned("active")),
            ("SubState".into(), owned("running")),
            ("InvocationID".into(), owned(vec![1_u8; 16])),
            ("DropInPaths".into(), owned(Vec::<String>::new())),
        ]),
        HashMap::from([
            ("MainPID".into(), owned(42_u32)),
            ("ExecStart".into(), owned(vec![launch()])),
        ]),
    )
}

fn bind(unit: &Properties, service: &Properties) -> Result<AuthenticationDaemonIdentity, String> {
    bind_polkit((":1.7", 102, 42), ":1.0", 102, unit, service, (true, true))
}

#[test]
fn polkit_identity_requires_exact_local_account_and_immutable_supervised_invocation() {
    let (unit, service) = facts();
    let identity = value(bind(&unit, &service));
    assert_eq!(identity.uid, 102);
    assert_eq!(identity.pid, 42);
    assert_eq!(identity.invocation, [1; 16]);
    for (peer, supervisor, account, immutable) in [
        ((":1.7", 0, 42), ":1.0", 102, (true, true)),
        ((":1.7", 103, 42), ":1.0", 102, (true, true)),
        ((":1.7", 102, 43), ":1.0", 102, (true, true)),
        ((":1.7", 102, 1), ":1.0", 102, (true, true)),
        ((":1.7", 102, 42), ":1.0", 0, (true, true)),
        (
            ("org.freedesktop.PolicyKit1", 102, 42),
            ":1.0",
            102,
            (true, true),
        ),
        (
            (":1.7", 102, 42),
            "org.freedesktop.systemd1",
            102,
            (true, true),
        ),
        ((":1.7", 102, 42), ":1.0", 102, (false, true)),
        ((":1.7", 102, 42), ":1.0", 102, (true, false)),
    ] {
        assert!(bind_polkit(peer, supervisor, account, &unit, &service, immutable).is_err());
    }
    for (key, replacement) in [
        ("Id", owned("another.service")),
        ("FragmentPath", owned("/run/systemd/system/polkit.service")),
        ("ActiveState", owned("inactive")),
        ("SubState", owned("exited")),
        ("InvocationID", owned(vec![0_u8; 16])),
        ("InvocationID", owned(vec![1_u8; 15])),
        ("InvocationID", owned("not-a-byte-array")),
        ("DropInPaths", owned(vec!["/run/override.conf".to_owned()])),
    ] {
        let (mut changed, service) = facts();
        changed.insert(key.into(), replacement);
        assert!(bind(&changed, &service).is_err());
    }
    for name in unit.keys() {
        let (mut changed, service) = facts();
        changed.remove(name);
        assert!(bind(&changed, &service).is_err());
    }
    for name in service.keys() {
        let (unit, mut changed) = facts();
        changed.remove(name);
        assert!(bind(&unit, &changed).is_err());
    }
}

#[test]
fn polkit_launch_cannot_substitute_image_argv_pid_or_finished_generation() {
    for index in 0..8 {
        let (unit, mut service) = facts();
        let mut changed = launch();
        match index {
            0 => changed.0 = "/another/image".into(),
            1 => changed.1.push("--another-option".into()),
            2 => changed.2 = true,
            3 => changed.3 = 0,
            4 => changed.4 = 0,
            5 => changed.5 = 11,
            6 => changed.7 = 43,
            _ => changed.9 = 1,
        }
        service.insert("ExecStart".into(), owned(vec![changed]));
        assert!(bind(&unit, &service).is_err());
    }
    for launches in [vec![], vec![launch(), launch()]] {
        let (unit, mut service) = facts();
        service.insert("ExecStart".into(), owned(launches));
        assert!(bind(&unit, &service).is_err());
    }
    let (unit, mut service) = facts();
    service.insert("MainPID".into(), owned(43_u32));
    assert!(bind(&unit, &service).is_err());
}
