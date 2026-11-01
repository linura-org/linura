use super::*;

fn stream() -> Stream {
    Stream {
        initial: 40,
        last: 40,
        valid: true,
        ancestors: BTreeSet::new(),
    }
}

#[test]
fn driver_and_bus_ancestor_events_invalidate_only_the_bound_kernel_lifetimes() {
    let (relative, ancestors) = card_path(std::path::Path::new(
        "class/drm/../../devices/pci0000:00/0000:00:02.0/drm/card0",
    ))
    .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(relative, "devices/pci0000:00/0000:00:02.0/drm/card0");
    for path in &ancestors {
        let mut stream = stream();
        stream.ancestors = ancestors.clone();
        let raw = String::from_utf8(event(41, "pci"))
            .unwrap_or_else(|_| unreachable!())
            .replace("/devices/test", path);
        assert!(stream.accept(raw.as_bytes(), true).is_err());
        assert!(!stream.valid);
    }
    for path in ["/devices/test", "/devices/pci0000:01/other"] {
        let mut stream = stream();
        stream.ancestors = ancestors.clone();
        let raw = String::from_utf8(event(41, "usb"))
            .unwrap_or_else(|_| unreachable!())
            .replace("/devices/test", path);
        assert!(stream.accept(raw.as_bytes(), true).is_ok());
    }
    for raw in [
        "/devices/pci/card0",
        "../../devices/pci/card0",
        "class/drm/../../../devices/pci/card0",
        "class/card0",
    ] {
        assert!(card_path(std::path::Path::new(raw)).is_err());
    }
}
fn event(seq: u64, subsystem: &str) -> Vec<u8> {
    format!("change@/devices/test\0ACTION=change\0DEVPATH=/devices/test\0SUBSYSTEM={subsystem}\0SEQNUM={seq}\0").into_bytes()
}

#[test]
fn kernel_events_are_ordered_and_do_not_revive_after_fault() {
    let mut stream = stream();
    assert!(stream.accept(&event(39, "drm"), true).is_ok()); // Before baseline.
    assert!(stream.accept(&event(40, "drm"), true).is_ok());
    assert!(stream.accept(&event(41, "input"), true).is_ok());
    assert!(stream.accept(&event(42, "block"), true).is_ok());
    assert!(stream.accept(&event(44, "input"), true).is_err()); // Lost event43.
    assert!(!stream.valid);
    assert!(stream.accept(&event(43, "input"), true).is_err());
}

#[test]
fn hotplug_and_even_identical_returned_geometry_cannot_restore_continuity() {
    for action in [
        "add", "remove", "change", "move", "online", "offline", "bind", "unbind",
    ] {
        let mut stream = stream();
        let raw = String::from_utf8(event(41, "drm")).unwrap_or_else(|_| unreachable!());
        let raw = raw.replace("change", action);
        assert!(stream.accept(raw.as_bytes(), true).is_err());
        assert!(stream.accept(&event(42, "input"), true).is_err());
    }
}

#[test]
fn malformed_duplicate_synthetic_or_untrusted_events_poison_the_stream() {
    let valid = String::from_utf8(event(41, "input")).unwrap_or_else(|_| unreachable!());
    let cases = [
        String::new(),
        valid.trim_end_matches('\0').into(),
        valid.replace("SEQNUM=41", "SEQNUM=041"),
        valid.replace("SEQNUM=41", "SEQNUM=0"),
        valid.replace("SEQNUM=41", "SEQNUM=18446744073709551615"),
        valid.replace("SEQNUM=41", "SEQNUM=41\0SEQNUM=41"),
        valid.replace("ACTION=change", "ACTION=add"),
        valid.replace("SUBSYSTEM=input", "SUBSYSTEM="),
        valid.replace("DEVPATH=/devices/test", "DEVPATH=/devices/../test"),
        valid.replace("SEQNUM=41", "SEQNUM=41\0SYNTH_UUID=0"),
        valid.replace("ACTION=change", "ACTION=unknown"),
        valid.replace("SUBSYSTEM=input", "subsystem=input"),
        valid.replace("SEQNUM=41", "SEQNUM=41\0BAD"),
        valid.replace(
            "SEQNUM=41",
            &format!("SEQNUM=41\0EXTRA={}", "x".repeat(4097)),
        ),
    ];
    for raw in cases {
        let mut stream = stream();
        assert!(stream.accept(raw.as_bytes(), true).is_err());
        assert!(!stream.valid);
        assert!(stream.accept(valid.as_bytes(), true).is_err());
    }
    for raw in [vec![255, 0], vec![0; MAX_EVENT_BYTES + 1]] {
        assert!(stream().accept(&raw, true).is_err());
    }
    let mut stream = stream();
    assert!(stream.accept(valid.as_bytes(), false).is_err());
    assert!(stream.accept(valid.as_bytes(), true).is_err());
}

#[test]
fn duplicates_rewinds_and_sequence_exhaustion_fail_closed() {
    for second in [39, 40, 41, 43, u64::MAX] {
        let mut stream = stream();
        assert!(stream.accept(&event(41, "input"), true).is_ok());
        assert!(stream.accept(&event(second, "input"), true).is_err());
    }
    for raw in [
        "",
        "01",
        "+1",
        "-1",
        "1\n",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        assert!(number(raw).is_err());
    }
}

#[test]
fn retained_attributes_are_reread_and_unknown_states_are_not_continuity() {
    // Portable mechanism fixture only: normal files do not reproduce kernfs
    // removal semantics. Actual unbind/remove requires native VM qualification.
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let root =
        std::env::temp_dir().join(format!("linura-kernel-attributes-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap_or_else(|e| unreachable!("{e}"));
    let open = |name: &str, value: &str| {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))
            .unwrap_or_else(|e| unreachable!("{e}"));
        file.write_all(value.as_bytes())
            .unwrap_or_else(|e| unreachable!("{e}"));
        file
    };
    let dev = open("dev", "226:0\n");
    let id = open("id", "42\n");
    let mut status = open("status", "connected\n");
    let connector = Connector {
        dev: dev.into(),
        id: id.into(),
        status: status
            .try_clone()
            .unwrap_or_else(|e| unreachable!("{e}"))
            .into(),
        expected: [226, 0, 42],
    };
    assert!(connector.verify().is_ok());
    for invalid in [
        "disconnected\n",
        "unknown\n",
        "connected",
        "connected\nextra\n",
        "",
    ] {
        status.set_len(0).unwrap_or_else(|e| unreachable!("{e}"));
        status
            .seek(SeekFrom::Start(0))
            .unwrap_or_else(|e| unreachable!("{e}"));
        status
            .write_all(invalid.as_bytes())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(connector.verify().is_err());
    }
    std::fs::remove_dir_all(root).unwrap_or_else(|e| unreachable!("{e}"));
}

#[test]
fn unread_stream_watermark_and_bad_transport_are_permanently_fenced() {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::{fs::OpenOptionsExt, net::UnixDatagram};
    for (index, message) in [
        None,
        Some(event(41, "input")),
        Some(vec![b'x'; MAX_EVENT_BYTES + 1]),
        None, // A completed sleep hidden by current PreparingForSleep=false.
        None, // A failed sleep still invalidates native output continuity.
    ]
    .into_iter()
    .enumerate()
    {
        let path = std::env::temp_dir().join(format!(
            "linura-kernel-sequence-{}-{index}",
            std::process::id()
        ));
        let mut sequence = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap_or_else(|e| unreachable!("{e}"));
        sequence
            .write_all(b"40\n")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let power_paths = [path.with_extension("success"), path.with_extension("fail")];
        let counters: Vec<_> = power_paths
            .iter()
            .map(|path| {
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                file.write_all(b"40\n")
                    .unwrap_or_else(|e| unreachable!("{e}"));
                file
            })
            .collect();
        let (receiver, sender) = UnixDatagram::pair().unwrap_or_else(|e| unreachable!("{e}"));
        receiver
            .set_nonblocking(true)
            .unwrap_or_else(|e| unreachable!("{e}"));
        // Deliberately invalid test-only subscription: this is NOT a kernel
        // continuity fixture or a deserialization/admission path.
        let mut witness = NativeDisplayKernelWitness {
            subscription: NativeDisplayKernelSubscription {
                sys: sequence
                    .try_clone()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .into(),
                sequence: sequence
                    .try_clone()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .into(),
                socket: receiver.into(),
                stream: stream(),
                power: PowerEpoch {
                    success: counters[0]
                        .try_clone()
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .into(),
                    fail: counters[1]
                        .try_clone()
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .into(),
                    expected: [40, 40],
                },
            },
            connectors: Vec::new(),
        };
        assert!(witness.verify().is_ok());
        if index >= 3 {
            rustix::io::pwrite(&counters[index - 3], b"41\n", 0)
                .unwrap_or_else(|e| unreachable!("{e}"));
        } else if let Some(bytes) = message {
            sender.send(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
        } else {
            // Lost final event, without a subsequent event to expose its gap.
            rustix::io::pwrite(&sequence, b"41\n", 0).unwrap_or_else(|e| unreachable!("{e}"));
        }
        assert!(witness.verify().is_err());
        rustix::io::pwrite(&sequence, b"40\n", 0).unwrap_or_else(|e| unreachable!("{e}"));
        for counter in &counters {
            rustix::io::pwrite(counter, b"40\n", 0).unwrap_or_else(|e| unreachable!("{e}"));
        }
        assert!(witness.verify().is_err());
        assert!(!witness.subscription.stream.valid);
        std::fs::remove_file(path).unwrap_or_else(|e| unreachable!("{e}"));
        for path in power_paths {
            std::fs::remove_file(path).unwrap_or_else(|e| unreachable!("{e}"));
        }
    }
}
