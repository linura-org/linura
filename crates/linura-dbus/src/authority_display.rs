//! Experimental read-only display report codec. No observation/approval or
//! executor authority crosses this client boundary.
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{
    DisplayLayout, DisplayMode, DisplayOutputId, DisplayOutputSet, DisplayTopologyId,
    NativeOutputCapabilities, ResourceId, SessionLockId,
};
use linura_protocol::DisplaySnapshot;

type OutputWire = (u64, u64, bool, Vec<(u32, u32, u32)>, bool);
pub(crate) type DisplaySnapshotWire = (String, String, u64, u64, Vec<OutputWire>);
pub(crate) const MAX_DISPLAY_REPLY_BYTES: usize = 64 * 1024;

pub(crate) fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "display client clock is unavailable")?
            .as_millis(),
    )
    .map_err(|_| "display client clock overflow".into())
}

pub(crate) fn encode_snapshot(
    snapshot: DisplaySnapshot,
    principal: &str,
    now: u64,
) -> Result<DisplaySnapshotWire, String> {
    snapshot.validate(now)?;
    if principal != format!("unix:uid:{}", snapshot.lock.epoch().uid()) {
        return Err("display snapshot belongs to another authenticated principal".into());
    }
    let mut outputs = Vec::new();
    for row in snapshot.layout.outputs() {
        let cap = snapshot
            .capabilities
            .iter()
            .find(|cap| cap.output() == row.output())
            .ok_or("display snapshot capability is missing")?;
        outputs.push((
            row.output().handle(),
            row.output().generation(),
            cap.can_disable(),
            cap.modes()
                .iter()
                .map(|mode| (mode.width(), mode.height(), mode.refresh_millihz()))
                .collect(),
            snapshot.powered_outputs.contains(row.output()),
        ));
    }
    Ok((
        snapshot
            .lock
            .resource_id()
            .map_err(|e| e.to_string())?
            .as_str()
            .into(),
        snapshot
            .layout
            .canonical_text()
            .map_err(|e| e.to_string())?,
        snapshot.observed_at_unix_ms,
        snapshot.valid_for_ms,
        outputs,
    ))
}

pub(crate) fn decode_snapshot(
    wire: DisplaySnapshotWire,
    now: u64,
) -> Result<DisplaySnapshot, String> {
    let (lock, layout, observed_at_unix_ms, valid_for_ms, rows) = wire;
    if lock.len() > 256 || layout.len() > 4096 || rows.is_empty() || rows.len() > 16 {
        return Err("display snapshot exceeds its complete inventory bounds".into());
    }
    let lock = SessionLockId::from_resource(&ResourceId::new(lock).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let topology = layout
        .strip_prefix("LNDL:1;")
        .and_then(|rest| rest.split_once(';'))
        .map(|(resource, _)| resource)
        .ok_or("display snapshot layout encoding is unsupported")?;
    let topology =
        DisplayTopologyId::from_resource(&ResourceId::new(topology).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut outputs = Vec::new();
    let mut capabilities = Vec::new();
    let mut powered_outputs = BTreeSet::new();
    for (handle, generation, can_disable, modes, powered) in rows {
        let output = DisplayOutputId::new(topology.clone(), handle, generation)
            .map_err(|e| e.to_string())?;
        if outputs.last().is_some_and(|last| last >= &output)
            || modes.is_empty()
            || modes.len() > 128
            || modes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(
                "display snapshot output/mode inventory is ambiguous or noncanonical".into(),
            );
        }
        let modes = modes
            .into_iter()
            .map(|(width, height, refresh)| {
                DisplayMode::new(width, height, refresh).map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        capabilities.push(
            NativeOutputCapabilities::new(output.clone(), modes, can_disable)
                .map_err(|e| e.to_string())?,
        );
        if powered {
            powered_outputs.insert(output.clone());
        }
        outputs.push(output);
    }
    let inventory = DisplayOutputSet::new(topology, outputs).map_err(|e| e.to_string())?;
    let layout = DisplayLayout::from_canonical_text(&inventory, &capabilities, &layout)
        .map_err(|e| e.to_string())?;
    let snapshot = DisplaySnapshot {
        lock,
        layout,
        capabilities,
        powered_outputs,
        observed_at_unix_ms,
        valid_for_ms,
    };
    snapshot.validate(now)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn wire() -> DisplaySnapshotWire {
        let lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1";
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        (
            lock.into(),
            format!("LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:0:0:-;2:4:disabled;"),
            1000,
            2000,
            vec![
                (
                    1,
                    2,
                    true,
                    vec![(1280, 720, 60000), (1920, 1080, 60000)],
                    true,
                ),
                (2, 4, true, vec![(1920, 1080, 60000)], false),
            ],
        )
    }

    #[test]
    fn discovery_wire_round_trips_complete_typed_inventory_and_original_freshness() {
        let wire = wire();
        let snapshot = value(decode_snapshot(wire.clone(), 1100));
        assert_eq!(snapshot.layout.outputs().len(), 2);
        assert_eq!(snapshot.capabilities[0].modes().len(), 2);
        assert_eq!(snapshot.powered_outputs.len(), 1);
        assert_eq!(
            value(encode_snapshot(snapshot.clone(), "unix:uid:1000", 1100)),
            wire
        );
        assert!(encode_snapshot(snapshot.clone(), "unix:uid:1001", 1100).is_err());
        assert!(encode_snapshot(snapshot, "unix:uid:1000", 3000).is_err());
        let message = value(zbus::Message::method_call(
            "/org/linura/Authority1",
            "GetOwnDisplaySnapshot",
        ))
        .build(&(wire.clone(),));
        let message = value(message);
        assert_eq!(
            message.body().signature().to_string(),
            "(sstta(ttba(uuu)b))"
        );
        let (decoded,): (DisplaySnapshotWire,) = value(message.body().deserialize());
        assert_eq!(
            value(decode_snapshot(decoded, 1100)),
            value(decode_snapshot(wire, 1100))
        );
    }

    #[test]
    fn discovery_rejects_substituted_incomplete_ambiguous_or_stale_reports() {
        for case in 0..20 {
            let mut wire = wire();
            match case {
                0 => wire.0 = wire.0.replace(":1000:", ":1001:"),
                1 => wire.0 = wire.0.replace(":42:", ":43:"),
                2 => wire.1 = wire.1.replace("1:2:enabled", "1:3:enabled"),
                3 => wire.2 = 0,
                4 => wire.2 = 1200,
                5 => wire.3 = 0,
                6 => wire.3 = 2001,
                7 => wire.4.clear(),
                8 => {
                    wire.4.pop();
                }
                9 => wire.4.push(wire.4[0].clone()),
                10 => {
                    let mode = wire.4[0].3[0];
                    wire.4[0].3.push(mode);
                }
                11 => wire.4[0].3.reverse(),
                12 => wire.4[0].3.clear(),
                13 => wire.4[0].3 = vec![(0, 1080, 60000)],
                14 => wire.4[1].4 = true,
                15 => wire.4.reverse(),
                16 => wire.4[0].1 += 1,
                17 => wire.1 = wire.1.replace("LNDL:1", "LNDL:2"),
                18 => wire.1 = "x".repeat(4097),
                _ => wire.3 = u64::MAX,
            }
            assert!(decode_snapshot(wire, 1100).is_err(), "case {case}");
        }
        assert!(decode_snapshot(wire(), 3000).is_err());
        let mut snapshot = value(decode_snapshot(wire(), 1100));
        snapshot.capabilities.push(snapshot.capabilities[0].clone());
        assert!(snapshot.validate(1100).is_err());
    }

    #[test]
    fn complete_sixteen_output_mode_inventory_fits_only_its_dedicated_reply_bound() {
        let mut wire = wire();
        let prefix = wire
            .1
            .split(";1:2:")
            .next()
            .unwrap_or_else(|| unreachable!())
            .to_owned();
        wire.1 = format!("{prefix};");
        wire.4.clear();
        let mut modes: Vec<_> = (800..927).map(|width| (width, 600, 60000)).collect();
        modes.push((1920, 1080, 60000));
        for handle in 1..=16 {
            wire.1
                .push_str(&format!("{handle}:2:enabled:1920:1080:60000:1000:0:0:0:-;"));
            wire.4.push((handle, 2, true, modes.clone(), true));
        }
        let snapshot = value(decode_snapshot(wire.clone(), 1100));
        assert_eq!(snapshot.capabilities.len(), 16);
        assert!(
            snapshot
                .capabilities
                .iter()
                .all(|cap| cap.modes().len() == 128)
        );
        let message = value(
            value(zbus::Message::method_call(
                "/org/linura/Authority1",
                "GetOwnDisplaySnapshot",
            ))
            .build(&(wire,)),
        );
        assert!(message.body().len() > 16 * 1024);
        assert!(message.body().len() < MAX_DISPLAY_REPLY_BYTES);
    }
}
