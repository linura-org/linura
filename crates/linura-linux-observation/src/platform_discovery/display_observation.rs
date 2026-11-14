//! Read-only Hyprland multi-output evidence via a freshly peer-attested IPC
//! connection. This is neither Control authorization nor a display executor.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use linura_core::{DisplayMode, DisplayScale, DisplayTransform};
use rustix::net::sockopt::socket_peercred;
use serde::Deserialize;

use super::{
    HYPRLAND_IO_TIMEOUT, LogindSessionTarget, PlatformProbeError, connect_system_bus,
    connect_unix_with_deadline, locate_verified_hyprland_socket,
    logind_session_for_pid_with_deadline, query_session_context,
};

const MAX_OUTPUTS: usize = 16;
const MAX_CONNECTOR_BYTES: usize = 128;
const MAX_MODES: usize = 128;
const NATIVE_OUTPUT_RESPONSE_MAX_BYTES: u64 = 256 * 1024;

/// Opaque live Hyprland peer evidence, bound to a selected logind session.
/// Peer PID is correlation only; not a policy approval or invocation credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyprlandDisplayObservation {
    pub session_id: String,
    pub uid: u32,
    pub peer_pid: u32,
    pub outputs: Vec<HyprlandNativeOutput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyprlandNativeOutput {
    pub id: u64,
    pub connector: String,
    pub available_modes: Vec<DisplayMode>,
    pub dpms_on: bool,
    pub current: Option<HyprlandOutputState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyprlandOutputState {
    pub mode: DisplayMode,
    pub x: i32,
    pub y: i32,
    pub scale: DisplayScale,
    pub transform: DisplayTransform,
    /// Native monitor ID, never a connector alias or authorization credential.
    pub mirror_of: Option<u64>,
}

// Deserialize the native vocabulary directly. Serde rejects repeated known
// fields (including escaped duplicates) and wrong scalar types. Unrelated
// native fields are ignored without retaining workspace titles, EDID or serials.
// This remains a read-only candidate; native API/version and generation
// attestation are still prerequisites for authoritative Control integration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeMonitor {
    id: u64,
    name: String,
    disabled: bool,
    available_modes: Vec<String>,
    width: Option<u32>,
    height: Option<u32>,
    refresh_rate: Option<f64>,
    x: Option<i32>,
    y: Option<i32>,
    scale: Option<f64>,
    transform: Option<u32>,
    dpms_status: bool,
    mirror_of: String,
}

/// Read-only observation: authenticate the exact peer on the *same stream* as
/// the query. Socket names, environment values, connector names and monitor
/// indices are only locators/correlation. No privileged effect is dispatched.
pub fn observe_hyprland_outputs(
    target: &LogindSessionTarget,
) -> Result<HyprlandDisplayObservation, PlatformProbeError> {
    let connection = connect_system_bus()?;
    let context = query_session_context(&connection, target)?;
    if context.desktop != "hyprland" {
        return Err(PlatformProbeError::new(
            "selected session is not an attested Hyprland desktop",
        ));
    }
    // Discovery rejects ambiguous peers. The final query connection must
    // re-check that its actual peer belongs to the same logind session.
    let socket = locate_verified_hyprland_socket(&connection, &context)?;
    let mut stream =
        connect_unix_with_deadline(&socket, HYPRLAND_IO_TIMEOUT, "Hyprland output IPC")?;
    let credentials = socket_peercred(&stream)
        .map_err(|_| PlatformProbeError::new("cannot attest Hyprland output IPC peer"))?;
    if credentials.uid.as_raw() != context.uid {
        return Err(PlatformProbeError::new(
            "Hyprland output IPC peer uid changed",
        ));
    }
    let peer_pid = u32::try_from(credentials.pid.as_raw_pid())
        .map_err(|_| PlatformProbeError::new("Hyprland output IPC peer pid is invalid"))?;
    let peer_session =
        logind_session_for_pid_with_deadline(&connection, peer_pid, HYPRLAND_IO_TIMEOUT)?;
    if peer_session.as_ref().map(|s| s.as_str()) != Some(context.session_object_path.as_str()) {
        return Err(PlatformProbeError::new(
            "Hyprland output IPC peer logind session changed",
        ));
    }
    let response = query_outputs(&mut stream, HYPRLAND_IO_TIMEOUT)?;
    let outputs = parse_hyprland_outputs(&response)?;
    Ok(HyprlandDisplayObservation {
        session_id: context.session_id,
        uid: context.uid,
        peer_pid,
        outputs,
    })
}

fn query_outputs(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<Vec<u8>, PlatformProbeError> {
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| PlatformProbeError::new("cannot set Hyprland output IPC write deadline"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| PlatformProbeError::new("cannot set Hyprland output IPC read deadline"))?;
    let started = Instant::now();
    stream
        .write_all(b"j/monitors all")
        .map_err(|_| PlatformProbeError::new("Hyprland monitor query was not delivered"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| PlatformProbeError::new("cannot close Hyprland monitor query input"))?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let remaining = timeout
            .checked_sub(started.elapsed())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                PlatformProbeError::new("Hyprland output query exceeded total deadline")
            })?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| PlatformProbeError::new("cannot limit Hyprland output read time"))?;
        let count = stream
            .read(&mut chunk)
            .map_err(|_| PlatformProbeError::new("Hyprland output query failed or timed out"))?;
        if count == 0 {
            break;
        }
        if response.len().saturating_add(count) > NATIVE_OUTPUT_RESPONSE_MAX_BYTES as usize {
            return Err(PlatformProbeError::new(
                "Hyprland monitor output exceeds bounded size",
            ));
        }
        response.extend_from_slice(&chunk[..count]);
    }
    Ok(response)
}

fn bounded_connector(name: &str) -> Result<(), PlatformProbeError> {
    if name.is_empty()
        || name.len() > MAX_CONNECTOR_BYTES
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(PlatformProbeError::new("native monitor name is malformed"));
    }
    Ok(())
}

fn finite_milli(raw: f64) -> Result<u32, PlatformProbeError> {
    if !raw.is_finite() || raw <= 0.0 || raw > 1000.0 {
        return Err(PlatformProbeError::new(
            "native numeric value outside bounds",
        ));
    }
    let milli = raw * 1000.0;
    let rounded = milli.round();
    // Permit only floating-point representation noise, never rounding native
    // state into another mode or scale. Lossy native mode advertisements must
    // remain unsupported until an exact mode source is independently qualified.
    if (milli - rounded).abs() > 0.000_001 {
        return Err(PlatformProbeError::new("native precision is ambiguous"));
    }
    Ok(rounded as u32)
}

fn required<T>(value: Option<T>) -> Result<T, PlatformProbeError> {
    value.ok_or_else(|| PlatformProbeError::new("enabled monitor state is incomplete"))
}

fn parse_mode_text(value: &str) -> Result<DisplayMode, PlatformProbeError> {
    if value.len() > 48 {
        return Err(PlatformProbeError::new(
            "available monitor mode exceeds bounds",
        ));
    }
    let (dimension, rate) = value
        .strip_suffix("Hz")
        .and_then(|text| text.split_once('@'))
        .ok_or_else(|| PlatformProbeError::new("available monitor mode format unsupported"))?;
    let (width, height) = dimension
        .split_once('x')
        .ok_or_else(|| PlatformProbeError::new("available monitor dimensions invalid"))?;
    let exact_positive = |raw: &str| -> Result<u32, PlatformProbeError> {
        if raw.is_empty() || raw.starts_with('0') || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PlatformProbeError::new("monitor dimensions not canonical"));
        }
        raw.parse()
            .map_err(|_| PlatformProbeError::new("monitor dimensions overflow"))
    };
    // Parse fixed decimal text directly; Rust float parsing would also accept
    // whitespace, signs, exponents and precision that cannot be represented.
    let (whole, fraction) = rate.split_once('.').unwrap_or((rate, ""));
    if fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || (rate.contains('.') && fraction.is_empty())
    {
        return Err(PlatformProbeError::new(
            "available refresh precision invalid",
        ));
    }
    let whole = exact_positive(whole)?;
    let fractional = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u32>()
            .map_err(|_| PlatformProbeError::new("available refresh invalid"))?
            * 10_u32.pow(3 - fraction.len() as u32)
    };
    let millihz = whole
        .checked_mul(1000)
        .and_then(|v| v.checked_add(fractional))
        .ok_or_else(|| PlatformProbeError::new("available refresh overflow"))?;
    DisplayMode::new(exact_positive(width)?, exact_positive(height)?, millihz)
        .map_err(|_| PlatformProbeError::new("available monitor mode invalid"))
}

fn parse_mirror(value: &str) -> Result<Option<u64>, PlatformProbeError> {
    if value == "none" {
        return Ok(None);
    }
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(PlatformProbeError::new(
            "native mirror identity is malformed",
        ));
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| PlatformProbeError::new("native mirror identity overflow"))
}

fn parse_hyprland_outputs(
    response: &[u8],
) -> Result<Vec<HyprlandNativeOutput>, PlatformProbeError> {
    if response.len() > NATIVE_OUTPUT_RESPONSE_MAX_BYTES as usize {
        return Err(PlatformProbeError::new(
            "Hyprland output response unbounded",
        ));
    }
    // Do not expose serde's diagnostic: unknown native material may contain
    // user data. The response and nesting bounds remain independent of schema.
    let items: Vec<NativeMonitor> = serde_json::from_slice(response)
        .map_err(|_| PlatformProbeError::new("Hyprland monitor JSON is malformed or ambiguous"))?;
    if items.is_empty() || items.len() > MAX_OUTPUTS {
        return Err(PlatformProbeError::new(
            "Hyprland monitor inventory unsupported",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut connectors = BTreeSet::new();
    let mut outputs = Vec::with_capacity(items.len());
    for item in items {
        bounded_connector(&item.name)?;
        if !ids.insert(item.id) || !connectors.insert(item.name.clone()) {
            return Err(PlatformProbeError::new(
                "native monitor inventory ambiguous",
            ));
        }
        // Disabled connectors still need their supported modes for a complete
        // layout/recovery candidate. Do not manufacture support from current mode.
        if item.available_modes.is_empty() || item.available_modes.len() > MAX_MODES {
            return Err(PlatformProbeError::new(
                "native available mode inventory invalid",
            ));
        }
        let mut modes = BTreeSet::new();
        for entry in item.available_modes {
            if !modes.insert(parse_mode_text(&entry)?) {
                return Err(PlatformProbeError::new("duplicate native mode"));
            }
        }
        let mirror_of = parse_mirror(&item.mirror_of)?;
        let current = if item.disabled {
            if mirror_of.is_some() {
                return Err(PlatformProbeError::new(
                    "disabled native output is mirrored",
                ));
            }
            None
        } else {
            let mode = DisplayMode::new(
                required(item.width)?,
                required(item.height)?,
                finite_milli(required(item.refresh_rate)?)?,
            )
            .map_err(|_| PlatformProbeError::new("native monitor mode is invalid"))?;
            if !modes.contains(&mode) {
                return Err(PlatformProbeError::new(
                    "exact native current mode not advertised",
                ));
            }
            let scale = DisplayScale::new(finite_milli(required(item.scale)?)?)
                .map_err(|_| PlatformProbeError::new("native scale is unsupported"))?;
            let transform = DisplayTransform::from_native(required(item.transform)?)
                .map_err(|_| PlatformProbeError::new("native transform is unsupported"))?;
            let x = required(item.x)?;
            let y = required(item.y)?;
            if x.unsigned_abs() > 65_536 || y.unsigned_abs() > 65_536 {
                return Err(PlatformProbeError::new("native position is unsupported"));
            }
            Some(HyprlandOutputState {
                mode,
                x,
                y,
                scale,
                transform,
                mirror_of,
            })
        };
        outputs.push(HyprlandNativeOutput {
            id: item.id,
            connector: item.name,
            available_modes: modes.into_iter().collect(),
            dpms_on: item.dpms_status,
            current,
        });
    }
    for output in &outputs {
        if let Some(state) = &output.current
            && let Some(target) = state.mirror_of
            && (target == output.id
                || !outputs.iter().any(|candidate| {
                    candidate.id == target
                        && candidate
                            .current
                            .as_ref()
                            .is_some_and(|state| state.mirror_of.is_none())
                }))
        {
            return Err(PlatformProbeError::new(
                "native mirror target is absent, disabled or chained",
            ));
        }
    }
    outputs.sort_by_key(|output| output.id);
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        br#"[{"id":0,"name":"DP-1","disabled":false,"width":1920,"height":1080,"refreshRate":60.0,"x":0,"y":0,"scale":1.0,"transform":0,"dpmsStatus":true,"mirrorOf":"none","availableModes":["1920x1080@60.00Hz"]},{"id":7,"name":"HDMI-A-1","disabled":true,"dpmsStatus":false,"mirrorOf":"none","availableModes":["1920x1080@60.00Hz"]}]"#.to_vec()
    }

    #[test]
    fn parsed_native_modes_and_disabled_outputs_remain_distinct() {
        let result =
            parse_hyprland_outputs(&sample()).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, 0);
        let current = result[0].current.as_ref().unwrap_or_else(|| unreachable!());
        assert_eq!(
            current.mode,
            DisplayMode::new(1920, 1080, 60_000).unwrap_or_else(|error| unreachable!("{error}"))
        );
        assert!(result[0].dpms_on);
        assert_eq!(current.mirror_of, None);
        assert!(result[1].current.is_none());
        assert_eq!(result[1].available_modes, result[0].available_modes);
    }

    #[test]
    fn malformed_modes_and_recycled_connector_identity_fail_closed() {
        let original: serde_json::Value =
            serde_json::from_slice(&sample()).unwrap_or_else(|error| unreachable!("{error}"));
        for field in ["id", "name"] {
            let mut duplicate = original.clone();
            duplicate[1][field] = duplicate[0][field].clone();
            assert!(parse_hyprland_outputs(duplicate.to_string().as_bytes()).is_err());
        }
        assert!(parse_mode_text("preferred").is_err());
        assert!(parse_mode_text("1920x1080@NaNHz").is_err());
        assert!(parse_hyprland_outputs(b"{}").is_err());
        assert!(parse_hyprland_outputs(br#"[{"id":0,"name":"DP-1","disabled":false}]"#).is_err());
    }

    #[test]
    fn output_inventory_rejects_nonfinite_scaling_and_unsupported_refresh() {
        let incorrect = String::from_utf8(sample())
            .unwrap_or_else(|error| unreachable!("{error}"))
            .replace("\"scale\":1.0", "\"scale\":0.0");
        assert!(parse_hyprland_outputs(incorrect.as_bytes()).is_err());
        assert!(parse_mode_text("1920x1080@0Hz").is_err());
    }
    fn document() -> serde_json::Value {
        serde_json::from_slice(&sample()).unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn every_required_field_is_mandatory_and_has_its_native_type() {
        let original = document();
        for key in [
            "id",
            "name",
            "disabled",
            "availableModes",
            "width",
            "height",
            "refreshRate",
            "x",
            "y",
            "scale",
            "transform",
            "dpmsStatus",
            "mirrorOf",
        ] {
            for replacement in [
                None,
                Some(serde_json::Value::Null),
                Some(serde_json::json!({})),
            ] {
                let mut bad = original.clone();
                let object = bad[0].as_object_mut().unwrap_or_else(|| unreachable!());
                if let Some(value) = replacement {
                    object.insert(key.into(), value);
                } else {
                    object.remove(key);
                }
                assert!(
                    parse_hyprland_outputs(bad.to_string().as_bytes()).is_err(),
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn duplicate_json_fields_cannot_override_native_state_even_when_escaped() {
        let original = String::from_utf8(sample()).unwrap_or_else(|e| unreachable!("{e}"));
        for (from, to) in [
            ("\"disabled\":false", "\"disabled\":true,\"disabled\":false"),
            ("\"id\":0", r#""id":7,"\u0069d":0"#),
            ("\"scale\":1.0", "\"scale\":null,\"scale\":1.0"),
            (
                "\"mirrorOf\":\"none\"",
                "\"mirrorOf\":\"7\",\"mirrorOf\":\"none\"",
            ),
        ] {
            assert!(parse_hyprland_outputs(original.replacen(from, to, 1).as_bytes()).is_err());
        }
    }

    #[test]
    fn mirror_power_and_disabled_mode_facts_are_not_silently_discarded() {
        let mut value = document();
        value[1] = value[0].clone();
        value[1]["id"] = serde_json::json!(7);
        value[1]["name"] = serde_json::json!("HDMI-A-1");
        value[1]["mirrorOf"] = serde_json::json!("0");
        value[1]["dpmsStatus"] = serde_json::json!(false);
        let result = parse_hyprland_outputs(value.to_string().as_bytes())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let state = result[1].current.as_ref().unwrap_or_else(|| unreachable!());
        assert_eq!(state.mirror_of, Some(0));
        assert!(!result[1].dpms_on);
        for invalid in ["7", "99", "00", "DP-1", "default", " 0", "+0"] {
            value[1]["mirrorOf"] = serde_json::json!(invalid);
            assert!(parse_hyprland_outputs(value.to_string().as_bytes()).is_err());
        }
        value[1]["mirrorOf"] = serde_json::json!("0");
        value[0]["mirrorOf"] = serde_json::json!("7");
        assert!(parse_hyprland_outputs(value.to_string().as_bytes()).is_err());
        value[0]["mirrorOf"] = serde_json::json!("none");
        value[0]["disabled"] = serde_json::json!(true);
        assert!(parse_hyprland_outputs(value.to_string().as_bytes()).is_err());
    }

    #[test]
    fn numeric_bounds_and_precision_cannot_be_normalized_into_support() {
        for mode in [
            "01920x1080@60Hz",
            "1920x1080@+60Hz",
            "1920x1080@6e1Hz",
            "1920x1080@60.Hz",
            "1920x1080@60.0001Hz",
            "1920x1080@60 Hz",
            "1920x1080@4294967295Hz",
            "1920x1080@infHz",
        ] {
            assert!(parse_mode_text(mode).is_err(), "{mode}");
        }
        for (field, value) in [
            ("scale", serde_json::json!(0.499)),
            ("scale", serde_json::json!(4.001)),
            ("scale", serde_json::json!(1.00001)),
            ("refreshRate", serde_json::json!(60.00001)),
            ("transform", serde_json::json!(8)),
            ("width", serde_json::json!(32769)),
            ("x", serde_json::json!(65537)),
            ("y", serde_json::json!(-65537)),
            ("id", serde_json::json!(-1)),
            ("id", serde_json::json!(0.5)),
        ] {
            let mut bad = document();
            bad[0][field] = value;
            assert!(
                parse_hyprland_outputs(bad.to_string().as_bytes()).is_err(),
                "{field}"
            );
        }
        let mut rounded = document();
        rounded[0]["refreshRate"] = serde_json::json!(59.951);
        rounded[0]["availableModes"] = serde_json::json!(["1920x1080@59.95Hz"]);
        assert!(parse_hyprland_outputs(rounded.to_string().as_bytes()).is_err());
    }

    #[test]
    fn parser_limits_include_disabled_modes_nesting_and_trailing_material() {
        assert!(
            parse_hyprland_outputs(&vec![b' '; NATIVE_OUTPUT_RESPONSE_MAX_BYTES as usize + 1])
                .is_err()
        );
        assert!(parse_hyprland_outputs(b"[]").is_err());
        let output = document()[0].clone();
        let too_many = serde_json::Value::Array(vec![output.clone(); MAX_OUTPUTS + 1]);
        assert!(parse_hyprland_outputs(too_many.to_string().as_bytes()).is_err());
        for modes in [
            serde_json::json!([]),
            serde_json::json!(["1920x1080@60Hz", "1920x1080@60.00Hz"]),
            serde_json::json!(vec!["1920x1080@60.00Hz"; MAX_MODES + 1]),
        ] {
            let mut bad = document();
            bad[1]["availableModes"] = modes;
            assert!(parse_hyprland_outputs(bad.to_string().as_bytes()).is_err());
        }
        let mut trailing = sample();
        trailing.extend_from_slice(b"[]");
        assert!(parse_hyprland_outputs(&trailing).is_err());
        let nested = format!(
            "[{{\"unrelated\":{}0{}}}]",
            "[".repeat(150),
            "]".repeat(150)
        );
        assert!(parse_hyprland_outputs(nested.as_bytes()).is_err());
    }

    #[test]
    fn ipc_query_is_fixed_and_never_accepts_an_unbounded_prefix() {
        for oversized in [false, true] {
            let (mut client, mut server) =
                UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
            let expected = sample();
            let worker = std::thread::spawn(move || {
                let mut query = Vec::new();
                server
                    .read_to_end(&mut query)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                assert_eq!(query, b"j/monitors all");
                let response = if oversized {
                    vec![b' '; NATIVE_OUTPUT_RESPONSE_MAX_BYTES as usize + 1]
                } else {
                    sample()
                };
                // The receiver may stop as soon as the bound is crossed.
                let _ = server.write_all(&response);
            });
            let result = query_outputs(&mut client, Duration::from_secs(2));
            if oversized {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap_or_else(|e| unreachable!("{e}")), expected);
            }
            worker
                .join()
                .unwrap_or_else(|_| unreachable!("IPC fixture thread"));
        }
    }

    #[test]
    fn stalled_ipc_never_becomes_a_successful_observation() {
        let (mut client, _server) = UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(query_outputs(&mut client, Duration::from_millis(25)).is_err());
    }
}
