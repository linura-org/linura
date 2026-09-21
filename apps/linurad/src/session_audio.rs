use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use linura_control::{
    AuthorizedTransientEffect, PlanPreviewControl, TRANSIENT_AUDIO_CAPABILITY,
    TRANSIENT_AUDIO_PROVIDER, TRANSIENT_AUDIO_RESOURCE_PREFIX, TRANSIENT_AUDIO_VOLUME_CHANGE_KEY,
    TRANSIENT_AUDIO_VOLUME_OPERATION_ID, TransientEffectControl, TransientEffectExecutor,
    TransientEffectExecutorError,
};
use linura_core::{
    CapabilityId, IntentId, OperationId, ProviderId, RequestId, ResourceId, SemanticReason,
};
use linura_dbus::{Session1AudioVolumeRequest, Session1Context, Session1Handler};
use linura_linux_observation::{
    LINURA_SESSION_AUDIO_HELPER_PATH, PipeWireSessionObserver, WIREPLUMBER_EXECUTABLE_PATH,
    pipewire_output_node_id, verify_packaged_session_audio_helper,
};
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};
use linura_observation_control::ObservationCoordinator;
use linura_protocol::PlanDesiredStateRequest;

use crate::session_audit::SqliteTransientAudit;

const AUDIO_INTENT_ORIGIN: &str = "intent:session-audio-volume";
const MAX_REASON_BYTES: usize = 1_024;
const EXECUTOR_TIMEOUT: Duration = Duration::from_secs(2);
const EXECUTOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
const EXECUTOR_MAX_OUTPUT_BYTES: u64 = 16 * 1024;
const STATE_DIR_ENV: &str = "LINURA_SESSION_STATE_DIR";
const SYSTEMD_STATE_DIR_ENV: &str = "STATE_DIRECTORY";
const AUDIT_DATABASE_FILE: &str = "transient-effects.sqlite3";

#[derive(Debug, Default)]
struct PipeWireVolumeExecutor;

impl PipeWireVolumeExecutor {
    fn validate_effect(
        effect: &AuthorizedTransientEffect,
    ) -> Result<(u32, u64, String, u16), TransientEffectExecutorError> {
        if effect.operation_id().as_str() != TRANSIENT_AUDIO_VOLUME_OPERATION_ID
            || effect.provider().as_str() != TRANSIENT_AUDIO_PROVIDER
        {
            return Err(executor_error(
                "transient audio executor received the wrong operation",
            ));
        }
        let node_id = pipewire_output_node_id(effect.resource()).map_err(|_| {
            executor_error("transient audio executor requires an exact output node")
        })?;
        if effect.desired_state().len() != 1 {
            return Err(executor_error(
                "transient audio executor requires exactly one desired attribute",
            ));
        }
        let desired = effect
            .desired_state()
            .get(TRANSIENT_AUDIO_VOLUME_CHANGE_KEY)
            .ok_or_else(|| executor_error("transient audio executor is missing volume_percent"))?;
        let volume_percent = parse_volume_percent(desired)?;
        let (object_serial, node_name) =
            expected_sink_identity(effect.pre_effect_observation(), effect.resource(), node_id)?;
        Ok((node_id, object_serial, node_name, volume_percent))
    }
}

impl TransientEffectExecutor for PipeWireVolumeExecutor {
    fn execute(
        &mut self,
        effect: &AuthorizedTransientEffect,
    ) -> Result<(), TransientEffectExecutorError> {
        let (node_id, object_serial, node_name, volume_percent) = Self::validate_effect(effect)?;
        run_identity_bound_volume_update(node_id, object_serial, &node_name, volume_percent)
    }

    fn verify_post_effect(
        &self,
        effect: &AuthorizedTransientEffect,
        post_effect: &ObservationEnvelope,
    ) -> Result<(), TransientEffectExecutorError> {
        let node_id = pipewire_output_node_id(effect.resource()).map_err(|_| {
            executor_error("post-effect verification requires an exact output node")
        })?;
        verify_same_sink_identity(
            effect.pre_effect_observation(),
            post_effect,
            effect.resource(),
            node_id,
        )
    }
}

pub(crate) struct SessionAudioRuntime {
    control: TransientEffectControl<PipeWireVolumeExecutor, SqliteTransientAudit>,
}

impl std::fmt::Debug for SessionAudioRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionAudioRuntime")
            .finish_non_exhaustive()
    }
}

impl SessionAudioRuntime {
    pub(crate) fn open(state_dir: &Path) -> Result<Self, String> {
        let mut coordinator = ObservationCoordinator::new();
        coordinator
            .register_observer(Box::new(PipeWireSessionObserver::new()))
            .map_err(|error| format!("cannot register session audio observer: {error}"))?;
        let previews = PlanPreviewControl::new(coordinator);
        let audit = SqliteTransientAudit::open(&state_dir.join(AUDIT_DATABASE_FILE))?;
        let control = TransientEffectControl::new(previews, PipeWireVolumeExecutor, audit)
            .map_err(|error| format!("cannot construct transient session Control: {error}"))?;
        Ok(Self { control })
    }
}

impl Session1Handler for SessionAudioRuntime {
    fn set_audio_output_volume(
        &mut self,
        context: Session1Context,
        request: Session1AudioVolumeRequest,
    ) -> Result<linura_control::TransientEffectReceipt, String> {
        validate_reason(&request.reason)?;
        if request.volume_percent > 100 {
            return Err("volume_percent must be in the inclusive range 0..100".into());
        }

        let request_id = RequestId::new(request.request_id).map_err(|error| error.to_string())?;
        let resource = ResourceId::new(format!(
            "{TRANSIENT_AUDIO_RESOURCE_PREFIX}{}",
            request.node_id
        ))
        .map_err(|error| error.to_string())?;
        let provider =
            ProviderId::new(TRANSIENT_AUDIO_PROVIDER).map_err(|error| error.to_string())?;
        let observation_capability =
            CapabilityId::new(TRANSIENT_AUDIO_CAPABILITY).map_err(|error| error.to_string())?;
        let operation_id = OperationId::new(TRANSIENT_AUDIO_VOLUME_OPERATION_ID)
            .map_err(|error| error.to_string())?;

        let plan_request = PlanDesiredStateRequest {
            request_id,
            provider,
            resource,
            observation_capability,
            reason: SemanticReason {
                summary: request.reason,
                intent_ids: vec![
                    IntentId::new(AUDIO_INTENT_ORIGIN).map_err(|error| error.to_string())?,
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            desired_state: BTreeMap::from([(
                TRANSIENT_AUDIO_VOLUME_CHANGE_KEY.to_owned(),
                request.volume_percent.to_string(),
            )]),
        };

        self.control
            .execute(context.principal, context.actor, operation_id, plan_request)
            .map_err(|error| error.to_string())
    }
}

pub(crate) fn state_dir() -> Result<PathBuf, String> {
    let path = if let Some(path) = env::var_os(STATE_DIR_ENV) {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os(SYSTEMD_STATE_DIR_ENV) {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("linura")
    } else if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".local/state/linura")
    } else {
        return Err(
            "cannot determine per-user Linura state directory; HOME/XDG_STATE_HOME are unset"
                .into(),
        );
    };
    if !path.is_absolute() {
        return Err("per-user Linura state directory must be absolute".into());
    }
    Ok(path)
}

fn validate_reason(reason: &str) -> Result<(), String> {
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.chars().any(char::is_control)
    {
        return Err("reason must be 1..1024 bytes without control characters".into());
    }
    Ok(())
}

fn parse_volume_percent(value: &str) -> Result<u16, TransientEffectExecutorError> {
    if value.is_empty()
        || value.len() > 3
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(executor_error(
            "volume_percent is not a canonical unsigned integer",
        ));
    }
    let parsed = value
        .parse::<u16>()
        .map_err(|_| executor_error("volume_percent exceeds the supported range"))?;
    if parsed > 100 {
        return Err(executor_error("volume_percent exceeds 100"));
    }
    Ok(parsed)
}

fn expected_sink_identity(
    observation: &ObservationEnvelope,
    expected_resource: &ResourceId,
    expected_node_id: u32,
) -> Result<(u64, String), TransientEffectExecutorError> {
    let capability = CapabilityId::new(TRANSIENT_AUDIO_CAPABILITY)
        .map_err(|_| executor_error("trusted audio capability identifier is invalid"))?;
    let provider = ProviderId::new(TRANSIENT_AUDIO_PROVIDER)
        .map_err(|_| executor_error("trusted audio provider identifier is invalid"))?;
    observation
        .validate(&provider, expected_resource, &capability)
        .map_err(|_| executor_error("pre-effect audio evidence binding is invalid"))?;
    if observation.authority != ObservationAuthority::NativeApi {
        return Err(executor_error(
            "pre-effect PipeWire evidence is not native authoritative evidence",
        ));
    }

    let node_id = match observation.attributes.get("node_id") {
        Some(ObservedValue::U64(value)) => u32::try_from(*value)
            .map_err(|_| executor_error("pre-effect PipeWire node id is out of range"))?,
        _ => {
            return Err(executor_error(
                "pre-effect PipeWire evidence is missing node identity",
            ));
        }
    };
    if node_id != expected_node_id || node_id == u32::MAX {
        return Err(executor_error(
            "pre-effect PipeWire node identity does not match the authorized resource",
        ));
    }

    let object_serial = match observation.attributes.get("object_serial") {
        Some(ObservedValue::U64(value)) => *value,
        _ => {
            return Err(executor_error(
                "pre-effect PipeWire evidence is missing object serial",
            ));
        }
    };
    let node_name = match observation.attributes.get("node_name") {
        Some(ObservedValue::Text(value)) => value.clone(),
        _ => {
            return Err(executor_error(
                "pre-effect PipeWire evidence is missing node name",
            ));
        }
    };
    if node_name.is_empty() || node_name.len() > 1_024 || node_name.chars().any(char::is_control) {
        return Err(executor_error(
            "pre-effect PipeWire node name is not canonical",
        ));
    }
    if observation.attributes.get("media_class")
        != Some(&ObservedValue::Text("Audio/Sink".to_owned()))
    {
        return Err(executor_error(
            "pre-effect PipeWire target is not an audio sink",
        ));
    }
    Ok((object_serial, node_name))
}

fn verify_same_sink_identity(
    pre_effect: &ObservationEnvelope,
    post_effect: &ObservationEnvelope,
    expected_resource: &ResourceId,
    expected_node_id: u32,
) -> Result<(), TransientEffectExecutorError> {
    let pre_identity = expected_sink_identity(pre_effect, expected_resource, expected_node_id)?;
    let post_identity = expected_sink_identity(post_effect, expected_resource, expected_node_id)?;
    if post_identity != pre_identity {
        return Err(executor_error(
            "post-effect PipeWire evidence refers to a different sink identity",
        ));
    }
    Ok(())
}

fn run_identity_bound_volume_update(
    node_id: u32,
    object_serial: u64,
    node_name: &str,
    volume_percent: u16,
) -> Result<(), TransientEffectExecutorError> {
    verify_packaged_session_audio_helper()
        .map_err(|_| executor_error("WirePlumber helper integrity validation failed"))?;
    let runtime_dir = wireplumber_runtime_dir()?;
    let node_name = spa_json_string(node_name)?;
    let arguments = format!(
        "{{ action = \"set-volume\", node_id = {node_id}, object_serial = \"{object_serial}\", node_name = {node_name}, volume_percent = {volume_percent} }}"
    );

    let mut child = Command::new(WIREPLUMBER_EXECUTABLE_PATH)
        .arg(LINURA_SESSION_AUDIO_HELPER_PATH)
        .arg(arguments)
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| executor_error("cannot start bounded WirePlumber volume executor"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| executor_error("WirePlumber volume executor stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| executor_error("WirePlumber volume executor stderr is unavailable"))?;
    let stdout_reader = thread::spawn(move || read_bounded_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_pipe(stderr));

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| executor_error("cannot observe WirePlumber volume executor state"))?
        {
            break status;
        }
        if started.elapsed() >= EXECUTOR_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(executor_error(
                "WirePlumber volume executor exceeded the two-second deadline",
            ));
        }
        thread::sleep(EXECUTOR_POLL_INTERVAL);
    };

    let stdout = join_bounded_pipe(stdout_reader)?;
    join_bounded_pipe(stderr_reader)?;
    if !status.success() {
        return Err(executor_error(
            "WirePlumber volume executor returned a non-zero status",
        ));
    }
    let output = String::from_utf8(stdout)
        .map_err(|_| executor_error("WirePlumber volume executor output is not UTF-8"))?;
    if output != "ok\t1\n" {
        return Err(executor_error(
            "WirePlumber volume executor returned an invalid receipt",
        ));
    }
    Ok(())
}

fn wireplumber_runtime_dir() -> Result<OsString, TransientEffectExecutorError> {
    let value = env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| executor_error("XDG_RUNTIME_DIR is unavailable for PipeWire"))?;
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        return Err(executor_error(
            "XDG_RUNTIME_DIR must be absolute for PipeWire",
        ));
    }
    let metadata = fs::metadata(&path)
        .map_err(|_| executor_error("XDG_RUNTIME_DIR cannot be inspected for PipeWire"))?;
    if !metadata.is_dir() {
        return Err(executor_error("XDG_RUNTIME_DIR is not a directory"));
    }
    Ok(value)
}

fn spa_json_string(value: &str) -> Result<String, TransientEffectExecutorError> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return Err(executor_error(
            "PipeWire node name cannot be encoded into the helper request",
        ));
    }
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            other => encoded.push(other),
        }
    }
    encoded.push('"');
    Ok(encoded)
}

fn read_bounded_pipe<R: Read>(reader: R) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    reader
        .take(EXECUTOR_MAX_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|_| "cannot read WirePlumber volume executor pipe".to_owned())?;
    if u64::try_from(output.len()).unwrap_or(u64::MAX) > EXECUTOR_MAX_OUTPUT_BYTES {
        return Err("WirePlumber volume executor output exceeds the bounded ceiling".into());
    }
    Ok(output)
}

fn join_bounded_pipe(
    handle: thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, TransientEffectExecutorError> {
    handle
        .join()
        .map_err(|_| executor_error("WirePlumber volume output reader terminated unexpectedly"))?
        .map_err(executor_error)
}

fn executor_error(detail: impl Into<String>) -> TransientEffectExecutorError {
    TransientEffectExecutorError::new(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, ProviderId, ResourceId};
    use linura_linux_observation::PIPEWIRE_DEFAULT_OUTPUT_RESOURCE;
    fn observation(serial: u64, node_name: &str) -> ObservationEnvelope {
        ObservationEnvelope {
            provider: ProviderId::new("pipewire").unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new("audio:session:output:42")
                .unwrap_or_else(|error| unreachable!("{error}")),
            capability: CapabilityId::new("audio.session.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1,
            valid_for_ms: 2_000,
            sequence: 1,
            attributes: BTreeMap::from([
                ("node_id".into(), ObservedValue::U64(42)),
                ("object_serial".into(), ObservedValue::U64(serial)),
                ("node_name".into(), ObservedValue::Text(node_name.into())),
                (
                    "media_class".into(),
                    ObservedValue::Text("Audio/Sink".into()),
                ),
            ]),
        }
    }

    #[test]
    fn authorized_sink_identity_requires_exact_bound_node_material() {
        let expected = observation(100, "sink-a");
        assert_eq!(
            expected_sink_identity(&expected, &expected.resource, 42)
                .unwrap_or_else(|error| unreachable!("{error}")),
            (100, "sink-a".to_owned())
        );
        assert!(expected_sink_identity(&expected, &expected.resource, 41).is_err());
        let wrong_resource = ResourceId::new("audio:session:output:41")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(expected_sink_identity(&expected, &wrong_resource, 42).is_err());

        let mut wrong_class = expected;
        wrong_class.attributes.insert(
            "media_class".into(),
            ObservedValue::Text("Audio/Source".into()),
        );
        assert!(expected_sink_identity(&wrong_class, &wrong_class.resource, 42).is_err());
    }

    #[test]
    fn post_effect_verification_rejects_recycled_pipewire_node_identity() {
        let pre = observation(100, "sink-a");
        let same = observation(100, "sink-a");
        verify_same_sink_identity(&pre, &same, &pre.resource, 42)
            .unwrap_or_else(|error| unreachable!("{error}"));

        let recycled_serial = observation(101, "sink-a");
        assert!(verify_same_sink_identity(&pre, &recycled_serial, &pre.resource, 42).is_err());

        let recycled_name = observation(100, "sink-b");
        assert!(verify_same_sink_identity(&pre, &recycled_name, &pre.resource, 42).is_err());
    }

    #[test]
    fn volume_value_is_exact_integer_and_never_amplifies_above_one_hundred_percent() {
        assert_eq!(
            parse_volume_percent("0").unwrap_or_else(|error| unreachable!("{error}")),
            0
        );
        assert_eq!(
            parse_volume_percent("100").unwrap_or_else(|error| unreachable!("{error}")),
            100
        );
        for value in ["", "00", "040", "+40", "-1", "101", "40.0", " 40"] {
            assert!(parse_volume_percent(value).is_err(), "{value}");
        }
    }

    #[test]
    fn helper_argument_encoding_cannot_inject_spa_json_material() {
        assert_eq!(
            spa_json_string("sink\"\\name").unwrap_or_else(|error| unreachable!("{error}")),
            "\"sink\\\"\\\\name\""
        );
        assert!(spa_json_string("bad\nname").is_err());
    }

    #[test]
    fn default_sink_alias_is_not_an_executor_resource() {
        let default = ResourceId::new(PIPEWIRE_DEFAULT_OUTPUT_RESOURCE)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(pipewire_output_node_id(&default).is_err());
    }

    #[test]
    fn session_state_directory_must_be_absolute_when_explicitly_configured() {
        if let Some(path) = env::var_os(STATE_DIR_ENV) {
            assert!(PathBuf::from(path).is_absolute());
        }
    }
}
