//! Non-privileged typed S17 client. No provider/executor handles, approval
//! assertions, credentials, caller-selected principal, or automatic retries.
use std::os::unix::net::UnixStream;
use std::time::Duration;

use async_io::{Async, Timer};
use futures_lite::future;
use linura_core::{
    IntentId, PolicyRevisionId, RequestId, ResourceId, SessionEpoch, SessionLockId,
    SessionTransition, SessionTransitionId,
};
use linura_protocol::{
    NativeSleepGateState, NativeSleepGateStatus, ProtectiveLockSettingReceipt,
    ProtectiveLockSettingRequest, SessionLockReceipt, SessionLockRequest, SessionLockRequestStatus,
    SessionTransitionCompletion, SessionTransitionReceipt, SessionTransitionRequest,
    SessionTransitionRequestStatus,
};

use crate::authority::{
    AuthorityReceiptWire, DisplayLayoutReceiptWire, ProtectiveLockSettingWire,
    SessionLockStatusWire, SessionTransitionStatusWire,
};
use crate::{
    AUTHORITY_INTERFACE_NAME, AUTHORITY_OBJECT_PATH, AUTHORITY_SERVICE_NAME, TransportError,
};

const CALL_BUDGET: Duration = Duration::from_secs(90);
const MAX_REPLY_BYTES: usize = 16 * 1024;
const REQUEST_PREFIX: &str = "request:v010:session-lock:";
const TRANSITION_PREFIX: &str = "request:v010:session-transition:";
const PROTECTIVE_SETTING_PREFIX: &str = "request:v010:protective-lock-setting:";

#[derive(Clone, Debug)]
pub struct Authority1Client {
    connection: zbus::blocking::Connection,
}

impl Authority1Client {
    pub fn begin_display_layout(
        &self,
        request: &linura_protocol::DisplayLayoutRequest,
    ) -> Result<linura_protocol::DisplayLayoutReceipt, TransportError> {
        let expected = linura_protocol::display_layout_request_id(&format!(
            "{}{}",
            linura_protocol::DISPLAY_LAYOUT_REQUEST_PREFIX,
            request.operation_id(),
        ))
        .map_err(TransportError::new)?;
        let receipt = decode_display_reply(
            self.call(
                "BeginDisplayLayout",
                &(request.operation_id(), request.material(), request.reason()),
            )?,
            &expected,
        )?;
        let material = linura_core::DisplayLayoutMaterial::decode(request.material())
            .map_err(|e| TransportError::new(e.to_string()))?;
        if receipt.resource
            != material
                .topology()
                .resource_id()
                .map_err(|e| TransportError::new(e.to_string()))?
        {
            return Err(TransportError::new(
                "display receipt refers to another topology",
            ));
        }
        Ok(receipt)
    }
    pub fn display_layout_status(
        &self,
        request_id: &RequestId,
    ) -> Result<linura_protocol::DisplayLayoutReceipt, TransportError> {
        linura_protocol::display_layout_request_id(request_id.as_str())
            .map_err(TransportError::new)?;
        decode_display_reply(
            self.call("GetDisplayLayoutStatus", &(request_id.as_str(),))?,
            request_id,
        )
    }
    pub fn confirm_display_layout(
        &self,
        request_id: &RequestId,
    ) -> Result<linura_protocol::DisplayLayoutReceipt, TransportError> {
        linura_protocol::display_layout_request_id(request_id.as_str())
            .map_err(TransportError::new)?;
        decode_display_reply(
            self.call("ConfirmDisplayLayout", &(request_id.as_str(),))?,
            request_id,
        )
    }
    pub fn revert_display_layout(
        &self,
        request_id: &RequestId,
    ) -> Result<linura_protocol::DisplayLayoutReceipt, TransportError> {
        linura_protocol::display_layout_request_id(request_id.as_str())
            .map_err(TransportError::new)?;
        decode_display_reply(
            self.call("RevertDisplayLayout", &(request_id.as_str(),))?,
            request_id,
        )
    }
    pub fn connect() -> Result<Self, TransportError> {
        // Never use DBUS_SYSTEM_BUS_ADDRESS, an autolaunched bus or caller's
        // connection as evidence. Authenticate the actual canonical bus peer.
        let connection = async_io::block_on(future::race(
            async {
                let stream = Async::<UnixStream>::connect("/run/dbus/system_bus_socket")
                    .await
                    .map_err(|_| TransportError::new("canonical system bus is unavailable"))?;
                let peer =
                    rustix::net::sockopt::socket_peercred(stream.get_ref()).map_err(|_| {
                        TransportError::new("system bus peer credentials are unavailable")
                    })?;
                if peer.uid.as_raw() != 0 {
                    return Err(TransportError::new("canonical system bus peer is not root"));
                }
                let stream = stream
                    .into_inner()
                    .map_err(|_| TransportError::new("system bus descriptor is unavailable"))?;
                let connection = zbus::connection::Builder::async_io_unix_stream(stream)
                    .method_timeout(CALL_BUDGET)
                    .max_queued(32)
                    .build()
                    .await
                    .map_err(TransportError::from)?;
                Ok(zbus::blocking::Connection::from(connection))
            },
            async {
                Timer::after(Duration::from_secs(2)).await;
                Err(TransportError::new(
                    "system bus connection/authentication exceeded its deadline",
                ))
            },
        ))?;
        Ok(Self { connection })
    }

    fn call<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        method: &str,
        body: &B,
    ) -> Result<zbus::Message, TransportError> {
        let reply = self.connection.call_method(
            Some(AUTHORITY_SERVICE_NAME),
            AUTHORITY_OBJECT_PATH,
            Some(AUTHORITY_INTERFACE_NAME),
            method,
            body,
        )?;
        let limit = if method == "GetOwnDisplaySnapshot" {
            crate::authority_display::MAX_DISPLAY_REPLY_BYTES
        } else {
            MAX_REPLY_BYTES
        };
        if reply.body().len() > limit {
            return Err(TransportError::new("Authority1 reply exceeds its bound"));
        }
        Ok(reply)
    }

    pub fn own_session_lock(&self) -> Result<SessionLockId, TransportError> {
        let resource: String = self.call("GetOwnSessionLock", &())?.body().deserialize()?;
        parse_lock(&resource)
    }

    /// Fresh caller-bound topology and advertised modes. No effects, approvals
    /// or hidden retries; clients must refresh expired reports before use.
    pub fn own_display_snapshot(&self) -> Result<linura_protocol::DisplaySnapshot, TransportError> {
        let reply = self.call("GetOwnDisplaySnapshot", &())?;
        if reply.body().signature().to_string() != "(sstta(ttba(uuu)b))" {
            return Err(TransportError::new(
                "display snapshot reply signature mismatch",
            ));
        }
        let (wire,): (crate::authority_display::DisplaySnapshotWire,) =
            reply.body().deserialize()?;
        crate::authority_display::decode_snapshot(
            wire,
            crate::authority_display::now_ms().map_err(TransportError::new)?,
        )
        .map_err(TransportError::new)
    }

    /// Process-retained machine-wide diagnostics, not current protection or a
    /// successful sleep claim. Restart starts at `Unobserved`; no retry/effect.
    pub fn own_native_sleep_gate_status(&self) -> Result<NativeSleepGateStatus, TransportError> {
        let ((epoch, state),): ((String, String),) = self
            .call("GetOwnNativeSleepGateStatus", &())?
            .body()
            .deserialize()?;
        decode_native_sleep_gate_status(&epoch, &state)
    }

    /// Local consent only. This does not lock, unlock, enter sleep or claim the
    /// protective native runtime is available. No automatic retry is performed.
    pub fn configure_protective_lock(
        &self,
        request: &ProtectiveLockSettingRequest,
    ) -> Result<ProtectiveLockSettingReceipt, TransportError> {
        let expected = protective_setting_request_identity(&request.operation_id)?;
        let resource = request
            .lock
            .resource_id()
            .map_err(|e| TransportError::new(e.to_string()))?;
        let (wire,): (ProtectiveLockSettingWire,) = self
            .call(
                "ConfigureProtectiveLock",
                &(
                    request.operation_id.as_str(),
                    resource.as_str(),
                    request.enabled,
                ),
            )?
            .body()
            .deserialize()?;
        let receipt = decode_protective_setting(wire)?;
        if receipt.request_id != expected
            || receipt.confirmed_lock != request.lock
            || receipt.enabled != request.enabled
        {
            return Err(TransportError::new(
                "Authority1 substituted the protective-lock configuration",
            ));
        }
        Ok(receipt)
    }

    /// Latest retained consent in an exact own-login namespace, not evidence of
    /// active login, usable policy, secure coverage or native sleep protection.
    pub fn recorded_protective_lock_setting(
        &self,
        epoch: &SessionEpoch,
    ) -> Result<Option<ProtectiveLockSettingReceipt>, TransportError> {
        let resource = epoch
            .resource_id()
            .map_err(|e| TransportError::new(e.to_string()))?;
        let records: Vec<ProtectiveLockSettingWire> = self
            .call("GetProtectiveLockSetting", &(resource.as_str(),))?
            .body()
            .deserialize()?;
        decode_protective_setting_records(records, epoch)
    }

    /// Read-only lost-reply lookup. Never restores a superseded enable record.
    pub fn protective_lock_setting_request_status(
        &self,
        request: &RequestId,
    ) -> Result<ProtectiveLockSettingReceipt, TransportError> {
        validate_protective_setting_request_id(request)?;
        let (wire,): (ProtectiveLockSettingWire,) = self
            .call(
                "GetProtectiveLockSettingRequestStatus",
                &(request.as_str(),),
            )?
            .body()
            .deserialize()?;
        let receipt = decode_protective_setting(wire)?;
        if &receipt.request_id != request {
            return Err(TransportError::new(
                "Authority1 substituted protective-lock history",
            ));
        }
        Ok(receipt)
    }

    pub fn own_session_transition(
        &self,
        action: &str,
    ) -> Result<SessionTransitionId, TransportError> {
        if !matches!(action, "suspend" | "logout" | "reboot" | "power-off") {
            return Err(TransportError::new(
                "session transition action is unsupported",
            ));
        }
        let resource: String = self
            .call("GetOwnSessionTransition", &(action,))?
            .body()
            .deserialize()?;
        let target = parse_transition(&resource)?;
        if target.transition().as_str() != action {
            return Err(TransportError::new(
                "Authority1 substituted the transition action",
            ));
        }
        Ok(target)
    }

    pub fn converge_session_transition(
        &self,
        request: &SessionTransitionRequest,
    ) -> Result<SessionTransitionReceipt, TransportError> {
        let request_id = request_identity_in_namespace(TRANSITION_PREFIX, &request.operation_id)?;
        if request.reason.is_empty()
            || request.reason.len() > 1024
            || request.reason.chars().any(char::is_control)
        {
            return Err(TransportError::new(
                "session reason must be 1..1024 bytes without control characters",
            ));
        }
        let resource = request
            .target
            .resource_id()
            .map_err(|e| TransportError::new(e.to_string()))?;
        let (wire,): (AuthorityReceiptWire,) = self
            .call(
                "ConvergeSessionTransition",
                &(
                    request.operation_id.as_str(),
                    resource.as_str(),
                    request.reason.as_str(),
                ),
            )?
            .body()
            .deserialize()?;
        let receipt = decode_transition_receipt(wire, &request_id)?;
        if receipt.target != request.target {
            return Err(TransportError::new(
                "Authority1 substituted the exact transition target",
            ));
        }
        Ok(receipt)
    }

    pub fn session_transition_request_status(
        &self,
        request_id: &RequestId,
    ) -> Result<SessionTransitionRequestStatus, TransportError> {
        validate_transition_request_id(request_id)?;
        let (wire,): (SessionTransitionStatusWire,) = self
            .call("GetSessionTransitionRequestStatus", &(request_id.as_str(),))?
            .body()
            .deserialize()?;
        decode_transition_status(wire, request_id)
    }

    pub fn recover_session_transition(
        &self,
        request_id: &RequestId,
    ) -> Result<SessionTransitionReceipt, TransportError> {
        validate_transition_request_id(request_id)?;
        let (wire,): (AuthorityReceiptWire,) = self
            .call("RecoverSessionTransition", &(request_id.as_str(),))?
            .body()
            .deserialize()?;
        decode_transition_receipt(wire, request_id)
    }

    pub fn acknowledge_session_transition(
        &self,
        request_id: &RequestId,
    ) -> Result<bool, TransportError> {
        validate_transition_request_id(request_id)?;
        self.call("AcknowledgeSessionTransition", &(request_id.as_str(),))?
            .body()
            .deserialize()
            .map_err(TransportError::from)
    }

    pub fn converge_session_lock(
        &self,
        request: &SessionLockRequest,
    ) -> Result<SessionLockReceipt, TransportError> {
        let request_id = request_identity(&request.operation_id)?;
        if request.reason.is_empty()
            || request.reason.len() > 1024
            || request.reason.chars().any(char::is_control)
        {
            return Err(TransportError::new(
                "session reason must be 1..1024 bytes without control characters",
            ));
        }
        let resource = request
            .lock
            .resource_id()
            .map_err(|error| TransportError::new(error.to_string()))?;
        let (wire,): (AuthorityReceiptWire,) = self
            .call(
                "ConvergeSessionLock",
                &(
                    request.operation_id.as_str(),
                    resource.as_str(),
                    request.secure,
                    request.reason.as_str(),
                ),
            )?
            .body()
            .deserialize()?;
        let receipt = decode_receipt(wire, &request_id)?;
        if receipt.lock != request.lock || receipt.secure != request.secure {
            return Err(TransportError::new(
                "Authority1 substituted the session request purpose or generation",
            ));
        }
        Ok(receipt)
    }

    /// Historical status only: never turn committed into current secure/unlocked
    /// coverage, or indeterminate into permission to replay the original effect.
    pub fn session_lock_request_status(
        &self,
        request_id: &RequestId,
    ) -> Result<SessionLockRequestStatus, TransportError> {
        validate_request_id(request_id)?;
        let (wire,): (SessionLockStatusWire,) = self
            .call("GetSessionLockRequestStatus", &(request_id.as_str(),))?
            .body()
            .deserialize()?;
        decode_status(wire, request_id)
    }

    pub fn recover_session_lock(
        &self,
        request_id: &RequestId,
    ) -> Result<SessionLockReceipt, TransportError> {
        validate_request_id(request_id)?;
        let (wire,): (AuthorityReceiptWire,) = self
            .call("RecoverSessionLock", &(request_id.as_str(),))?
            .body()
            .deserialize()?;
        decode_receipt(wire, request_id)
    }

    /// Retire only an already committed release. This cannot dispatch an effect
    /// or approve another generation, even if the caller retries a lost reply.
    pub fn acknowledge_session_lock_release(
        &self,
        request_id: &RequestId,
    ) -> Result<bool, TransportError> {
        validate_request_id(request_id)?;
        self.call("AcknowledgeSessionLockRelease", &(request_id.as_str(),))?
            .body()
            .deserialize()
            .map_err(TransportError::from)
    }
}

fn decode_display_reply(
    reply: zbus::Message,
    expected: &RequestId,
) -> Result<linura_protocol::DisplayLayoutReceipt, TransportError> {
    if reply.body().signature().to_string() != "(sssst)" {
        return Err(TransportError::new(
            "display lifecycle reply has a different wire shape",
        ));
    }
    let (wire,): (DisplayLayoutReceiptWire,) = reply.body().deserialize()?;
    decode_display_receipt(wire, expected)
}

fn decode_display_receipt(
    wire: DisplayLayoutReceiptWire,
    expected: &RequestId,
) -> Result<linura_protocol::DisplayLayoutReceipt, TransportError> {
    let (request_id, transaction_id, resource, state, deadline) = wire;
    let request_id =
        linura_protocol::display_layout_request_id(&request_id).map_err(TransportError::new)?;
    if &request_id != expected
        || !self::transaction_id(&transaction_id)
        || resource.len() > 256
        || deadline == 0
        || deadline > i64::MAX as u64
    {
        return Err(TransportError::new(
            "display lifecycle receipt is malformed or substituted",
        ));
    }
    let resource = ResourceId::new(resource).map_err(|e| TransportError::new(e.to_string()))?;
    linura_core::DisplayTopologyId::from_resource(&resource)
        .map_err(|e| TransportError::new(e.to_string()))?;
    let state = linura_protocol::DisplayLayoutState::from_wire(&state)
        .ok_or_else(|| TransportError::new("display lifecycle receipt has an unknown state"))?;
    let receipt = linura_protocol::DisplayLayoutReceipt {
        request_id,
        transaction_id,
        resource,
        state,
        confirmation_expires_at_unix_ms: deadline,
    };
    receipt.validate().map_err(TransportError::new)?;
    Ok(receipt)
}

fn decode_native_sleep_gate_status(
    epoch: &str,
    state: &str,
) -> Result<NativeSleepGateStatus, TransportError> {
    if epoch.len() > 256 || state.len() > 32 {
        return Err(TransportError::new(
            "native sleep diagnostic exceeds its bounds",
        ));
    }
    let resource = ResourceId::new(epoch).map_err(|e| TransportError::new(e.to_string()))?;
    let epoch =
        SessionEpoch::from_resource(&resource).map_err(|e| TransportError::new(e.to_string()))?;
    if epoch.uid() == 0
        || epoch
            .resource_id()
            .map_err(|e| TransportError::new(e.to_string()))?
            != resource
    {
        return Err(TransportError::new(
            "native sleep diagnostic has a noncanonical login",
        ));
    }
    let state = NativeSleepGateState::parse(state)
        .ok_or_else(|| TransportError::new("native sleep diagnostic state is unsupported"))?;
    Ok(NativeSleepGateStatus { epoch, state })
}

fn parse_lock(resource: &str) -> Result<SessionLockId, TransportError> {
    if resource.len() > 256 {
        return Err(TransportError::new("session resource exceeds its bound"));
    }
    SessionLockId::from_resource(
        &ResourceId::new(resource).map_err(|error| TransportError::new(error.to_string()))?,
    )
    .map_err(|error| TransportError::new(error.to_string()))
}

pub(crate) fn request_identity(operation: &str) -> Result<RequestId, TransportError> {
    request_identity_in_namespace(REQUEST_PREFIX, operation)
}

pub(crate) fn protective_setting_request_identity(
    operation: &str,
) -> Result<RequestId, TransportError> {
    request_identity_in_namespace(PROTECTIVE_SETTING_PREFIX, operation)
}

pub(crate) fn validate_protective_setting_request_id(
    request: &RequestId,
) -> Result<(), TransportError> {
    let operation = request
        .as_str()
        .strip_prefix(PROTECTIVE_SETTING_PREFIX)
        .ok_or_else(|| {
            TransportError::new("request is outside the protective-lock setting namespace")
        })?;
    if protective_setting_request_identity(operation)? != *request {
        return Err(TransportError::new(
            "noncanonical protective-lock configuration identity",
        ));
    }
    Ok(())
}

fn decode_protective_setting(
    wire: ProtectiveLockSettingWire,
) -> Result<ProtectiveLockSettingReceipt, TransportError> {
    let (request, resource, enabled, intent, revision, confirmed_at, latest) = wire;
    if request.len() > 128
        || intent.len() > 128
        || revision.len() > 128
        || confirmed_at == 0
        || confirmed_at > i64::MAX as u64
    {
        return Err(TransportError::new(
            "protective-lock history exceeds its bounds",
        ));
    }
    let request = RequestId::new(request).map_err(|e| TransportError::new(e.to_string()))?;
    validate_protective_setting_request_id(&request)?;
    let confirmed_lock = parse_lock(&resource)?;
    if confirmed_lock.epoch().uid() == 0 {
        return Err(TransportError::new(
            "root protective-lock settings are unsupported",
        ));
    }
    for (value, prefix) in [
        (&intent, "intent:s17:protective-lock:"),
        (&revision, "policy:protective-lock:v1:"),
    ] {
        let digest = value.strip_prefix(prefix).ok_or_else(|| {
            TransportError::new("protective-lock history has an unsupported lineage")
        })?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || digest.bytes().all(|byte| byte == b'0')
        {
            return Err(TransportError::new(
                "protective-lock history has a noncanonical digest",
            ));
        }
    }
    Ok(ProtectiveLockSettingReceipt {
        request_id: request,
        confirmed_lock,
        enabled,
        intent_id: IntentId::new(intent).map_err(|e| TransportError::new(e.to_string()))?,
        revision_id: PolicyRevisionId::new(revision)
            .map_err(|e| TransportError::new(e.to_string()))?,
        confirmed_at_unix_ms: confirmed_at,
        latest_for_epoch: latest,
    })
}

fn decode_protective_setting_records(
    mut records: Vec<ProtectiveLockSettingWire>,
    epoch: &SessionEpoch,
) -> Result<Option<ProtectiveLockSettingReceipt>, TransportError> {
    if records.len() > 1 {
        return Err(TransportError::new("protective-lock setting is ambiguous"));
    }
    records
        .pop()
        .map(|wire| {
            let receipt = decode_protective_setting(wire)?;
            if receipt.confirmed_lock.epoch() != epoch || !receipt.latest_for_epoch {
                return Err(TransportError::new(
                    "Authority1 substituted the latest protective-lock epoch",
                ));
            }
            Ok(receipt)
        })
        .transpose()
}

fn request_identity_in_namespace(
    prefix: &str,
    operation: &str,
) -> Result<RequestId, TransportError> {
    if operation.is_empty()
        || operation.len() > 64
        || operation.starts_with('-')
        || operation.ends_with('-')
        || operation.contains("--")
        || !operation
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(TransportError::new(
            "session operation id must be a canonical 1..64-byte lowercase slug",
        ));
    }
    RequestId::new(format!("{prefix}{operation}"))
        .map_err(|error| TransportError::new(error.to_string()))
}

fn validate_request_id(request: &RequestId) -> Result<(), TransportError> {
    let operation = request
        .as_str()
        .strip_prefix(REQUEST_PREFIX)
        .ok_or_else(|| TransportError::new("request is outside the S17 session-lock namespace"))?;
    if request_identity(operation)? != *request {
        return Err(TransportError::new(
            "session request identity is noncanonical",
        ));
    }
    Ok(())
}

fn validate_transition_request_id(request: &RequestId) -> Result<(), TransportError> {
    let operation = request
        .as_str()
        .strip_prefix(TRANSITION_PREFIX)
        .ok_or_else(|| TransportError::new("request is outside the S17 transition namespace"))?;
    if request_identity_in_namespace(TRANSITION_PREFIX, operation)? != *request {
        return Err(TransportError::new(
            "transition request identity is noncanonical",
        ));
    }
    Ok(())
}

fn parse_transition(resource: &str) -> Result<SessionTransitionId, TransportError> {
    if resource.len() > 256 {
        return Err(TransportError::new(
            "session transition resource exceeds its bound",
        ));
    }
    SessionTransitionId::from_resource(
        &ResourceId::new(resource).map_err(|e| TransportError::new(e.to_string()))?,
    )
    .map_err(|e| TransportError::new(e.to_string()))
}

fn decode_transition_status(
    wire: SessionTransitionStatusWire,
    expected: &RequestId,
) -> Result<SessionTransitionRequestStatus, TransportError> {
    validate_transition_request_id(expected)?;
    let (request, transaction, resource, state) = wire;
    if request != expected.as_str()
        || !transaction_id(&transaction)
        || !matches!(
            state.as_str(),
            "prepared"
                | "indeterminate"
                | "verified"
                | "committed"
                | "aborted"
                | "recovery-blocked"
        )
    {
        return Err(TransportError::new(
            "Authority1 returned malformed or substituted transition status",
        ));
    }
    Ok(SessionTransitionRequestStatus {
        request_id: expected.clone(),
        transaction_id: transaction,
        target: parse_transition(&resource)?,
        state,
    })
}

fn decode_transition_receipt(
    wire: AuthorityReceiptWire,
    expected: &RequestId,
) -> Result<SessionTransitionReceipt, TransportError> {
    validate_transition_request_id(expected)?;
    validate_completion_wire(&wire, expected)?;
    let (transaction, _, resource, desired, effect, dispatch, execution, _, _, recovered, stages) =
        wire;
    if desired != "true" {
        return Err(TransportError::new(
            "transition completion postcondition is unsupported",
        ));
    }
    let target = parse_transition(&resource)?;
    let completion = match target.transition() {
        SessionTransition::Suspend { .. } => SessionTransitionCompletion::ResumedSecurely,
        SessionTransition::Logout => SessionTransitionCompletion::OriginalSessionEnded,
        SessionTransition::Reboot | SessionTransition::PowerOff => {
            SessionTransitionCompletion::OriginalBootEnded
        }
    };
    Ok(SessionTransitionReceipt {
        transaction_id: transaction,
        request_id: expected.clone(),
        target,
        completion,
        effect_digest: effect,
        dispatch_digest: (!dispatch.is_empty()).then_some(dispatch),
        execution_disposition: (!execution.is_empty()).then_some(execution),
        recovered,
        stages,
    })
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn transaction_id(value: &str) -> bool {
    value
        .strip_prefix("transaction:v1:")
        .is_some_and(hex_digest)
}

fn decode_status(
    wire: SessionLockStatusWire,
    expected: &RequestId,
) -> Result<SessionLockRequestStatus, TransportError> {
    validate_request_id(expected)?;
    let (request, transaction, resource, secure, state) = wire;
    if request != expected.as_str()
        || !transaction_id(&transaction)
        || !matches!(
            state.as_str(),
            "prepared"
                | "indeterminate"
                | "verified"
                | "committed"
                | "aborted"
                | "recovery-blocked"
        )
    {
        return Err(TransportError::new(
            "Authority1 returned malformed or substituted historical session status",
        ));
    }
    Ok(SessionLockRequestStatus {
        request_id: expected.clone(),
        transaction_id: transaction,
        lock: parse_lock(&resource)?,
        secure,
        state,
    })
}

fn decode_receipt(
    wire: AuthorityReceiptWire,
    expected: &RequestId,
) -> Result<SessionLockReceipt, TransportError> {
    validate_request_id(expected)?;
    validate_completion_wire(&wire, expected)?;
    let (transaction, _, resource, desired, effect, dispatch, execution, _, _, recovered, stages) =
        wire;
    if !matches!(desired.as_str(), "true" | "false") {
        return Err(TransportError::new(
            "managed lock postcondition is unsupported",
        ));
    }
    Ok(SessionLockReceipt {
        transaction_id: transaction,
        request_id: expected.clone(),
        lock: parse_lock(&resource)?,
        secure: desired == "true",
        effect_digest: effect,
        dispatch_digest: (!dispatch.is_empty()).then_some(dispatch),
        execution_disposition: (!execution.is_empty()).then_some(execution),
        recovered,
        stages,
    })
}

fn validate_completion_wire(
    wire: &AuthorityReceiptWire,
    expected: &RequestId,
) -> Result<(), TransportError> {
    let (
        transaction,
        plan,
        _,
        _,
        effect,
        dispatch,
        execution,
        verification,
        state,
        recovered,
        stages,
    ) = wire;
    if plan != expected.as_str()
        || !transaction_id(transaction)
        || !hex_digest(effect)
        || !dispatch.is_empty() && !hex_digest(dispatch)
        || !matches!(execution.as_str(), "" | "dispatched" | "indeterminate")
        || dispatch.is_empty() != execution.is_empty()
        || (!*recovered && execution.is_empty())
        || verification != "satisfied"
        || state != "committed"
        || stages
            .iter()
            .map(String::as_str)
            .ne(linura_lifecycle::MUTATION_STAGES
                .iter()
                .map(|stage| stage.as_str()))
    {
        return Err(TransportError::new(
            "Authority1 returned incomplete, substituted or unsupported managed session completion",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn display_wire_shape_and_receipts_bind_exact_request_and_closed_lifecycle_state() {
        let expected = value(linura_protocol::display_layout_request_id(
            "request:v010:display-layout:test",
        ));
        let wire: DisplayLayoutReceiptWire = (
            expected.as_str().into(), format!("transaction:v1:{}", "1".repeat(64)),
            "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3".into(),
            "awaiting-confirmation".into(), 15000,
        );
        let message = value(zbus::Message::method_call("/org/linura/Fixture", "Receipt"));
        let message = value(message.build(&(wire.clone(),)));
        assert_eq!(message.body().signature().to_string(), "(sssst)");
        let decoded = value(decode_display_reply(message, &expected));
        assert_eq!(
            decoded.state,
            linura_protocol::DisplayLayoutState::AwaitingConfirmation
        );
        assert_eq!(decoded.confirmation_expires_at_unix_ms, 15000);
        let message = value(zbus::Message::method_call("/org/linura/Fixture", "Receipt"));
        // A one-tuple wrapper is intentionally transparent to zvariant. Use
        // an actually different wire type, rather than mistaking that Rust
        // spelling for a distinct D-Bus signature.
        let wrong_shape = value(message.build(&(
            wire.0.clone(),
            wire.1.clone(),
            wire.2.clone(),
            wire.3.clone(),
            wire.4.to_string(),
        )));
        assert_eq!(wrong_shape.body().signature().to_string(), "(sssss)");
        assert!(decode_display_reply(wrong_shape, &expected).is_err());
        for field in 0..5 {
            let mut substituted = wire.clone();
            match field {
                0 => substituted.0 = "request:v010:display-layout:other".into(),
                1 => substituted.1 = "transaction:placeholder".into(),
                2 => substituted.2 = "display:topology:current".into(),
                3 => substituted.3 = "success".into(),
                _ => substituted.4 = 0,
            }
            assert!(decode_display_receipt(substituted, &expected).is_err());
        }
    }
    #[test]
    fn native_sleep_diagnostics_decode_only_canonical_bounded_login_and_closed_states() {
        let epoch = "session:epoch:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42";
        for state in ["unobserved", "checking", "coverage-fenced", "denied"] {
            assert_eq!(
                decode_native_sleep_gate_status(epoch, state)
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .state
                    .as_str(),
                state
            );
        }
        for state in [
            "",
            "secure",
            "sleeping",
            "committed",
            "allowed",
            "DENIED",
            "denied\n",
        ] {
            assert!(decode_native_sleep_gate_status(epoch, state).is_err());
        }
        for bad in [
            epoch.replace(":1000:", ":0:"),
            epoch.replace(":1000:", ":01000:"),
            epoch.replace(":42", ":0"),
            epoch.replace(":c2:", ":../:"),
            epoch.replace(
                "abcd1234-1234-4567-89ab-0123456789ab",
                "00000000-0000-0000-0000-000000000000",
            ),
            format!("{epoch}:extra"),
            "x".repeat(257),
        ] {
            assert!(decode_native_sleep_gate_status(&bad, "denied").is_err());
        }
    }

    use super::*;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn wire() -> AuthorityReceiptWire {
        (format!("transaction:v1:{}", "1".repeat(64)), "request:v010:session-lock:test".into(),
        "session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7".into(),
        "false".into(), "2".repeat(64), "3".repeat(64), "dispatched".into(), "satisfied".into(), "committed".into(), false,
        linura_lifecycle::MUTATION_STAGES.iter().map(|stage| stage.as_str().into()).collect())
    }
    #[test]
    fn power_receipts_bind_the_exact_transition_and_never_claim_current_power_off_or_causation() {
        let expected = value(request_identity_in_namespace(TRANSITION_PREFIX, "test"));
        for (action, baseline, completion) in [
            ("suspend", 10, SessionTransitionCompletion::ResumedSecurely),
            (
                "logout",
                0,
                SessionTransitionCompletion::OriginalSessionEnded,
            ),
            ("reboot", 0, SessionTransitionCompletion::OriginalBootEnded),
            (
                "power-off",
                0,
                SessionTransitionCompletion::OriginalBootEnded,
            ),
        ] {
            let mut sample = wire();
            sample.1 = expected.as_str().into();
            sample.2 = format!(
                "session:transition:{action}:{baseline}:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7"
            );
            sample.3 = "true".into();
            let receipt = value(decode_transition_receipt(sample.clone(), &expected));
            assert_eq!(receipt.completion, completion);
            assert_eq!(value(receipt.target.resource_id()).as_str(), sample.2);
            assert!(decode_receipt(sample.clone(), &expected).is_err());
            for kind in [
                "identity",
                "resource",
                "desired",
                "verification",
                "state",
                "stages",
                "dispatch",
            ] {
                let mut bad = sample.clone();
                match kind {
                    "identity" => bad.1 = value(request_identity("test")).as_str().into(),
                    "resource" => bad.2 = wire().2,
                    "desired" => bad.3 = "false".into(),
                    "verification" => bad.7 = "not-satisfied".into(),
                    "state" => bad.8 = "indeterminate".into(),
                    "stages" => {
                        bad.10.swap(7, 8);
                    }
                    _ => bad.5.clear(),
                }
                assert!(
                    decode_transition_receipt(bad, &expected).is_err(),
                    "{action} {kind}"
                );
            }
            let historical = value(decode_transition_status(
                (
                    sample.1.clone(),
                    sample.0.clone(),
                    sample.2.clone(),
                    "indeterminate".into(),
                ),
                &expected,
            ));
            assert_eq!(historical.state, "indeterminate");
            let mut recovered = sample;
            recovered.9 = true;
            recovered.5.clear();
            recovered.6.clear();
            assert!(value(decode_transition_receipt(recovered, &expected)).recovered);
        }
        assert!(validate_request_id(&expected).is_err());
        assert!(validate_transition_request_id(&value(request_identity("test"))).is_err());
    }

    #[test]
    fn typed_receipt_retains_exact_completion_but_rejects_partial_unknown_or_substituted_results() {
        let request = value(request_identity("test"));
        let receipt = value(decode_receipt(wire(), &request));
        assert!(!receipt.secure && !receipt.recovered);
        assert_eq!(receipt.request_id, request);
        for mode in 0..12 {
            let mut bad = wire();
            match mode {
                0 => bad.0 = "transaction:unbound".into(),
                1 => bad.1 = "request:v010:session-lock:other".into(),
                2 => bad.2 = "session:lock:bad".into(),
                3 => bad.3 = "FALSE".into(),
                4 => bad.4 = "f".repeat(63),
                5 => bad.5 = "A".repeat(64),
                6 => bad.6 = "rejected-before-dispatch".into(),
                7 => bad.7 = "not-satisfied".into(),
                8 => bad.8 = "verified".into(),
                9 => {
                    bad.10.pop();
                }
                10 => {
                    bad.5.clear();
                    bad.6.clear();
                }
                _ => bad.10.swap(7, 8),
            }
            assert!(decode_receipt(bad, &request).is_err(), "mode {mode}");
        }
        let mut historical_retry = wire();
        historical_retry.5.clear();
        historical_retry.6.clear();
        historical_retry.9 = true;
        assert!(decode_receipt(historical_retry, &request).is_ok());
    }
    #[test]
    fn historical_status_does_not_become_a_completion_receipt() {
        let request = value(request_identity("test"));
        let sample = wire();
        for state in [
            "prepared",
            "indeterminate",
            "verified",
            "committed",
            "aborted",
            "recovery-blocked",
        ] {
            let status = value(decode_status(
                (
                    request.as_str().into(),
                    sample.0.clone(),
                    sample.2.clone(),
                    false,
                    state.into(),
                ),
                &request,
            ));
            assert_eq!(status.state, state);
        }
        assert!(
            decode_status(
                (
                    request.as_str().into(),
                    sample.0,
                    sample.2,
                    false,
                    "allowed-to-retry".into()
                ),
                &request
            )
            .is_err()
        );
        for operation in ["", "-x", "x-", "x--y", "Upper", "a/b", "password prose"] {
            assert!(request_identity(operation).is_err());
        }
        assert!(validate_request_id(&value(RequestId::new("request:v06:test"))).is_err());
    }

    fn setting_wire() -> ProtectiveLockSettingWire {
        (
            value(protective_setting_request_identity("enable"))
                .as_str()
                .into(),
            wire().2,
            true,
            format!("intent:s17:protective-lock:{}", "a".repeat(64)),
            format!("policy:protective-lock:v1:{}", "b".repeat(64)),
            1,
            true,
        )
    }

    #[test]
    fn protective_setting_receipts_are_bounded_exact_history_not_execution() {
        let original = setting_wire();
        let receipt = value(decode_protective_setting(original.clone()));
        assert!(receipt.enabled && receipt.latest_for_epoch);
        let epoch = receipt.confirmed_lock.epoch().clone();
        assert!(value(decode_protective_setting_records(Vec::new(), &epoch)).is_none());
        assert_eq!(
            value(decode_protective_setting_records(
                vec![original.clone()],
                &epoch
            )),
            Some(receipt)
        );
        assert!(
            decode_protective_setting_records(vec![original.clone(), original.clone()], &epoch)
                .is_err()
        );
        for mode in 0..13 {
            let mut bad = original.clone();
            match mode {
                0 => bad.0 = value(request_identity("enable")).as_str().into(),
                1 => bad.0 = format!("{PROTECTIVE_SETTING_PREFIX}Upper"),
                2 => bad.1 = bad.1.replace(":1000:", ":0:"),
                3 => bad.1 = "session:lock:unbound".into(),
                4 => bad.3 = "x".repeat(129),
                5 => bad.3 = format!("intent:s17:protective-lock:{}", "A".repeat(64)),
                6 => bad.3 = format!("intent:s17:protective-lock:{}", "0".repeat(64)),
                7 => bad.4 = format!("policy:other:{}", "b".repeat(64)),
                8 => bad.4.pop().map(|_| ()).unwrap_or_default(),
                9 => bad.4 = format!("policy:protective-lock:v1:{}", "B".repeat(64)),
                10 => bad.4 = format!("policy:protective-lock:v1:{}", "0".repeat(64)),
                11 => bad.5 = 0,
                _ => bad.5 = u64::MAX,
            }
            assert!(decode_protective_setting(bad).is_err(), "mode {mode}");
        }
        let mut stale = original.clone();
        stale.6 = false;
        // A valid superseded receipt can be inspected, but cannot be returned
        // as the latest setting or treated as active consent.
        assert!(!value(decode_protective_setting(stale.clone())).latest_for_epoch);
        assert!(decode_protective_setting_records(vec![stale], &epoch).is_err());
        let mut another_epoch = original;
        another_epoch.1 = another_epoch.1.replace(":c2:", ":c3:");
        assert!(decode_protective_setting_records(vec![another_epoch], &epoch).is_err());
        for operation in ["", "-x", "x-", "x--y", "Upper", "a/b", "a b"] {
            assert!(protective_setting_request_identity(operation).is_err());
        }
        assert!(protective_setting_request_identity(&"a".repeat(65)).is_err());
        assert!(
            validate_protective_setting_request_id(&value(request_identity("enable"))).is_err()
        );
    }
}
