use std::fmt::{Debug, Formatter};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use linura_control::{
    AuthenticatedPrincipal, ManagedApprovalAuthorizer, ManagedApprovalChallenge,
    ManagedMutationReceipt, TrustedHumanApproval,
};
use linura_core::{
    Actor, ActorId, ActorKind, PrincipalId, ResourceId, SessionLockId, SessionTransitionId,
};
use zbus::message::Header;

use super::{
    ContractAnnotatedInterface, TransportError, authenticated_caller, fdo_failed,
    principal_from_caller,
};

pub const AUTHORITY_SERVICE_NAME: &str = "org.linura.Authority1";
pub const AUTHORITY_OBJECT_PATH: &str = "/org/linura/Authority1";
pub const AUTHORITY_INTERFACE_NAME: &str = "org.linura.Authority1";
pub const AUTHORITY_CONTRACT_ID: &str = "dbus.org.linura.Authority1";
pub const AUTHORITY_CONTRACT_VERSION: &str = "1";
pub const AUTHORITY_CONTRACT_STABILITY: &str = "experimental";
pub const MANAGE_SYSTEMD_ACTIVE_STATE_ACTION: &str =
    "org.linura.authority.manage-systemd-active-state";
pub const UNLOCK_SESSION_ACTION: &str = "org.linura.authority.unlock-session";

const POLKIT_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(60);
const POLKIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

const AUTHORITY_CONTRACT_ANNOTATIONS: [(&str, &str); 3] = [
    ("org.linura.ContractId", AUTHORITY_CONTRACT_ID),
    ("org.linura.ContractVersion", AUTHORITY_CONTRACT_VERSION),
    ("org.linura.Stability", AUTHORITY_CONTRACT_STABILITY),
];

pub type AuthorityReceiptWire = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    bool,
    Vec<String>,
);
pub type BacklightCandidateWire = (String, String, u32, u32, u32);
pub type SessionLockStatusWire = (String, String, String, bool, String);
pub type SessionTransitionStatusWire = (String, String, String, String);
pub(crate) type ProtectiveLockSettingWire = (String, String, bool, String, String, u64, bool);

fn protective_setting_wire(
    receipt: linura_protocol::ProtectiveLockSettingReceipt,
) -> Result<ProtectiveLockSettingWire, String> {
    Ok((
        receipt.request_id.as_str().into(),
        receipt
            .confirmed_lock
            .resource_id()
            .map_err(|e| e.to_string())?
            .as_str()
            .into(),
        receipt.enabled,
        receipt.intent_id.as_str().into(),
        receipt.revision_id.as_str().into(),
        receipt.confirmed_at_unix_ms,
        receipt.latest_for_epoch,
    ))
}

fn session_status_wire(
    status: linura_protocol::SessionLockRequestStatus,
) -> Result<SessionLockStatusWire, String> {
    Ok((
        status.request_id.as_str().into(),
        status.transaction_id,
        status
            .lock
            .resource_id()
            .map_err(|error| error.to_string())?
            .as_str()
            .into(),
        status.secure,
        status.state,
    ))
}

pub struct Authority1Context {
    pub principal: AuthenticatedPrincipal,
    pub actor: Actor,
    pub approval: Box<dyn ManagedApprovalAuthorizer>,
}

impl Debug for Authority1Context {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authority1Context")
            .field("principal", &self.principal.as_str())
            .field("actor", &self.actor)
            .field("approval", &"candidate-bound-authorizer")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority1ManagedRequest {
    pub operation_id: String,
    pub unit: String,
    pub desired_active_state: String,
    pub reason: String,
}

/// Transport-authenticated identity for the read-only backlight query.
/// The sender and PID are never decoded from Actor provenance or client input.
#[derive(Debug)]
pub struct Authority1BacklightContext {
    bus_guid: String,
    principal: AuthenticatedPrincipal,
    sender: String,
    pid: u32,
}

impl Authority1BacklightContext {
    fn from_caller(caller: &super::CallerIdentity, bus_guid: &str) -> zbus::fdo::Result<Self> {
        if bus_guid.len() != 32
            || !bus_guid.bytes().all(|byte| byte.is_ascii_hexdigit())
            || caller.uid == 0
            || caller.pid == 0
            || caller.pid > i32::MAX as u32
            || zbus::names::UniqueName::try_from(caller.unique_bus_name.as_str()).is_err()
        {
            return Err(fdo_failed("backlight caller identity is unsupported"));
        }
        Ok(Self {
            bus_guid: bus_guid.into(),
            principal: principal_from_caller(caller)?,
            sender: caller.unique_bus_name.clone(),
            pid: caller.pid,
        })
    }

    pub fn principal(&self) -> &AuthenticatedPrincipal {
        &self.principal
    }
    pub fn bus_guid(&self) -> &str {
        &self.bus_guid
    }
    pub fn sender(&self) -> &str {
        &self.sender
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority1SessionContext {
    pub principal: AuthenticatedPrincipal,
    pub actor: Actor,
}

pub trait Authority1Handler: Send + 'static {
    fn own_native_backlight_candidate(
        &mut self,
        context: Authority1BacklightContext,
    ) -> Result<BacklightCandidateWire, String>;
    fn own_native_sleep_gate_status(
        &mut self,
        context: Authority1SessionContext,
    ) -> Result<linura_protocol::NativeSleepGateStatus, String>;
    fn configure_protective_lock(
        &mut self,
        context: Authority1SessionContext,
        request: linura_protocol::ProtectiveLockSettingRequest,
    ) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String>;
    fn recorded_protective_lock_setting(
        &mut self,
        context: Authority1SessionContext,
        epoch: linura_core::SessionEpoch,
    ) -> Result<Option<linura_protocol::ProtectiveLockSettingReceipt>, String>;
    fn protective_lock_setting_request_status(
        &mut self,
        context: Authority1SessionContext,
        request: linura_core::RequestId,
    ) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String>;
    fn own_session_transition(
        &mut self,
        context: Authority1SessionContext,
        action: String,
    ) -> Result<String, String>;
    fn converge_session_transition(
        &mut self,
        context: Authority1SessionContext,
        request: linura_protocol::SessionTransitionRequest,
    ) -> Result<ManagedMutationReceipt, String>;
    fn recover_session_transition(
        &mut self,
        context: Authority1SessionContext,
        request_id: linura_core::RequestId,
    ) -> Result<ManagedMutationReceipt, String>;
    fn session_transition_request_status(
        &mut self,
        context: Authority1SessionContext,
        request_id: linura_core::RequestId,
    ) -> Result<linura_protocol::SessionTransitionRequestStatus, String>;
    fn acknowledge_session_transition(
        &mut self,
        context: Authority1SessionContext,
        request_id: linura_core::RequestId,
    ) -> Result<bool, String>;
    fn own_session_lock(&mut self, context: Authority1SessionContext) -> Result<String, String>;
    fn converge_session_lock(
        &mut self,
        context: Authority1SessionContext,
        request: linura_protocol::SessionLockRequest,
    ) -> Result<ManagedMutationReceipt, String>;
    fn recover_session_lock(
        &mut self,
        context: Authority1SessionContext,
        request_id: linura_core::RequestId,
    ) -> Result<ManagedMutationReceipt, String>;
    fn session_lock_request_status(
        &mut self,
        context: Authority1SessionContext,
        request_id: linura_core::RequestId,
    ) -> Result<linura_protocol::SessionLockRequestStatus, String>;
    fn acknowledge_session_lock_release(
        &mut self,
        context: Authority1SessionContext,
        request_id: linura_core::RequestId,
    ) -> Result<bool, String>;
    fn converge_systemd_active_state(
        &mut self,
        context: Authority1Context,
        request: Authority1ManagedRequest,
    ) -> Result<ManagedMutationReceipt, String>;
}

#[derive(Clone, Debug)]
struct PolkitManagedApprovalAuthorizer {
    sender: String,
    principal: PrincipalId,
}

impl PolkitManagedApprovalAuthorizer {
    fn new(sender: String, principal: PrincipalId) -> Self {
        Self { sender, principal }
    }
}

impl ManagedApprovalAuthorizer for PolkitManagedApprovalAuthorizer {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        if challenge.principal() != &self.principal {
            return Err(
                "Polkit approval challenge principal differs from authenticated caller".into(),
            );
        }
        authorize_human_candidate(&self.sender, challenge)?;
        Ok(TrustedHumanApproval::from_authorized_challenge(
            self.principal.clone(),
            challenge,
        ))
    }
}

struct Authority1Service {
    handler: Arc<Mutex<Box<dyn Authority1Handler>>>,
}

impl Debug for Authority1Service {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authority1Service")
            .finish_non_exhaustive()
    }
}

impl Authority1Service {
    fn new(handler: impl Authority1Handler) -> Self {
        Self {
            handler: Arc::new(Mutex::new(Box::new(handler))),
        }
    }

    async fn with_handler<R, F>(&self, operation: F) -> zbus::fdo::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut dyn Authority1Handler) -> Result<R, String> + Send + 'static,
    {
        let handler = Arc::clone(&self.handler);
        blocking::unblock(move || {
            let mut guard = handler
                .lock()
                .map_err(|_| "Authority1 handler lock is poisoned".to_owned())?;
            operation(guard.as_mut())
        })
        .await
        .map_err(fdo_failed)
    }
}

async fn session_context(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<Authority1SessionContext> {
    let caller = authenticated_caller(connection, header).await?;
    if caller.uid == 0 {
        return Err(fdo_failed("root graphical sessions are unsupported"));
    }
    let principal = principal_from_caller(&caller)?;
    let mut actor = caller.actor;
    // This marks an interaction request, not proof of human approval. The
    // native owner must independently confirm/authenticate the exact challenge.
    actor.kind = ActorKind::Human;
    actor.interactive = true;
    Ok(Authority1SessionContext { principal, actor })
}

#[zbus::interface(name = "org.linura.Authority1")]
impl Authority1Service {
    /// Read-only own-session native backlight sample; no authority to write.
    /// Return unsupported/unavailable when hardware or identity is ambiguous.
    #[zbus(out_args("candidate"))]
    async fn get_own_native_backlight_candidate(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(BacklightCandidateWire,)> {
        let caller = authenticated_caller(connection, &header).await?;
        let context =
            Authority1BacklightContext::from_caller(&caller, connection.server_guid().as_str())?;
        let handler = self.handler.clone();
        // A diagnostic must never queue behind human approval, durable
        // commits or native power transitions. No cached success on busy.
        blocking::unblock(move || {
            let mut handler = handler
                .try_lock()
                .map_err(|_| fdo_failed("backlight observation busy or unavailable"))?;
            handler
                .own_native_backlight_candidate(context)
                .map(|candidate| (candidate,))
                .map_err(fdo_failed)
        })
        .await
    }

    #[zbus(out_args("status"))]
    async fn get_own_native_sleep_gate_status(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<((String, String),)> {
        let context = session_context(connection, &header).await?;
        let handler = self.handler.clone();
        // Status reads must not queue behind a native authentication or managed
        // suspend. Busy means unavailable, never cached "protected" success.
        blocking::unblock(move || {
            let mut handler = handler
                .try_lock()
                .map_err(|_| fdo_failed("sleep diagnostics busy or unavailable"))?;
            let status = handler
                .own_native_sleep_gate_status(context)
                .map_err(fdo_failed)?;
            Ok(((
                status
                    .epoch
                    .resource_id()
                    .map_err(|e| fdo_failed(e.to_string()))?
                    .as_str()
                    .into(),
                status.state.as_str().into(),
            ),))
        })
        .await
    }

    #[zbus(out_args("receipt"))]
    async fn configure_protective_lock(
        &self,
        operation_id: &str,
        resource: &str,
        enabled: bool,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(ProtectiveLockSettingWire,)> {
        let context = session_context(connection, &header).await?;
        super::authority_client::protective_setting_request_identity(operation_id)
            .map_err(|e| fdo_failed(e.to_string()))?;
        if resource.len() > 256 {
            return Err(fdo_failed("protective-lock resource exceeds its bound"));
        }
        let lock = SessionLockId::from_resource(
            &ResourceId::new(resource).map_err(|e| fdo_failed(e.to_string()))?,
        )
        .map_err(|e| fdo_failed(e.to_string()))?;
        if context.principal.as_str() != format!("unix:uid:{}", lock.epoch().uid()) {
            return Err(fdo_failed(
                "protective-lock policy belongs to another principal",
            ));
        }
        let request = linura_protocol::ProtectiveLockSettingRequest {
            operation_id: operation_id.into(),
            lock,
            enabled,
        };
        self.with_handler(move |handler| {
            protective_setting_wire(handler.configure_protective_lock(context, request)?)
                .map(|receipt| (receipt,))
        })
        .await
    }

    #[zbus(out_args("records"))]
    async fn get_protective_lock_setting(
        &self,
        epoch: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<Vec<ProtectiveLockSettingWire>> {
        let context = session_context(connection, &header).await?;
        if epoch.len() > 256 {
            return Err(fdo_failed("protective-lock epoch exceeds its bound"));
        }
        let epoch = linura_core::SessionEpoch::from_resource(
            &ResourceId::new(epoch).map_err(|e| fdo_failed(e.to_string()))?,
        )
        .map_err(|e| fdo_failed(e.to_string()))?;
        if context.principal.as_str() != format!("unix:uid:{}", epoch.uid()) {
            return Err(fdo_failed(
                "protective-lock history belongs to another principal",
            ));
        }
        self.with_handler(move |handler| {
            handler
                .recorded_protective_lock_setting(context, epoch)?
                .map(protective_setting_wire)
                .transpose()
                .map(|record| record.into_iter().collect())
        })
        .await
    }

    #[zbus(out_args("receipt"))]
    async fn get_protective_lock_setting_request_status(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(ProtectiveLockSettingWire,)> {
        let context = session_context(connection, &header).await?;
        if request_id.len() > 128 {
            return Err(fdo_failed("protective-lock request exceeds its bound"));
        }
        let request =
            linura_core::RequestId::new(request_id).map_err(|e| fdo_failed(e.to_string()))?;
        super::authority_client::validate_protective_setting_request_id(&request)
            .map_err(|e| fdo_failed(e.to_string()))?;
        self.with_handler(move |handler| {
            protective_setting_wire(
                handler.protective_lock_setting_request_status(context, request)?,
            )
            .map(|receipt| (receipt,))
        })
        .await
    }

    #[zbus(out_args("resource"))]
    async fn get_own_session_transition(
        &self,
        action: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let context = session_context(connection, &header).await?;
        if !matches!(action, "suspend" | "logout" | "reboot" | "power-off") {
            return Err(fdo_failed("session transition action is unsupported"));
        }
        let action = action.to_owned();
        self.with_handler(move |handler| handler.own_session_transition(context, action))
            .await
    }

    #[zbus(out_args("receipt"))]
    async fn converge_session_transition(
        &self,
        operation_id: &str,
        resource: &str,
        reason: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(AuthorityReceiptWire,)> {
        let context = session_context(connection, &header).await?;
        if operation_id.len() > 64 || resource.len() > 256 || reason.len() > 1024 {
            return Err(fdo_failed("session transition request exceeds its bound"));
        }
        let target = SessionTransitionId::from_resource(
            &ResourceId::new(resource).map_err(|e| fdo_failed(e.to_string()))?,
        )
        .map_err(|e| fdo_failed(e.to_string()))?;
        if context.principal.as_str() != format!("unix:uid:{}", target.lock().epoch().uid()) {
            return Err(fdo_failed(
                "session transition belongs to another principal",
            ));
        }
        let request = linura_protocol::SessionTransitionRequest {
            operation_id: operation_id.into(),
            target,
            reason: reason.into(),
        };
        self.with_handler(move |handler| {
            handler
                .converge_session_transition(context, request)
                .map(|receipt| (receipt_wire(receipt),))
        })
        .await
    }

    #[zbus(out_args("receipt"))]
    async fn recover_session_transition(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(AuthorityReceiptWire,)> {
        let context = session_context(connection, &header).await?;
        let request_id = transition_request_identity(request_id)?;
        self.with_handler(move |handler| {
            handler
                .recover_session_transition(context, request_id)
                .map(|receipt| (receipt_wire(receipt),))
        })
        .await
    }

    #[zbus(out_args("status"))]
    async fn get_session_transition_request_status(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(SessionTransitionStatusWire,)> {
        let context = session_context(connection, &header).await?;
        let request_id = transition_request_identity(request_id)?;
        self.with_handler(move |handler| {
            let status = handler.session_transition_request_status(context, request_id)?;
            Ok(((
                status.request_id.as_str().into(),
                status.transaction_id,
                status
                    .target
                    .resource_id()
                    .map_err(|e| e.to_string())?
                    .as_str()
                    .into(),
                status.state,
            ),))
        })
        .await
    }

    #[zbus(out_args("acknowledged"))]
    async fn acknowledge_session_transition(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let context = session_context(connection, &header).await?;
        let request_id = transition_request_identity(request_id)?;
        self.with_handler(move |handler| {
            handler.acknowledge_session_transition(context, request_id)
        })
        .await
    }

    #[zbus(out_args("status"))]
    async fn get_session_lock_request_status(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(SessionLockStatusWire,)> {
        let context = session_context(connection, &header).await?;
        if request_id.len() > 128 {
            return Err(fdo_failed("session request id exceeds its bound"));
        }
        let request_id = linura_core::RequestId::new(request_id)
            .map_err(|error| fdo_failed(error.to_string()))?;
        self.with_handler(move |handler| {
            session_status_wire(handler.session_lock_request_status(context, request_id)?)
                .map(|status| (status,))
        })
        .await
    }

    #[zbus(out_args("acknowledged"))]
    async fn acknowledge_session_lock_release(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let context = session_context(connection, &header).await?;
        if request_id.len() > 128 {
            return Err(fdo_failed("session request id exceeds its bound"));
        }
        let request_id = linura_core::RequestId::new(request_id)
            .map_err(|error| fdo_failed(error.to_string()))?;
        self.with_handler(move |handler| {
            handler.acknowledge_session_lock_release(context, request_id)
        })
        .await
    }

    #[zbus(out_args("resource"))]
    async fn get_own_session_lock(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let context = session_context(connection, &header).await?;
        self.with_handler(move |handler| handler.own_session_lock(context))
            .await
    }

    #[zbus(out_args("receipt"))]
    async fn converge_session_lock(
        &self,
        operation_id: &str,
        resource: &str,
        secure: bool,
        reason: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(AuthorityReceiptWire,)> {
        let context = session_context(connection, &header).await?;
        if operation_id.len() > 64 || resource.len() > 256 || reason.len() > 1024 {
            return Err(fdo_failed("session lock request exceeds its bound"));
        }
        let lock = SessionLockId::from_resource(
            &ResourceId::new(resource).map_err(|e| fdo_failed(e.to_string()))?,
        )
        .map_err(|e| fdo_failed(e.to_string()))?;
        if context.principal.as_str() != format!("unix:uid:{}", lock.epoch().uid()) {
            return Err(fdo_failed("session lock belongs to a different principal"));
        }
        let request = linura_protocol::SessionLockRequest {
            operation_id: operation_id.into(),
            lock,
            secure,
            reason: reason.into(),
        };
        self.with_handler(move |handler| {
            handler
                .converge_session_lock(context, request)
                .map(|receipt| (receipt_wire(receipt),))
        })
        .await
    }

    #[zbus(out_args("receipt"))]
    async fn recover_session_lock(
        &self,
        request_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(AuthorityReceiptWire,)> {
        let context = session_context(connection, &header).await?;
        let request_id =
            linura_core::RequestId::new(request_id).map_err(|e| fdo_failed(e.to_string()))?;
        self.with_handler(move |handler| {
            handler
                .recover_session_lock(context, request_id)
                .map(|receipt| (receipt_wire(receipt),))
        })
        .await
    }

    async fn converge_systemd_active_state(
        &self,
        operation_id: &str,
        unit: &str,
        desired_active_state: &str,
        reason: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<AuthorityReceiptWire> {
        let caller = authenticated_caller(connection, &header).await?;
        let principal = principal_from_caller(&caller)?;
        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| fdo_failed(error.to_string()))?;
        let actor = Actor {
            id: ActorId::new(format!(
                "authority-dbus:v1:{}:{}:uid:{}:pid:{}",
                caller.unique_bus_name.len(),
                caller.unique_bus_name,
                caller.uid,
                caller.pid
            ))
            .map_err(|error| fdo_failed(error.to_string()))?,
            kind: ActorKind::Human,
            interactive: true,
        };
        let context = Authority1Context {
            principal,
            actor,
            approval: Box::new(PolkitManagedApprovalAuthorizer::new(
                caller.unique_bus_name.clone(),
                principal_id,
            )),
        };
        let request = Authority1ManagedRequest {
            operation_id: operation_id.to_owned(),
            unit: unit.to_owned(),
            desired_active_state: desired_active_state.to_owned(),
            reason: reason.to_owned(),
        };

        // Planning, risk/policy review and candidate construction happen inside
        // Control first. Polkit is invoked later through the authorizer only if
        // that exact canonical candidate actually requires administrator approval.
        // The authorization subprocess is independently time-bounded, so this
        // serialized authority section cannot be held indefinitely by an abandoned prompt.
        self.with_handler(move |handler| {
            handler
                .converge_systemd_active_state(context, request)
                .and_then(systemd_receipt_wire)
        })
        .await
    }
}

fn authorize_human_candidate(
    sender: &str,
    challenge: &ManagedApprovalChallenge,
) -> Result<(), String> {
    let arguments = polkit_arguments(sender, challenge)?;
    let mut child = Command::new("/usr/bin/pkcheck")
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            "unix:path=/run/dbus/system_bus_socket",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Polkit authorization service is unavailable: {error}"))?;
    let status = wait_for_polkit(&mut child, POLKIT_AUTHORIZATION_TIMEOUT)?;
    if status.success() {
        Ok(())
    } else {
        Err("native purpose-scoped approval was denied or unavailable".into())
    }
}

fn wait_for_polkit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot observe Polkit authorization process: {error}"))?
        {
            return Ok(status);
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            child.kill().map_err(|error| {
                format!("cannot cancel timed-out Polkit authorization: {error}")
            })?;
            child
                .wait()
                .map_err(|error| format!("cannot reap timed-out Polkit authorization: {error}"))?;
            return Err("administrator approval timed out".into());
        }
        thread::sleep(std::cmp::min(
            POLKIT_POLL_INTERVAL,
            timeout.saturating_sub(elapsed),
        ));
    }
}

fn polkit_arguments(
    sender: &str,
    challenge: &ManagedApprovalChallenge,
) -> Result<Vec<String>, String> {
    let action = polkit_action_for(
        challenge.resource(),
        challenge.change_key(),
        challenge.desired_value(),
        challenge.principal(),
    )?;
    let summary = format!(
        "{} -> {}={} (plan {})",
        challenge.resource().as_str(),
        challenge.change_key(),
        challenge.desired_value(),
        challenge.plan_id().as_str()
    );
    // Never place free-form human prose on a process command line. The request
    // digest already binds the exact reason and the rest of the canonical request;
    // argv carries only constrained identifiers/state plus cryptographic digests.
    let details = [
        ("linura.summary", summary),
        (
            "linura.request_id",
            challenge.request_id().as_str().to_owned(),
        ),
        ("linura.plan_id", challenge.plan_id().as_str().to_owned()),
        (
            "linura.request_digest",
            challenge.request_digest().to_owned(),
        ),
        (
            "linura.observation_digest",
            challenge.observation_digest().to_owned(),
        ),
        ("linura.review_digest", challenge.review_digest().to_owned()),
        ("linura.resource", challenge.resource().as_str().to_owned()),
        ("linura.change_key", challenge.change_key().to_owned()),
        ("linura.desired_value", challenge.desired_value().to_owned()),
    ];

    // Keep the closed native action selection explicit at the argv boundary.
    // Neither an action string from a caller nor a dynamically resolved action
    // can reach pkcheck; the namespace anti-substitution guard checks both arms.
    let mut arguments = match action {
        NativeApprovalAction::ManageSystemd => vec![
            "--action-id".to_owned(),
            MANAGE_SYSTEMD_ACTIVE_STATE_ACTION.to_owned(),
        ],
        NativeApprovalAction::UnlockSession => {
            vec!["--action-id".to_owned(), UNLOCK_SESSION_ACTION.to_owned()]
        }
    };
    arguments.extend([
        "--system-bus-name".to_owned(),
        sender.to_owned(),
        "--allow-user-interaction".to_owned(),
    ]);
    for (key, value) in details {
        arguments.push("--detail".to_owned());
        arguments.push(key.to_owned());
        arguments.push(value);
    }
    Ok(arguments)
}

/// Map a sealed Control-owned challenge to a fixed native authorization action.
/// This is not policy evaluation and cannot manufacture an approval class. The
/// private challenge constructor has already checked the reviewed requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeApprovalAction {
    ManageSystemd,
    UnlockSession,
}

fn polkit_action_for(
    resource: &ResourceId,
    key: &str,
    desired: &str,
    principal: &PrincipalId,
) -> Result<NativeApprovalAction, String> {
    if key == "active_state"
        && matches!(desired, "active" | "inactive")
        && resource
            .as_str()
            .starts_with("systemd:unit:linura-managed-")
        && resource.as_str().ends_with(".service")
    {
        return Ok(NativeApprovalAction::ManageSystemd);
    }
    let lock = SessionLockId::from_resource(resource)
        .map_err(|_| "approval challenge has no qualified native purpose".to_owned())?;
    if lock.epoch().uid() == 0
        || key != "secure"
        || principal.as_str() != format!("unix:uid:{}", lock.epoch().uid())
    {
        return Err("approval challenge has a different native session owner or purpose".into());
    }
    match desired {
        "true" => Err("locking requires native candidate-bound human confirmation; Polkit active-user permission is not confirmation".into()),
        "false" => Ok(NativeApprovalAction::UnlockSession),
        _ => Err("approval challenge has an unsupported native lock state".into()),
    }
}

fn transition_request_identity(value: &str) -> zbus::fdo::Result<linura_core::RequestId> {
    if value.len() > 128 || !value.starts_with("request:v010:session-transition:") {
        return Err(fdo_failed(
            "request is outside the S17 transition namespace",
        ));
    }
    linura_core::RequestId::new(value).map_err(|e| fdo_failed(e.to_string()))
}

fn systemd_receipt_wire(receipt: ManagedMutationReceipt) -> Result<AuthorityReceiptWire, String> {
    if receipt.change_key != "active_state"
        || !matches!(receipt.desired_value.as_str(), "active" | "inactive")
    {
        return Err("systemd receipt has a non-systemd desired state".into());
    }
    Ok(receipt_wire(receipt))
}

fn receipt_wire(receipt: ManagedMutationReceipt) -> AuthorityReceiptWire {
    (
        receipt.transaction_id,
        receipt.plan_id,
        receipt.resource,
        receipt.desired_value,
        receipt.effect_digest,
        receipt.dispatch_digest.unwrap_or_default(),
        receipt.execution_disposition.unwrap_or_default(),
        receipt.verification_disposition,
        receipt.final_state,
        receipt.recovered,
        receipt.stages,
    )
}

fn authority1_service(
    handler: impl Authority1Handler,
) -> ContractAnnotatedInterface<Authority1Service> {
    ContractAnnotatedInterface::new(
        Authority1Service::new(handler),
        &AUTHORITY_CONTRACT_ANNOTATIONS,
    )
}

pub fn serve_authority1(
    connection: zbus::blocking::Connection,
    handler: impl Authority1Handler,
) -> Result<(), TransportError> {
    // The composition root establishes/authenticates this connection and owns
    // the fixed service name before constructing native integrations. Keeping
    // this exact connection is essential: peer identity is a unique bus sender,
    // not merely the daemon's PID/UID. Do not reconnect inside this adapter.
    let owner: String = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )?
    .call("GetNameOwner", &(AUTHORITY_SERVICE_NAME,))?;
    if connection
        .unique_name()
        .is_none_or(|name| name.as_str() != owner)
    {
        return Err(TransportError::new(
            "Authority1 connection does not own its canonical name",
        ));
    }
    let service = authority1_service(handler);
    connection
        .object_server()
        .at(AUTHORITY_OBJECT_PATH, service)?;
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    #[test]
    fn backlight_context_retains_transport_identity_independently_of_actor() {
        let mut caller = super::super::actor_from_credentials(":1.42", 1000, 51)
            .unwrap_or_else(|error| unreachable!("{error}"));
        // Actor remains untrusted provenance even when it resembles a sender.
        caller.actor.id =
            ActorId::new("dbus:forged:uid:0:pid:1").unwrap_or_else(|error| unreachable!("{error}"));
        let context =
            Authority1BacklightContext::from_caller(&caller, "0123456789abcdef0123456789abcdef")
                .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(context.principal().as_str(), "unix:uid:1000");
        assert_eq!(context.sender(), ":1.42");
        assert_eq!(context.bus_guid(), "0123456789abcdef0123456789abcdef");
        assert_eq!(context.pid(), 51);
    }

    #[test]
    fn backlight_context_rejects_root_missing_pid_and_nonunique_sender() {
        for (name, uid, pid) in [
            (":1.42", 0, 51),
            (":1.42", 1000, 0),
            (":1.42", 1000, u32::MAX),
            ("org.linura.Caller", 1000, 51),
            ("", 1000, 51),
            (":bad\n", 1000, 51),
        ] {
            let mut caller = super::super::actor_from_credentials(":1.42", uid, pid)
                .unwrap_or_else(|error| unreachable!("{error}"));
            caller.unique_bus_name = name.into();
            assert!(
                Authority1BacklightContext::from_caller(
                    &caller,
                    "0123456789abcdef0123456789abcdef"
                )
                .is_err()
            );
        }
    }

    #[derive(Debug)]
    struct NeverCalled;

    impl Authority1Handler for NeverCalled {
        fn own_native_backlight_candidate(
            &mut self,
            _: Authority1BacklightContext,
        ) -> Result<BacklightCandidateWire, String> {
            Err("introspection must not query native backlight".into())
        }
        fn own_native_sleep_gate_status(
            &mut self,
            _: Authority1SessionContext,
        ) -> Result<linura_protocol::NativeSleepGateStatus, String> {
            Err("introspection must not query sleep diagnostics".into())
        }
        fn configure_protective_lock(
            &mut self,
            _: Authority1SessionContext,
            _: linura_protocol::ProtectiveLockSettingRequest,
        ) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String> {
            Err("introspection must not change protective policy".into())
        }
        fn recorded_protective_lock_setting(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::SessionEpoch,
        ) -> Result<Option<linura_protocol::ProtectiveLockSettingReceipt>, String> {
            Err("introspection must not query protective policy".into())
        }
        fn protective_lock_setting_request_status(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String> {
            Err("introspection must not query protective history".into())
        }
        fn own_session_transition(
            &mut self,
            _: Authority1SessionContext,
            _: String,
        ) -> Result<String, String> {
            Err("introspection must not query native transitions".into())
        }
        fn converge_session_transition(
            &mut self,
            _: Authority1SessionContext,
            _: linura_protocol::SessionTransitionRequest,
        ) -> Result<ManagedMutationReceipt, String> {
            Err("introspection must not dispatch transitions".into())
        }
        fn recover_session_transition(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<ManagedMutationReceipt, String> {
            Err("introspection must not recover transitions".into())
        }
        fn session_transition_request_status(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<linura_protocol::SessionTransitionRequestStatus, String> {
            Err("introspection must not query historical transitions".into())
        }
        fn acknowledge_session_transition(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<bool, String> {
            Err("introspection must not acknowledge transitions".into())
        }
        fn session_lock_request_status(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<linura_protocol::SessionLockRequestStatus, String> {
            Err("introspection must not query retained state".into())
        }
        fn acknowledge_session_lock_release(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<bool, String> {
            Err("introspection must not acknowledge".into())
        }
        fn own_session_lock(&mut self, _: Authority1SessionContext) -> Result<String, String> {
            Err("introspection must not query native state".into())
        }
        fn converge_session_lock(
            &mut self,
            _: Authority1SessionContext,
            _: linura_protocol::SessionLockRequest,
        ) -> Result<ManagedMutationReceipt, String> {
            Err("introspection must not mutate".into())
        }
        fn recover_session_lock(
            &mut self,
            _: Authority1SessionContext,
            _: linura_core::RequestId,
        ) -> Result<ManagedMutationReceipt, String> {
            Err("introspection must not recover".into())
        }
        fn converge_systemd_active_state(
            &mut self,
            _context: Authority1Context,
            _request: Authority1ManagedRequest,
        ) -> Result<ManagedMutationReceipt, String> {
            Err("introspection must not call the authority handler".into())
        }
    }

    fn required_source_offset(haystack: &str, needle: &str) -> usize {
        let offset = haystack.find(needle);
        assert!(
            offset.is_some(),
            "required source marker is missing: {needle}"
        );
        offset.unwrap_or_default()
    }

    #[test]
    fn systemd_receipt_wire_rejects_cross_route_state() {
        let receipt = ManagedMutationReceipt {
            transaction_id: "transaction:1".into(),
            plan_id: "plan:1".into(),
            resource: "systemd:unit:linura-managed-example.service".into(),
            change_key: "active_state".into(),
            desired_value: "active".into(),
            effect_digest: "digest".into(),
            dispatch_digest: None,
            execution_disposition: None,
            verification_disposition: "verified".into(),
            final_state: "complete".into(),
            recovered: false,
            stages: Vec::new(),
        };
        assert!(systemd_receipt_wire(receipt.clone()).is_ok());
        let mut wrong_route = receipt.clone();
        wrong_route.change_key = "secure".into();
        assert!(systemd_receipt_wire(wrong_route).is_err());
        let mut wrong_state = receipt;
        wrong_state.desired_value = "true".into();
        assert!(systemd_receipt_wire(wrong_state).is_err());
    }

    #[test]
    fn authority_contract_is_explicitly_experimental() {
        assert_eq!(AUTHORITY_SERVICE_NAME, "org.linura.Authority1");
        assert_eq!(AUTHORITY_INTERFACE_NAME, "org.linura.Authority1");
        assert_eq!(AUTHORITY_CONTRACT_ID, "dbus.org.linura.Authority1");
        assert_eq!(AUTHORITY_CONTRACT_VERSION, "1");
        assert_eq!(AUTHORITY_CONTRACT_STABILITY, "experimental");
    }

    #[test]
    fn native_approval_actions_never_promote_owner_unlock_to_administrator() {
        let owner =
            PrincipalId::new("unix:uid:1000").unwrap_or_else(|error| unreachable!("{error}"));
        let lock =
            ResourceId::new("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7")
                .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(polkit_action_for(&lock, "secure", "true", &owner).is_err());
        assert_eq!(
            polkit_action_for(&lock, "secure", "false", &owner),
            Ok(NativeApprovalAction::UnlockSession)
        );
        let root = PrincipalId::new("unix:uid:0").unwrap_or_else(|error| unreachable!("{error}"));
        assert!(polkit_action_for(&lock, "secure", "false", &root).is_err());
        for (key, desired) in [
            ("active_state", "active"),
            ("secure", "FALSE"),
            ("power", "reboot"),
        ] {
            assert!(polkit_action_for(&lock, key, desired, &owner).is_err());
        }
    }

    #[test]
    fn live_authority_introspection_matches_canonical_surface() {
        let service = authority1_service(NeverCalled);
        let mut live = String::new();
        service.introspect_to_writer(&mut live, 0);
        let canonical = include_str!("../../../interfaces/dbus/org.linura.Authority1.xml");

        for &(name, value) in &AUTHORITY_CONTRACT_ANNOTATIONS {
            let marker = format!("name=\"{name}\" value=\"{value}\"");
            assert_eq!(canonical.matches(&marker).count(), 1, "canonical {name}");
            assert_eq!(live.matches(&marker).count(), 1, "live {name}");
        }
        let method = "<method name=\"ConvergeSystemdActiveState\">";
        assert!(canonical.contains(method));
        assert!(live.contains(method));
        for argument in ["operation_id", "unit", "desired_active_state", "reason"] {
            let marker = format!("name=\"{argument}\" type=\"s\" direction=\"in\"");
            assert!(canonical.contains(&marker), "canonical {argument}");
            assert!(live.contains(&marker), "live {argument}");
        }
        let receipt = "type=\"(sssssssssbas)\" direction=\"out\"";
        assert_eq!(canonical.matches(receipt).count(), 5, "canonical receipts");
        assert_eq!(live.matches(receipt).count(), 5, "live receipts");
        for method in [
            "GetOwnNativeSleepGateStatus",
            "GetOwnNativeBacklightCandidate",
            "ConfigureProtectiveLock",
            "GetProtectiveLockSetting",
            "GetProtectiveLockSettingRequestStatus",
            "GetOwnSessionLock",
            "ConvergeSessionLock",
            "RecoverSessionLock",
            "GetOwnSessionTransition",
            "ConvergeSessionTransition",
            "RecoverSessionTransition",
            "GetSessionTransitionRequestStatus",
            "AcknowledgeSessionTransition",
        ] {
            let marker = format!("<method name=\"{method}\">");
            assert!(canonical.contains(&marker), "canonical {method}");
            assert!(live.contains(&marker), "live {method}");
        }
        for (method, shape) in [
            ("GetOwnNativeSleepGateStatus", "(ss)"),
            ("GetOwnNativeBacklightCandidate", "(ssuuu)"),
            ("ConfigureProtectiveLock", "(ssbsstb)"),
            ("GetProtectiveLockSetting", "a(ssbsstb)"),
            ("GetProtectiveLockSettingRequestStatus", "(ssbsstb)"),
        ] {
            for (label, xml) in [("canonical", canonical), ("live", live.as_str())] {
                let marker = format!("<method name=\"{method}\">");
                let method_xml = xml
                    .split_once(&marker)
                    .unwrap_or_else(|| unreachable!())
                    .1
                    .split_once("</method>")
                    .unwrap_or_else(|| unreachable!())
                    .0;
                assert!(
                    method_xml.contains(&format!("type=\"{shape}\" direction=\"out\"")),
                    "{label} {method}"
                );
                if matches!(
                    method,
                    "GetOwnNativeSleepGateStatus" | "GetOwnNativeBacklightCandidate"
                ) {
                    assert!(
                        !method_xml.contains("direction=\"in\""),
                        "{label} diagnostic identity is transport-derived"
                    );
                }
            }
        }
    }

    #[test]
    fn source_orders_polkit_after_control_candidate_construction() {
        let source = include_str!("authority.rs");
        let method = &source[source
            .find("async fn converge_systemd_active_state")
            .unwrap_or_default()..];
        let handler = method.find("self.with_handler").unwrap_or(usize::MAX);
        let eager_pkcheck = method[..handler.min(method.len())].find("pkcheck");
        assert!(eager_pkcheck.is_none());
        assert!(source.contains("ManagedApprovalChallenge"));
        assert!(source.contains("--detail"));
        assert!(source.contains("linura.request_digest"));
        assert!(source.contains("linura.review_digest"));
        assert!(source.contains("linura.observation_digest"));
    }

    #[test]
    fn polkit_argv_excludes_free_form_reason_and_wait_is_bounded() {
        let source = include_str!("authority.rs");
        let authorize_start = required_source_offset(source, "fn authorize_human_candidate(");
        let wait_relative =
            required_source_offset(&source[authorize_start..], "\nfn wait_for_polkit(");
        let wait_start = authorize_start + wait_relative;
        let arguments_relative =
            required_source_offset(&source[wait_start..], "\nfn polkit_arguments(");
        let arguments_start = wait_start + arguments_relative;
        let receipt_relative =
            required_source_offset(&source[arguments_start..], "\nfn receipt_wire(");
        let receipt_start = arguments_start + receipt_relative;

        let authorization = &source[authorize_start..wait_start];
        let wait = &source[wait_start..arguments_start];
        let arguments = &source[arguments_start..receipt_start];

        assert!(!arguments.contains("\"linura.reason\""));
        assert!(!arguments.contains("challenge.reason()"));
        assert!(authorization.contains("POLKIT_AUTHORIZATION_TIMEOUT"));
        assert!(authorization.contains(".spawn()"));
        assert!(wait.contains(".try_wait()"));
        assert!(wait.contains(".kill()"));
        assert!(wait.contains(".wait()"));
    }
}
