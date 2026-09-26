use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};

use linura_control::{
    AuthenticatedPrincipal, TransientEffectReceipt, TransientEffectReceiptStatus,
};
use linura_core::{Actor, RiskClass};
use zbus::message::Header;

use super::{
    ContractAnnotatedInterface, SERVICE_NAME, TransportError, authenticated_caller, fdo_failed,
    principal_from_caller,
};

pub const SESSION_OBJECT_PATH: &str = "/org/linura/Session1";
pub const SESSION_INTERFACE_NAME: &str = "org.linura.Session1";
pub const SESSION_CONTRACT_ID: &str = "dbus.org.linura.Session1";
pub const SESSION_CONTRACT_VERSION: &str = "1";
pub const SESSION_CONTRACT_STABILITY: &str = "experimental";

const SESSION_CONTRACT_ANNOTATIONS: [(&str, &str); 3] = [
    ("org.linura.ContractId", SESSION_CONTRACT_ID),
    ("org.linura.ContractVersion", SESSION_CONTRACT_VERSION),
    ("org.linura.Stability", SESSION_CONTRACT_STABILITY),
];

pub type SessionEffectReceiptWire = (String, String, String, String, String, String, String);
type SessionEffectReplyWire = (SessionEffectReceiptWire,);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionEffectReceipt {
    pub operation_id: String,
    pub plan_id: String,
    pub request_id: String,
    pub risk: String,
    pub pre_effect_evidence_id: String,
    pub post_effect_evidence_id: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session1Context {
    pub principal: AuthenticatedPrincipal,
    pub actor: Actor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session1AudioVolumeRequest {
    pub request_id: String,
    pub node_id: u32,
    pub volume_percent: u16,
    pub reason: String,
}

pub trait Session1Handler: Send + 'static {
    fn set_audio_output_volume(
        &mut self,
        context: Session1Context,
        request: Session1AudioVolumeRequest,
    ) -> Result<TransientEffectReceipt, String>;
}

pub(crate) struct Session1Service {
    handler: Arc<Mutex<Box<dyn Session1Handler>>>,
}

impl Debug for Session1Service {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session1Service")
            .finish_non_exhaustive()
    }
}

impl Session1Service {
    fn new(handler: impl Session1Handler) -> Self {
        Self {
            handler: Arc::new(Mutex::new(Box::new(handler))),
        }
    }

    async fn with_handler<R, F>(&self, operation: F) -> zbus::fdo::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut dyn Session1Handler) -> Result<R, String> + Send + 'static,
    {
        let handler = Arc::clone(&self.handler);
        blocking::unblock(move || {
            let mut guard = handler
                .lock()
                .map_err(|_| "Session1 handler lock is poisoned".to_owned())?;
            operation(guard.as_mut())
        })
        .await
        .map_err(fdo_failed)
    }
}

#[zbus::interface(name = "org.linura.Session1")]
impl Session1Service {
    #[zbus(out_args("receipt"))]
    async fn set_audio_output_volume(
        &self,
        request_id: &str,
        node_id: u32,
        volume_percent: u16,
        reason: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(SessionEffectReceiptWire,)> {
        let caller = authenticated_caller(connection, &header).await?;
        let service_uid = session_service_uid(connection).await?;
        require_same_session_uid(caller.uid, service_uid)?;
        let context = Session1Context {
            principal: principal_from_caller(&caller)?,
            actor: caller.actor,
        };
        let request = Session1AudioVolumeRequest {
            request_id: request_id.to_owned(),
            node_id,
            volume_percent,
            reason: reason.to_owned(),
        };
        self.with_handler(move |handler| {
            handler
                .set_audio_output_volume(context, request)
                // zbus treats a top-level tuple return as multiple D-Bus out arguments.
                // Wrap the receipt tuple once so Session1 emits the canonical single
                // `(sssssss)` struct declared by org.linura.Session1.xml.
                .map(|receipt| (receipt_wire(receipt),))
        })
        .await
    }
}

async fn session_service_uid(connection: &zbus::Connection) -> zbus::fdo::Result<u32> {
    let unique_name = connection
        .unique_name()
        .ok_or_else(|| fdo_failed("Session1 requires a message-bus unique service identity"))?;
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .map_err(|error| fdo_failed(error.to_string()))?;
    proxy
        .call("GetConnectionUnixUser", &(unique_name.as_str(),))
        .await
        .map_err(|error| fdo_failed(error.to_string()))
}

fn require_same_session_uid(caller_uid: u32, service_uid: u32) -> zbus::fdo::Result<()> {
    if caller_uid != service_uid {
        return Err(fdo_failed(
            "Session1 rejects callers outside the owning user session",
        ));
    }
    Ok(())
}

fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::ReadOnly => "read-only",
        RiskClass::UserState => "user-state",
        RiskClass::SystemMutation => "system-mutation",
        RiskClass::SecuritySensitive => "security-sensitive",
        RiskClass::Destructive => "destructive",
    }
}

fn status_name(status: TransientEffectReceiptStatus) -> &'static str {
    match status {
        TransientEffectReceiptStatus::NoChange => "no-change",
        TransientEffectReceiptStatus::Verified => "verified",
    }
}

fn receipt_wire(receipt: TransientEffectReceipt) -> SessionEffectReceiptWire {
    (
        receipt.operation_id.as_str().to_owned(),
        receipt.plan_id.as_str().to_owned(),
        receipt.request_id.as_str().to_owned(),
        risk_name(receipt.risk).to_owned(),
        receipt.pre_effect_evidence_id,
        receipt.post_effect_evidence_id.unwrap_or_default(),
        status_name(receipt.status).to_owned(),
    )
}

fn receipt_from_wire(
    wire: SessionEffectReceiptWire,
) -> Result<SessionEffectReceipt, TransportError> {
    let (operation_id, plan_id, request_id, risk, pre_effect_evidence_id, post, status) = wire;
    if operation_id.is_empty()
        || plan_id.is_empty()
        || request_id.is_empty()
        || pre_effect_evidence_id.is_empty()
    {
        return Err(TransportError::new(
            "Session1 returned an incomplete transient-effect receipt",
        ));
    }
    if !matches!(
        risk.as_str(),
        "read-only" | "user-state" | "system-mutation" | "security-sensitive" | "destructive"
    ) {
        return Err(TransportError::new(
            "Session1 returned an unknown risk class",
        ));
    }
    if !matches!(status.as_str(), "no-change" | "verified") {
        return Err(TransportError::new(
            "Session1 returned an unknown receipt status",
        ));
    }
    let post_effect_evidence_id = if post.is_empty() { None } else { Some(post) };
    if status == "verified" && post_effect_evidence_id.is_none() {
        return Err(TransportError::new(
            "Session1 verified receipt is missing post-effect evidence",
        ));
    }
    if status == "no-change" && post_effect_evidence_id.is_some() {
        return Err(TransportError::new(
            "Session1 no-change receipt unexpectedly carries post-effect evidence",
        ));
    }
    Ok(SessionEffectReceipt {
        operation_id,
        plan_id,
        request_id,
        risk,
        pre_effect_evidence_id,
        post_effect_evidence_id,
        status,
    })
}

pub(crate) fn session1_service(
    handler: impl Session1Handler,
) -> ContractAnnotatedInterface<Session1Service> {
    ContractAnnotatedInterface::new(Session1Service::new(handler), &SESSION_CONTRACT_ANNOTATIONS)
}

#[derive(Debug)]
pub struct Session1Client {
    connection: zbus::blocking::Connection,
}

impl Session1Client {
    pub fn connect() -> Result<Self, TransportError> {
        Ok(Self {
            connection: zbus::blocking::Connection::session()?,
        })
    }

    fn proxy(&self) -> Result<zbus::blocking::Proxy<'_>, TransportError> {
        zbus::blocking::Proxy::new(
            &self.connection,
            SERVICE_NAME,
            SESSION_OBJECT_PATH,
            SESSION_INTERFACE_NAME,
        )
        .map_err(TransportError::from)
    }

    pub fn set_audio_output_volume(
        &self,
        request_id: &str,
        node_id: u32,
        volume_percent: u16,
        reason: &str,
    ) -> Result<SessionEffectReceipt, TransportError> {
        let (wire,): SessionEffectReplyWire = self
            .proxy()?
            .call(
                "SetAudioOutputVolume",
                &(request_id, node_id, volume_percent, reason),
            )
            .map_err(TransportError::from)?;
        receipt_from_wire(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{OperationId, PlanId, RequestId};
    use zbus::object_server::Interface;

    #[derive(Debug)]
    struct NeverCalled;

    impl Session1Handler for NeverCalled {
        fn set_audio_output_volume(
            &mut self,
            _context: Session1Context,
            _request: Session1AudioVolumeRequest,
        ) -> Result<TransientEffectReceipt, String> {
            Err("introspection must not call the session handler".into())
        }
    }

    fn receipt(status: TransientEffectReceiptStatus) -> TransientEffectReceipt {
        TransientEffectReceipt {
            operation_id: OperationId::new("operation:audio.output.set-session-volume")
                .unwrap_or_else(|error| unreachable!("{error}")),
            plan_id: PlanId::new("plan:test").unwrap_or_else(|error| unreachable!("{error}")),
            request_id: RequestId::new("request:test")
                .unwrap_or_else(|error| unreachable!("{error}")),
            risk: RiskClass::UserState,
            pre_effect_evidence_id: "observation:pre".into(),
            post_effect_evidence_id: match status {
                TransientEffectReceiptStatus::NoChange => None,
                TransientEffectReceiptStatus::Verified => Some("observation:post".into()),
            },
            status,
        }
    }

    #[test]
    fn session_contract_is_explicitly_experimental_and_shares_only_the_service_process() {
        assert_eq!(SERVICE_NAME, "org.linura.Control1");
        assert_eq!(SESSION_OBJECT_PATH, "/org/linura/Session1");
        assert_eq!(SESSION_INTERFACE_NAME, "org.linura.Session1");
        assert_eq!(SESSION_CONTRACT_ID, "dbus.org.linura.Session1");
        assert_eq!(SESSION_CONTRACT_VERSION, "1");
        assert_eq!(SESSION_CONTRACT_STABILITY, crate::CONTRACT_STABILITY);
    }

    #[test]
    fn session_caller_must_match_the_owning_user_session() {
        assert!(require_same_session_uid(1000, 1000).is_ok());
        assert!(require_same_session_uid(1001, 1000).is_err());
    }

    #[test]
    fn live_session_introspection_matches_canonical_surface() {
        let service = session1_service(NeverCalled);
        let mut live = String::new();
        service.introspect_to_writer(&mut live, 0);
        let canonical = include_str!("../../../interfaces/dbus/org.linura.Session1.xml");

        for &(name, value) in &SESSION_CONTRACT_ANNOTATIONS {
            let marker = format!("name=\"{name}\" value=\"{value}\"");
            assert_eq!(canonical.matches(&marker).count(), 1, "canonical {name}");
            assert_eq!(live.matches(&marker).count(), 1, "live {name}");
        }
        assert!(canonical.contains("<method name=\"SetAudioOutputVolume\">"));
        assert!(live.contains("<method name=\"SetAudioOutputVolume\">"));
        for (name, kind) in [
            ("request_id", "s"),
            ("node_id", "u"),
            ("volume_percent", "q"),
            ("reason", "s"),
        ] {
            let marker = format!("name=\"{name}\" type=\"{kind}\" direction=\"in\"");
            assert!(canonical.contains(&marker), "canonical {name}");
            assert!(live.contains(&marker), "live {name}");
        }
        let receipt_marker = "name=\"receipt\" type=\"(sssssss)\" direction=\"out\"";
        assert_eq!(canonical.matches(receipt_marker).count(), 1);
        assert_eq!(live.matches(receipt_marker).count(), 1);
    }

    #[test]
    fn receipt_wire_round_trip_preserves_verified_evidence() {
        let decoded = receipt_from_wire(receipt_wire(receipt(
            TransientEffectReceiptStatus::Verified,
        )))
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(decoded.status, "verified");
        assert_eq!(
            decoded.post_effect_evidence_id.as_deref(),
            Some("observation:post")
        );
    }
}
