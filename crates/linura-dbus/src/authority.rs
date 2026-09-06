use std::fmt::{Debug, Formatter};
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use linura_control::{
    AuthenticatedPrincipal, ManagedApprovalAuthorizer, ManagedApprovalChallenge,
    ManagedMutationReceipt, TrustedHumanApproval,
};
use linura_core::{Actor, ActorId, ActorKind, PrincipalId};
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

pub trait Authority1Handler: Send + 'static {
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

#[zbus::interface(name = "org.linura.Authority1")]
impl Authority1Service {
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
                .map(receipt_wire)
        })
        .await
    }
}

fn authorize_human_candidate(
    sender: &str,
    challenge: &ManagedApprovalChallenge,
) -> Result<(), String> {
    let arguments = polkit_arguments(sender, challenge);
    let mut child = Command::new("/usr/bin/pkcheck")
        .args(arguments)
        .spawn()
        .map_err(|error| format!("Polkit authorization service is unavailable: {error}"))?;
    let status = wait_for_polkit(&mut child, POLKIT_AUTHORIZATION_TIMEOUT)?;
    if status.success() {
        Ok(())
    } else {
        Err("administrator approval was denied or unavailable".into())
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

fn polkit_arguments(sender: &str, challenge: &ManagedApprovalChallenge) -> Vec<String> {
    let summary = format!(
        "{} -> active_state={} (plan {})",
        challenge.resource().as_str(),
        challenge.desired_active_state(),
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
        (
            "linura.desired_active_state",
            challenge.desired_active_state().to_owned(),
        ),
    ];

    let mut arguments = vec![
        "--action-id".to_owned(),
        MANAGE_SYSTEMD_ACTIVE_STATE_ACTION.to_owned(),
        "--system-bus-name".to_owned(),
        sender.to_owned(),
        "--allow-user-interaction".to_owned(),
    ];
    for (key, value) in details {
        arguments.push("--detail".to_owned());
        arguments.push(key.to_owned());
        arguments.push(value);
    }
    arguments
}

fn receipt_wire(receipt: ManagedMutationReceipt) -> AuthorityReceiptWire {
    (
        receipt.transaction_id,
        receipt.plan_id,
        receipt.resource,
        receipt.desired_active_state,
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

pub fn serve_authority1(handler: impl Authority1Handler) -> Result<(), TransportError> {
    let service = authority1_service(handler);
    let _connection = zbus::blocking::connection::Builder::system()?
        .name(AUTHORITY_SERVICE_NAME)?
        .serve_at(AUTHORITY_OBJECT_PATH, service)?
        .build()?;
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    #[derive(Debug)]
    struct NeverCalled;

    impl Authority1Handler for NeverCalled {
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
    fn authority_contract_is_explicitly_experimental() {
        assert_eq!(AUTHORITY_SERVICE_NAME, "org.linura.Authority1");
        assert_eq!(AUTHORITY_INTERFACE_NAME, "org.linura.Authority1");
        assert_eq!(AUTHORITY_CONTRACT_ID, "dbus.org.linura.Authority1");
        assert_eq!(AUTHORITY_CONTRACT_VERSION, "1");
        assert_eq!(AUTHORITY_CONTRACT_STABILITY, "experimental");
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
        assert_eq!(canonical.matches(receipt).count(), 1, "canonical receipt");
        assert_eq!(live.matches(receipt).count(), 1, "live receipt");
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
