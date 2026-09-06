#![forbid(unsafe_code)]

mod authority;
mod planning;

pub use authority::{
    AUTHORITY_CONTRACT_ID, AUTHORITY_CONTRACT_STABILITY, AUTHORITY_CONTRACT_VERSION,
    AUTHORITY_INTERFACE_NAME, AUTHORITY_OBJECT_PATH, AUTHORITY_SERVICE_NAME, Authority1Context,
    Authority1Handler, Authority1ManagedRequest, AuthorityReceiptWire,
    MANAGE_SYSTEMD_ACTIVE_STATE_ACTION, serve_authority1,
};

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter, Write};
use std::sync::{Arc, Mutex};

use linura_control::{AuthenticatedPrincipal, PlanPreviewControl};
use linura_core::{
    Actor, ActorId, ActorKind, CapabilityId, PlanId, ProviderId, ResourceId, SupportLevel,
};
use linura_graph::{EdgeKind, NodeId, SystemGraph};
use linura_observation_control::ObservationCoordinator;
use linura_protocol::{
    ObservationExplanation, ObservationRequest, ObservationResponse, PlanDesiredStateRequest,
    PlanPreview, PlanReview, ProtocolVersion, ProviderSnapshot,
};
use planning::{PlanPreviewWire, PlanRequestWire, PlanReviewWire};
use zbus::blocking::{Connection as BlockingConnection, Proxy as BlockingProxy};
use zbus::message::Header;
use zbus::object_server::{DispatchResult2, Interface, SignalEmitter};
use zbus::zvariant::{OwnedValue, Value};

pub const SERVICE_NAME: &str = "org.linura.Control1";
pub const OBJECT_PATH: &str = "/org/linura/Control1";
pub const INTERFACE_NAME: &str = "org.linura.Control1";
pub const CONTRACT_ID: &str = "dbus.org.linura.Control1";
pub const CONTRACT_VERSION: &str = "1";
pub const CONTRACT_STABILITY: &str = "experimental";

const CONTRACT_ANNOTATIONS: [(&str, &str); 3] = [
    ("org.linura.ContractId", CONTRACT_ID),
    ("org.linura.ContractVersion", CONTRACT_VERSION),
    ("org.linura.Stability", CONTRACT_STABILITY),
];

pub type CallerWire = (String, String, bool, u32, u32, String);
pub type ProviderWire = (String, String, String);
pub type CapabilityWire = (String, String, String, String);
pub type CapabilitiesWire = (Vec<ProviderWire>, Vec<CapabilityWire>);
pub type ObservationWire = (
    String,
    String,
    String,
    String,
    String,
    u64,
    u64,
    u64,
    Vec<(String, String)>,
);
pub type GraphWire = (
    Vec<(String, Vec<(String, String)>)>,
    Vec<(String, String, String, String)>,
);
pub type ExplanationWire = (String, String, String, String, String, String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerIdentity {
    pub actor: Actor,
    pub uid: u32,
    pub pid: u32,
    pub unique_bus_name: String,
}

impl CallerIdentity {
    #[must_use]
    pub fn to_wire(&self) -> CallerWire {
        (
            self.actor.id.as_str().into(),
            actor_kind_name(self.actor.kind).into(),
            self.actor.interactive,
            self.uid,
            self.pid,
            self.unique_bus_name.clone(),
        )
    }
}

#[derive(Debug)]
pub struct Control1Service {
    state: Arc<Mutex<PlanPreviewControl>>,
}

impl Control1Service {
    #[must_use]
    pub fn new(coordinator: ObservationCoordinator) -> Self {
        Self {
            state: Arc::new(Mutex::new(PlanPreviewControl::new(coordinator))),
        }
    }

    async fn with_state<R, F>(&self, operation: F) -> zbus::fdo::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut PlanPreviewControl) -> Result<R, String> + Send + 'static,
    {
        let state = Arc::clone(&self.state);
        blocking::unblock(move || {
            let mut guard = state
                .lock()
                .map_err(|_| "Control1 state lock is poisoned".to_string())?;
            operation(&mut guard)
        })
        .await
        .map_err(fdo_failed)
    }
}

#[zbus::interface(name = "org.linura.Control1")]
impl Control1Service {
    // Canonical Experimental Control1. Version 1 names this wire
    // generation; stability is governed independently by the contract registry.
    async fn get_protocol_version(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(u16, String)> {
        let _caller = authenticated_caller(connection, &header).await?;
        let version = ProtocolVersion::default();
        Ok((version.major, version.product_version.into()))
    }

    async fn who_am_i(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<CallerWire> {
        authenticated_caller(connection, &header)
            .await
            .map(|caller| caller.to_wire())
    }

    async fn capabilities(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<CapabilitiesWire> {
        let _caller = authenticated_caller(connection, &header).await?;
        self.with_state(|state| {
            state
                .provider_snapshot()
                .map(provider_wire)
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn observe(
        &self,
        provider: &str,
        resource: &str,
        capability: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<ObservationWire> {
        let _caller = authenticated_caller(connection, &header).await?;
        let request = ObservationRequest {
            provider: parse_provider(provider)?,
            resource: parse_resource(resource)?,
            capability: parse_capability(capability)?,
        };
        self.with_state(move |state| {
            state
                .observe(&request)
                .map(observation_wire)
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn graph(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<GraphWire> {
        let _caller = authenticated_caller(connection, &header).await?;
        self.with_state(|state| {
            state
                .graph_snapshot()
                .map(|graph| graph_wire(&graph))
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn explain_observation(
        &self,
        resource: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<ExplanationWire> {
        let _caller = authenticated_caller(connection, &header).await?;
        let resource = parse_resource(resource)?;
        self.with_state(move |state| {
            state
                .explain_observation(&resource)
                .map(explanation_wire)
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn plan_desired_state(
        &self,
        request: PlanRequestWire,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<PlanPreviewWire> {
        let caller = authenticated_caller(connection, &header).await?;
        let principal = principal_from_caller(&caller)?;
        let request = planning::plan_request_from_wire(request).map_err(fdo_failed)?;
        self.with_state(move |state| {
            state
                .plan_desired_state(principal, caller.actor, request)
                .map(|preview| planning::plan_preview_wire(&preview))
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn get_plan_preview(
        &self,
        plan_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<PlanPreviewWire> {
        let caller = authenticated_caller(connection, &header).await?;
        let principal = principal_from_caller(&caller)?;
        let plan_id = PlanId::new(plan_id).map_err(|error| fdo_failed(error.to_string()))?;
        self.with_state(move |state| {
            state
                .get_plan_preview(&principal, &plan_id)
                .map(|preview| planning::plan_preview_wire(&preview))
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn explain_plan_preview(
        &self,
        plan_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<PlanPreviewWire> {
        let caller = authenticated_caller(connection, &header).await?;
        let principal = principal_from_caller(&caller)?;
        let plan_id = PlanId::new(plan_id).map_err(|error| fdo_failed(error.to_string()))?;
        self.with_state(move |state| {
            state
                .explain_plan_preview(&principal, &plan_id)
                .map(|preview| planning::plan_preview_wire(&preview))
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn review_plan(
        &self,
        plan_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<PlanReviewWire> {
        let caller = authenticated_caller(connection, &header).await?;
        let principal = principal_from_caller(&caller)?;
        let plan_id = PlanId::new(plan_id).map_err(|error| fdo_failed(error.to_string()))?;
        self.with_state(move |state| {
            state
                .review_plan(&principal, &plan_id)
                .map(|review| planning::plan_review_wire(&review))
                .map_err(|error| error.to_string())
        })
        .await
    }

    async fn explain_plan_review(
        &self,
        plan_id: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<PlanReviewWire> {
        let caller = authenticated_caller(connection, &header).await?;
        let principal = principal_from_caller(&caller)?;
        let plan_id = PlanId::new(plan_id).map_err(|error| fdo_failed(error.to_string()))?;
        self.with_state(move |state| {
            state
                .explain_plan_review(&principal, &plan_id)
                .map(|review| planning::plan_review_wire(&review))
                .map_err(|error| error.to_string())
        })
        .await
    }
}

/// Adds contract lifecycle annotations to the macro-generated D-Bus introspection while delegating
/// all dispatch, property and task-spawning behavior to the generated interface implementation.
///
/// zbus intentionally treats manual [`Interface`] implementations as unstable. Linura pins zbus
/// exactly, and this adapter is covered by compile-time and introspection regression tests, so an
/// upstream trait change must be handled deliberately during dependency upgrades.
#[derive(Debug)]
struct ContractAnnotatedInterface<T> {
    inner: T,
    annotations: &'static [(&'static str, &'static str)],
}

impl<T> ContractAnnotatedInterface<T> {
    const fn new(inner: T, annotations: &'static [(&'static str, &'static str)]) -> Self {
        Self { inner, annotations }
    }
}

#[zbus::export::async_trait::async_trait]
impl<T> Interface for ContractAnnotatedInterface<T>
where
    T: Interface + 'static,
{
    fn name() -> zbus::names::InterfaceName<'static>
    where
        Self: Sized,
    {
        T::name()
    }

    fn spawn_tasks_for_methods(&self) -> bool {
        self.inner.spawn_tasks_for_methods()
    }

    async fn get(
        &self,
        property_name: &str,
        server: &zbus::ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<zbus::fdo::Result<OwnedValue>> {
        self.inner
            .get(property_name, server, connection, header, emitter)
            .await
    }

    async fn get_all(
        &self,
        object_server: &zbus::ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        self.inner
            .get_all(object_server, connection, header, emitter)
            .await
    }

    fn set<'call>(
        &'call self,
        property_name: &'call str,
        value: &'call Value<'_>,
        object_server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        header: Option<&'call Header<'_>>,
        emitter: &'call SignalEmitter<'_>,
    ) -> DispatchResult2<'call> {
        self.inner.set(
            property_name,
            value,
            object_server,
            connection,
            header,
            emitter,
        )
    }

    async fn set_mut(
        &mut self,
        property_name: &str,
        value: &Value<'_>,
        object_server: &zbus::ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<zbus::fdo::Result<()>> {
        self.inner
            .set_mut(
                property_name,
                value,
                object_server,
                connection,
                header,
                emitter,
            )
            .await
    }

    fn call<'call>(
        &'call self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        msg: &'call zbus::Message,
        name: zbus::names::MemberName<'call>,
    ) -> DispatchResult2<'call> {
        self.inner.call(server, connection, msg, name)
    }

    fn call_mut<'call>(
        &'call mut self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        msg: &'call zbus::Message,
        name: zbus::names::MemberName<'call>,
    ) -> DispatchResult2<'call> {
        self.inner.call_mut(server, connection, msg, name)
    }

    fn introspect_to_writer(&self, writer: &mut dyn Write, level: usize) {
        let mut generated = String::new();
        self.inner.introspect_to_writer(&mut generated, level);
        write_annotated_introspection(writer, &generated, self.annotations);
    }
}

fn escape_xml_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn write_annotated_introspection(
    writer: &mut dyn Write,
    generated: &str,
    annotations: &[(&str, &str)],
) {
    let Some(closing_start) = generated.rfind("</interface>") else {
        let _ = writer.write_str(generated);
        return;
    };
    let line_start = generated[..closing_start]
        .rfind('\n')
        .map_or(closing_start, |position| position + 1);
    let close_indent = &generated[line_start..closing_start];

    if writer.write_str(&generated[..line_start]).is_err() {
        return;
    }
    for &(name, value) in annotations {
        let name = escape_xml_attribute(name);
        let value = escape_xml_attribute(value);
        if writeln!(
            writer,
            "{close_indent}  <annotation name=\"{name}\" value=\"{value}\"/>"
        )
        .is_err()
        {
            return;
        }
    }
    let _ = writer.write_str(&generated[line_start..]);
}

fn control1_service(
    coordinator: ObservationCoordinator,
) -> ContractAnnotatedInterface<Control1Service> {
    ContractAnnotatedInterface::new(Control1Service::new(coordinator), &CONTRACT_ANNOTATIONS)
}

pub fn serve(coordinator: ObservationCoordinator) -> Result<(), TransportError> {
    let service = control1_service(coordinator);
    let _connection = zbus::blocking::connection::Builder::session()?
        .name(SERVICE_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()?;
    loop {
        std::thread::park();
    }
}

#[derive(Debug)]
pub struct Control1Client {
    connection: BlockingConnection,
}

impl Control1Client {
    pub fn connect() -> Result<Self, TransportError> {
        Ok(Self {
            connection: BlockingConnection::session()?,
        })
    }

    fn proxy(&self) -> Result<BlockingProxy<'_>, TransportError> {
        BlockingProxy::new(&self.connection, SERVICE_NAME, OBJECT_PATH, INTERFACE_NAME)
            .map_err(TransportError::from)
    }

    pub fn who_am_i(&self) -> Result<CallerWire, TransportError> {
        self.proxy()?
            .call("WhoAmI", &())
            .map_err(TransportError::from)
    }

    pub fn capabilities(&self) -> Result<CapabilitiesWire, TransportError> {
        self.proxy()?
            .call("Capabilities", &())
            .map_err(TransportError::from)
    }

    pub fn observe(
        &self,
        provider: &str,
        resource: &str,
        capability: &str,
    ) -> Result<ObservationWire, TransportError> {
        self.proxy()?
            .call("Observe", &(provider, resource, capability))
            .map_err(TransportError::from)
    }

    pub fn graph(&self) -> Result<GraphWire, TransportError> {
        self.proxy()?
            .call("Graph", &())
            .map_err(TransportError::from)
    }

    pub fn explain(&self, resource: &str) -> Result<ExplanationWire, TransportError> {
        self.proxy()?
            .call("ExplainObservation", &(resource,))
            .map_err(TransportError::from)
    }

    pub fn plan_desired_state(
        &self,
        request: &PlanDesiredStateRequest,
    ) -> Result<PlanPreview, TransportError> {
        let wire = planning::plan_request_wire(request);
        let response: PlanPreviewWire = self
            .proxy()?
            .call("PlanDesiredState", &(wire,))
            .map_err(TransportError::from)?;
        planning::plan_preview_from_wire(response).map_err(TransportError::new)
    }

    pub fn get_plan_preview(&self, plan_id: &PlanId) -> Result<PlanPreview, TransportError> {
        let response: PlanPreviewWire = self
            .proxy()?
            .call("GetPlanPreview", &(plan_id.as_str(),))
            .map_err(TransportError::from)?;
        planning::plan_preview_from_wire(response).map_err(TransportError::new)
    }

    pub fn explain_plan_preview(&self, plan_id: &PlanId) -> Result<PlanPreview, TransportError> {
        let response: PlanPreviewWire = self
            .proxy()?
            .call("ExplainPlanPreview", &(plan_id.as_str(),))
            .map_err(TransportError::from)?;
        planning::plan_preview_from_wire(response).map_err(TransportError::new)
    }

    pub fn review_plan(&self, plan_id: &PlanId) -> Result<PlanReview, TransportError> {
        let response: PlanReviewWire = self
            .proxy()?
            .call("ReviewPlan", &(plan_id.as_str(),))
            .map_err(TransportError::from)?;
        planning::plan_review_from_wire(response).map_err(TransportError::new)
    }

    pub fn explain_plan_review(&self, plan_id: &PlanId) -> Result<PlanReview, TransportError> {
        let response: PlanReviewWire = self
            .proxy()?
            .call("ExplainPlanReview", &(plan_id.as_str(),))
            .map_err(TransportError::from)?;
        planning::plan_review_from_wire(response).map_err(TransportError::new)
    }
}

#[derive(Debug)]
pub struct TransportError {
    message: String,
}

impl TransportError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for TransportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

impl From<zbus::Error> for TransportError {
    fn from(error: zbus::Error) -> Self {
        Self::new(error.to_string())
    }
}

async fn authenticated_caller(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<CallerIdentity> {
    let sender = header
        .sender()
        .ok_or_else(|| fdo_failed("D-Bus method call has no authenticated sender"))?;
    let unique_bus_name = sender.as_str().to_string();
    if !unique_bus_name.starts_with(':') || unique_bus_name.chars().any(char::is_control) {
        return Err(fdo_failed(
            "D-Bus sender is not a canonical unique bus name",
        ));
    }
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .map_err(|error| fdo_failed(error.to_string()))?;
    let uid: u32 = proxy
        .call("GetConnectionUnixUser", &(unique_bus_name.as_str(),))
        .await
        .map_err(|error| fdo_failed(error.to_string()))?;
    let pid: u32 = proxy
        .call("GetConnectionUnixProcessID", &(unique_bus_name.as_str(),))
        .await
        .map_err(|error| fdo_failed(error.to_string()))?;
    actor_from_credentials(&unique_bus_name, uid, pid)
}

fn actor_from_credentials(
    unique_bus_name: &str,
    uid: u32,
    pid: u32,
) -> zbus::fdo::Result<CallerIdentity> {
    let actor_id = ActorId::new(format!(
        "dbus:v1:{}:{unique_bus_name}:uid:{uid}:pid:{pid}",
        unique_bus_name.len()
    ))
    .map_err(|error| fdo_failed(error.to_string()))?;
    Ok(CallerIdentity {
        actor: Actor {
            id: actor_id,
            kind: ActorKind::Service,
            interactive: false,
        },
        uid,
        pid,
        unique_bus_name: unique_bus_name.into(),
    })
}

fn principal_from_caller(caller: &CallerIdentity) -> zbus::fdo::Result<AuthenticatedPrincipal> {
    AuthenticatedPrincipal::new(format!("unix:uid:{}", caller.uid))
        .map_err(|error| fdo_failed(error.to_string()))
}

fn provider_wire(snapshot: ProviderSnapshot) -> CapabilitiesWire {
    let providers = snapshot
        .providers
        .into_iter()
        .map(|health| {
            (
                health.provider.as_str().into(),
                health.availability.as_str().into(),
                health.reason.unwrap_or_default(),
            )
        })
        .collect();
    let capabilities = snapshot
        .capabilities
        .into_iter()
        .map(|capability| {
            (
                capability.id.as_str().into(),
                capability
                    .provider
                    .as_ref()
                    .map_or_else(String::new, |provider| provider.as_str().into()),
                support_level_name(capability.support).into(),
                capability.reason.unwrap_or_default(),
            )
        })
        .collect();
    (providers, capabilities)
}

fn observation_wire(response: ObservationResponse) -> ObservationWire {
    let observation = response.observation;
    let attributes = observation
        .attributes
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect();
    (
        observation.provider.as_str().into(),
        observation.resource.as_str().into(),
        observation.capability.as_str().into(),
        observation.authority.as_str().into(),
        response.freshness.as_str().into(),
        observation.observed_at_unix_ms,
        observation.valid_for_ms,
        observation.sequence,
        attributes,
    )
}

fn graph_wire(graph: &SystemGraph) -> GraphWire {
    let nodes = graph
        .nodes()
        .map(|node| {
            (
                node_id_name(&node.id),
                node.attributes
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            )
        })
        .collect();
    let mut edges: Vec<_> = graph
        .edges()
        .iter()
        .map(|edge| {
            (
                node_id_name(&edge.from),
                node_id_name(&edge.to),
                edge_kind_name(edge.kind).into(),
                edge.reason.clone(),
            )
        })
        .collect();
    edges.sort();
    (nodes, edges)
}

fn explanation_wire(explanation: ObservationExplanation) -> ExplanationWire {
    (
        explanation.resource.as_str().into(),
        explanation.provider.as_str().into(),
        explanation.capability.as_str().into(),
        explanation.freshness.as_str().into(),
        explanation.evidence_id,
        explanation.authority,
    )
}

fn node_id_name(node: &NodeId) -> String {
    match node {
        NodeId::Intent(id) => format!("intent:{}", id.as_str()),
        NodeId::Setup(id) => format!("setup:{}", id.as_str()),
        NodeId::Requirement(id) => format!("requirement:{}", id.as_str()),
        NodeId::Capability(id) => format!("capability:{}", id.as_str()),
        NodeId::Provider(id) => format!("provider:{}", id.as_str()),
        NodeId::Resource(id) => format!("resource:{}", id.as_str()),
        NodeId::Evidence(id) => format!("evidence:{id}"),
        NodeId::Workflow(id) => format!("workflow:{id}"),
    }
}

const fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Requires => "requires",
        EdgeKind::Provides => "provides",
        EdgeKind::Conflicts => "conflicts",
        EdgeKind::Replaces => "replaces",
        EdgeKind::Recommends => "recommends",
        EdgeKind::Optional => "optional",
        EdgeKind::Owns => "owns",
        EdgeKind::SharedBy => "shared-by",
        EdgeKind::DerivedFrom => "derived-from",
        EdgeKind::Realizes => "realizes",
        EdgeKind::ObservedBy => "observed-by",
        EdgeKind::EvidenceFor => "evidence-for",
    }
}

const fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

const fn support_level_name(level: SupportLevel) -> &'static str {
    match level {
        SupportLevel::Supported => "supported",
        SupportLevel::Unsupported => "unsupported",
        SupportLevel::Degraded => "degraded",
        SupportLevel::Unknown => "unknown",
    }
}

fn parse_provider(value: &str) -> zbus::fdo::Result<ProviderId> {
    ProviderId::new(value).map_err(|error| fdo_failed(error.to_string()))
}

fn parse_resource(value: &str) -> zbus::fdo::Result<ResourceId> {
    ResourceId::new(value).map_err(|error| fdo_failed(error.to_string()))
}

fn parse_capability(value: &str) -> zbus::fdo::Result<CapabilityId> {
    CapabilityId::new(value).map_err(|error| fdo_failed(error.to_string()))
}

fn fdo_failed(message: impl Into<String>) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_service_name_matches_control1_contract() {
        assert_eq!(SERVICE_NAME, "org.linura.Control1");
        assert_eq!(INTERFACE_NAME, "org.linura.Control1");
    }

    #[test]
    fn actor_identity_binds_bus_name_uid_and_pid() {
        let first = actor_from_credentials(":1.42", 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let second = actor_from_credentials(":1.43", 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(first.actor.id, second.actor.id);
        assert_eq!(first.uid, 1000);
        assert_eq!(first.pid, 2000);
        assert!(!first.actor.interactive);
        assert_eq!(first.actor.kind, ActorKind::Service);
    }

    #[test]
    fn actor_identity_rejects_malformed_bus_identity() {
        assert!(actor_from_credentials(":1.42\nspoof", 1000, 2000).is_err());
    }

    #[test]
    fn principal_namespace_is_stable_across_bus_reconnects() {
        let first = actor_from_credentials(":1.42", 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let second = actor_from_credentials(":1.43", 1000, 2001)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(first.actor.id, second.actor.id);
        assert_eq!(
            principal_from_caller(&first).unwrap_or_else(|error| unreachable!("{error}")),
            principal_from_caller(&second).unwrap_or_else(|error| unreachable!("{error}"))
        );
    }

    #[test]
    fn runtime_contract_is_explicitly_experimental() {
        assert_eq!(CONTRACT_ID, "dbus.org.linura.Control1");
        assert_eq!(CONTRACT_VERSION, "1");
        assert_eq!(CONTRACT_STABILITY, "experimental");
    }

    #[test]
    fn live_introspection_publishes_canonical_contract_metadata() {
        let service = control1_service(ObservationCoordinator::new());
        let mut live = String::new();
        service.introspect_to_writer(&mut live, 0);
        let canonical = include_str!("../../../interfaces/dbus/org.linura.Control1.xml");

        for &(name, value) in &CONTRACT_ANNOTATIONS {
            let marker = format!("name=\"{name}\" value=\"{value}\"");
            assert_eq!(canonical.matches(&marker).count(), 1, "canonical {name}");
            assert_eq!(live.matches(&marker).count(), 1, "live {name}");
        }
        for method in [
            "PlanDesiredState",
            "GetPlanPreview",
            "ExplainPlanPreview",
            "ReviewPlan",
            "ExplainPlanReview",
        ] {
            let marker = format!("<method name=\"{method}\">");
            assert!(canonical.contains(&marker), "canonical {method}");
            assert!(live.contains(&marker), "live {method}");
        }
    }

    #[test]
    fn node_wire_ids_are_type_namespaced() {
        let provider = ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            node_id_name(&NodeId::Provider(provider)),
            "provider:systemd"
        );
    }
}
