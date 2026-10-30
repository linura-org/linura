use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::os::unix::net::UnixStream;
use std::task::Poll;
use std::time::{Duration, Instant};

use async_io::{Async, Timer};
use futures_lite::future;
use zbus::blocking::Connection;
use zbus::zvariant::OwnedValue;

const BUS_PATH: &str = "/run/dbus/system_bus_socket";
const CONTROL_SERVICE: &str = "org.linura.Authority1";
const EXECUTOR_SERVICE: &str = "org.linura.Executor.Session1";
const CONNECT_BUDGET: Duration = Duration::from_secs(2);
pub(crate) const CALL_BUDGET: Duration = Duration::from_millis(500);
pub(crate) const PROBE_BUDGET: Duration = Duration::from_secs(2);
pub(crate) const MAX_REPLY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_DISPLAY_REPLY_BYTES: usize = 384 * 1024;
pub(crate) const INTERACTION_BUDGET: Duration = Duration::from_secs(60);

fn reply_limit(role: NativeSessionRole, path: &str, interface: &str, method: &str) -> usize {
    if path == "/org/linura/SecurityOwner1"
        && interface == "org.linura.SecurityOwner1"
        && ((method == "ObserveDisplay" && role == NativeSessionRole::Control)
            || (method == "ObservePreparedDisplay" && role == NativeSessionRole::Executor))
    {
        MAX_DISPLAY_REPLY_BYTES
    } else {
        MAX_REPLY_BYTES
    }
}

pub(crate) enum NativeCallError {
    TransitionPending,
    CredentialPeerVanished,
    EndpointPeerVanished,
    EndpointAbsent,
    Failure(String),
}
impl NativeCallError {
    fn other(label: impl Into<String>) -> Self {
        Self::Failure(label.into())
    }
    fn remote(error: &zbus::Error, method: &str) -> Self {
        if matches!(error, zbus::Error::MethodError(_, _, message) if message.body().len() > MAX_REPLY_BYTES)
        {
            return Self::other("native session reply exceeded its size bound");
        }
        // Only the fixed helper's private method can retain this closed denial
        // diagnostic. It is always a hard failure, never a typed pending reply.
        if method == "ProtectBeforeSleep"
            && error_named(error, "org.freedesktop.DBus.Error.AccessDenied")
            && let zbus::Error::MethodError(_, Some(description), _) = error
            && let Some(label) = sleep_gate_denial(description)
        {
            return Self::Failure(label);
        }
        // These typed negatives are usable only while inspecting a complete
        // owner-discovery snapshot. Other callers still receive hard failures.
        if method == "GetConnectionCredentials"
            && error_named(error, "org.freedesktop.DBus.Error.NameHasNoOwner")
        {
            return Self::CredentialPeerVanished;
        }
        if method == "Introspect" {
            if [
                "org.freedesktop.DBus.Error.NameHasNoOwner",
                "org.freedesktop.DBus.Error.ServiceUnknown",
            ]
            .iter()
            .any(|name| error_named(error, name))
            {
                return Self::EndpointPeerVanished;
            }
            if [
                "org.freedesktop.DBus.Error.UnknownObject",
                "org.freedesktop.DBus.Error.UnknownInterface",
                "org.freedesktop.DBus.Error.UnknownMethod",
            ]
            .iter()
            .any(|name| error_named(error, name))
            {
                return Self::EndpointAbsent;
            }
        }
        // Only this typed reply from the already attested observation endpoint
        // denotes a known transition. No other error can await settling.
        if method == "ObserveLock"
            && matches!(error,
                zbus::Error::MethodError(name, _, _)
                    if name.as_str() == "org.linura.Private.NativeTransitionPending")
        {
            Self::TransitionPending
        } else {
            Self::Failure(native_call_failure(error, method))
        }
    }
    pub(crate) fn label(self) -> String {
        match self {
            Self::TransitionPending => native_failure_label("transition-pending", "ObserveLock"),
            Self::CredentialPeerVanished => {
                native_failure_label("peer-unavailable", "GetConnectionCredentials")
            }
            Self::EndpointPeerVanished => native_failure_label("peer-unavailable", "Introspect"),
            Self::EndpointAbsent => native_failure_label("unsupported", "Introspect"),
            Self::Failure(label) => label,
        }
    }
}

fn sleep_gate_denial(description: &str) -> Option<String> {
    let (stage, reason) = description
        .strip_prefix("native-sleep-gate-denied stage=")?
        .split_once(" reason=")?;
    if ![
        "attestation",
        "entry",
        "coverage",
        "completion",
        "unclassified",
    ]
    .contains(&stage)
        || ![
            "helper-image",
            "helper-arguments",
            "helper-mismatch",
            "helper-identity",
            "unit-contract",
            "unit-programs",
            "unit-codec",
            "assets",
            "generation",
            "deadline",
            "supervisor",
            "no-session",
            "session-class",
            "session-inventory",
            "control-busy",
            "coverage-generation",
            "fence-refused",
            "transport-denied",
            "transport-timeout",
            "process-generation",
            "unclassified",
        ]
        .contains(&reason)
    {
        return None;
    }
    Some(format!(
        "native-sleep-gate-denied stage={stage} reason={reason}"
    ))
}

fn error_named(error: &zbus::Error, expected: &str) -> bool {
    use zbus::DBusError;
    match error {
        zbus::Error::MethodError(name, _, _) => name.as_str() == expected,
        zbus::Error::FDO(error) => error.name().as_str() == expected,
        _ => false,
    }
}

fn native_call_failure(error: &zbus::Error, method: &str) -> String {
    use zbus::DBusError;
    let name = match error {
        zbus::Error::MethodError(name, _, _) => Some(name.as_str()),
        zbus::Error::FDO(error) => {
            return native_named_failure(error.name().as_str(), method);
        }
        zbus::Error::InputOutput(_) | zbus::Error::Connection(_, _) => {
            return native_failure_label("transport", method);
        }
        zbus::Error::InvalidReply
        | zbus::Error::InvalidField
        | zbus::Error::MissingField
        | zbus::Error::IncorrectEndian
        | zbus::Error::ExcessData
        | zbus::Error::Variant(_) => return native_failure_label("malformed", method),
        _ => None,
    };
    native_named_failure(name.unwrap_or_default(), method)
}

fn native_named_failure(name: &str, method: &str) -> String {
    let category = match name {
        "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner" => "peer-unavailable",
        "org.freedesktop.DBus.Error.AccessDenied" | "org.freedesktop.DBus.Error.AuthFailed" => {
            "access-denied"
        }
        "org.freedesktop.DBus.Error.NoReply"
        | "org.freedesktop.DBus.Error.Timeout"
        | "org.freedesktop.DBus.Error.TimedOut" => "no-reply",
        "org.freedesktop.DBus.Error.UnknownMethod"
        | "org.freedesktop.DBus.Error.UnknownInterface"
        | "org.freedesktop.DBus.Error.UnknownObject"
        | "org.freedesktop.DBus.Error.NotSupported" => "unsupported",
        "org.freedesktop.DBus.Error.InvalidArgs"
        | "org.freedesktop.DBus.Error.InvalidSignature" => "arguments",
        "org.linura.Private.NativeTransitionPending" if method == "ObserveLock" => {
            "transition-pending"
        }
        "org.linura.Private.NativeUnavailable" => "native-unavailable",
        _ => "remote-failure",
    };
    native_failure_label(category, method)
}

fn native_failure_label(category: &str, method: &str) -> String {
    // Only source-owned labels leave the adapter. Never format error details,
    // messages, names, addresses, request bodies or caller-selected methods.
    let stage = match method {
        "ArmApproval" => "approval-arm",
        "ConsumeApproval" => "approval-consume",
        "GetNameOwner" => "owner-lookup",
        "Get" | "GetAll" => "properties",
        "GetConnectionCredentials" | "GetConnectionUnixUser" | "GetConnectionUnixProcessID" => {
            "credentials"
        }
        "GetUnit" => "unit-lookup",
        "GetSession" => "session-lookup",
        "CheckAuthorization" => "authentication",
        "ObserveLock" => "lock-observation",
        "VerifyReleased" => "release-verification",
        "RetainedVerifiedRelease" => "retained-release",
        "CommitVerifiedRelease" => "release-commit",
        "DispatchPreparedLock" => "lock-dispatch",
        _ => "mechanism",
    };
    format!("native session call failed: class={category}; stage={stage}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSessionRole {
    Control,
    Executor,
}

impl NativeSessionRole {
    pub(crate) fn service(self) -> &'static str {
        match self {
            Self::Control => CONTROL_SERVICE,
            Self::Executor => EXECUTOR_SERVICE,
        }
    }
}

#[derive(Clone)]
pub struct NativeSessionChannel {
    pub(crate) connection: Connection,
    pub(crate) role: NativeSessionRole,
}

impl Debug for NativeSessionChannel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSessionChannel")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl NativeSessionChannel {
    pub fn connect(role: NativeSessionRole) -> Result<Self, String> {
        Ok(Self {
            connection: connect_native_bus(Some(role))?,
            role,
        })
    }

    /// Concrete adapter composition only: register the service on the SAME
    /// connection that sends native owner calls. Never pass this to core,
    /// Control-domain, policy, agents, public SDKs or QML contexts.
    pub fn service_connection(&self) -> Connection {
        self.connection.clone()
    }

    pub(crate) fn require_role(&self, expected: NativeSessionRole) -> Result<(), String> {
        if self.role != expected {
            return Err("native channel has the wrong service role".into());
        }
        let owner: String = self
            .bus_call("GetNameOwner", &(expected.service(),), Instant::now())?
            .body()
            .deserialize()
            .map_err(|_| "native service owner reply is malformed".to_owned())?;
        if self
            .connection
            .unique_name()
            .is_none_or(|name| name.as_str() != owner)
        {
            return Err("native channel no longer owns its canonical service name".into());
        }
        Ok(())
    }
}

pub(crate) fn connect_native_bus(role: Option<NativeSessionRole>) -> Result<Connection, String> {
    async_io::block_on(future::race(
        async {
            let stream = Async::<UnixStream>::connect(BUS_PATH)
                .await
                .map_err(|_| "canonical native session bus is unavailable".to_owned())?;
            let peer = rustix::net::sockopt::socket_peercred(stream.get_ref())
                .map_err(|_| "native session bus kernel peer cannot be authenticated".to_owned())?;
            if peer.uid.as_raw() != 0 {
                return Err("native session bus kernel peer is not root".into());
            }
            let stream = stream
                .into_inner()
                .map_err(|_| "native bus descriptor is unavailable".to_owned())?;
            let builder = zbus::connection::Builder::async_io_unix_stream(stream)
                .method_timeout(INTERACTION_BUDGET)
                .max_queued(64);
            let builder = match role {
                Some(NativeSessionRole::Control) => builder
                    .name(CONTROL_SERVICE)
                    .map_err(|_| "canonical native control name is invalid".to_owned())?,
                Some(NativeSessionRole::Executor) => builder
                    .name(EXECUTOR_SERVICE)
                    .map_err(|_| "canonical native executor name is invalid".to_owned())?,
                None => builder,
            };
            let connection = builder.build().await.map_err(|_| {
                "native session bus authentication/name acquisition failed".to_owned()
            })?;
            Ok::<Connection, String>(Connection::from(connection))
        },
        async {
            Timer::after(CONNECT_BUDGET).await;
            Err("native session bus connect/authentication exceeded its deadline".into())
        },
    ))
}

impl NativeSessionChannel {
    pub(crate) fn call<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
        started: Instant,
    ) -> Result<zbus::Message, String> {
        self.call_classified(owner, path, interface, method, body, started)
            .map_err(NativeCallError::label)
    }

    pub(crate) fn call_classified<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
        started: Instant,
    ) -> Result<zbus::Message, NativeCallError> {
        // Body bounds precede deserialization; every native probe retains its
        // original aggregate deadline, including all name/identity rechecks.
        if started.elapsed() >= PROBE_BUDGET {
            return Err(NativeCallError::other(
                "native session probe deadline expired",
            ));
        }
        let reply = self.call_with_budget_classified(
            owner,
            path,
            interface,
            method,
            body,
            CALL_BUDGET.min(PROBE_BUDGET.saturating_sub(started.elapsed())),
        )?;
        if started.elapsed() >= PROBE_BUDGET {
            return Err(NativeCallError::other(
                "native session reply exceeded its time or size bound",
            ));
        }
        Ok(reply)
    }

    pub(crate) fn call_with_budget<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
        budget: Duration,
    ) -> Result<zbus::Message, String> {
        self.call_with_budget_classified(owner, path, interface, method, body, budget)
            .map_err(NativeCallError::label)
    }

    pub(crate) fn call_with_budget_classified<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
        budget: Duration,
    ) -> Result<zbus::Message, NativeCallError> {
        if budget.is_zero() || budget > INTERACTION_BUDGET {
            return Err(NativeCallError::other("native call budget is unsupported"));
        }
        // The connection's maximum is reserved for human authentication. Every
        // mechanism/identity call retains its own shorter aggregate deadline.
        let reply = async_io::block_on(future::race(
            async {
                self.connection
                    .inner()
                    .call_method(Some(owner), path, Some(interface), method, body)
                    .await
                    .map_err(|error| NativeCallError::remote(&error, method))
            },
            async {
                Timer::after(budget).await;
                Err(NativeCallError::other(native_failure_label(
                    "deadline", method,
                )))
            },
        ))?;
        let maximum = reply_limit(self.role, path, interface, method);
        if reply.body().len() > maximum {
            return Err(NativeCallError::other(
                "native session reply exceeded its size bound",
            ));
        }
        Ok(reply)
    }

    pub(crate) fn bus_call<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        method: &str,
        body: &B,
        started: Instant,
    ) -> Result<zbus::Message, String> {
        self.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            method,
            body,
            started,
        )
    }

    /// Fixed read-only fields from one already-attested peer/interface. This
    /// neither caches metadata nor replaces the caller's fresh revalidation.
    pub(crate) fn fixed_properties(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        names: &[&str],
        started: Instant,
    ) -> Result<HashMap<String, OwnedValue>, String> {
        validate_property_batch(names, names.len())?;
        let budget = property_batch_budget(started.elapsed())?;
        let requests = names
            .iter()
            .map(|name| async move {
                let reply = self
                    .connection
                    .inner()
                    .call_method(
                        Some(owner),
                        path,
                        Some("org.freedesktop.DBus.Properties"),
                        "Get",
                        &(interface, *name),
                    )
                    .await
                    .map_err(|error| NativeCallError::remote(&error, "Get"))?;
                require_property_sender(&reply, owner)?;
                Ok(reply)
            })
            .collect();
        let values = async_io::block_on(collect_properties(names, requests, budget))?;
        if started.elapsed() >= PROBE_BUDGET {
            return Err("native session reply exceeded its time or size bound".into());
        }
        Ok(values)
    }
}

fn require_property_sender(reply: &zbus::Message, owner: &str) -> Result<(), NativeCallError> {
    if reply
        .header()
        .sender()
        .is_none_or(|sender| sender.as_str() != owner)
    {
        return Err(NativeCallError::other(native_failure_label(
            "malformed",
            "Get",
        )));
    }
    Ok(())
}

fn property_batch_budget(elapsed: Duration) -> Result<Duration, String> {
    PROBE_BUDGET
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| CALL_BUDGET.min(remaining))
        .ok_or_else(|| "native session probe deadline expired".into())
}

fn validate_property_batch(names: &[&str], request_count: usize) -> Result<(), String> {
    if names.is_empty()
        || names.len() > 32
        || names.len() != request_count
        || names.iter().enumerate().any(|(index, name)| {
            name.is_empty()
                || name.len() > 64
                || name.as_bytes()[0].is_ascii_digit()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                || names[..index].contains(name)
        })
    {
        return Err("native property batch contract is unsupported".into());
    }
    Ok(())
}

async fn collect_properties<F>(
    names: &[&str],
    requests: Vec<F>,
    budget: Duration,
) -> Result<HashMap<String, OwnedValue>, String>
where
    F: Future<Output = Result<zbus::Message, NativeCallError>>,
{
    validate_property_batch(names, requests.len())?;
    if budget.is_zero() || budget > CALL_BUDGET {
        return Err("native property batch budget is unsupported".into());
    }
    // Every request shares one absolute primitive/remainder deadline and one
    // aggregate reply bound. No sequential timer can renew either allowance.
    let deadline = Instant::now() + budget;
    let mut requests: Vec<_> = requests.into_iter().map(Box::pin).collect();
    let mut values: Vec<Option<OwnedValue>> = names.iter().map(|_| None).collect();
    let mut bytes = 0_usize;
    let result = future::race(
        std::future::poll_fn(|context| {
            for (index, request) in requests.iter_mut().enumerate() {
                if values[index].is_some() {
                    continue;
                }
                let reply = match Future::poll(request.as_mut(), context) {
                    Poll::Pending => continue,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.label())),
                    Poll::Ready(Ok(reply)) => reply,
                };
                bytes = match bytes.checked_add(reply.body().len()) {
                    Some(bytes) if bytes <= MAX_REPLY_BYTES => bytes,
                    _ => {
                        return Poll::Ready(Err(
                            "native session reply exceeded its size bound".into()
                        ));
                    }
                };
                let value = match reply.body().deserialize::<OwnedValue>() {
                    Ok(value) => value,
                    Err(_) => {
                        return Poll::Ready(Err("native service properties are malformed".into()));
                    }
                };
                values[index] = Some(value);
            }
            if values.iter().any(Option::is_none) {
                return Poll::Pending;
            }
            Poll::Ready(
                names
                    .iter()
                    .zip(values.iter_mut())
                    .map(|(name, value)| value.take().map(|value| ((*name).to_owned(), value)))
                    .collect::<Option<HashMap<_, _>>>()
                    .ok_or_else(|| "native property batch is incomplete".into()),
            )
        }),
        async {
            Timer::after(deadline.saturating_duration_since(Instant::now())).await;
            Err(native_failure_label("deadline", "Get"))
        },
    )
    .await;
    if Instant::now() >= deadline {
        return Err(native_failure_label("deadline", "Get"));
    }
    result
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn expanded_display_reply_bound_requires_exact_role_endpoint_and_method() {
        use super::*;
        for role in [NativeSessionRole::Control, NativeSessionRole::Executor] {
            for path in ["/org/linura/SecurityOwner1", "/org/linura/Other"] {
                for interface in ["org.linura.SecurityOwner1", "org.linura.Other"] {
                    for method in [
                        "ObserveDisplay",
                        "ObservePreparedDisplay",
                        "ObserveLock",
                        "GetAll",
                    ] {
                        let admitted = path == "/org/linura/SecurityOwner1"
                            && interface == "org.linura.SecurityOwner1"
                            && matches!(
                                (role, method),
                                (NativeSessionRole::Control, "ObserveDisplay")
                                    | (NativeSessionRole::Executor, "ObservePreparedDisplay")
                            );
                        assert_eq!(
                            reply_limit(role, path, interface, method),
                            if admitted {
                                MAX_DISPLAY_REPLY_BYTES
                            } else {
                                MAX_REPLY_BYTES
                            }
                        );
                    }
                }
            }
        }
    }
    use super::*;

    fn property_reply(value: OwnedValue) -> Result<zbus::Message, zbus::Error> {
        let call = zbus::Message::method_call("/org/freedesktop/systemd1/unit/example", "Get")?
            .build(&("org.freedesktop.systemd1.Unit", "Example"))?;
        zbus::Message::method_return(&call.header())?
            .sender(":1.2")?
            .build(&value)
    }

    #[test]
    fn property_replies_require_the_actual_attested_unique_sender() -> Result<(), zbus::Error> {
        let reply = property_reply(1_u32.into())?;
        assert!(require_property_sender(&reply, ":1.2").is_ok());
        assert!(require_property_sender(&reply, ":1.3").is_err());
        let call = zbus::Message::method_call("/org/freedesktop/systemd1/unit/example", "Get")?
            .build(&())?;
        let missing =
            zbus::Message::method_return(&call.header())?.build(&OwnedValue::from(1_u32))?;
        assert!(require_property_sender(&missing, ":1.2").is_err());
        Ok(())
    }

    #[test]
    fn property_reads_are_pipelined_and_return_only_a_complete_map() -> Result<(), zbus::Error> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let arrived = Arc::new(AtomicUsize::new(0));
        let requests = [1_u32, 2]
            .into_iter()
            .map(|value| {
                let arrived = arrived.clone();
                let reply = property_reply(value.into());
                async move {
                    arrived.fetch_add(1, Ordering::SeqCst);
                    std::future::poll_fn(|context| {
                        if arrived.load(Ordering::SeqCst) == 2 {
                            Poll::Ready(())
                        } else {
                            context.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    reply.map_err(|error| NativeCallError::remote(&error, "Get"))
                }
            })
            .collect();
        // A serial implementation cannot complete: neither reply is ready
        // until BOTH requests have actually been polled.
        let result = async_io::block_on(collect_properties(
            &["First", "Second"],
            requests,
            CALL_BUDGET,
        ));
        let values = result.map_err(zbus::Error::Failure)?;
        assert_eq!(arrived.load(Ordering::SeqCst), 2);
        assert_eq!(values.len(), 2);
        assert_eq!(u32::try_from(&values["First"])?, 1);
        assert_eq!(u32::try_from(&values["Second"])?, 2);
        Ok(())
    }

    #[test]
    fn property_batch_preserves_primitive_and_remaining_probe_limits() {
        assert_eq!(CALL_BUDGET, Duration::from_millis(500));
        assert_eq!(PROBE_BUDGET, Duration::from_secs(2));
        for elapsed in [Duration::ZERO, Duration::from_millis(1_500)] {
            assert_eq!(property_batch_budget(elapsed), Ok(CALL_BUDGET));
        }
        assert_eq!(
            property_batch_budget(Duration::from_millis(1_999)),
            Ok(Duration::from_millis(1))
        );
        for elapsed in [PROBE_BUDGET, PROBE_BUDGET + CALL_BUDGET, Duration::MAX] {
            assert!(property_batch_budget(elapsed).is_err());
        }
        for budget in [Duration::ZERO, CALL_BUDGET + Duration::from_millis(1)] {
            let result = async_io::block_on(collect_properties(
                &["First"],
                vec![std::future::pending()],
                budget,
            ));
            assert!(result.is_err());
        }
        for names in [&[][..], &["First", "First"][..], &["Invalid.Name"][..]] {
            assert!(validate_property_batch(names, names.len()).is_err());
        }
        assert!(validate_property_batch(&["First"], 0).is_err());
        assert!(validate_property_batch(&["First"], 2).is_err());
        let names: Vec<_> = (0..33).map(|index| format!("Field{index}")).collect();
        let names: Vec<_> = names.iter().map(String::as_str).collect();
        assert!(validate_property_batch(&names, names.len()).is_err());
    }

    #[test]
    fn property_batch_rejects_partial_failed_malformed_and_aggregate_oversize_replies()
    -> Result<(), zbus::Error> {
        let call = zbus::Message::method_call("/org/freedesktop/systemd1/unit/example", "Get")?
            .build(&())?;
        let malformed =
            zbus::Message::method_return(&call.header())?.build(&("private-wire-marker",))?;
        let error =
            zbus::Message::error(&call.header(), "org.freedesktop.DBus.Error.AccessDenied")?
                .build(&("private-wire-marker",))?;
        let denied = NativeCallError::remote(&zbus::Error::from(error), "Get");
        for second in [Ok(malformed), Err(denied)] {
            let result = async_io::block_on(collect_properties(
                &["First", "Second"],
                vec![
                    std::future::ready(Ok(property_reply(1_u32.into())?)),
                    std::future::ready(second),
                ],
                CALL_BUDGET,
            ));
            assert!(matches!(result, Err(ref error) if !error.contains("private-wire-marker")));
        }
        let payload = zbus::zvariant::Str::from("x".repeat(MAX_REPLY_BYTES / 2));
        let first = property_reply(OwnedValue::from(payload))?;
        assert!(first.body().len() < MAX_REPLY_BYTES);
        let result = async_io::block_on(collect_properties(
            &["First", "Second"],
            vec![
                std::future::ready(Ok(first.clone())),
                std::future::ready(Ok(first)),
            ],
            CALL_BUDGET,
        ));
        assert!(result.is_err()); // Each reply fits; their combined payload does not.
        Ok(())
    }

    #[test]
    fn property_batch_rejects_expired_pending_and_late_ready_replies() -> Result<(), zbus::Error> {
        let result = async_io::block_on(collect_properties(
            &["First"],
            vec![std::future::pending()],
            Duration::from_millis(2),
        ));
        assert!(result.is_err());
        let reply = property_reply(1_u32.into())?;
        let late = async move {
            // Model a synchronous sender/decoder stalling its first poll.
            // Even a now-ready result cannot win against an expired clock.
            std::thread::sleep(Duration::from_millis(10));
            Ok(reply)
        };
        let result = async_io::block_on(collect_properties(
            &["First"],
            vec![late],
            Duration::from_millis(2),
        ));
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn sleep_denials_are_bounded_method_specific_hard_failures_with_closed_text()
    -> Result<(), zbus::Error> {
        let call = zbus::Message::method_call("/org/linura/SleepGate1", "ProtectBeforeSleep")?
            .build(&())?;
        let reply =
            zbus::Message::error(&call.header(), "org.freedesktop.DBus.Error.AccessDenied")?
                .build(&("private-wire-marker",))?;
        let label = "native-sleep-gate-denied stage=attestation reason=unit-contract";
        let wire_reply =
            zbus::Message::error(&call.header(), "org.freedesktop.DBus.Error.AccessDenied")?
                .build(&(label,))?;
        assert_eq!(
            NativeCallError::remote(&zbus::Error::from(wire_reply), "ProtectBeforeSleep").label(),
            label
        );
        let error = zbus::Error::MethodError(
            "org.freedesktop.DBus.Error.AccessDenied".try_into()?,
            Some(label.into()),
            reply.clone(),
        );
        assert!(
            matches!(NativeCallError::remote(&error, "ProtectBeforeSleep"), NativeCallError::Failure(ref actual) if actual == label)
        );
        for method in ["ObserveLock", "Introspect", "DispatchPreparedLock"] {
            let actual = NativeCallError::remote(&error, method);
            assert!(matches!(actual, NativeCallError::Failure(_)));
            assert!(!actual.label().contains("native-sleep-gate-denied"));
        }
        for description in [
            format!("{label}\nprivate-wire-marker"),
            format!("{label} private-wire-marker"),
            "native-sleep-gate-denied stage=private-wire-marker reason=unit-contract".into(),
            "native-sleep-gate-denied stage=attestation reason=private-wire-marker".into(),
        ] {
            let error = zbus::Error::MethodError(
                "org.freedesktop.DBus.Error.AccessDenied".try_into()?,
                Some(description),
                reply.clone(),
            );
            assert_eq!(
                NativeCallError::remote(&error, "ProtectBeforeSleep").label(),
                "native session call failed: class=access-denied; stage=mechanism"
            );
        }
        let wrong_name = zbus::Error::MethodError(
            "org.example.Private".try_into()?,
            Some(label.into()),
            reply.clone(),
        );
        assert!(
            !NativeCallError::remote(&wrong_name, "ProtectBeforeSleep")
                .label()
                .contains(label)
        );
        let oversized =
            zbus::Message::error(&call.header(), "org.freedesktop.DBus.Error.AccessDenied")?
                .build(&("x".repeat(MAX_REPLY_BYTES + 1),))?;
        let error = zbus::Error::MethodError(
            "org.freedesktop.DBus.Error.AccessDenied".try_into()?,
            Some(label.into()),
            oversized,
        );
        assert_eq!(
            NativeCallError::remote(&error, "ProtectBeforeSleep").label(),
            "native session reply exceeded its size bound"
        );
        Ok(())
    }

    #[test]
    fn discovery_negatives_are_typed_method_specific_bounded_and_private() -> Result<(), zbus::Error>
    {
        for (name, method, kind) in [
            (
                "org.freedesktop.DBus.Error.NameHasNoOwner",
                "GetConnectionCredentials",
                0,
            ),
            ("org.freedesktop.DBus.Error.NameHasNoOwner", "Introspect", 1),
            ("org.freedesktop.DBus.Error.ServiceUnknown", "Introspect", 1),
            ("org.freedesktop.DBus.Error.UnknownObject", "Introspect", 2),
            (
                "org.freedesktop.DBus.Error.UnknownInterface",
                "Introspect",
                2,
            ),
            ("org.freedesktop.DBus.Error.UnknownMethod", "Introspect", 2),
        ] {
            let message =
                zbus::Message::method_call("/org/linura/SecurityOwner1", method)?.build(&())?;
            let error = zbus::Error::MethodError(
                name.try_into()?,
                Some("private-wire-marker".into()),
                message,
            );
            let classified = NativeCallError::remote(&error, method);
            assert!(matches!(
                (&classified, kind),
                (NativeCallError::CredentialPeerVanished, 0)
                    | (NativeCallError::EndpointPeerVanished, 1)
                    | (NativeCallError::EndpointAbsent, 2)
            ));
            assert!(!classified.label().contains("private-wire-marker"));
            for other in [
                "ObserveLock",
                "ArmApproval",
                "CheckAuthorization",
                "GetNameOwner",
                "Get",
                "GetAll",
            ] {
                assert!(matches!(
                    NativeCallError::remote(&error, other),
                    NativeCallError::Failure(_)
                ));
            }
            let oversized = zbus::Message::method_call("/org/linura/SecurityOwner1", method)?
                .build(&vec![0_u8; MAX_REPLY_BYTES + 1])?;
            let error = zbus::Error::MethodError(name.try_into()?, None, oversized);
            assert!(matches!(
                NativeCallError::remote(&error, method),
                NativeCallError::Failure(_)
            ));
        }
        let disappeared = zbus::Error::FDO(Box::new(zbus::fdo::Error::NameHasNoOwner(
            "private-wire-marker".into(),
        )));
        assert!(matches!(
            NativeCallError::remote(&disappeared, "GetConnectionCredentials"),
            NativeCallError::CredentialPeerVanished
        ));
        for error in [
            zbus::Error::FDO(Box::new(zbus::fdo::Error::AccessDenied(
                "private-wire-marker".into(),
            ))),
            zbus::Error::FDO(Box::new(zbus::fdo::Error::NoReply(
                "private-wire-marker".into(),
            ))),
            zbus::Error::InvalidReply,
            zbus::Error::Failure(
                "org.freedesktop.DBus.Error.NameHasNoOwner private-wire-marker".into(),
            ),
        ] {
            for method in ["GetConnectionCredentials", "Introspect"] {
                let classified = NativeCallError::remote(&error, method);
                assert!(matches!(classified, NativeCallError::Failure(_)));
                assert!(!classified.label().contains("private-wire-marker"));
            }
        }
        Ok(())
    }

    #[test]
    fn only_the_typed_bounded_observation_pending_reply_can_settle() -> Result<(), zbus::Error> {
        let message =
            zbus::Message::method_call("/org/linura/SecurityOwner1", "ObserveLock")?.build(&())?;
        let pending = zbus::Error::MethodError(
            "org.linura.Private.NativeTransitionPending".try_into()?,
            Some("private-wire-marker".into()),
            message,
        );
        assert!(matches!(
            NativeCallError::remote(&pending, "ObserveLock"),
            NativeCallError::TransitionPending
        ));
        for method in [
            "ArmApproval",
            "VerifyReleased",
            "DispatchPreparedLock",
            "private-wire-marker",
        ] {
            assert!(matches!(
                NativeCallError::remote(&pending, method),
                NativeCallError::Failure(_)
            ));
        }
        for error in [
            zbus::Error::Failure(
                "org.linura.Private.NativeTransitionPending private-wire-marker".into(),
            ),
            zbus::Error::FDO(Box::new(zbus::fdo::Error::AccessDenied(
                "private-wire-marker".into(),
            ))),
            zbus::Error::FDO(Box::new(zbus::fdo::Error::NoReply(
                "private-wire-marker".into(),
            ))),
            zbus::Error::InvalidReply,
        ] {
            let classified = NativeCallError::remote(&error, "ObserveLock");
            assert!(matches!(classified, NativeCallError::Failure(_)));
            assert!(!classified.label().contains("private-wire-marker"));
        }
        let message = zbus::Message::method_call("/org/linura/SecurityOwner1", "ObserveLock")?
            .build(&vec![0_u8; MAX_REPLY_BYTES + 1])?;
        let oversized = zbus::Error::MethodError(
            "org.linura.Private.NativeTransitionPending".try_into()?,
            None,
            message,
        );
        assert!(matches!(
            NativeCallError::remote(&oversized, "ObserveLock"),
            NativeCallError::Failure(_)
        ));
        Ok(())
    }

    #[test]
    fn call_diagnostics_only_expose_fixed_classes_and_stages() -> Result<(), zbus::Error> {
        for (method, stage) in [
            ("ObserveLock", "lock-observation"),
            ("Introspect", "mechanism"),
            ("private-wire-marker", "mechanism"),
        ] {
            let failure = NativeCallError::other(native_failure_label("deadline", method));
            assert!(matches!(&failure, NativeCallError::Failure(_)));
            assert_eq!(
                failure.label(),
                format!("native session call failed: class=deadline; stage={stage}")
            );
        }
        for (error, category) in [
            (
                zbus::fdo::Error::AccessDenied("private-wire-marker".into()),
                "access-denied",
            ),
            (
                zbus::fdo::Error::NoReply("private-wire-marker".into()),
                "no-reply",
            ),
            (
                zbus::fdo::Error::NameHasNoOwner("private-wire-marker".into()),
                "peer-unavailable",
            ),
            (
                zbus::fdo::Error::UnknownMethod("private-wire-marker".into()),
                "unsupported",
            ),
            (
                zbus::fdo::Error::InvalidArgs("private-wire-marker".into()),
                "arguments",
            ),
            (
                zbus::fdo::Error::Failed("private-wire-marker".into()),
                "remote-failure",
            ),
        ] {
            let error = zbus::Error::FDO(Box::new(error));
            assert_eq!(
                native_call_failure(&error, "ArmApproval"),
                format!("native session call failed: class={category}; stage=approval-arm")
            );
        }
        for name in ["org.example.private_wire_marker", "private-wire-marker"] {
            assert_eq!(
                native_named_failure(name, "private-wire-marker"),
                "native session call failed: class=remote-failure; stage=mechanism"
            );
        }
        let error = zbus::Error::Failure("private-wire-marker".into());
        assert_eq!(
            native_call_failure(&error, "ConsumeApproval"),
            "native session call failed: class=remote-failure; stage=approval-consume"
        );
        for (name, category) in [
            ("org.freedesktop.DBus.Error.NoReply", "no-reply"),
            ("org.example.private_wire_marker", "remote-failure"),
        ] {
            let message =
                zbus::Message::method_call("/org/linura/Diagnostics", "Probe")?.build(&())?;
            let error = zbus::Error::MethodError(
                name.try_into()?,
                Some("private-wire-marker".into()),
                message,
            );
            assert_eq!(
                native_call_failure(&error, "ArmApproval"),
                format!("native session call failed: class={category}; stage=approval-arm")
            );
        }
        Ok(())
    }
}
