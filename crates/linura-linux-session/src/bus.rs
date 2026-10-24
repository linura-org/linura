use std::fmt::{Debug, Formatter};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use async_io::{Async, Timer};
use futures_lite::future;
use zbus::blocking::Connection;

const BUS_PATH: &str = "/run/dbus/system_bus_socket";
const CONTROL_SERVICE: &str = "org.linura.Authority1";
const EXECUTOR_SERVICE: &str = "org.linura.Executor.Session1";
const CONNECT_BUDGET: Duration = Duration::from_secs(2);
pub(crate) const CALL_BUDGET: Duration = Duration::from_millis(500);
pub(crate) const PROBE_BUDGET: Duration = Duration::from_secs(2);
pub(crate) const MAX_REPLY_BYTES: usize = 64 * 1024;
pub(crate) const INTERACTION_BUDGET: Duration = Duration::from_secs(60);

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
        "GetAll" => "properties",
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
        if reply.body().len() > MAX_REPLY_BYTES {
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
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

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
