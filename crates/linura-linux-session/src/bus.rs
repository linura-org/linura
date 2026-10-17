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
const MAX_REPLY_BYTES: usize = 64 * 1024;
pub(crate) const INTERACTION_BUDGET: Duration = Duration::from_secs(60);

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
        // Body bounds precede deserialization; every native probe retains its
        // original aggregate deadline, including all name/identity rechecks.
        if started.elapsed() >= PROBE_BUDGET {
            return Err("native session probe deadline expired".into());
        }
        let reply = self.call_with_budget(
            owner,
            path,
            interface,
            method,
            body,
            CALL_BUDGET.min(PROBE_BUDGET.saturating_sub(started.elapsed())),
        )?;
        if started.elapsed() >= PROBE_BUDGET {
            return Err("native session reply exceeded its time or size bound".into());
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
        if budget.is_zero() || budget > INTERACTION_BUDGET {
            return Err("native call budget is unsupported".into());
        }
        // The connection's maximum is reserved for human authentication. Every
        // mechanism/identity call retains its own shorter aggregate deadline.
        let reply = async_io::block_on(future::race(
            async {
                self.connection
                    .inner()
                    .call_method(Some(owner), path, Some(interface), method, body)
                    .await
                    .map_err(|_| "native session call failed or timed out".to_owned())
            },
            async {
                Timer::after(budget).await;
                Err("native session call exceeded its deadline".into())
            },
        ))?;
        if reply.body().len() > MAX_REPLY_BYTES {
            return Err("native session reply exceeded its size bound".into());
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
