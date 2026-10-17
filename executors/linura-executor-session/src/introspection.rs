//! Fixed contract metadata only. Dispatch always delegates to zbus's generated
//! implementation; this adapter cannot change authorization or method results.
//! zbus is pinned exactly because its manual Interface trait is unstable.
use std::collections::HashMap;
use std::fmt::Write;
use zbus::message::Header;
use zbus::object_server::{DispatchResult2, Interface, SignalEmitter};
use zbus::zvariant::{OwnedValue, Value};

#[derive(Debug)]
pub(crate) struct SessionContract<T>(pub T);

#[zbus::export::async_trait::async_trait]
impl<T: Interface + 'static> Interface for SessionContract<T> {
    fn name() -> zbus::names::InterfaceName<'static> {
        T::name()
    }
    fn spawn_tasks_for_methods(&self) -> bool {
        self.0.spawn_tasks_for_methods()
    }
    async fn get(
        &self,
        name: &str,
        server: &zbus::ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<zbus::fdo::Result<OwnedValue>> {
        self.0.get(name, server, connection, header, emitter).await
    }
    async fn get_all(
        &self,
        server: &zbus::ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        self.0.get_all(server, connection, header, emitter).await
    }
    fn set<'a>(
        &'a self,
        name: &'a str,
        value: &'a Value<'_>,
        server: &'a zbus::ObjectServer,
        connection: &'a zbus::Connection,
        header: Option<&'a Header<'_>>,
        emitter: &'a SignalEmitter<'_>,
    ) -> DispatchResult2<'a> {
        self.0.set(name, value, server, connection, header, emitter)
    }
    async fn set_mut(
        &mut self,
        name: &str,
        value: &Value<'_>,
        server: &zbus::ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<zbus::fdo::Result<()>> {
        self.0
            .set_mut(name, value, server, connection, header, emitter)
            .await
    }
    fn call<'a>(
        &'a self,
        server: &'a zbus::ObjectServer,
        connection: &'a zbus::Connection,
        message: &'a zbus::Message,
        name: zbus::names::MemberName<'a>,
    ) -> DispatchResult2<'a> {
        self.0.call(server, connection, message, name)
    }
    fn call_mut<'a>(
        &'a mut self,
        server: &'a zbus::ObjectServer,
        connection: &'a zbus::Connection,
        message: &'a zbus::Message,
        name: zbus::names::MemberName<'a>,
    ) -> DispatchResult2<'a> {
        self.0.call_mut(server, connection, message, name)
    }
    fn introspect_to_writer(&self, writer: &mut dyn Write, level: usize) {
        let mut generated = String::new();
        self.0.introspect_to_writer(&mut generated, level);
        let Some(closing) = generated.rfind("</interface>") else {
            return;
        };
        if writer.write_str(&generated[..closing]).is_err() {
            return;
        }
        for (name, value) in [
            ("org.linura.ContractId", "dbus.org.linura.Executor.Session1"),
            ("org.linura.ContractVersion", "1"),
            ("org.linura.Stability", "experimental"),
        ] {
            if writeln!(writer, "<annotation name=\"{name}\" value=\"{value}\"/>").is_err() {
                return;
            }
        }
        let _ = writer.write_str(&generated[closing..]);
    }
}
