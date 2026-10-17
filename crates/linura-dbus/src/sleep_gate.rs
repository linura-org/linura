//! Private received-metadata boundary for the fixed native pre-start helper.
//! A successful reply means already-secure coverage is fenced, never that sleep
//! was authorized or that this adapter dispatched an effect.
use std::sync::{Arc, Mutex};

use zbus::message::Header;

use crate::{ContractAnnotatedInterface, TransportError};

pub const SLEEP_GATE_OBJECT_PATH: &str = "/org/linura/SleepGate1";
pub const SLEEP_GATE_INTERFACE_NAME: &str = "org.linura.SleepGate1";
const ANNOTATIONS: [(&str, &str); 3] = [
    ("org.linura.ContractId", "dbus.org.linura.SleepGate1"),
    ("org.linura.ContractVersion", "1"),
    ("org.linura.Stability", "experimental"),
];

// Composition-only handler. The native adapter must independently attest the
// actual received sender; a root UID or this transport dispatch is not policy.
pub trait NativeSleepGateHandler: Send + 'static {
    fn protect_received_helper(&mut self, sender: &str) -> Result<(), String>;
}

struct SleepGateService {
    handler: Arc<Mutex<Box<dyn NativeSleepGateHandler>>>,
}

#[zbus::interface(name = "org.linura.SleepGate1")]
impl SleepGateService {
    #[zbus(out_args("fenced"))]
    async fn protect_before_sleep(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = header
            .sender()
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "native sleep gate requires authenticated received metadata".into(),
                )
            })?
            .as_str()
            .to_owned();
        let handler = self.handler.clone();
        blocking::unblock(move || {
            let mut handler = handler.try_lock().map_err(|_| {
                zbus::fdo::Error::Failed(
                    "native sleep gate is busy or poisoned; continuation denied".into(),
                )
            })?;
            handler
                .protect_received_helper(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            Ok(true)
        })
        .await
    }
}

pub fn register_native_sleep_gate(
    connection: &zbus::blocking::Connection,
    handler: impl NativeSleepGateHandler,
) -> Result<(), TransportError> {
    if <SleepGateService as zbus::object_server::Interface>::name().as_str()
        != SLEEP_GATE_INTERFACE_NAME
    {
        return Err(TransportError::new("native sleep gate contract mismatch"));
    }
    let service = ContractAnnotatedInterface::new(
        SleepGateService {
            handler: Arc::new(Mutex::new(Box::new(handler))),
        },
        &ANNOTATIONS,
    );
    if !connection
        .object_server()
        .at(SLEEP_GATE_OBJECT_PATH, service)?
    {
        return Err(TransportError::new(
            "native sleep gate is already registered",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    struct DenyNative;
    impl NativeSleepGateHandler for DenyNative {
        fn protect_received_helper(&mut self, sender: &str) -> Result<(), String> {
            assert_eq!(sender, ":1.7");
            Err("not the independently supervised native helper".into())
        }
    }
    fn service() -> SleepGateService {
        SleepGateService {
            handler: Arc::new(Mutex::new(Box::new(DenyNative))),
        }
    }
    #[test]
    fn live_private_gate_contract_has_no_caller_selected_identity_or_operation() {
        let service = ContractAnnotatedInterface::new(service(), &ANNOTATIONS);
        let mut live = String::new();
        service.introspect_to_writer(&mut live, 0);
        let canonical = include_str!("../../../interfaces/dbus/org.linura.SleepGate1.xml");
        for (name, value) in ANNOTATIONS {
            let marker = format!("name=\"{name}\" value=\"{value}\"");
            assert_eq!(live.matches(&marker).count(), 1);
            assert_eq!(canonical.matches(&marker).count(), 1);
        }
        assert_eq!(live.matches("<method ").count(), 1);
        assert!(live.contains("<method name=\"ProtectBeforeSleep\">"));
        assert!(live.contains("name=\"fenced\" type=\"b\" direction=\"out\""));
        assert!(!live.contains("direction=\"in\""));
    }
    #[test]
    fn missing_received_sender_unattested_sender_and_busy_native_gate_deny() {
        let build = zbus::Message::method_call(SLEEP_GATE_OBJECT_PATH, "ProtectBeforeSleep")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let missing = build
            .clone()
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let received = build
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let service = service();
        assert!(async_io::block_on(service.protect_before_sleep(missing.header())).is_err());
        assert!(async_io::block_on(service.protect_before_sleep(received.header())).is_err());
        let _busy = service
            .handler
            .lock()
            .unwrap_or_else(|e| unreachable!("{e}"));
        let result = async_io::block_on(service.protect_before_sleep(received.header()));
        assert!(matches!(result, Err(zbus::fdo::Error::Failed(_))));
    }
}
