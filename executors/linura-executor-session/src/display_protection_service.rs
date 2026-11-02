//! Independently supervised, bounded protection mechanisms. No output writes,
//! planning, policy, human approval, desired state or recovery orchestration.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use linura_linux_session::{
    NativeDisplayKernelSubscription, NativeDisplayRecoveryCheckpoint, NativeSessionChannel,
    NativeSessionRole,
};
use linura_provider_sdk::ComponentDigest;
use zbus::message::Header;

const INTERFACE_NAME: &str = "org.linura.DisplayProtection1";
const PATH: &str = "/org/linura/DisplayProtection1";
const MAX_PENDING: usize = 32;
const ORIGINAL_PROBE: Duration = Duration::from_secs(2);

struct Pending<T> {
    started: Instant,
    sender: String,
    subscription: T,
}

#[derive(Clone)]
struct NativeProtection {
    channel: NativeSessionChannel,
    pending: Arc<Mutex<BTreeMap<String, Pending<NativeDisplayKernelSubscription>>>>,
    witnesses: Arc<super::display_kernel::Witnesses>,
}

fn unavailable() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("original display protection unavailable; no retry".into())
}
fn sender(header: &Header<'_>) -> zbus::fdo::Result<String> {
    header
        .sender()
        .map(|name| name.as_str().to_owned())
        .ok_or_else(|| {
            zbus::fdo::Error::AccessDenied("display protection has no authenticated caller".into())
        })
}
fn dispatch(raw: &str) -> zbus::fdo::Result<ComponentDigest> {
    let digest = ComponentDigest::parse_hex(raw).map_err(|_| unavailable())?;
    if digest.to_hex() != raw || digest == ComponentDigest::from_bytes([0; 32]) {
        return Err(unavailable());
    }
    Ok(digest)
}

fn consume<T>(
    pending: &mut BTreeMap<String, Pending<T>>,
    sender: &str,
    digest: &ComponentDigest,
    now: Instant,
) -> zbus::fdo::Result<T> {
    let original = pending.remove(&digest.to_hex()).ok_or_else(unavailable)?;
    if original.sender != sender
        || now
            .checked_duration_since(original.started)
            .is_none_or(|age| age >= ORIGINAL_PROBE)
    {
        return Err(unavailable());
    }
    Ok(original.subscription)
}
trait ProtectionPort: Clone + Send + Sync + 'static {
    fn begin(&self, sender: &str, dispatch: ComponentDigest) -> zbus::fdo::Result<bool>;
    fn reserve(&self, sender: &str, payload: &[u8]) -> zbus::fdo::Result<bool>;
    fn verify(&self, sender: &str, dispatch: ComponentDigest) -> zbus::fdo::Result<bool>;
}

#[derive(Clone)]
struct ProtectionService<P: ProtectionPort>(P);

impl NativeProtection {
    fn admit(&self, sender: &str) -> zbus::fdo::Result<()> {
        self.channel
            .require_trusted_display_executor_sender(sender)
            .map_err(|_| {
                zbus::fdo::Error::AccessDenied(
                    "display protection requires the supervised executor".into(),
                )
            })
    }
}

impl ProtectionPort for NativeProtection {
    fn begin(&self, sender: &str, digest: ComponentDigest) -> zbus::fdo::Result<bool> {
        self.admit(sender)?;
        let mut pending = self.pending.try_lock().map_err(|_| unavailable())?;
        // Only never-dispatched subscriptions expire. Persisted attempts,
        // inhibitors and original witnesses have no automatic TTL cleanup.
        pending.retain(|_, value| value.started.elapsed() < ORIGINAL_PROBE);
        let key = digest.to_hex();
        if pending.len() >= MAX_PENDING || pending.contains_key(&key) {
            return Err(unavailable());
        }
        let started = Instant::now();
        let subscription = NativeDisplayKernelSubscription::begin().map_err(|_| unavailable())?;
        if started.elapsed() >= ORIGINAL_PROBE {
            return Err(unavailable());
        }
        self.admit(sender)?;
        pending.insert(
            key,
            Pending {
                started,
                sender: sender.into(),
                subscription,
            },
        );
        Ok(true)
    }
    fn reserve(&self, sender: &str, payload: &[u8]) -> zbus::fdo::Result<bool> {
        self.admit(sender)?;
        let digest =
            NativeDisplayRecoveryCheckpoint::stored_dispatch(payload).map_err(|_| unavailable())?;
        let subscription = consume(
            &mut *self.pending.try_lock().map_err(|_| unavailable())?,
            sender,
            &digest,
            Instant::now(),
        )?;
        self.witnesses
            .reserve_stored(&digest, payload, subscription, &self.channel)
            .map_err(|_| unavailable())?;
        self.admit(sender)?;
        Ok(true)
    }
    fn verify(&self, sender: &str, digest: ComponentDigest) -> zbus::fdo::Result<bool> {
        self.admit(sender)?;
        self.witnesses
            .verify(&digest, &self.channel)
            .map_err(|_| unavailable())?;
        self.admit(sender)?;
        Ok(true)
    }
}

#[zbus::interface(name = "org.linura.DisplayProtection1")]
impl<P: ProtectionPort> ProtectionService<P> {
    #[zbus(out_args("accepted"))]
    async fn begin(
        &self,
        dispatch_digest: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = sender(&header)?;
        let digest = dispatch(dispatch_digest)?;
        let service = self.clone();
        blocking::unblock(move || service.0.begin(&sender, digest)).await
    }

    #[zbus(out_args("accepted"))]
    async fn reserve(
        &self,
        checkpoint: &[u8],
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = sender(&header)?;
        if checkpoint.len() > 384 * 1024 {
            return Err(unavailable());
        }
        let payload = checkpoint.to_vec();
        let service = self.clone();
        blocking::unblock(move || service.0.reserve(&sender, &payload)).await
    }

    #[zbus(out_args("accepted"))]
    async fn verify(
        &self,
        dispatch_digest: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let sender = sender(&header)?;
        let digest = dispatch(dispatch_digest)?;
        let service = self.clone();
        blocking::unblock(move || service.0.verify(&sender, digest)).await
    }
}

pub(super) fn serve() -> Result<(), String> {
    let channel = NativeSessionChannel::connect(NativeSessionRole::DisplayProtection)?;
    let connection = channel.service_connection();
    let service = super::introspection::SessionContract(ProtectionService(NativeProtection {
        channel,
        pending: Arc::new(Mutex::new(BTreeMap::new())),
        witnesses: Arc::new(super::display_kernel::Witnesses::default()),
    }));
    connection
        .object_server()
        .at(PATH, service)
        .map_err(|_| format!("{INTERFACE_NAME} registration failed"))?;
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    #[derive(Clone)]
    struct DenyProtection;
    impl ProtectionPort for DenyProtection {
        fn begin(&self, _: &str, _: ComponentDigest) -> zbus::fdo::Result<bool> {
            Err(unavailable())
        }
        fn reserve(&self, _: &str, _: &[u8]) -> zbus::fdo::Result<bool> {
            Err(unavailable())
        }
        fn verify(&self, _: &str, _: ComponentDigest) -> zbus::fdo::Result<bool> {
            Err(unavailable())
        }
    }

    #[test]
    fn private_service_has_no_effect_or_orchestration_endpoint() {
        let mut xml = String::new();
        let service =
            super::super::introspection::SessionContract(ProtectionService(DenyProtection));
        service.introspect_to_writer(&mut xml, 0);
        assert!(xml.contains("org.linura.DisplayProtection1"));
        let canonical = include_str!("../../../interfaces/dbus/org.linura.DisplayProtection1.xml");
        for text in [&xml, canonical] {
            assert_eq!(text.matches("<method ").count(), 3);
            for marker in [
                "name=\"dispatch_digest\" type=\"s\" direction=\"in\"",
                "name=\"checkpoint\" type=\"ay\" direction=\"in\"",
                "name=\"accepted\" type=\"b\" direction=\"out\"",
                "name=\"org.linura.ContractId\" value=\"dbus.org.linura.DisplayProtection1\"",
                "name=\"org.linura.ContractVersion\" value=\"1\"",
                "name=\"org.linura.Stability\" value=\"experimental\"",
            ] {
                assert!(text.contains(marker), "{marker}");
            }
        }
        for method in ["Begin", "Reserve", "Verify"] {
            assert!(xml.contains(&format!("name=\"{method}\"")));
        }
        for forbidden in ["Apply", "Confirm", "Revert", "Execute", "Unlock", "Suspend"] {
            assert!(!xml.contains(&format!("name=\"{forbidden}\"")));
        }
    }

    #[test]
    fn malformed_or_zero_dispatch_is_never_a_protection_scope() {
        for raw in [
            String::new(),
            "0".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
        ] {
            assert!(dispatch(&raw).is_err());
        }
        assert!(dispatch(&"ab".repeat(32)).is_ok());
    }
    #[test]
    fn original_subscription_is_consumed_once_in_the_same_executor_and_window() {
        let digest = ComponentDigest::from_bytes([1; 32]);
        let started = Instant::now();
        let mut pending = BTreeMap::new();
        for (sender, now, succeeds) in [
            (":1.7", started, true),
            (":1.8", started, false),
            (":1.7", started + ORIGINAL_PROBE, false),
            (":1.7", started - Duration::from_millis(1), false),
        ] {
            pending.insert(
                digest.to_hex(),
                Pending {
                    started,
                    sender: ":1.7".into(),
                    subscription: 42,
                },
            );
            let result = consume(&mut pending, sender, &digest, now);
            assert_eq!(result.is_ok(), succeeds);
            if succeeds {
                assert_eq!(result.ok(), Some(42));
            }
            assert!(consume(&mut pending, ":1.7", &digest, started).is_err());
            assert!(pending.is_empty());
        }
    }

    #[test]
    fn protection_rpc_requires_transport_sender_and_bounded_correlation() {
        let service = ProtectionService(DenyProtection);
        let anonymous = zbus::Message::method_call(PATH, "Begin")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let digest = ComponentDigest::from_bytes([1; 32]).to_hex();
        assert!(matches!(
            async_io::block_on(service.begin(&digest, anonymous.header())),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let message = zbus::Message::method_call(PATH, "Begin")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        // A current bus sender and valid digest cannot acquire a protection by
        // themselves. The production port also requires exact service admission.
        assert!(async_io::block_on(service.begin(&digest, message.header())).is_err());
        assert!(async_io::block_on(service.verify(&digest, message.header())).is_err());
        assert!(
            async_io::block_on(service.reserve(b"historical bytes", message.header())).is_err()
        );
        assert!(async_io::block_on(service.begin(&"0".repeat(64), message.header())).is_err());
        assert!(
            async_io::block_on(service.reserve(&vec![0; 384 * 1024 + 1], message.header()))
                .is_err()
        );
    }
}
