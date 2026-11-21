//! Authenticated, one-use original native release-spend witness. The caller
//! durably spends LNRX before ACK. This channel does NOT itself remove a
//! compositor, S17, input, power, Root admission or startup fence.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

const RESERVED: u8 = 1;
const SPENT: u8 = 2;
const TRANSFERRED: u8 = 3;
const FRAME_BYTES: usize = 48;
const PURPOSE: &[u8; 8] = b"LNRW:1\n\0";
const ORDINARY_PURPOSE: &[u8; 8] = b"LNOW:1\n\0";
const BUDGET: Duration = Duration::from_secs(1);

fn unavailable() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("original native release grant unavailable; permanently spent".into())
}

/// An original Root invocation owns this state, not a disk file, replacement
/// session or D-Bus caller. After any worker exit it becomes unobservable.
#[derive(Debug)]
pub(super) struct ChannelState(AtomicU8);

impl ChannelState {
    pub(super) fn reserved() -> Arc<Self> {
        Arc::new(Self(AtomicU8::new(RESERVED)))
    }
    pub(super) fn pending(&self) -> bool {
        self.0.load(Ordering::Acquire) == RESERVED
    }
    pub(super) fn held(&self) -> bool {
        self.0.load(Ordering::Acquire) == SPENT
    }
    pub(super) fn transferred(&self) -> bool {
        self.0.load(Ordering::Acquire) == TRANSFERRED
    }
    pub(super) fn transfer(self: &Arc<Self>) -> zbus::fdo::Result<Transferred> {
        self.0
            .compare_exchange(SPENT, TRANSFERRED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| unavailable())?;
        Ok(Transferred(self.clone()))
    }
    fn spend(&self) -> zbus::fdo::Result<()> {
        self.0
            .compare_exchange(RESERVED, SPENT, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| unavailable())
    }
}

pub(super) struct Lifetime(Arc<ChannelState>);
impl Lifetime {
    pub(super) fn new(state: Arc<ChannelState>) -> Self {
        Self(state)
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        // The transferred guard becomes the sole lifetime owner. Closing the
        // old spend endpoint must not revoke its correctly moved anchor.
        let mut phase = self.0.0.load(Ordering::Acquire);
        while phase != TRANSFERRED {
            match self
                .0
                .0
                .compare_exchange(phase, 0, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(current) => phase = current,
            }
        }
    }
}
pub(super) struct Transferred(Arc<ChannelState>);
impl super::display_completion_grant::CompletionAnchor for Transferred {
    fn live(&self) -> zbus::fdo::Result<()> {
        if self.0.transferred() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
}
impl Drop for Transferred {
    fn drop(&mut self) {
        self.0.0.store(0, Ordering::Release);
    }
}

/// Accept exactly one authenticated LNRW frame bound to the complete original
/// immutable LNRN reservation SHA-256. Every read fragment is credentialed.
/// The original deadline is fixed at entry; busy peers cannot extend it.
/// Durable spent recording precedes ACK. No native physical-release outcome
/// or completed Control transaction is reported by this mechanism.
pub(super) fn serve(
    stream: &mut UnixStream,
    digest: &[u8; 32],
    lifetime: Lifetime,
    authenticate: impl FnMut(&rustix::net::UCred) -> zbus::fdo::Result<()>,
    verify: impl FnMut() -> zbus::fdo::Result<()>,
    persist_spent: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    serve_purpose(
        stream,
        digest,
        lifetime,
        PURPOSE,
        authenticate,
        verify,
        persist_spent,
    )
    .map(drop)
}

/// Same bounded credential transport, with a distinct ordinary-release purpose.
/// An original-restoration frame can never spend an ordinary preparation.
pub(super) fn serve_ordinary(
    stream: &mut UnixStream,
    digest: &[u8; 32],
    lifetime: Lifetime,
    authenticate: impl FnMut(&rustix::net::UCred) -> zbus::fdo::Result<()>,
    verify: impl FnMut() -> zbus::fdo::Result<()>,
    persist_spent: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<Lifetime> {
    serve_purpose(
        stream,
        digest,
        lifetime,
        ORDINARY_PURPOSE,
        authenticate,
        verify,
        persist_spent,
    )
}

fn serve_purpose(
    stream: &mut UnixStream,
    digest: &[u8; 32],
    lifetime: Lifetime,
    purpose: &[u8; 8],
    mut authenticate: impl FnMut(&rustix::net::UCred) -> zbus::fdo::Result<()>,
    mut verify: impl FnMut() -> zbus::fdo::Result<()>,
    mut persist_spent: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<Lifetime> {
    stream.set_nonblocking(false).map_err(|_| unavailable())?;
    let deadline = Instant::now().checked_add(BUDGET).ok_or_else(unavailable)?;
    let mut bytes = [0_u8; FRAME_BYTES];
    let mut read = 0;
    verify()?;
    while read < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(unavailable)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| unavailable())?;
        let end = (read + 16).min(FRAME_BYTES);
        let (size, credentials) = super::native_message::read_chunk(stream, &mut bytes[read..end])
            .map_err(|_| unavailable())?;
        authenticate(&credentials)?;
        if size == 0 {
            return Err(unavailable());
        }
        read += size;
    }
    if bytes[..8] != purpose[..]
        || bytes[8..16] != 1_u64.to_be_bytes()
        || bytes[16..] != digest[..]
        || Instant::now() >= deadline
        || !lifetime.0.pending()
    {
        return Err(unavailable());
    }
    verify()?;
    if Instant::now() >= deadline {
        return Err(unavailable());
    }
    // If persistence or post-readback fails the reservation remains spent or
    // indeterminate, never recovered by recreating this channel.
    persist_spent()?;
    if Instant::now() >= deadline {
        return Err(unavailable());
    }
    verify()?;
    lifetime.0.spend()?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(unavailable)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| unavailable())?;
    stream.write_all(&bytes).map_err(|_| unavailable())?;
    if Instant::now() >= deadline {
        return Err(unavailable());
    }
    Ok(lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn pair() -> (UnixStream, UnixStream) {
        let (root, native) = value(UnixStream::pair());
        value(rustix::net::sockopt::set_socket_passcred(&root, true));
        value(native.set_read_timeout(Some(Duration::from_secs(2))));
        (root, native)
    }
    fn frame(digest: [u8; 32]) -> [u8; FRAME_BYTES] {
        let mut value = [0; FRAME_BYTES];
        value[..8].copy_from_slice(PURPOSE);
        value[8..16].copy_from_slice(&1_u64.to_be_bytes());
        value[16..].copy_from_slice(&digest);
        value
    }
    fn same_sender(sender: &rustix::net::UCred) -> zbus::fdo::Result<()> {
        if sender.pid == rustix::process::getpid() && sender.uid == rustix::process::getuid() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
    #[test]
    fn ordinary_purpose_authenticates_every_fragment_and_persists_before_ack() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let (durable_tx, durable_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut fragments = 0;
            let result = serve_ordinary(
                &mut root,
                &[9; 32],
                lifetime,
                |sender| {
                    fragments += 1;
                    same_sender(sender)
                },
                || Ok(()),
                || {
                    value(durable_tx.send(()));
                    Ok(())
                },
            );
            assert!(result.is_ok());
            assert!(fragments >= 3);
        });
        let mut sent = frame([9; 32]);
        sent[..8].copy_from_slice(ORDINARY_PURPOSE);
        value(native.write_all(&sent));
        let mut received = [0; FRAME_BYTES];
        value(native.read_exact(&mut received));
        value(durable_rx.recv_timeout(Duration::from_secs(1)));
        assert_eq!(received, sent);
        value(worker.join());
        assert!(!state.pending());
        assert!(native.write_all(&sent).is_err() || native.read_exact(&mut received).is_err());
    }

    #[test]
    fn ordinary_rejects_original_purpose_identity_drift_storage_failure_and_unknown_commit() {
        for fault in 0..7 {
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let worker = std::thread::spawn(move || {
                let writes = std::cell::Cell::new(0);
                let mut fragments = 0;
                let result = serve_ordinary(
                    &mut root,
                    &[9; 32],
                    lifetime,
                    |sender| {
                        same_sender(sender)?;
                        fragments += 1;
                        if fault == 3 || (fault == 4 && fragments > 1) {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        if fault == 6 && writes.get() > 0 {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    },
                    || {
                        writes.set(writes.get() + 1);
                        if fault == 5 {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(result.is_err());
                assert_eq!(writes.get(), usize::from(fault >= 5));
            });
            let mut sent = frame([9; 32]);
            sent[..8].copy_from_slice(ORDINARY_PURPOSE);
            match fault {
                0 => sent[..8].copy_from_slice(PURPOSE),
                1 => sent[15] = 2,
                2 => sent[16] ^= 1,
                _ => {}
            }
            value(native.write_all(&sent));
            assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
            value(worker.join());
            assert!(!state.pending());
        }
    }

    #[test]
    fn ordinary_lost_ack_does_not_repeat_persistence_or_reopen_channel() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let (durable_tx, durable_rx) = std::sync::mpsc::channel();
        let (lost_tx, lost_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = serve_ordinary(
                &mut root,
                &[9; 32],
                lifetime,
                same_sender,
                || Ok(()),
                || {
                    value(durable_tx.send(()));
                    value(lost_rx.recv_timeout(Duration::from_secs(1)));
                    Ok(())
                },
            );
            assert!(result.is_err());
        });
        let mut sent = frame([9; 32]);
        sent[..8].copy_from_slice(ORDINARY_PURPOSE);
        value(native.write_all(&sent));
        value(durable_rx.recv_timeout(Duration::from_secs(1)));
        drop(native);
        value(lost_tx.send(()));
        value(worker.join());
        assert!(!state.pending());
    }

    #[test]
    fn exact_original_native_spend_is_once_and_requires_durable_before_ack() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let (persisted_tx, persisted_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut checks = 0;
            assert!(
                serve(
                    &mut root,
                    &[7; 32],
                    lifetime,
                    same_sender,
                    || {
                        checks += 1;
                        Ok(())
                    },
                    || {
                        value(persisted_tx.send(()));
                        Ok(())
                    },
                )
                .is_ok()
            );
            checks
        });
        let sent = frame([7; 32]);
        value(native.write_all(&sent));
        let mut reply = [0; FRAME_BYTES];
        value(native.read_exact(&mut reply));
        value(persisted_rx.recv_timeout(Duration::from_secs(1)));
        assert_eq!(reply, sent);
        assert_eq!(value(worker.join()), 3);
        assert!(!state.pending());
        // A second request cannot receive a grant from this original worker.
        assert!(native.write_all(&sent).is_err() || native.read_exact(&mut reply).is_err());
    }
    #[test]
    fn malformed_purpose_sequence_digest_and_denied_peer_never_persist() {
        for fault in 0..4 {
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        |sender| {
                            same_sender(sender)?;
                            if fault == 3 {
                                Err(unavailable())
                            } else {
                                Ok(())
                            }
                        },
                        || Ok(()),
                        || unreachable!("malformed or unauthenticated spend cannot persist"),
                    )
                    .is_err()
                );
            });
            let mut request = frame([7; 32]);
            if fault == 0 {
                request[0] = b'X';
            } else if fault == 1 {
                request[15] = 2;
            } else if fault == 2 {
                request[16] ^= 1;
            }
            value(native.write_all(&request));
            assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
            value(worker.join());
            assert!(!state.pending());
        }
    }
    #[test]
    fn lost_ack_or_persistence_error_never_reopens_the_original_grant() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let worker = std::thread::spawn(move || {
            assert!(
                serve(
                    &mut root,
                    &[7; 32],
                    lifetime,
                    same_sender,
                    || Ok(()),
                    || Err(unavailable()),
                )
                .is_err()
            );
        });
        value(native.write_all(&frame([7; 32])));
        assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
        value(worker.join());
        assert!(!state.pending());
    }
    #[test]
    fn fragment_authentication_is_rechecked_and_mismatch_is_terminal() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut fragments = 0;
            assert!(
                serve(
                    &mut root,
                    &[7; 32],
                    lifetime,
                    |sender| {
                        same_sender(sender)?;
                        fragments += 1;
                        if fragments == 1 {
                            value(first_tx.send(()));
                            Ok(())
                        } else {
                            Err(unavailable())
                        }
                    },
                    || Ok(()),
                    || unreachable!("later fragment cannot persist"),
                )
                .is_err()
            );
        });
        let bytes = frame([7; 32]);
        value(native.write_all(&bytes[..16]));
        value(first_rx.recv_timeout(Duration::from_secs(1)));
        value(native.write_all(&bytes[16..]));
        assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
        value(worker.join());
        assert!(!state.pending());
    }
}
