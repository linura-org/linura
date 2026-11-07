//! Private native quiescence channel. Every fragment needs actual admitted
//! native-process credentials. No message retires history or releases protection.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

const RESERVED: u8 = 1;
const QUIESCED: u8 = 2;
const FRAME_BYTES: usize = 48;
const BUDGET: Duration = Duration::from_secs(1);

fn unavailable() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("native terminal continuity unavailable; no retry or release".into())
}

/// Recorded before publication. Only the original native channel may advance
/// Reserved to Quiesced, and channel loss permanently invalidates that report.
#[derive(Debug)]
pub(super) struct ChannelState(AtomicU8);
impl ChannelState {
    pub(super) fn reserved() -> Arc<Self> {
        Arc::new(Self(AtomicU8::new(RESERVED)))
    }
    pub(super) fn phase(&self) -> zbus::fdo::Result<u32> {
        match self.0.load(Ordering::Acquire) {
            RESERVED => Ok(1),
            QUIESCED => Ok(2),
            _ => Err(unavailable()),
        }
    }
    fn quiesce(&self) -> zbus::fdo::Result<()> {
        self.0
            .compare_exchange(RESERVED, QUIESCED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| unavailable())
    }
}

/// Created immediately after memory reservation, before any fallible storage or
/// descriptor work. It moves once into the worker; every exit retains ownership
/// but prevents disk/memory from claiming continuing native quiescence.
pub(super) struct Lifetime(Arc<ChannelState>);
impl Lifetime {
    pub(super) fn new(state: Arc<ChannelState>) -> Self {
        Self(state)
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.0.store(0, Ordering::Release);
    }
}

/// The exact full terminal reservation SHA-256 binds each message. Sequence 1
/// accepts only LNFQ (native held-scene quiescence); later messages accept only
/// LNFV (fresh continuity). The compositor must independently consume its actual
/// terminal receipt and verify native safety frames before sending LNFQ.
pub(super) fn serve(
    stream: &mut UnixStream,
    reservation_digest: &[u8; 32],
    lifetime: Lifetime,
    mut authenticate: impl FnMut(&rustix::net::UCred) -> zbus::fdo::Result<()>,
    mut verify: impl FnMut(bool) -> zbus::fdo::Result<()>,
    mut persist_quiescence: impl FnMut() -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    stream.set_nonblocking(false).map_err(|_| unavailable())?;
    let mut sequence = 1_u64;
    loop {
        let mut request = [0; FRAME_BYTES];
        let mut read = 0;
        let mut pending: Option<Instant> = None;
        while read < request.len() {
            let remaining = match pending {
                Some(deadline) => deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(unavailable)?,
                None => BUDGET,
            };
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| unavailable())?;
            // Keep the shared SCM_CREDENTIALS parser's unchanged 16-byte cap.
            let end = (read + 16).min(FRAME_BYTES);
            match super::native_message::read_chunk(stream, &mut request[read..end]) {
                Ok((size, sender)) => {
                    if pending.is_none() {
                        pending = Some(Instant::now().checked_add(BUDGET).ok_or_else(unavailable)?);
                    }
                    authenticate(&sender)?;
                    read += size;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && read == 0 =>
                {
                    verify(sequence == 1)?;
                }
                Err(_) => return Err(unavailable()),
            }
        }
        let purpose = if sequence == 1 {
            b"LNFQ:1\n\0"
        } else {
            b"LNFV:1\n\0"
        };
        if request[..8] != purpose[..]
            || request[8..16] != sequence.to_be_bytes()
            || request[16..] != reservation_digest[..]
        {
            return Err(unavailable());
        }
        let deadline = pending.ok_or_else(unavailable)?;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        verify(sequence == 1)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(unavailable)?;
        // Reserve the transition before acknowledging. A failed write cannot
        // repeat quiescence; Lifetime then makes continuing reports unavailable.
        if sequence == 1 {
            // Sync and verify the separate immutable marker before advertising
            // native quiescence or acknowledging the original sender. A lost
            // marker or ACK is indeterminate and never grants a retry.
            persist_quiescence()?;
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            lifetime.0.quiesce()?;
        } else if lifetime.0.phase()? != u32::from(QUIESCED) {
            return Err(unavailable());
        }
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| unavailable())?;
        stream.write_all(&request).map_err(|_| unavailable())?;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        sequence = sequence.checked_add(1).ok_or_else(unavailable)?;
    }
}

#[cfg(test)]
mod tests {
    // Socket/state fixtures only; no native safety-frame or PAM qualification.
    use super::*;
    use std::io::{Read, Write};

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn pair() -> (UnixStream, UnixStream) {
        let (root, native) = value(UnixStream::pair());
        value(rustix::net::sockopt::set_socket_passcred(&root, true));
        value(native.set_read_timeout(Some(Duration::from_secs(3))));
        (root, native)
    }
    fn frame(sequence: u64, quiesce: bool, digest: [u8; 32]) -> [u8; FRAME_BYTES] {
        let mut bytes = [0; FRAME_BYTES];
        bytes[..8].copy_from_slice(if quiesce {
            b"LNFQ:1\n\0"
        } else {
            b"LNFV:1\n\0"
        });
        bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
        bytes[16..].copy_from_slice(&digest);
        bytes
    }
    fn same_process(sender: &rustix::net::UCred) -> zbus::fdo::Result<()> {
        if sender.pid == rustix::process::getpid() && sender.uid == rustix::process::getuid() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
    #[test]
    fn publication_failure_invalidates_reports_without_reviving_reservation_state() {
        let state = ChannelState::reserved();
        assert_eq!(value(state.phase()), 1);
        drop(Lifetime::new(state.clone()));
        assert!(state.phase().is_err());
        assert!(state.quiesce().is_err());
    }
    #[test]
    fn exact_native_quiescence_is_once_and_every_later_probe_needs_fresh_continuity() {
        for lost in [false, true] {
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let worker = std::thread::spawn(move || {
                let mut checks = 0;
                let result = serve(&mut root, &[7; 32], lifetime, same_process, |initial| {
                    checks += 1;
                    assert_eq!(initial, checks == 1);
                    if lost && checks == 2 {
                        Err(unavailable())
                    } else {
                        Ok(())
                    }
                }, || Ok(()));
                assert!(result.is_err());
                checks
            });
            let first = frame(1, true, [7; 32]);
            value(native.write_all(&first));
            let mut response = [0; FRAME_BYTES];
            value(native.read_exact(&mut response));
            assert_eq!(response, first);
            assert_eq!(value(state.phase()), 2);
            if lost {
                value(native.write_all(&frame(2, false, [7; 32])));
                assert!(native.read_exact(&mut response).is_err());
            } else {
                let next = frame(2, false, [7; 32]);
                value(native.write_all(&next));
                value(native.read_exact(&mut response));
                assert_eq!(response, next);
                // Strict sequence does not allow another Q, even with valid identity.
                value(native.write_all(&frame(3, true, [7; 32])));
                assert!(native.read_exact(&mut response).is_err());
            }
            assert_eq!(value(worker.join()), 2);
            assert!(state.phase().is_err());
        }
    }
    #[test]
    fn persistence_failure_does_not_acknowledge_or_freshen_the_native_channel() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let worker = std::thread::spawn(move || {
            assert!(
                serve(
                    &mut root,
                    &[7; 32],
                    lifetime,
                    same_process,
                    |_| Ok(()),
                    || Err(unavailable()),
                )
                .is_err()
            );
        });
        value(native.write_all(&frame(1, true, [7; 32])));
        assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
        value(worker.join());
        assert!(state.phase().is_err());
    }

    #[test]
    fn another_purpose_sequence_or_reservation_cannot_quiesce_or_reset_the_channel() {
        for request in [
            frame(1, false, [7; 32]),
            frame(0, true, [7; 32]),
            frame(2, true, [7; 32]),
            frame(1, true, [8; 32]),
        ] {
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(&mut root, &[7; 32], lifetime, same_process, |_| {
                        unreachable!("invalid message must not reach witness verification")
                    }, || unreachable!("invalid native purpose cannot persist"))
                    .is_err()
                );
            });
            value(native.write_all(&request));
            assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
            value(worker.join());
            assert!(state.phase().is_err());
        }
    }
    #[test]
    fn every_fragment_requires_native_identity_before_any_transition_or_acknowledgement() {
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let (sent, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut fragments = 0;
            let result = serve(
                &mut root,
                &[7; 32],
                lifetime,
                |sender| {
                    same_process(sender)?;
                    fragments += 1;
                    if fragments == 1 {
                        value(sent.send(()));
                        Ok(())
                    } else {
                        Err(unavailable())
                    }
                },
                |_| unreachable!("foreign later fragment must refuse before verification"),
                || unreachable!("foreign fragment cannot persist"),
            );
            assert!(result.is_err());
        });
        let request = frame(1, true, [7; 32]);
        value(native.write_all(&request[..16]));
        value(received.recv_timeout(Duration::from_secs(2)));
        value(native.write_all(&request[16..]));
        assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
        value(worker.join());
        assert!(state.phase().is_err());
    }
    #[test]
    fn fragment_authentication_and_verification_share_the_original_partial_message_budget() {
        for slow_authentication in [false, true] {
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
                            same_process(sender)?;
                            if slow_authentication {
                                std::thread::sleep(Duration::from_millis(1100));
                            }
                            Ok(())
                        },
                        |_| {
                            assert!(!slow_authentication);
                            std::thread::sleep(Duration::from_millis(1100));
                            Ok(())
                        },
                        || unreachable!("expired fragment cannot persist"),
                    )
                    .is_err()
                );
            });
            value(native.write_all(&frame(1, true, [7; 32])));
            assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
            value(worker.join());
            assert!(state.phase().is_err());
        }
    }
}
