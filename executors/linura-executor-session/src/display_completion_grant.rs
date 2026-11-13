//! Actual-peer current-lifetime transfer. The initial ACK follows a durable
//! spend and a move of the original quiescence anchor. It proves neither
//! physical retirement nor ReleasedCurrent; independent Control joins do that.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use super::display_finalization_grant::Transferred;

const RESERVED: u8 = 1;
const TRANSFER_SPENT: u8 = 2;
const POWER_SPENT: u8 = 3;
const CURRENT_SPENT: u8 = 4;
const RETIREMENT_SPENT: u8 = 5;
const SUCCESSOR_SPENT: u8 = 6;
const FRAME_BYTES: usize = 48;
const BUDGET: Duration = Duration::from_secs(1);

fn unavailable() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("native completion lifetime unavailable; no replay".into())
}

#[derive(Debug)]
pub(super) struct ChannelState(AtomicU8);
impl ChannelState {
    pub(super) fn reserved() -> Arc<Self> {
        Arc::new(Self(AtomicU8::new(RESERVED)))
    }
    pub(super) fn pending(&self) -> bool {
        self.0.load(Ordering::Acquire) == RESERVED
    }
    pub(super) fn transferred(&self) -> bool {
        matches!(
            self.0.load(Ordering::Acquire),
            TRANSFER_SPENT | POWER_SPENT | CURRENT_SPENT | RETIREMENT_SPENT | SUCCESSOR_SPENT
        )
    }
    pub(super) fn power_spent(&self) -> bool {
        matches!(
            self.0.load(Ordering::Acquire),
            POWER_SPENT | CURRENT_SPENT | RETIREMENT_SPENT | SUCCESSOR_SPENT
        )
    }
    pub(super) fn current_spent(&self) -> bool {
        matches!(
            self.0.load(Ordering::Acquire),
            CURRENT_SPENT | RETIREMENT_SPENT | SUCCESSOR_SPENT
        )
    }
    pub(super) fn retirement_spent(&self) -> bool {
        matches!(
            self.0.load(Ordering::Acquire),
            RETIREMENT_SPENT | SUCCESSOR_SPENT
        )
    }
    pub(super) fn successor_spent(&self) -> bool {
        self.0.load(Ordering::Acquire) == SUCCESSOR_SPENT
    }
    fn spend(&self) -> zbus::fdo::Result<()> {
        self.0
            .compare_exchange(
                RESERVED,
                TRANSFER_SPENT,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
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
        self.0.0.store(0, Ordering::Release);
    }
}

/// Every fragment is authenticated against the original admitted native PID,
/// start identity and immutable executable. Idle continuity cannot renew the
/// original first-effect window. Partial messages have one absolute budget.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve(
    stream: &mut UnixStream,
    digest: &[u8; 32],
    lifetime: Lifetime,
    mut authenticate: impl FnMut(&rustix::net::UCred) -> zbus::fdo::Result<()>,
    mut verify: impl FnMut(bool) -> zbus::fdo::Result<()>,
    mut spend_and_transfer: impl FnMut() -> zbus::fdo::Result<Transferred>,
    mut retire_power: impl FnMut(&[u8; 32]) -> zbus::fdo::Result<()>,
    mut commit_current: impl FnMut(&[u8; 32]) -> zbus::fdo::Result<()>,
    mut retire_current: impl FnMut(&[u8; 32]) -> zbus::fdo::Result<()>,
    mut transfer_successor: impl FnMut(&[u8; 32]) -> zbus::fdo::Result<()>,
) -> zbus::fdo::Result<()> {
    stream.set_nonblocking(false).map_err(|_| unavailable())?;
    let mut sequence = 1_u64;
    let mut transferred: Option<Transferred> = None;
    loop {
        if let Some(anchor) = &transferred {
            anchor.live()?;
        }
        let mut bytes = [0; FRAME_BYTES];
        let mut read = 0;
        let mut deadline: Option<Instant> = None;
        while read < FRAME_BYTES {
            let remaining = match deadline {
                Some(end) => end
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(unavailable)?,
                None => BUDGET,
            };
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| unavailable())?;
            let end = (read + 16).min(FRAME_BYTES);
            match super::native_message::read_chunk(stream, &mut bytes[read..end]) {
                Ok((size, sender)) => {
                    if size == 0 {
                        return Err(unavailable());
                    }
                    if deadline.is_none() {
                        deadline =
                            Some(Instant::now().checked_add(BUDGET).ok_or_else(unavailable)?);
                    }
                    authenticate(&sender)?;
                    read += size;
                }
                Err(error)
                    if read == 0
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                {
                    verify(sequence == 1)?;
                    if let Some(anchor) = &transferred {
                        anchor.live()?;
                    }
                }
                Err(_) => return Err(unavailable()),
            }
        }
        let power = sequence > 1 && &bytes[..8] == b"LNPR:1\n\0";
        let current = sequence > 1 && &bytes[..8] == b"LNCF:1\n\0";
        let retirement = sequence > 1 && &bytes[..8] == b"LNCA:1\n\0";
        let successor = sequence > 1 && &bytes[..8] == b"LNSA:1\n\0";
        let purpose = if successor {
            b"LNSA:1\n\0"
        } else if retirement {
            b"LNCA:1\n\0"
        } else if current {
            b"LNCF:1\n\0"
        } else if power {
            b"LNPR:1\n\0"
        } else if sequence == 1 {
            b"LNCH:1\n\0"
        } else {
            b"LNCV:1\n\0"
        };
        let end = deadline.ok_or_else(unavailable)?;
        if bytes[..8] != purpose[..]
            || bytes[8..16] != sequence.to_be_bytes()
            || (!power && !current && !retirement && !successor && bytes[16..] != digest[..])
            || Instant::now() >= end
        {
            return Err(unavailable());
        }
        verify(sequence == 1)?;
        if Instant::now() >= end {
            return Err(unavailable());
        }
        if sequence == 1 {
            // Publication/spend ambiguity is terminal. The old lifetime is
            // MOVED, never recreated; dropping this worker invalidates both.
            let anchor = spend_and_transfer()?;
            anchor.live()?;
            transferred = Some(anchor);
            lifetime.0.spend()?;
        } else if !lifetime.0.transferred() {
            return Err(unavailable());
        }
        if power {
            if lifetime.0.power_spent() {
                return Err(unavailable());
            }
            retire_power(bytes[16..].try_into().map_err(|_| unavailable())?)?;
            lifetime
                .0
                .0
                .compare_exchange(
                    TRANSFER_SPENT,
                    POWER_SPENT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| unavailable())?;
        }
        if current {
            if !lifetime.0.power_spent() || lifetime.0.current_spent() {
                return Err(unavailable());
            }
            commit_current(bytes[16..].try_into().map_err(|_| unavailable())?)?;
            lifetime
                .0
                .0
                .compare_exchange(
                    POWER_SPENT,
                    CURRENT_SPENT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| unavailable())?;
        }
        if retirement {
            if !lifetime.0.current_spent() || lifetime.0.retirement_spent() {
                return Err(unavailable());
            }
            retire_current(bytes[16..].try_into().map_err(|_| unavailable())?)?;
            lifetime
                .0
                .0
                .compare_exchange(
                    CURRENT_SPENT,
                    RETIREMENT_SPENT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| unavailable())?;
        }
        if successor {
            if !lifetime.0.retirement_spent() || lifetime.0.successor_spent() {
                return Err(unavailable());
            }
            transfer_successor(bytes[16..].try_into().map_err(|_| unavailable())?)?;
            lifetime
                .0
                .0
                .compare_exchange(
                    RETIREMENT_SPENT,
                    SUCCESSOR_SPENT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| unavailable())?;
        }
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(unavailable)?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| unavailable())?;
        stream.write_all(&bytes).map_err(|_| unavailable())?;
        if Instant::now() >= end {
            return Err(unavailable());
        }
        sequence = sequence.checked_add(1).ok_or_else(unavailable)?;
    }
}

#[cfg(test)]
mod tests {
    // Real local credential-bearing sockets; no physical display qualification.
    use super::super::display_finalization_grant as original;
    use super::*;
    use std::io::Read;
    use std::sync::atomic::AtomicUsize;

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn pair() -> (UnixStream, UnixStream) {
        let (root, native) = value(UnixStream::pair());
        value(rustix::net::sockopt::set_socket_passcred(&root, true));
        value(native.set_read_timeout(Some(Duration::from_secs(3))));
        (root, native)
    }
    fn identity(sender: &rustix::net::UCred) -> zbus::fdo::Result<()> {
        if sender.pid == rustix::process::getpid() && sender.uid == rustix::process::getuid() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
    fn frame(purpose: &[u8; 8], sequence: u64, digest: [u8; 32]) -> [u8; FRAME_BYTES] {
        let mut bytes = [0; FRAME_BYTES];
        bytes[..8].copy_from_slice(purpose);
        bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
        bytes[16..].copy_from_slice(&digest);
        bytes
    }
    fn quiesced() -> (
        Arc<original::ChannelState>,
        UnixStream,
        std::thread::JoinHandle<()>,
    ) {
        let (mut root, mut native) = pair();
        let state = original::ChannelState::reserved();
        let lifetime = original::Lifetime::new(state.clone());
        let worker = std::thread::spawn(move || {
            let _result = original::serve(
                &mut root,
                &[4; 32],
                lifetime,
                identity,
                |_| Ok(()),
                || Ok(()),
            );
        });
        let request = frame(b"LNFQ:1\n\0", 1, [4; 32]);
        value(native.write_all(&request));
        let mut response = [0; FRAME_BYTES];
        value(native.read_exact(&mut response));
        assert_eq!(response, request);
        assert_eq!(value(state.phase()), 2);
        (state, native, worker)
    }

    #[test]
    fn lifetime_moves_once_and_old_eof_cannot_destroy_the_new_owner() {
        let (old, old_native, old_worker) = quiesced();
        let (mut root, mut native) = pair();
        let state = ChannelState::reserved();
        let lifetime = Lifetime::new(state.clone());
        let retained = old.clone();
        let spends = Arc::new(AtomicUsize::new(0));
        let worker_spends = spends.clone();
        let worker = std::thread::spawn(move || {
            assert!(
                serve(
                    &mut root,
                    &[7; 32],
                    lifetime,
                    identity,
                    |_| Ok(()),
                    || {
                        assert_eq!(worker_spends.fetch_add(1, Ordering::AcqRel), 0);
                        retained.transfer()
                    },
                    |_| Err(unavailable()),
                    |_| Err(unavailable()),
                    |_| Err(unavailable()),
                    |_| Err(unavailable()),
                )
                .is_err()
            );
        });
        let request = frame(b"LNCH:1\n\0", 1, [7; 32]);
        value(native.write_all(&request));
        let mut response = [0; FRAME_BYTES];
        value(native.read_exact(&mut response));
        assert_eq!(response, request);
        assert!(state.transferred());
        assert!(old.transferred());
        assert!(old.phase().is_err()); // Never report legacy quiescence/release.
        assert!(old.transfer().is_err());
        drop(old_native);
        value(old_worker.join());
        assert!(old.transferred());
        let probe = frame(b"LNCV:1\n\0", 2, [7; 32]);
        value(native.write_all(&probe));
        value(native.read_exact(&mut response));
        assert_eq!(response, probe);
        assert_eq!(spends.load(Ordering::Acquire), 1);
        // Replaying the initial purpose cannot renew either live anchor.
        value(native.write_all(&frame(b"LNCH:1\n\0", 3, [7; 32])));
        assert!(native.read_exact(&mut response).is_err());
        value(worker.join());
        assert!(!state.transferred());
        assert!(!old.transferred());
        assert!(old.transfer().is_err());
        assert_eq!(spends.load(Ordering::Acquire), 1);
    }

    #[test]
    fn foreign_purpose_sequence_digest_or_fragment_cannot_spend_or_acknowledge() {
        for fault in 0..5 {
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let worker = std::thread::spawn(move || {
                let mut fragments = 0;
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        |sender| {
                            identity(sender)?;
                            fragments += 1;
                            if fault == 4 && fragments > 1 {
                                Err(unavailable())
                            } else {
                                Ok(())
                            }
                        },
                        |_| unreachable!("invalid frame cannot verify"),
                        || unreachable!("invalid frame cannot spend"),
                        |_| unreachable!("invalid frame cannot retire power"),
                        |_| unreachable!("invalid frame cannot commit current"),
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                    )
                    .is_err()
                );
            });
            let request = match fault {
                0 => frame(b"LNCV:1\n\0", 1, [7; 32]),
                1 => frame(b"LNCH:1\n\0", 0, [7; 32]),
                2 => frame(b"LNCH:1\n\0", 2, [7; 32]),
                3 => frame(b"LNCH:1\n\0", 1, [8; 32]),
                _ => frame(b"LNCH:1\n\0", 1, [7; 32]),
            };
            value(native.write_all(&request));
            assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
            value(worker.join());
            assert!(!state.pending());
            assert!(!state.transferred());
        }
    }

    #[test]
    fn stale_continuity_or_failed_durable_spend_never_transfers_the_old_lifetime() {
        for stale in [true, false] {
            let (old, old_native, old_worker) = quiesced();
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let spends = Arc::new(AtomicUsize::new(0));
            let worker_spends = spends.clone();
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        identity,
                        |_| if stale { Err(unavailable()) } else { Ok(()) },
                        || {
                            worker_spends.fetch_add(1, Ordering::AcqRel);
                            Err(unavailable())
                        },
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                    )
                    .is_err()
                );
            });
            value(native.write_all(&frame(b"LNCH:1\n\0", 1, [7; 32])));
            assert!(native.read_exact(&mut [0; FRAME_BYTES]).is_err());
            value(worker.join());
            assert_eq!(spends.load(Ordering::Acquire), usize::from(!stale));
            assert!(!state.transferred());
            assert_eq!(value(old.phase()), 2);
            drop(old_native);
            value(old_worker.join());
            assert!(old.transfer().is_err());
        }
    }
    #[test]
    fn power_permission_is_a_separate_durable_one_use_spend_on_the_original_lifetime() {
        // A failed publication, foreign digest, reused sequence and replay all
        // close the lifetime without a power ACK or another transfer.
        for fault in 0..5 {
            let (old, old_native, old_worker) = quiesced();
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let retained = old.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let spent = calls.clone();
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        identity,
                        |_| Ok(()),
                        || retained.transfer(),
                        |digest| {
                            spent.fetch_add(1, Ordering::AcqRel);
                            if fault == 1 || digest != &[8; 32] {
                                return Err(unavailable());
                            }
                            Ok(())
                        },
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                    )
                    .is_err()
                );
            });
            let mut response = [0; FRAME_BYTES];
            value(native.write_all(&frame(b"LNCH:1\n\0", 1, [7; 32])));
            value(native.read_exact(&mut response));
            drop(old_native);
            value(old_worker.join());
            let request = frame(
                b"LNPR:1\n\0",
                if fault == 3 { 1 } else { 2 },
                if fault == 2 { [9; 32] } else { [8; 32] },
            );
            value(native.write_all(&request));
            if matches!(fault, 1..=3) {
                assert!(native.read_exact(&mut response).is_err());
            } else {
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
                assert!(state.power_spent());
                // Ordinary continuity still uses the ORIGINAL completion digest.
                let probe = frame(b"LNCV:1\n\0", 3, [7; 32]);
                value(native.write_all(&probe));
                value(native.read_exact(&mut response));
                assert_eq!(response, probe);
                value(native.write_all(&frame(
                    b"LNPR:1\n\0",
                    if fault == 4 { 2 } else { 4 },
                    [8; 32],
                )));
                assert!(native.read_exact(&mut response).is_err());
            }
            value(worker.join());
            assert!(!state.transferred());
            assert!(!old.transferred());
            assert_eq!(calls.load(Ordering::Acquire), usize::from(fault != 3));
        }
    }
    #[test]
    fn committed_current_requires_original_power_phase_and_durable_distinct_spend() {
        // Actual credential-bearing socket: failure, out-of-order purpose,
        // foreign digest, and replay must never acknowledge permanent lifetime.
        for fault in 0..5 {
            let (old, old_native, old_worker) = quiesced();
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let retained = old.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let spent = calls.clone();
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        identity,
                        |_| Ok(()),
                        || retained.transfer(),
                        |digest| if digest == &[8; 32] {
                            Ok(())
                        } else {
                            Err(unavailable())
                        },
                        |digest| {
                            spent.fetch_add(1, Ordering::AcqRel);
                            if fault == 1 || digest != &[9; 32] {
                                Err(unavailable())
                            } else {
                                Ok(())
                            }
                        },
                        |_| Err(unavailable()),
                        |_| Err(unavailable()),
                    )
                    .is_err()
                );
            });
            let mut response = [0; FRAME_BYTES];
            value(native.write_all(&frame(b"LNCH:1\n\0", 1, [7; 32])));
            value(native.read_exact(&mut response));
            drop(old_native);
            value(old_worker.join());
            if fault != 2 {
                value(native.write_all(&frame(b"LNPR:1\n\0", 2, [8; 32])));
                value(native.read_exact(&mut response));
                assert!(state.power_spent());
                assert!(!state.current_spent());
            }
            let request = frame(
                b"LNCF:1\n\0",
                if fault == 2 { 2 } else { 3 },
                if fault == 3 { [6; 32] } else { [9; 32] },
            );
            value(native.write_all(&request));
            if matches!(fault, 1..=3) {
                assert!(native.read_exact(&mut response).is_err());
            } else {
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
                assert!(state.current_spent());
                let probe = frame(b"LNCV:1\n\0", 4, [7; 32]);
                value(native.write_all(&probe));
                value(native.read_exact(&mut response));
                assert_eq!(response, probe);
                value(native.write_all(&frame(
                    b"LNCF:1\n\0",
                    if fault == 4 { 3 } else { 5 },
                    [9; 32],
                )));
                assert!(native.read_exact(&mut response).is_err());
            }
            value(worker.join());
            assert!(!state.current_spent());
            assert!(!old.transferred());
            assert_eq!(calls.load(Ordering::Acquire), usize::from(fault != 2));
        }
    }
    #[test]
    fn final_retirement_is_distinct_from_committed_current_and_cannot_replay() {
        for fault in 0..5 {
            let (old, old_native, old_worker) = quiesced();
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let retained = old.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let spent = calls.clone();
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        identity,
                        |_| Ok(()),
                        || retained.transfer(),
                        |digest| if digest == &[8; 32] {
                            Ok(())
                        } else {
                            Err(unavailable())
                        },
                        |digest| if digest == &[9; 32] {
                            Ok(())
                        } else {
                            Err(unavailable())
                        },
                        |digest| {
                            spent.fetch_add(1, Ordering::AcqRel);
                            if fault == 1 || digest != &[10; 32] {
                                Err(unavailable())
                            } else {
                                Ok(())
                            }
                        },
                        |_| Err(unavailable()),
                    )
                    .is_err()
                );
            });
            let mut response = [0; FRAME_BYTES];
            for (purpose, sequence, digest) in
                [(b"LNCH:1\n\0", 1, [7; 32]), (b"LNPR:1\n\0", 2, [8; 32])]
            {
                let request = frame(purpose, sequence, digest);
                value(native.write_all(&request));
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
            }
            drop(old_native);
            value(old_worker.join());
            if fault != 2 {
                let request = frame(b"LNCF:1\n\0", 3, [9; 32]);
                value(native.write_all(&request));
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
                assert!(state.current_spent());
                assert!(!state.retirement_spent()); // Committed-current ACK never retires the final fence.
            }
            let request = frame(
                b"LNCA:1\n\0",
                if matches!(fault, 2 | 4) { 3 } else { 4 },
                if fault == 3 { [11; 32] } else { [10; 32] },
            );
            value(native.write_all(&request));
            if fault != 0 {
                assert!(native.read_exact(&mut response).is_err());
            } else {
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
                assert!(state.retirement_spent() && state.current_spent() && state.power_spent());
                let probe = frame(b"LNCV:1\n\0", 5, [7; 32]);
                value(native.write_all(&probe));
                value(native.read_exact(&mut response));
                assert_eq!(response, probe);
                value(native.write_all(&frame(b"LNCA:1\n\0", 6, [10; 32])));
                assert!(native.read_exact(&mut response).is_err());
            }
            value(worker.join());
            assert_eq!(
                calls.load(Ordering::Acquire),
                usize::from(!matches!(fault, 2 | 4))
            );
            assert!(!state.retirement_spent() && !old.transferred());
        }
    }
    #[test]
    fn successor_requires_final_retirement_exact_grant_and_one_spend_even_after_lost_ack() {
        for fault in 0..7 {
            let (old, old_native, old_worker) = quiesced();
            let (mut root, mut native) = pair();
            let state = ChannelState::reserved();
            let lifetime = Lifetime::new(state.clone());
            let retained = old.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let spent = calls.clone();
            let worker = std::thread::spawn(move || {
                assert!(
                    serve(
                        &mut root,
                        &[7; 32],
                        lifetime,
                        identity,
                        |_| Ok(()),
                        || retained.transfer(),
                        |digest| if digest == &[8; 32] {
                            Ok(())
                        } else {
                            Err(unavailable())
                        },
                        |digest| if digest == &[9; 32] {
                            Ok(())
                        } else {
                            Err(unavailable())
                        },
                        |digest| if digest == &[10; 32] {
                            Ok(())
                        } else {
                            Err(unavailable())
                        },
                        |digest| {
                            spent.fetch_add(1, Ordering::AcqRel);
                            if fault == 3 || digest != &[11; 32] {
                                Err(unavailable())
                            } else {
                                Ok(())
                            }
                        }
                    )
                    .is_err()
                );
            });
            let mut response = [0; FRAME_BYTES];
            for (purpose, sequence, digest) in [
                (b"LNCH:1\n\0", 1, [7; 32]),
                (b"LNPR:1\n\0", 2, [8; 32]),
                (b"LNCF:1\n\0", 3, [9; 32]),
                (b"LNCA:1\n\0", 4, [10; 32]),
            ] {
                if fault == 1 && sequence == 4 {
                    break;
                }
                let request = frame(purpose, sequence, digest);
                value(native.write_all(&request));
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
            }
            drop(old_native);
            value(old_worker.join());
            let sequence = if fault == 1 {
                4
            } else if fault == 4 {
                0
            } else {
                5
            };
            let purpose = if fault == 5 {
                b"LNCH:1\n\0"
            } else {
                b"LNSA:1\n\0"
            };
            let request = frame(
                purpose,
                sequence,
                if fault == 2 { [12; 32] } else { [11; 32] },
            );
            value(native.write_all(&request));
            if fault == 0 {
                value(native.read_exact(&mut response));
                assert_eq!(response, request);
                assert!(state.successor_spent() && state.retirement_spent());
                let probe = frame(b"LNCV:1\n\0", 6, [7; 32]);
                value(native.write_all(&probe));
                value(native.read_exact(&mut response));
                assert_eq!(response, probe);
                value(native.write_all(&frame(b"LNSA:1\n\0", 7, [11; 32])));
                assert!(native.read_exact(&mut response).is_err());
                drop(native);
            } else if fault == 6 {
                drop(native); // The durable callback cannot be replayed after a missing ACK.
            } else {
                assert!(native.read_exact(&mut response).is_err());
                drop(native);
            }
            value(worker.join());
            assert_eq!(
                calls.load(Ordering::Acquire),
                usize::from(!matches!(fault, 1 | 4 | 5))
            );
            assert!(!state.transferred()); // Closure revokes liveness, never the spent history.
        }
    }
}
