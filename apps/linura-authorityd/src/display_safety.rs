//! Control schedules original display compensation before S17 interactions.
//! This readiness cannot authorize lock, power, unlock or another display write.
use linura_core::SessionLockId;
use linura_linux_session::{NativeDisplaySafetyRequest, NativeSessionChannel};
use std::thread;
use std::time::Duration;

pub(crate) fn prepare(channel: &NativeSessionChannel, lock: &SessionLockId) -> Result<(), String> {
    let request = NativeDisplaySafetyRequest::new(lock.clone())?;
    complete(
        &mut || channel.retire_display_for_security(&request),
        &|| request.remaining(),
        &thread::sleep,
    )
}
fn complete(
    probe: &mut impl FnMut() -> Result<bool, String>,
    remaining: &impl Fn() -> Result<Duration, String>,
    wait: &impl Fn(Duration),
) -> Result<(), String> {
    loop {
        remaining()?;
        let ready = probe()?;
        remaining()?; // A late true reply cannot permit the next S17 stage.
        if ready {
            return Ok(());
        }
        wait(Duration::from_millis(25).min(remaining()?));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn only_fresh_native_readiness_completes_and_queries_never_dispatch() {
        let calls = Cell::new(0);
        let waits = Cell::new(0);
        let mut probe = || {
            calls.set(calls.get() + 1);
            Ok(calls.get() == 3)
        };
        assert!(
            complete(
                &mut probe,
                &|| Ok(Duration::from_millis(100)),
                &|duration| {
                    assert_eq!(duration, Duration::from_millis(25));
                    waits.set(waits.get() + 1);
                }
            )
            .is_ok()
        );
        assert_eq!(calls.get(), 3);
        assert_eq!(waits.get(), 2);
    }
    #[test]
    fn expiry_unknown_and_late_readiness_never_continue() {
        for mode in 0..3 {
            let expired = Cell::new(mode == 0);
            let calls = Cell::new(0);
            let mut probe = || {
                calls.set(calls.get() + 1);
                if mode == 1 {
                    Err("owner unavailable".into())
                } else {
                    expired.set(true);
                    Ok(true)
                }
            };
            assert!(
                complete(
                    &mut probe,
                    &|| if expired.get() {
                        Err("original budget expired".into())
                    } else {
                        Ok(Duration::from_millis(100))
                    },
                    &|_| unreachable!()
                )
                .is_err()
            );
            assert_eq!(calls.get(), u32::from(mode != 0));
        }
    }
}
