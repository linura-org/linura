//! Fixed bounded access to retained original protection. Waiting for an
//! existing observation never reacquires a witness or renews an authorization.
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

pub(super) const BUDGET: Duration = Duration::from_secs(2);
pub(super) fn acquire<T>(
    retained: &Mutex<T>,
    budget: Duration,
) -> Result<MutexGuard<'_, T>, &'static str> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or("protection clock unavailable")?;
    loop {
        if Instant::now() >= deadline {
            return Err("original protection access timed out");
        }
        match retained.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err("original protection is unavailable"),
            Err(TryLockError::WouldBlock) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|value| !value.is_zero())
                    .ok_or("original protection access timed out")?;
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn contention_waits_for_the_same_fresh_object_without_resetting_the_budget() {
        let retained = Arc::new(Mutex::new(1));
        let guard = retained.lock().unwrap_or_else(|_| unreachable!());
        let probe = retained.clone();
        let worker = std::thread::spawn(move || {
            let mut value =
                acquire(&probe, Duration::from_secs(1)).unwrap_or_else(|_| unreachable!());
            assert_eq!(*value, 2);
            *value = 3;
        });
        // A same-thread conflicting access must be bounded, never deadlock.
        assert!(acquire(&retained, Duration::from_millis(5)).is_err());
        let mut guard = guard;
        *guard = 2;
        drop(guard);
        worker.join().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            *acquire(&retained, Duration::from_secs(1)).unwrap_or_else(|_| unreachable!()),
            3
        );
        assert!(acquire(&retained, Duration::ZERO).is_err());
    }
}
