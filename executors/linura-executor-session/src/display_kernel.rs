//! Retain live kernel witnesses and original recovery power blockers. Historical checkpoint files
//! cannot repopulate this map after restart. Control alone owns recovery policy,
//! phase transitions and eventual qualified retirement.
use std::collections::BTreeMap;
use std::sync::Mutex;

use linura_linux_session::{
    NativeDisplayKernelSubscription, NativeDisplayKernelWitness, NativeDisplayPowerFence,
    NativeDisplayRecoveryCheckpoint, NativeDisplayRetiredPowerFence, NativeSessionChannel,
};
use linura_provider_sdk::ComponentDigest;
use sha2::{Digest, Sha256};

#[derive(Debug, Default)]
pub(super) struct Witnesses(Mutex<BTreeMap<String, Protection>>);
#[derive(Debug)]
struct Protection {
    valid: bool,
    dispatch: ComponentDigest,
    checkpoint_digest: ComponentDigest,
    kernel: NativeDisplayKernelWitness,
    power: PowerWitness,
}
#[derive(Debug)]
enum PowerWitness {
    Held(NativeDisplayPowerFence),
    Retired {
        preparation: ComponentDigest,
        original: NativeDisplayRetiredPowerFence,
    },
    Failed,
}
impl Witnesses {
    /// Ordinary startup must consider retained in-memory history even when a
    /// checkpoint disappeared. Invalid/lost witnesses remain unresolved too.
    pub(super) fn clear_for_startup(&self) -> Result<bool, String> {
        history_empty(&self.0)
    }
    pub(super) fn reserve_stored(
        &self,
        dispatch: &ComponentDigest,
        payload: &[u8],
        subscription: NativeDisplayKernelSubscription,
        channel: &NativeSessionChannel,
    ) -> Result<(), String> {
        let mut witnesses = self
            .0
            .try_lock()
            .map_err(|_| "kernel witness busy or unavailable")?;
        let key = dispatch.to_hex();
        if witnesses.len() >= 256 || witnesses.contains_key(&key) {
            return Err("original kernel witness cannot be replaced or redelivered".into());
        }
        let mut witness = Protection {
            valid: true,
            dispatch: *dispatch,
            checkpoint_digest: ComponentDigest::from_bytes(Sha256::digest(payload).into()),
            kernel: {
                let outputs = NativeDisplayRecoveryCheckpoint::reservation_kernel_outputs(
                    payload,
                    dispatch,
                    subscription.began_boot_ms(),
                )?;
                subscription.bind(&outputs)?
            },
            power: PowerWitness::Held(channel.retain_display_recovery_power_fence(*dispatch)?),
        };
        super::display_checkpoint::reserve_stored(dispatch, payload)?;
        // Retain even failed post-sync protection alongside its durable record.
        // Neither uncertainty nor a failed native call permits replacing it.
        let verified = witness.verify(channel);
        witnesses.insert(key, witness);
        verified
    }
    pub(super) fn verify(
        &self,
        dispatch: &ComponentDigest,
        channel: &NativeSessionChannel,
    ) -> Result<(), String> {
        self.with_witness(dispatch, |protection| protection.verify(channel))
    }
    /// Fresh observation of retained original protection. Exact historical
    /// bytes are returned only while the same live witnesses still verify;
    /// no restart, cache, digest or file can reconstruct those witnesses.
    pub(super) fn read_original(
        &self,
        dispatch: &ComponentDigest,
        channel: &NativeSessionChannel,
    ) -> Result<Vec<u8>, String> {
        self.with_witness(dispatch, |protection| {
            if !matches!(protection.power, PowerWitness::Held(_)) {
                return Err("original power is no longer in the held phase".into());
            }
            let result = (|| {
                protection.verify(channel)?;
                let payload = super::display_checkpoint::read_original(
                    dispatch,
                    &protection.checkpoint_digest,
                )?;
                protection.verify(channel)?;
                Ok(payload)
            })();
            if result.is_err() {
                protection.valid = false;
            }
            result
        })
    }
    /// Called under original Root admission only after the exact durable
    /// exclusive preparation. This retains checkpoint/kernel provenance.
    pub(super) fn retire_power(
        &self,
        dispatch: &ComponentDigest,
        preparation: ComponentDigest,
        channel: &NativeSessionChannel,
        require_current: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        self.with_witness(dispatch, |protection| {
            if preparation == ComponentDigest::from_bytes([0; 32]) {
                return Err("root power preparation missing".into());
            }
            protection.verify(channel)?;
            require_current()?; // both ORIGINAL effect clocks, after all I/O
            let PowerWitness::Held(original) =
                std::mem::replace(&mut protection.power, PowerWitness::Failed)
            else {
                return Err("root power already consumed".into());
            };
            protection.power = PowerWitness::Retired {
                preparation,
                original: original.retire(),
            };
            Ok(())
        })
    }
    pub(super) fn read_retired_original(
        &self,
        dispatch: &ComponentDigest,
        preparation: &ComponentDigest,
        channel: &NativeSessionChannel,
    ) -> Result<Vec<u8>, String> {
        self.with_witness(dispatch, |protection| {
            let result = (|| {
                protection.verify_retired(preparation, channel)?;
                let payload = super::display_checkpoint::read_original(
                    dispatch,
                    &protection.checkpoint_digest,
                )?;
                protection.verify_retired(preparation, channel)?;
                Ok(payload)
            })();
            if result.is_err() {
                protection.valid = false;
            }
            result
        })
    }
    pub(super) fn verify_retired_power_absent(
        &self,
        dispatch: &ComponentDigest,
        preparation: &ComponentDigest,
        channel: &NativeSessionChannel,
    ) -> Result<(), String> {
        self.with_witness(dispatch, |protection| {
            protection.verify_retired(preparation, channel)?;
            let PowerWitness::Retired { original, .. } = &protection.power else {
                return Err("original power not retired".into());
            };
            channel.verify_retired_display_recovery_power_fence(original)?;
            protection.verify_retired(preparation, channel)
        })
    }
    fn with_witness<T>(
        &self,
        dispatch: &ComponentDigest,
        verify: impl FnOnce(&mut Protection) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut witnesses =
            super::protection_lock::acquire(&self.0, super::protection_lock::BUDGET)?;
        verify(
            witnesses
                .get_mut(&dispatch.to_hex())
                .ok_or("original kernel witness lost; no reacquisition or continuation")?,
        )
    }
}
fn history_empty<T>(history: &Mutex<BTreeMap<String, T>>) -> Result<bool, String> {
    history
        .try_lock()
        .map(|entries| entries.is_empty())
        .map_err(|_| "original witness history busy or unavailable".into())
}

impl Protection {
    fn verify(&mut self, channel: &NativeSessionChannel) -> Result<(), String> {
        if !matches!(self.power, PowerWitness::Held(_)) {
            return Err("original power is no longer in the held phase".into());
        }
        let result = (|| {
            if !self.valid {
                return Err("original display protection was lost; no continuation".into());
            }
            super::display_checkpoint::validate(&self.dispatch, &self.checkpoint_digest)?;
            self.kernel.verify()?;
            let PowerWitness::Held(original) = &mut self.power else {
                return Err("original power unavailable".into());
            };
            channel.verify_display_recovery_power_fence(original)?;
            // Bus probes consume time while kernel changes can queue independently.
            self.kernel.verify()
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }
    fn verify_retired(
        &mut self,
        preparation: &ComponentDigest,
        channel: &NativeSessionChannel,
    ) -> Result<(), String> {
        let PowerWitness::Retired {
            preparation: expected,
            ..
        } = &self.power
        else {
            return Err("root power retirement unavailable".into());
        };
        if preparation != expected {
            return Err("root power retirement has another preparation".into());
        }
        let result = (|| {
            if !self.valid {
                return Err("original kernel witness lost".into());
            }
            super::display_checkpoint::validate(&self.dispatch, &self.checkpoint_digest)?;
            self.kernel.verify()?;
            let PowerWitness::Retired { original, .. } = &self.power else {
                return Err("root power retirement unavailable".into());
            };
            channel.verify_retired_display_power_lifetime(original)?;
            self.kernel.verify()
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_cannot_ignore_retained_invalid_busy_or_poisoned_witness_history() {
        // Comparison-only history contents; constructing kernel witnesses is
        // deliberately unavailable to this unit fixture.
        let history = Mutex::new(BTreeMap::<String, bool>::new());
        assert_eq!(history_empty(&history), Ok(true));
        for valid in [true, false] {
            history
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .insert("retained-original".into(), valid);
            assert_eq!(history_empty(&history), Ok(false));
        }
        {
            let _guard = history.lock().unwrap_or_else(|_| unreachable!());
            assert!(history_empty(&history).is_err());
        }
        let result = std::panic::catch_unwind(|| {
            let _guard = history.lock().unwrap_or_else(|_| unreachable!());
            std::panic::resume_unwind(Box::new(()));
        });
        assert!(result.is_err());
        assert!(history_empty(&history).is_err());
        assert_eq!(Witnesses::default().clear_for_startup(), Ok(true));
    }

    #[test]
    fn restart_or_unknown_attempt_never_reacquires_a_witness() {
        let witnesses = Witnesses::default();
        let digest = ComponentDigest::from_bytes([1; 32]);
        let forbidden = |_: &mut Protection| -> Result<(), String> {
            unreachable!("missing/contended witness must never be used")
        };
        assert!(witnesses.with_witness(&digest, forbidden).is_err());
        let _lock = witnesses.0.lock().unwrap_or_else(|_| unreachable!());
        assert!(witnesses.with_witness(&digest, forbidden).is_err());
        assert!(
            Witnesses::default()
                .with_witness(&digest, forbidden)
                .is_err()
        );
    }
}
