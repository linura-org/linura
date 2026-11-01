//! Retain live kernel witnesses and original recovery power blockers. Historical checkpoint files
//! cannot repopulate this map after restart. Control alone owns recovery policy,
//! phase transitions and eventual qualified retirement.
use std::collections::BTreeMap;
use std::sync::Mutex;

use linura_linux_session::{
    NativeDisplayKernelSubscription, NativeDisplayKernelWitness, NativeDisplayPowerFence,
    NativeDisplayRecoveryCheckpoint, NativeSessionChannel,
};
use linura_provider_sdk::ComponentDigest;

#[derive(Debug, Default)]
pub(super) struct Witnesses(Mutex<BTreeMap<String, Protection>>);
#[derive(Debug)]
struct Protection {
    kernel: NativeDisplayKernelWitness,
    power: NativeDisplayPowerFence,
}
impl Witnesses {
    pub(super) fn reserve(
        &self,
        record: &NativeDisplayRecoveryCheckpoint,
        subscription: NativeDisplayKernelSubscription,
        channel: &NativeSessionChannel,
    ) -> Result<(), String> {
        let mut witnesses = self
            .0
            .try_lock()
            .map_err(|_| "kernel witness busy or unavailable")?;
        let key = record.dispatch_digest().to_hex();
        if witnesses.len() >= 256 || witnesses.contains_key(&key) {
            return Err("original kernel witness cannot be replaced or redelivered".into());
        }
        let mut witness = Protection {
            kernel: subscription.bind(record.kernel_outputs())?,
            power: channel.retain_display_recovery_power_fence()?,
        };
        super::display_checkpoint::reserve(record)?;
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
    fn with_witness(
        &self,
        dispatch: &ComponentDigest,
        verify: impl FnOnce(&mut Protection) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut witnesses = self
            .0
            .try_lock()
            .map_err(|_| "kernel witness busy or unavailable")?;
        verify(
            witnesses
                .get_mut(&dispatch.to_hex())
                .ok_or("original kernel witness lost; no reacquisition or continuation")?,
        )
    }
}
impl Protection {
    fn verify(&mut self, channel: &NativeSessionChannel) -> Result<(), String> {
        self.kernel.verify()?;
        channel.verify_display_recovery_power_fence(&mut self.power)?;
        // Bus probes consume time while kernel changes can queue independently.
        self.kernel.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_or_unknown_attempt_never_reacquires_a_witness() {
        let witnesses = Witnesses::default();
        let digest = ComponentDigest::from_bytes([1; 32]);
        let forbidden =
            |_: &mut Protection| unreachable!("missing/contended witness must never be used");
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
