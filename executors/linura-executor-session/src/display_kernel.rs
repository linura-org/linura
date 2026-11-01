//! Retain only live read-only mechanism witnesses. Historical checkpoint files
//! cannot repopulate this map after restart. Control alone owns recovery policy,
//! phase transitions and eventual qualified retirement.
use std::collections::BTreeMap;
use std::sync::Mutex;

use linura_linux_session::{
    NativeDisplayKernelSubscription, NativeDisplayKernelWitness, NativeDisplayRecoveryCheckpoint,
};
use linura_provider_sdk::ComponentDigest;

#[derive(Debug, Default)]
pub(super) struct Witnesses(Mutex<BTreeMap<String, NativeDisplayKernelWitness>>);
impl Witnesses {
    pub(super) fn reserve(
        &self,
        record: &NativeDisplayRecoveryCheckpoint,
        subscription: NativeDisplayKernelSubscription,
    ) -> Result<(), String> {
        let mut witnesses = self
            .0
            .try_lock()
            .map_err(|_| "kernel witness busy or unavailable")?;
        let key = record.dispatch_digest().to_hex();
        if witnesses.len() >= 256 || witnesses.contains_key(&key) {
            return Err("original kernel witness cannot be replaced or redelivered".into());
        }
        let mut witness = subscription.bind(record.kernel_outputs())?;
        super::display_checkpoint::reserve(record)?;
        // Retain even a failed post-sync witness alongside its durable record.
        // Neither uncertainty nor a failed native call permits replacing it.
        let verified = witness.verify();
        witnesses.insert(key, witness);
        verified
    }
    pub(super) fn verify(&self, dispatch: &ComponentDigest) -> Result<(), String> {
        self.0
            .try_lock()
            .map_err(|_| "kernel witness busy or unavailable")?
            .get_mut(&dispatch.to_hex())
            .ok_or("original kernel witness lost; no reacquisition or continuation")?
            .verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_or_unknown_attempt_never_reacquires_a_witness() {
        let witnesses = Witnesses::default();
        let digest = ComponentDigest::from_bytes([1; 32]);
        assert!(witnesses.verify(&digest).is_err());
        let _lock = witnesses.0.lock().unwrap_or_else(|_| unreachable!());
        assert!(witnesses.verify(&digest).is_err());
        assert!(Witnesses::default().verify(&digest).is_err());
    }
}
