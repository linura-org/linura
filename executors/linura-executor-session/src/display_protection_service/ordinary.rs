//! Same-invocation ordinary preparation; no physical effect or release grant.
use super::*;

fn check_clocks(
    last: &mut (u64, u64),
    deadline: (u64, u64),
    now: (u64, u64),
) -> zbus::fdo::Result<()> {
    if now.0 < last.0 || now.1 < last.1 || now.0 >= deadline.0 || now.1 >= deadline.1 {
        return Err(unavailable());
    }
    *last = now;
    Ok(())
}

impl NativeProtection {
    pub(super) fn reserve_ordinary_release_mechanism(
        &self,
        sender: &str,
        record: NativeDisplayOrdinaryReleasePreparation,
    ) -> zbus::fdo::Result<bool> {
        self.admit_control(sender)?;
        let window = record.window();
        let mut last_clock = (window.observed_unix_ms, window.observed_boot_ms);
        let mut check_clock = || {
            check_clocks(
                &mut last_clock,
                (window.deadline_unix_ms, window.deadline_boot_ms),
                (unix_ms()?, boot_ms()?),
            )
        };
        check_clock()?;
        let material = record.decoded_material().map_err(|_| unavailable())?;
        let scope = material.release_scope().map_err(|_| unavailable())?;
        let key = scope.resource_id().map_err(|_| unavailable())?;
        let mut admission = super::super::protection_lock::acquire(
            &self.admission,
            super::super::protection_lock::BUDGET,
        )
        .map_err(|_| unavailable())?;
        let payload = self.ordinary_original_for_scope(&admission, &scope)?;
        record
            .validate_original(&payload)
            .map_err(|_| unavailable())?;
        self.admit_control(sender)?;
        check_clock()?;
        if admission.ordinary_releases.len() >= MAX_PENDING
            || admission.ordinary_releases.contains_key(key.as_str())
        {
            return Err(unavailable());
        }
        // Irreversibly claim this live invocation before any fallible durable
        // write. Missing files, readback loss or a replacement Control do not
        // recreate the original preparation or physical release authority.
        admission
            .ordinary_releases
            .insert(key.as_str().into(), (record.record_digest(), sender.into()));
        super::super::display_checkpoint::reserve_ordinary_release(&record)
            .map_err(|_| unavailable())?;
        if super::super::display_checkpoint::read_ordinary_release(&record)
            .map_err(|_| unavailable())?
            != record.canonical_bytes()
            || self.ordinary_original_for_scope(&admission, &scope)? != payload
        {
            return Err(unavailable());
        }
        self.admit_control(sender)?;
        check_clock()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_clocks_cannot_expire_or_rewind_after_an_intermediate_check() {
        let mut last = (1000, 100);
        assert!(check_clocks(&mut last, (3000, 2100), (2500, 1600)).is_ok());
        for now in [(2499, 1600), (2500, 1599), (3000, 1600), (2500, 2100)] {
            let mut previous = last;
            assert!(check_clocks(&mut previous, (3000, 2100), now).is_err());
            assert_eq!(previous, last);
        }
        assert!(check_clocks(&mut last, (3000, 2100), (2999, 2099)).is_ok());
        assert!(check_clocks(&mut last, (3000, 2100), (3000, 2100)).is_err());
    }
}
