//! Identity of one native pre-sleep invocation, not a sleep/lock credential.
//! The native adapter must attest the invocation; accepting this identifier from
//! a caller does not authenticate an event or establish its physical cause.

use std::fmt::{Display, Formatter};

use crate::{BootId, RequestId, ResourceId, SessionEpoch};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SleepInvocationId {
    boot: BootId,
    invocation: String,
}

impl SleepInvocationId {
    pub fn new(boot: BootId, invocation: impl Into<String>) -> Result<Self, SleepInvocationError> {
        let invocation = invocation.into();
        if !crate::session_epoch::canonical_nonzero_uuid(&invocation) {
            return Err(SleepInvocationError);
        }
        Ok(Self { boot, invocation })
    }

    #[must_use]
    pub const fn boot(&self) -> &BootId {
        &self.boot
    }

    #[must_use]
    pub fn invocation(&self) -> &str {
        &self.invocation
    }

    pub fn resource_id(&self) -> Result<ResourceId, SleepInvocationError> {
        ResourceId::new(format!(
            "session:sleep-entry:{}:{}",
            self.boot.as_str(),
            self.invocation
        ))
        .map_err(|_| SleepInvocationError)
    }

    pub fn from_protective_request_id(
        request: &RequestId,
        epoch: &SessionEpoch,
    ) -> Result<Self, SleepInvocationError> {
        let suffix = request
            .as_str()
            .strip_prefix("request:v010:protective-lock:")
            .ok_or(SleepInvocationError)?;
        let mut fields = suffix.split(':');
        let boot = BootId::new(fields.next().ok_or(SleepInvocationError)?)
            .map_err(|_| SleepInvocationError)?;
        let event = Self::new(boot, fields.next().ok_or(SleepInvocationError)?)?;
        if event.protective_request_id(epoch)? != *request {
            return Err(SleepInvocationError);
        }
        Ok(event)
    }

    /// One stable protective-lock request per native invocation and login epoch.
    /// Owner restart or a retry must not allocate fresh dispatch authority.
    pub fn protective_request_id(
        &self,
        epoch: &SessionEpoch,
    ) -> Result<RequestId, SleepInvocationError> {
        if self.boot != *epoch.boot() || epoch.uid() == 0 {
            return Err(SleepInvocationError);
        }
        RequestId::new(format!(
            "request:v010:protective-lock:{}:{}:{}:{}:{}",
            self.boot.as_str(),
            self.invocation,
            epoch.uid(),
            epoch.session_id(),
            epoch.created_monotonic_us(),
        ))
        .map_err(|_| SleepInvocationError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SleepInvocationError;

impl Display for SleepInvocationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native sleep invocation or session scope is not canonical")
    }
}

impl std::error::Error for SleepInvocationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    #[test]
    fn invocation_rejects_nil_aliases_and_substitution() {
        let boot = id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab"));
        for value in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "98765432-1234-4567-89AB-0123456789ab",
            "987654321234456789ab0123456789ab",
        ] {
            assert!(SleepInvocationId::new(boot.clone(), value).is_err());
        }
        let event = id(SleepInvocationId::new(
            boot.clone(),
            "98765432-1234-4567-89ab-0123456789ab",
        ));
        let epoch = id(SessionEpoch::new(boot.clone(), 1000, "c2", 42));
        let request = id(event.protective_request_id(&epoch));
        assert_eq!(
            id(SleepInvocationId::from_protective_request_id(
                &request, &epoch
            )),
            event
        );
        for bad in [
            request.as_str().replace(":1000:", ":01000:"),
            format!("{}:extra", request.as_str()),
            request.as_str().replace("protective-lock", "session-lock"),
        ] {
            assert!(
                SleepInvocationId::from_protective_request_id(&id(RequestId::new(bad)), &epoch)
                    .is_err()
            );
        }
        assert_eq!(request, id(event.protective_request_id(&epoch)));
        assert_ne!(
            request,
            id(event.protective_request_id(&id(SessionEpoch::new(boot.clone(), 1000, "c2", 43))))
        );
        assert_ne!(
            request,
            id(event.protective_request_id(&id(SessionEpoch::new(boot.clone(), 1001, "c2", 42))))
        );
        assert!(
            event
                .protective_request_id(&id(SessionEpoch::new(boot, 0, "c2", 42)))
                .is_err()
        );
        let other_boot = id(BootId::new("abcd1234-1234-4567-89ab-0123456789ac"));
        assert!(
            event
                .protective_request_id(&id(SessionEpoch::new(other_boot, 1000, "c2", 42)))
                .is_err()
        );
    }
}
