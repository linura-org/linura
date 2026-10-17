//! Exact native transition identity. Identity is neither OS permission, policy
//! approval nor prepared execution authority. Adapters acquire the baseline;
//! Control must independently review/revalidate it before a managed handoff.

use std::fmt::{Display, Formatter};

use crate::{ResourceId, SessionLockId};

const PREFIX: &str = "session:transition:";
const PERMISSION_PREFIX: &str = "session:power-permission:";

/// Terminating actions are distinct even when a later boot can only establish
/// that the original boot ended. A reboot/power-off acknowledgement, an awake
/// snapshot or a changed lock generation never proves a suspend/resume cycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionTransition {
    Suspend { successful_cycles_before: u64 },
    Logout,
    Reboot,
    PowerOff,
}

impl SessionTransition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspend { .. } => "suspend",
            Self::Logout => "logout",
            Self::Reboot => "reboot",
            Self::PowerOff => "power-off",
        }
    }

    #[must_use]
    pub const fn successful_cycles_before(self) -> Option<u64> {
        match self {
            Self::Suspend {
                successful_cycles_before,
            } => Some(successful_cycles_before),
            Self::Logout | Self::Reboot | Self::PowerOff => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionTransitionId {
    lock: SessionLockId,
    transition: SessionTransition,
}

impl SessionTransitionId {
    pub fn new(
        lock: SessionLockId,
        transition: SessionTransition,
    ) -> Result<Self, SessionTransitionError> {
        if lock.epoch().uid() == 0 {
            return Err(SessionTransitionError::UnsupportedOwner);
        }
        if transition.successful_cycles_before() == Some(u64::MAX) {
            return Err(SessionTransitionError::ExhaustedSuspendGeneration);
        }
        Ok(Self { lock, transition })
    }

    pub fn from_resource(resource: &ResourceId) -> Result<Self, SessionTransitionError> {
        // Bound before splitting/allocating. No aliases, ambient current-session
        // handles, implicit action, or caller-selected fallback generations.
        if resource.as_str().len() > 256 {
            return Err(SessionTransitionError::InvalidResource);
        }
        let suffix = resource
            .as_str()
            .strip_prefix(PREFIX)
            .ok_or(SessionTransitionError::InvalidResource)?;
        let (action, rest) = suffix
            .split_once(':')
            .ok_or(SessionTransitionError::InvalidResource)?;
        let (baseline, lock_suffix) = rest
            .split_once(':')
            .ok_or(SessionTransitionError::InvalidResource)?;
        if baseline.is_empty()
            || baseline.len() > 20
            || (baseline.len() > 1 && baseline.starts_with('0'))
            || !baseline.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(SessionTransitionError::InvalidResource);
        }
        let baseline: u64 = baseline
            .parse()
            .map_err(|_| SessionTransitionError::InvalidResource)?;
        let transition = match (action, baseline) {
            ("suspend", successful_cycles_before) => SessionTransition::Suspend {
                successful_cycles_before,
            },
            ("logout", 0) => SessionTransition::Logout,
            ("reboot", 0) => SessionTransition::Reboot,
            ("power-off", 0) => SessionTransition::PowerOff,
            _ => return Err(SessionTransitionError::InvalidResource),
        };
        let lock_resource = ResourceId::new(format!("session:lock:{lock_suffix}"))
            .map_err(|_| SessionTransitionError::InvalidResource)?;
        let lock = SessionLockId::from_resource(&lock_resource)
            .map_err(|_| SessionTransitionError::InvalidResource)?;
        Self::new(lock, transition)
    }

    pub fn resource_id(&self) -> Result<ResourceId, SessionTransitionError> {
        let lock = self
            .lock
            .resource_id()
            .map_err(|_| SessionTransitionError::InvalidResource)?;
        let suffix = lock
            .as_str()
            .strip_prefix("session:lock:")
            .ok_or(SessionTransitionError::InvalidResource)?;
        let text = format!(
            "{PREFIX}{}:{}:{suffix}",
            self.transition.as_str(),
            self.transition.successful_cycles_before().unwrap_or(0)
        );
        if text.len() > 256 {
            return Err(SessionTransitionError::InvalidResource);
        }
        ResourceId::new(text).map_err(|_| SessionTransitionError::InvalidResource)
    }

    /// Permission is a distinct observed fact, not transition completion.
    /// Keep graph/current-evidence identity separate without losing any of
    /// the action, baseline, owner invocation or session-generation binding.
    pub fn permission_resource_id(&self) -> Result<ResourceId, SessionTransitionError> {
        let transition = self.resource_id()?;
        let suffix = transition
            .as_str()
            .strip_prefix(PREFIX)
            .ok_or(SessionTransitionError::InvalidResource)?;
        let text = format!("{PERMISSION_PREFIX}{suffix}");
        if text.len() > 256 || self.transition == SessionTransition::Logout {
            return Err(SessionTransitionError::InvalidResource);
        }
        ResourceId::new(text).map_err(|_| SessionTransitionError::InvalidResource)
    }

    pub fn from_permission_resource(resource: &ResourceId) -> Result<Self, SessionTransitionError> {
        if resource.as_str().len() > 256 {
            return Err(SessionTransitionError::InvalidResource);
        }
        let suffix = resource
            .as_str()
            .strip_prefix(PERMISSION_PREFIX)
            .ok_or(SessionTransitionError::InvalidResource)?;
        let target = Self::from_resource(
            &ResourceId::new(format!("{PREFIX}{suffix}"))
                .map_err(|_| SessionTransitionError::InvalidResource)?,
        )?;
        if target.permission_resource_id()? != *resource {
            return Err(SessionTransitionError::InvalidResource);
        }
        Ok(target)
    }

    #[must_use]
    pub const fn lock(&self) -> &SessionLockId {
        &self.lock
    }

    #[must_use]
    pub const fn transition(&self) -> SessionTransition {
        self.transition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTransitionError {
    UnsupportedOwner,
    ExhaustedSuspendGeneration,
    InvalidResource,
}

impl Display for SessionTransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedOwner => "root graphical session transitions are unsupported",
            Self::ExhaustedSuspendGeneration => "native suspend generation cannot advance",
            Self::InvalidResource => "session transition identity is not canonical",
        })
    }
}
impl std::error::Error for SessionTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootId, SecurityOwnerInvocationId, SessionEpoch};

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn lock() -> SessionLockId {
        id(SessionLockId::new(
            id(SessionEpoch::new(
                id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
                1000,
                "c2",
                42,
            )),
            id(SecurityOwnerInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            7,
        ))
    }
    #[test]
    fn every_action_and_suspend_baseline_has_a_distinct_exact_resource() {
        let mut resources = std::collections::BTreeSet::new();
        for transition in [
            SessionTransition::Suspend {
                successful_cycles_before: 0,
            },
            SessionTransition::Suspend {
                successful_cycles_before: 1,
            },
            SessionTransition::Logout,
            SessionTransition::Reboot,
            SessionTransition::PowerOff,
        ] {
            let transition = id(SessionTransitionId::new(lock(), transition));
            let resource = id(transition.resource_id());
            assert!(resources.insert(resource.clone()));
            assert_eq!(
                id(SessionTransitionId::from_resource(&resource)),
                transition
            );
            assert_eq!(transition.lock(), &lock());
        }
    }
    #[test]
    fn permission_facts_have_disjoint_exact_resources_and_no_logout_permission_alias() {
        for action in [
            SessionTransition::Suspend {
                successful_cycles_before: 10,
            },
            SessionTransition::Reboot,
            SessionTransition::PowerOff,
        ] {
            let target = id(SessionTransitionId::new(lock(), action));
            let transition = id(target.resource_id());
            let permission = id(target.permission_resource_id());
            assert_ne!(permission, transition);
            assert_eq!(
                id(SessionTransitionId::from_permission_resource(&permission)),
                target
            );
            assert!(SessionTransitionId::from_permission_resource(&transition).is_err());
            assert!(SessionTransitionId::from_resource(&permission).is_err());
            let aliased = id(ResourceId::new(
                permission.as_str().replace(":1000:", ":01000:"),
            ));
            assert!(SessionTransitionId::from_permission_resource(&aliased).is_err());
        }
        let logout = id(SessionTransitionId::new(lock(), SessionTransition::Logout));
        assert!(logout.permission_resource_id().is_err());
        let aliased = id(ResourceId::new(
            id(logout.resource_id())
                .as_str()
                .replace(PREFIX, PERMISSION_PREFIX),
        ));
        assert!(SessionTransitionId::from_permission_resource(&aliased).is_err());
    }

    #[test]
    fn unsupported_aliases_and_exhausted_native_generations_fail_closed() {
        let canonical =
            id(id(SessionTransitionId::new(lock(), SessionTransition::Reboot)).resource_id());
        for invalid in [
            canonical.as_str().replace("reboot:0:", "reboot:1:"),
            canonical.as_str().replace("reboot:0:", "reboot:00:"),
            canonical.as_str().replace("reboot:0:", "Reboot:0:"),
            canonical.as_str().replace("reboot:0:", "hibernate:0:"),
            canonical
                .as_str()
                .replace("reboot:0:", "suspend:18446744073709551616:"),
            canonical.as_str().replace(":1000:", ":01000:"),
            canonical.as_str().replace(":1000:", ":0:"),
            canonical.as_str().replace(":c2:", ":self:") + ":extra",
            "session:transition:reboot:0:current".into(),
        ] {
            assert!(SessionTransitionId::from_resource(&id(ResourceId::new(invalid))).is_err());
        }
        assert!(
            SessionTransitionId::new(
                lock(),
                SessionTransition::Suspend {
                    successful_cycles_before: u64::MAX
                }
            )
            .is_err()
        );
        assert!(SessionTransitionId::from_resource(&id(lock().resource_id())).is_err());
    }
    #[test]
    fn all_native_scope_components_remain_bound_through_the_transition() {
        let original = id(SessionTransitionId::new(
            lock(),
            SessionTransition::PowerOff,
        ));
        let resource = id(original.resource_id());
        for (from, to) in [
            ("abcd1234", "abcd1235"),
            (":1000:", ":1001:"),
            (":c2:", ":c3:"),
            (":42:", ":43:"),
            ("98765432", "98765433"),
            (":7", ":8"),
        ] {
            let changed = id(SessionTransitionId::from_resource(&id(ResourceId::new(
                resource.as_str().replace(from, to),
            ))));
            assert_ne!(changed, original);
        }
    }
}
