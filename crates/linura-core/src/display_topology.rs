//! S21 display identity and bounded output candidates. Neither native
//! observation, Control policy, approval nor mutation authority is conveyed.
//!
//! Native adapters must independently attest the logind session, seat,
//! compositor invocation and complete output set. Connector names, EDID,
//! Wayland handles and client-provided UUIDs are never execution credentials.

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use crate::session_epoch::canonical_nonzero_uuid;
use crate::{ResourceId, SessionEpoch};

const RESOURCE_PREFIX: &str = "display:topology:";
const SESSION_PREFIX: &str = "session:epoch:";
const MAX_SEAT_BYTES: usize = 32;
const MAX_OUTPUTS: usize = 16;

/// A compositor instance, not the native security-owner process. An adapter
/// must attest the invocation separately from client-provided correlation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompositorInvocationId(String);

impl CompositorInvocationId {
    pub fn new(value: impl Into<String>) -> Result<Self, DisplayIdentityError> {
        let value = value.into();
        if !canonical_nonzero_uuid(&value) {
            return Err(DisplayIdentityError::InvalidCompositorInvocation);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete context needed to identify an observed output topology. The
/// topology generation changes on hotplug, compositor replacement and every
/// materially different output inventory; identities are not authorization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayTopologyId {
    session: SessionEpoch,
    seat: String,
    compositor: CompositorInvocationId,
    generation: u64,
}

impl DisplayTopologyId {
    pub fn new(
        session: SessionEpoch,
        seat: impl Into<String>,
        compositor: CompositorInvocationId,
        generation: u64,
    ) -> Result<Self, DisplayIdentityError> {
        let seat = seat.into();
        if session.uid() == 0 {
            return Err(DisplayIdentityError::RootGraphicalSession);
        }
        if seat.is_empty()
            || seat.len() > MAX_SEAT_BYTES
            || matches!(seat.as_str(), "self" | "auto" | "current")
            || !seat
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(DisplayIdentityError::InvalidSeat);
        }
        if generation == 0 || generation == u64::MAX {
            return Err(DisplayIdentityError::InvalidTopologyGeneration);
        }
        Ok(Self {
            session,
            seat,
            compositor,
            generation,
        })
    }

    pub fn from_resource(resource: &ResourceId) -> Result<Self, DisplayIdentityError> {
        if resource.as_str().len() > 256 {
            return Err(DisplayIdentityError::InvalidResource);
        }
        let suffix = resource
            .as_str()
            .strip_prefix(RESOURCE_PREFIX)
            .ok_or(DisplayIdentityError::InvalidResource)?;
        let parts: Vec<_> = suffix.split(':').collect();
        let [boot, uid, session, created, seat, invocation, generation] = parts.as_slice() else {
            return Err(DisplayIdentityError::InvalidResource);
        };
        let epoch = ResourceId::new(format!("{SESSION_PREFIX}{boot}:{uid}:{session}:{created}"))
            .map_err(|_| DisplayIdentityError::InvalidResource)?;
        let session = SessionEpoch::from_resource(&epoch)
            .map_err(|_| DisplayIdentityError::InvalidResource)?;
        let id = Self::new(
            session,
            *seat,
            CompositorInvocationId::new(*invocation)?,
            canonical_generation(generation)?,
        )?;
        if id.resource_id()? != *resource {
            return Err(DisplayIdentityError::InvalidResource);
        }
        Ok(id)
    }

    pub fn resource_id(&self) -> Result<ResourceId, DisplayIdentityError> {
        let epoch = self
            .session
            .resource_id()
            .map_err(|_| DisplayIdentityError::InvalidResource)?;
        let suffix = epoch
            .as_str()
            .strip_prefix(SESSION_PREFIX)
            .ok_or(DisplayIdentityError::InvalidResource)?;
        ResourceId::new(format!(
            "{RESOURCE_PREFIX}{suffix}:{}:{}:{}",
            self.seat,
            self.compositor.as_str(),
            self.generation
        ))
        .map_err(|_| DisplayIdentityError::InvalidResource)
    }

    #[must_use]
    pub const fn session(&self) -> &SessionEpoch {
        &self.session
    }

    #[must_use]
    pub fn seat(&self) -> &str {
        &self.seat
    }

    #[must_use]
    pub const fn compositor(&self) -> &CompositorInvocationId {
        &self.compositor
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// A scoped candidate output handle plus its native observation generation.
/// Recycled connector names or numeric handles cannot match an older scope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayOutputId {
    topology: DisplayTopologyId,
    handle: u64,
    generation: u64,
}

impl DisplayOutputId {
    pub fn new(
        topology: DisplayTopologyId,
        handle: u64,
        generation: u64,
    ) -> Result<Self, DisplayIdentityError> {
        // A native monitor identifier may be zero; it is correlation only.
        if generation == 0 || generation == u64::MAX {
            return Err(DisplayIdentityError::InvalidOutputGeneration);
        }
        Ok(Self {
            topology,
            handle,
            generation,
        })
    }

    #[must_use]
    pub const fn topology(&self) -> &DisplayTopologyId {
        &self.topology
    }

    #[must_use]
    pub const fn handle(&self) -> u64 {
        self.handle
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// A bounded, internally consistent observation candidate. Only a trusted
/// native observer may assert completeness and validity for the actual
/// compositor; this constructor cannot establish output security coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayOutputSet {
    topology: DisplayTopologyId,
    outputs: Vec<DisplayOutputId>,
}

impl DisplayOutputSet {
    pub fn new(
        topology: DisplayTopologyId,
        outputs: Vec<DisplayOutputId>,
    ) -> Result<Self, DisplayIdentityError> {
        if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
            return Err(DisplayIdentityError::InvalidOutputCount);
        }
        let mut handles = BTreeSet::new();
        for output in &outputs {
            if output.topology() != &topology {
                return Err(DisplayIdentityError::MixedTopology);
            }
            if !handles.insert(output.handle()) {
                return Err(DisplayIdentityError::AmbiguousOutput);
            }
        }
        Ok(Self { topology, outputs })
    }

    #[must_use]
    pub const fn topology(&self) -> &DisplayTopologyId {
        &self.topology
    }

    #[must_use]
    pub fn outputs(&self) -> &[DisplayOutputId] {
        &self.outputs
    }
}

fn canonical_generation(value: &str) -> Result<u64, DisplayIdentityError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DisplayIdentityError::InvalidResource);
    }
    value
        .parse()
        .map_err(|_| DisplayIdentityError::InvalidResource)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayIdentityError {
    InvalidCompositorInvocation,
    RootGraphicalSession,
    InvalidSeat,
    InvalidTopologyGeneration,
    InvalidOutputGeneration,
    InvalidOutputCount,
    MixedTopology,
    AmbiguousOutput,
    InvalidResource,
}

impl Display for DisplayIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCompositorInvocation => "compositor invocation is not a canonical UUID",
            Self::RootGraphicalSession => "root graphical sessions are not supported",
            Self::InvalidSeat => "display seat is not a canonical native seat identifier",
            Self::InvalidTopologyGeneration => "display topology generation cannot advance",
            Self::InvalidOutputGeneration => "display output handle or generation is invalid",
            Self::InvalidOutputCount => "display output candidate count is unsupported",
            Self::MixedTopology => "display output candidates mix topology generations",
            Self::AmbiguousOutput => "display output candidates reuse a native handle",
            Self::InvalidResource => "display topology resource identity is not canonical",
        })
    }
}

impl std::error::Error for DisplayIdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BootId;

    const BOOT: &str = "abcd1234-1234-4567-89ab-0123456789ab";
    const COMPOSITOR: &str = "98765432-1234-4567-89ab-0123456789ab";

    fn id<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn session() -> SessionEpoch {
        id(SessionEpoch::new(id(BootId::new(BOOT)), 1000, "c2", 42))
    }

    fn topology() -> DisplayTopologyId {
        id(DisplayTopologyId::new(
            session(),
            "seat0",
            id(CompositorInvocationId::new(COMPOSITOR)),
            7,
        ))
    }

    #[test]
    fn exact_topology_round_trips_without_ambient_aliases() {
        let topology = topology();
        let resource = id(topology.resource_id());
        assert_eq!(
            resource.as_str(),
            format!("display:topology:{BOOT}:1000:c2:42:seat0:{COMPOSITOR}:7")
        );
        assert_eq!(id(DisplayTopologyId::from_resource(&resource)), topology);
        assert_eq!(topology.session(), &session());
        assert_eq!(topology.seat(), "seat0");
        assert_eq!(topology.compositor().as_str(), COMPOSITOR);
        assert_eq!(topology.generation(), 7);
    }

    #[test]
    fn every_native_scope_and_generation_changes_identity() {
        let original = topology();
        for changed in [
            id(DisplayTopologyId::new(
                id(SessionEpoch::new(id(BootId::new(BOOT)), 1001, "c2", 42)),
                "seat0",
                id(CompositorInvocationId::new(COMPOSITOR)),
                7,
            )),
            id(DisplayTopologyId::new(
                session(),
                "seat1",
                id(CompositorInvocationId::new(COMPOSITOR)),
                7,
            )),
            id(DisplayTopologyId::new(
                session(),
                "seat0",
                id(CompositorInvocationId::new(
                    "98765432-1234-4567-89ab-0123456789ac",
                )),
                7,
            )),
            id(DisplayTopologyId::new(
                session(),
                "seat0",
                id(CompositorInvocationId::new(COMPOSITOR)),
                8,
            )),
        ] {
            assert_ne!(original, changed);
            assert_ne!(id(original.resource_id()), id(changed.resource_id()));
        }
    }

    #[test]
    fn refuses_root_ambient_or_unbound_native_identity() {
        for seat in ["", "self", "auto", "current", "../seat0", "seat:0", "é"] {
            assert!(
                DisplayTopologyId::new(
                    session(),
                    seat,
                    id(CompositorInvocationId::new(COMPOSITOR)),
                    7,
                )
                .is_err()
            );
        }
        assert!(
            DisplayTopologyId::new(
                session(),
                "a".repeat(33),
                id(CompositorInvocationId::new(COMPOSITOR)),
                7,
            )
            .is_err()
        );
        for invalid in ["", "00000000-0000-0000-0000-000000000000", "INVALID"] {
            assert!(CompositorInvocationId::new(invalid).is_err());
        }
        for generation in [0, u64::MAX] {
            assert!(
                DisplayTopologyId::new(
                    session(),
                    "seat0",
                    id(CompositorInvocationId::new(COMPOSITOR)),
                    generation,
                )
                .is_err()
            );
        }
        assert!(
            DisplayTopologyId::new(
                id(SessionEpoch::new(id(BootId::new(BOOT)), 0, "c2", 42)),
                "seat0",
                id(CompositorInvocationId::new(COMPOSITOR)),
                7,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_resource_replay_aliases_and_noncanonical_generations() {
        let valid = id(topology().resource_id());
        for suffix in [":extra", ":0", ":07", " "] {
            let candidate = id(ResourceId::new(format!("{}{suffix}", valid.as_str())));
            assert!(DisplayTopologyId::from_resource(&candidate).is_err());
        }
        assert!(ResourceId::new(format!("{}\n", valid.as_str())).is_err());
        for bad in [
            format!("display:topology:{BOOT}:01000:c2:42:seat0:{COMPOSITOR}:7"),
            format!("display:topology:{BOOT}:1000:c2:042:seat0:{COMPOSITOR}:7"),
            format!("display:topology:{BOOT}:1000:c2:42:seat0:{COMPOSITOR}:07"),
            format!("display:topology:{BOOT}:1000:c2:42:seat0:{COMPOSITOR}:18446744073709551616"),
            format!("display:topology:{BOOT}:1000:c2:42:self:{COMPOSITOR}:7"),
            format!("display:topology:{BOOT}:1000:c2:42:seat0:{COMPOSITOR}:0"),
        ] {
            let candidate = id(ResourceId::new(bad));
            assert!(DisplayTopologyId::from_resource(&candidate).is_err());
        }
        assert!(DisplayTopologyId::from_resource(&id(ResourceId::new("display:current"))).is_err());
    }

    #[test]
    fn output_identity_rejects_reused_handles_and_stale_topology() {
        let original = topology();
        let first = id(DisplayOutputId::new(original.clone(), 12, 1));
        let next_generation = id(DisplayOutputId::new(original.clone(), 12, 2));
        assert_ne!(first, next_generation);
        assert_eq!(first.handle(), 12);
        assert_eq!(first.generation(), 1);
        assert_eq!(first.topology(), &original);
        let stale = id(DisplayOutputId::new(
            id(DisplayTopologyId::new(
                session(),
                "seat0",
                id(CompositorInvocationId::new(COMPOSITOR)),
                8,
            )),
            14,
            1,
        ));
        assert_eq!(
            DisplayOutputSet::new(original.clone(), vec![first.clone(), stale]),
            Err(DisplayIdentityError::MixedTopology)
        );
        assert_eq!(
            DisplayOutputSet::new(original.clone(), vec![first, next_generation]),
            Err(DisplayIdentityError::AmbiguousOutput)
        );
        assert!(DisplayOutputId::new(original.clone(), 0, 1).is_ok());
        for (handle, generation) in [(0, 0), (1, 0), (1, u64::MAX)] {
            assert!(DisplayOutputId::new(original.clone(), handle, generation).is_err());
        }
    }

    #[test]
    fn bounded_output_candidate_set_cannot_alias_a_displaced_output() {
        let topology = topology();
        let one = id(DisplayOutputId::new(topology.clone(), 1, 10));
        let two = id(DisplayOutputId::new(topology.clone(), 2, 11));
        let set = id(DisplayOutputSet::new(
            topology.clone(),
            vec![one.clone(), two],
        ));
        assert_eq!(set.outputs().len(), 2);
        assert_eq!(set.topology(), &topology);
        assert_eq!(
            DisplayOutputSet::new(topology.clone(), vec![]),
            Err(DisplayIdentityError::InvalidOutputCount)
        );
        assert_eq!(
            DisplayOutputSet::new(topology.clone(), vec![one.clone(); 17]),
            Err(DisplayIdentityError::InvalidOutputCount)
        );
        assert_eq!(
            DisplayOutputSet::new(topology, vec![one.clone(), one]),
            Err(DisplayIdentityError::AmbiguousOutput)
        );
    }
}
