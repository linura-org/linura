//! S21-4: strict storage effect contract, never a native execution permit.
//!
//! The existing Control registry intentionally does not register storage.
//! The generation digest must eventually be derived from trusted physical
//! media, source owner, original session, namespace and operation scope.
//! A well-formed resource is *not* proof of that attestation or authorization.

use linura_core::{ProviderId, ResourceId, RiskClass};
use linura_provider_sdk::EffectDescriptor;

use crate::operation_registry::{STORAGE_CANDIDATE_ROUTES, STORAGE_PROVIDER};

pub const STORAGE_GENERATION_DIGEST_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    Mount,
    Unmount,
    Eject,
    PowerOff,
}

impl StorageOperation {
    pub const ALL: [Self; 4] = [Self::Mount, Self::Unmount, Self::Eject, Self::PowerOff];

    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Mount => 0,
            Self::Unmount => 1,
            Self::Eject => 2,
            Self::PowerOff => 3,
        }
    }

    #[must_use]
    pub const fn operation_id(self) -> &'static str {
        STORAGE_CANDIDATE_ROUTES[self.index()].0
    }

    #[must_use]
    pub const fn resource_prefix(self) -> &'static str {
        STORAGE_CANDIDATE_ROUTES[self.index()].1
    }

    #[must_use]
    pub const fn change_key(self) -> &'static str {
        STORAGE_CANDIDATE_ROUTES[self.index()].2
    }

    #[must_use]
    pub const fn desired_value(self) -> &'static str {
        STORAGE_CANDIDATE_ROUTES[self.index()].3
    }

    #[must_use]
    pub const fn risk_floor(self) -> RiskClass {
        STORAGE_CANDIDATE_ROUTES[self.index()].4
    }

    /// Method identity is not read from any caller-supplied payload.
    #[must_use]
    pub const fn fixed_method(self) -> &'static str {
        match self {
            Self::Mount => "filesystem-mount",
            Self::Unmount => "filesystem-unmount",
            Self::Eject => "drive-eject",
            Self::PowerOff => "drive-power-off",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageContractError {
    InvalidResource,
    UnknownOperation,
    InvalidEffect,
}

/// Canonically encoded proposal only; it cannot be used as a native permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedStorageEffect {
    operation: StorageOperation,
    resource: ResourceId,
}

impl ProposedStorageEffect {
    /// The 64-character digest is syntax-bound, not self-attesting. Control
    /// must derive the real identity and bind it to a durable authorized plan.
    pub fn new(
        operation: StorageOperation,
        generation_digest: &str,
    ) -> Result<Self, StorageContractError> {
        if generation_digest.len() != STORAGE_GENERATION_DIGEST_BYTES
            || generation_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || generation_digest.bytes().all(|byte| byte == b'0')
        {
            return Err(StorageContractError::InvalidResource);
        }
        let resource = ResourceId::new(format!(
            "{}{}",
            operation.resource_prefix(),
            generation_digest
        ))
        .map_err(|_| StorageContractError::InvalidResource)?;
        Ok(Self {
            operation,
            resource,
        })
    }

    #[must_use]
    pub const fn operation(&self) -> StorageOperation {
        self.operation
    }

    #[must_use]
    pub const fn resource(&self) -> &ResourceId {
        &self.resource
    }

    /// Fixed semantic data only. Arbitrary D-Bus methods, device paths,
    /// mountpoints, options, uid overrides and force flags cannot be encoded.
    pub fn descriptor(&self) -> Result<EffectDescriptor, StorageContractError> {
        EffectDescriptor::new(
            ProviderId::new(STORAGE_PROVIDER).map_err(|_| StorageContractError::InvalidEffect)?,
            self.resource.clone(),
            self.operation.fixed_method(),
            format!(
                "resource={}\n{}={}\n",
                self.resource.as_str(),
                self.operation.change_key(),
                self.operation.desired_value()
            )
            .into_bytes(),
        )
        .map_err(|_| StorageContractError::InvalidEffect)
    }

    /// The entire native-effect encoding must round-trip *exactly*.
    pub fn from_descriptor(effect: &EffectDescriptor) -> Result<Self, StorageContractError> {
        if effect.provider.as_str() != STORAGE_PROVIDER
            || effect.canonical_payload.len() > linura_provider_sdk::MAX_EFFECT_PAYLOAD_BYTES
        {
            return Err(StorageContractError::InvalidEffect);
        }
        for operation in StorageOperation::ALL {
            if let Some(digest) = effect
                .resource
                .as_str()
                .strip_prefix(operation.resource_prefix())
            {
                let candidate = Self::new(operation, digest)?;
                return if candidate.descriptor()? == *effect {
                    Ok(candidate)
                } else {
                    Err(StorageContractError::InvalidEffect)
                };
            }
        }
        Err(StorageContractError::UnknownOperation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "8af490c1".repeat(8)
    }

    fn valid(kind: StorageOperation) -> EffectDescriptor {
        ProposedStorageEffect::new(kind, &digest())
            .unwrap_or_else(|e| unreachable!("{e:?}"))
            .descriptor()
            .unwrap_or_else(|e| unreachable!("{e:?}"))
    }

    #[test]
    fn four_noninterchangeable_methods_resources_and_risks() {
        let cases = [
            (
                StorageOperation::Mount,
                "mounted",
                "true",
                RiskClass::SecuritySensitive,
            ),
            (
                StorageOperation::Unmount,
                "mounted",
                "false",
                RiskClass::Destructive,
            ),
            (
                StorageOperation::Eject,
                "ejected",
                "true",
                RiskClass::Destructive,
            ),
            (
                StorageOperation::PowerOff,
                "powered_off",
                "true",
                RiskClass::Destructive,
            ),
        ];
        for (kind, key, value, risk) in cases {
            let effect = valid(kind);
            assert_eq!(kind.risk_floor(), risk);
            assert_eq!(effect.operation, kind.fixed_method());
            assert_eq!(
                effect.canonical_payload,
                format!("resource={}\n{key}={value}\n", effect.resource.as_str()).as_bytes()
            );
            assert_eq!(
                ProposedStorageEffect::from_descriptor(&effect).map(|change| change.operation()),
                Ok(kind),
            );
            for other in StorageOperation::ALL {
                if other == kind {
                    continue;
                }
                let mut substituted = effect.clone();
                substituted.operation = other.fixed_method().into();
                assert_eq!(
                    ProposedStorageEffect::from_descriptor(&substituted),
                    Err(StorageContractError::InvalidEffect)
                );
                substituted = effect.clone();
                substituted.resource = valid(other).resource;
                assert_eq!(
                    ProposedStorageEffect::from_descriptor(&substituted),
                    Err(StorageContractError::InvalidEffect)
                );
            }
        }
    }

    #[test]
    fn no_paths_options_aliases_or_unreviewed_arguments() {
        let effect = valid(StorageOperation::Mount);
        let data = String::from_utf8(effect.canonical_payload.clone())
            .unwrap_or_else(|e| unreachable!("{e}"));
        for payload in [
            format!("{data}options=rw\n"),
            "method=Filesystem.Mount\n".into(),
            format!("resource={}\nmounted=TRUE\n", effect.resource.as_str()),
            format!("resource={}\nmounted=true", effect.resource.as_str()),
            format!(
                "resource={}\nmounted=true\nforce=true\n",
                effect.resource.as_str()
            ),
            format!(
                "resource={}\nmounted=true\nmounted=true\n",
                effect.resource.as_str()
            ),
        ] {
            let mut tampered = effect.clone();
            tampered.canonical_payload = payload.into_bytes();
            assert_eq!(
                ProposedStorageEffect::from_descriptor(&tampered),
                Err(StorageContractError::InvalidEffect)
            );
        }
        let mut other_provider = effect.clone();
        other_provider.provider =
            ProviderId::new("systemd").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            ProposedStorageEffect::from_descriptor(&other_provider),
            Err(StorageContractError::InvalidEffect)
        );
        let mut invalid_utf8 = effect;
        invalid_utf8.canonical_payload = vec![0xff];
        assert_eq!(
            ProposedStorageEffect::from_descriptor(&invalid_utf8),
            Err(StorageContractError::InvalidEffect)
        );
    }

    #[test]
    fn malformed_resource_generation_cannot_select_any_disk() {
        let bad_generations = [
            "".to_owned(),
            "0".repeat(64),
            "AF".repeat(32),
            "z".repeat(64),
            "8af490c1".repeat(7),
            "8af490c1".repeat(9),
        ];
        for digest in &bad_generations {
            assert_eq!(
                ProposedStorageEffect::new(StorageOperation::Mount, digest),
                Err(StorageContractError::InvalidResource)
            );
        }
        let mut malformed = valid(StorageOperation::Unmount);
        malformed.resource = ResourceId::new("storage:filesystem:unmount:/dev/sda1")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            ProposedStorageEffect::from_descriptor(&malformed),
            Err(StorageContractError::InvalidResource)
        );
    }

    #[test]
    fn none_of_the_four_storage_operations_is_live() {
        let registry = crate::operation_registry::trusted_builtin_operation_registry()
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(registry.len(), 7);
        for operation in StorageOperation::ALL {
            let id = linura_core::OperationId::new(operation.operation_id())
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(registry.descriptor(&id).is_none());
        }
    }
}
