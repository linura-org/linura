//! S17 Linura-owned policy enrollment/revocation, not an external effect. No
//! executor, effect permit or client-authored policy decision exists here.
//! Production composition supplies authenticated caller identity, the protected
//! store/Control signer, registered native observers and a purpose-specific
//! owner-authentication adapter. Chat/profile/model input is never approval.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linura_core::{
    CapabilityId, IntentId, OperationClass, PolicyRevisionId, PrincipalId, ProviderId, RequestId,
    RiskClass, SessionEpoch, SessionLockId,
};
use linura_policy::ProtectiveLockSetting;
use linura_protocol::ObservationRequest;
use linura_transaction::{
    ContentDigest, ProtectiveLockSettingRecord, ProtectiveLockSettingStore,
    TransactionAuthoritySigner, digest_parts,
};

use crate::durable_authority::digest_observation;
use crate::{
    AuthenticatedPrincipal, ManagedApprovalAuthorizer, ManagedApprovalChallenge,
    PlanPreviewControl, SessionAction, SessionSafetyReview,
};

pub const PROTECTIVE_LOCK_SETTING_REQUEST_PREFIX: &str = "request:v010:protective-lock-setting:";
const POLICY_REVISION: &str = "policy:protective-lock-enrollment:v1";
const INTERACTION_BUDGET: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectiveLockConfigurationRequest {
    pub operation_id: String,
    pub lock: SessionLockId,
    pub enabled: bool,
}

impl ProtectiveLockConfigurationRequest {
    #[must_use]
    pub const fn operation_class(&self) -> OperationClass {
        OperationClass::LinuraOwnedState
    }
    #[must_use]
    pub const fn risk_floor(&self) -> RiskClass {
        RiskClass::SecuritySensitive
    }
}

/// A historical configuration receipt. `latest_for_epoch` means only the latest
/// recorded revision in that login namespace, not that the login is still active
/// or the policy usable. It is never native coverage or a sleep permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectiveLockConfigurationReceipt {
    pub record: ProtectiveLockSettingRecord,
    pub latest_for_epoch: bool,
}

#[derive(Debug)]
pub struct ProtectiveLockSettingsControl {
    store: Box<dyn ProtectiveLockSettingStore>,
    signer: TransactionAuthoritySigner,
}

impl ProtectiveLockSettingsControl {
    pub fn new(
        store: Box<dyn ProtectiveLockSettingStore>,
        signer: TransactionAuthoritySigner,
    ) -> Result<Self, String> {
        store.integrity_check().map_err(|e| e.to_string())?;
        Ok(Self { store, signer })
    }

    /// Fresh authenticated durable data only; this value itself is NOT a grant
    /// credential. Consumers must re-read it at managed prepare and handoff.
    pub fn current(
        &self,
        owner: &PrincipalId,
        epoch: &SessionEpoch,
    ) -> Result<Option<ProtectiveLockSetting>, String> {
        self.store
            .current(owner, epoch)
            .map_err(|e| e.to_string())?
            .map(|record| setting_from_record(&record))
            .transpose()
    }

    /// Historical local configuration query. No native coverage or active-login
    /// assertion is made, and callers can read only their own non-root namespace.
    pub fn recorded_for_epoch(
        &self,
        principal: &AuthenticatedPrincipal,
        epoch: &SessionEpoch,
    ) -> Result<Option<ProtectiveLockConfigurationReceipt>, String> {
        let owner = PrincipalId::new(principal.as_str()).map_err(|e| e.to_string())?;
        if epoch.uid() == 0 || owner.as_str() != format!("unix:uid:{}", epoch.uid()) {
            return Err("protective-lock history belongs to another principal".into());
        }
        self.store
            .current(&owner, epoch)
            .map_err(|e| e.to_string())?
            .map(|record| self.receipt(record))
            .transpose()
    }

    /// Read-only lost-reply lookup. Never reapplies an enable or asks for new
    /// approval; current native session identity is deliberately not inferred.
    pub fn request_status(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<ProtectiveLockConfigurationReceipt, String> {
        let suffix = request_id
            .as_str()
            .strip_prefix(PROTECTIVE_LOCK_SETTING_REQUEST_PREFIX)
            .ok_or("protective-lock request has another purpose")?;
        if &configuration_request_id(suffix)? != request_id {
            return Err("noncanonical protective-lock request identity".into());
        }
        let owner = PrincipalId::new(principal.as_str()).map_err(|e| e.to_string())?;
        let uid = owner
            .as_str()
            .strip_prefix("unix:uid:")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|uid| *uid != 0 && owner.as_str() == format!("unix:uid:{uid}"))
            .ok_or("protective-lock history requires a non-root owner")?;
        let record = self
            .store
            .request(&owner, request_id)
            .map_err(|e| e.to_string())?
            .ok_or("protective-lock request is not retained for this owner")?;
        if record.owner() != &owner || record.epoch().uid() != uid {
            return Err("protective-lock history owner integrity mismatch".into());
        }
        self.receipt(record)
    }

    pub fn configure(
        &mut self,
        previews: &mut PlanPreviewControl,
        principal: &AuthenticatedPrincipal,
        request: &ProtectiveLockConfigurationRequest,
        authorizer: &dyn ManagedApprovalAuthorizer,
    ) -> Result<ProtectiveLockConfigurationReceipt, String> {
        self.configure_with_clock(previews, principal, request, authorizer, now)
    }

    fn configure_with_clock(
        &mut self,
        previews: &mut PlanPreviewControl,
        principal: &AuthenticatedPrincipal,
        request: &ProtectiveLockConfigurationRequest,
        authorizer: &dyn ManagedApprovalAuthorizer,
        clock: impl Fn() -> Result<u64, String>,
    ) -> Result<ProtectiveLockConfigurationReceipt, String> {
        let owner = PrincipalId::new(principal.as_str()).map_err(|e| e.to_string())?;
        if request.lock.epoch().uid() == 0
            || principal.as_str() != format!("unix:uid:{}", request.lock.epoch().uid())
        {
            return Err(
                "protective-lock setting belongs only to the authenticated non-root session owner"
                    .into(),
            );
        }
        let request_id = configuration_request_id(&request.operation_id)?;
        // Read-only exact retry never asks for a second approval or applies an
        // old enable record again. A superseded receipt is not active consent.
        if let Some(record) = self
            .store
            .request(&owner, &request_id)
            .map_err(|e| e.to_string())?
        {
            if record.confirmed_lock() != &request.lock || record.enabled() != request.enabled {
                return Err(
                    "protective-lock request identity was reused with different content".into(),
                );
            }
            return self.receipt(record);
        }
        let first_sample = clock()?;
        if first_sample == 0 {
            return Err("protective-lock configuration clock is unavailable".into());
        }
        let previous = self
            .store
            .current(&owner, request.lock.epoch())
            .map_err(|e| e.to_string())?;
        let (observed, _) = observe_owner(previews, principal, &request.lock, &clock)?;
        let owner_epoch = request
            .lock
            .epoch()
            .resource_id()
            .map_err(|e| e.to_string())?;
        let resource = request.lock.resource_id().map_err(|e| e.to_string())?;
        let desired = request.enabled.to_string();
        let request_digest = digest_parts(
            "linura.protective-lock.configuration-request.v1",
            [
                owner.as_str().as_bytes(),
                request_id.as_str().as_bytes(),
                owner_epoch.as_str().as_bytes(),
                resource.as_str().as_bytes(),
                desired.as_bytes(),
                previous
                    .as_ref()
                    .map_or("", |r| r.digest().as_str())
                    .as_bytes(),
            ],
        );
        let review_digest = digest_parts(
            "linura.protective-lock.configuration-review.v1",
            [
                POLICY_REVISION.as_bytes(),
                request_digest.as_str().as_bytes(),
                observed.as_str().as_bytes(),
            ],
        );
        let challenge = ManagedApprovalChallenge::protective_setting(
            owner.clone(),
            request_id.clone(),
            &request.lock,
            request.enabled,
            (
                request_digest.as_str(),
                observed.as_str(),
                review_digest.as_str(),
            ),
        )?;
        let started = Instant::now();
        let approval = authorizer.authorize(&challenge)?;
        let approved_at = clock()?;
        let proof_consumed = Instant::now();
        if started.elapsed() >= INTERACTION_BUDGET || !approval.matches_challenge(&challenge) {
            return Err(
                "protective-lock configuration lacks fresh exact purpose-bound owner approval"
                    .into(),
            );
        }
        let approval_expiry = approved_at
            .checked_add(2000)
            .ok_or("protective-lock approval clock overflow")?;
        if approved_at
            .checked_sub(first_sample)
            .is_none_or(|elapsed| elapsed >= 60_000)
        {
            return Err("protective-lock owner interaction clock rolled back or expired".into());
        }
        // No retained native facts/current revision survive a slow interaction
        // as execution authority. Re-observe the exact owner+lock and read the
        // store again before the atomic compare-and-swap update.
        let (_, facts_expiry) = observe_owner(previews, principal, &request.lock, &clock)?;
        let expires_at_unix_ms = facts_expiry.min(approval_expiry);
        let latest = self
            .store
            .current(&owner, request.lock.epoch())
            .map_err(|e| e.to_string())?;
        if latest != previous {
            return Err("protective-lock setting changed during owner authentication".into());
        }
        let confirmed_at = clock()?;
        if confirmed_at < approved_at
            || confirmed_at >= expires_at_unix_ms
            || proof_consumed.elapsed() >= Duration::from_millis(2000)
        {
            return Err("protective-lock enrollment evidence expired".into());
        }
        let intent = IntentId::new(format!(
            "intent:s17:protective-lock:{}",
            request_digest.hex()
        ))
        .map_err(|e| e.to_string())?;
        let record = ProtectiveLockSettingRecord::new(
            owner,
            request.lock.epoch().clone(),
            intent,
            request_id,
            previous.as_ref().map(|r| r.digest().clone()),
            request.enabled,
            request.lock.clone(),
            approved_at,
            review_digest,
        )
        .map_err(|e| e.to_string())?;
        let update = self
            .signer
            .authorize_protective_lock_setting(record, expires_at_unix_ms)
            .map_err(|e| e.to_string())?;
        let record = self.store.apply(&update).map_err(|e| e.to_string())?;
        self.receipt(record)
    }

    fn receipt(
        &self,
        record: ProtectiveLockSettingRecord,
    ) -> Result<ProtectiveLockConfigurationReceipt, String> {
        let latest_for_epoch = self
            .store
            .current(record.owner(), record.epoch())
            .map_err(|e| e.to_string())?
            .as_ref()
            == Some(&record);
        Ok(ProtectiveLockConfigurationReceipt {
            record,
            latest_for_epoch,
        })
    }
}

impl ProtectiveLockConfigurationReceipt {
    /// Public projection contains provenance only, never store seals or a
    /// retained object that can be submitted for execution.
    pub fn public_receipt(&self) -> Result<linura_protocol::ProtectiveLockSettingReceipt, String> {
        let setting = setting_from_record(&self.record)?;
        Ok(linura_protocol::ProtectiveLockSettingReceipt {
            request_id: self.record.request().clone(),
            confirmed_lock: self.record.confirmed_lock().clone(),
            enabled: self.record.enabled(),
            intent_id: self.record.intent().clone(),
            revision_id: setting.revision().clone(),
            confirmed_at_unix_ms: self.record.confirmed_at_unix_ms(),
            latest_for_epoch: self.latest_for_epoch,
        })
    }
}

fn setting_from_record(
    record: &ProtectiveLockSettingRecord,
) -> Result<ProtectiveLockSetting, String> {
    ProtectiveLockSetting::new(
        record.owner().clone(),
        record.epoch().clone(),
        record.intent().clone(),
        PolicyRevisionId::new(format!(
            "policy:protective-lock:v1:{}",
            record.digest().hex()
        ))
        .map_err(|e| e.to_string())?,
        record.enabled(),
    )
    .map_err(str::to_owned)
}

fn configuration_request_id(operation: &str) -> Result<RequestId, String> {
    if operation.is_empty()
        || operation.len() > 64
        || operation.starts_with('-')
        || operation.ends_with('-')
        || operation.contains("--")
        || !operation
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(
            "protective-lock setting operation must be a canonical bounded S17 operation slug"
                .into(),
        );
    }
    RequestId::new(format!(
        "{PROTECTIVE_LOCK_SETTING_REQUEST_PREFIX}{operation}"
    ))
    .map_err(|e| e.to_string())
}

fn observe_owner(
    previews: &mut PlanPreviewControl,
    principal: &AuthenticatedPrincipal,
    lock: &SessionLockId,
    clock: &impl Fn() -> Result<u64, String>,
) -> Result<(ContentDigest, u64), String> {
    let session = previews
        .observe(&ObservationRequest {
            provider: ProviderId::new("logind").map_err(|e| e.to_string())?,
            capability: CapabilityId::new("session.epoch.observe").map_err(|e| e.to_string())?,
            resource: lock.epoch().resource_id().map_err(|e| e.to_string())?,
        })
        .map_err(|e| e.to_string())?
        .observation;
    let native_lock = previews
        .observe(&ObservationRequest {
            provider: ProviderId::new("session-locker").map_err(|e| e.to_string())?,
            capability: CapabilityId::new("session.secure-lock.observe")
                .map_err(|e| e.to_string())?,
            resource: lock.resource_id().map_err(|e| e.to_string())?,
        })
        .map_err(|e| e.to_string())?
        .observation;
    let sampled = clock()?;
    if sampled == 0 || session.observed_at_unix_ms == 0 || native_lock.observed_at_unix_ms == 0 {
        return Err("protective-lock configuration clock is unavailable".into());
    }
    let owner = SessionSafetyReview::review(
        principal,
        lock.epoch(),
        SessionAction::Lock,
        &session,
        sampled,
    )
    .map_err(|e| e.to_string())?;
    if owner
        .require_secure_coverage(&native_lock, sampled)
        .map_err(|e| e.to_string())?
        != *lock
    {
        return Err("protective-lock configuration owner/lock generation changed".into());
    }
    let expiry = [
        session
            .observed_at_unix_ms
            .checked_add(session.valid_for_ms),
        native_lock
            .observed_at_unix_ms
            .checked_add(native_lock.valid_for_ms),
    ]
    .into_iter()
    .try_fold(u64::MAX, |end, value| {
        value
            .map(|v| end.min(v))
            .ok_or("protective-lock evidence time overflow")
    })?;
    let digest = digest_parts(
        "linura.protective-lock.configuration-observation.v1",
        [
            digest_observation(&session)
                .map_err(|e| e.to_string())?
                .as_str()
                .as_bytes(),
            digest_observation(&native_lock)
                .map_err(|e| e.to_string())?
                .as_str()
                .as_bytes(),
        ],
    );
    Ok((digest, expiry))
}

fn now() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "protective-lock clock unavailable")?
            .as_millis(),
    )
    .map_err(|_| "protective-lock clock overflow".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustedHumanApproval;
    use linura_core::{BootId, Capability, ResourceId, SecurityOwnerInvocationId, SupportLevel};
    use linura_observation::{
        ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability,
        ProviderHealth,
    };
    use linura_observation_control::ObservationCoordinator;
    use linura_provider_sdk::{Observer, ProviderError};
    use linura_transaction::{
        ProtectiveLockSettingUpdate, TransactionAuthorityKey, TransactionAuthorityVerifier,
        TransactionStoreError,
    };
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn test_key_material() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        let read = File::open("/dev/urandom")
            .and_then(|file| file.take(32).read_to_end(&mut bytes))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(read, 32);
        bytes
    }

    fn authority() -> (TransactionAuthoritySigner, TransactionAuthorityVerifier) {
        id(TransactionAuthorityKey::new(test_key_material())).split()
    }
    #[derive(Debug, Default)]
    struct Records {
        entries: Vec<ProtectiveLockSettingRecord>,
        corrupt: bool,
    }
    #[derive(Debug)]
    struct Store {
        records: Arc<Mutex<Records>>,
        verifier: TransactionAuthorityVerifier,
    }
    impl ProtectiveLockSettingStore for Store {
        fn current(
            &self,
            owner: &PrincipalId,
            epoch: &SessionEpoch,
        ) -> Result<Option<ProtectiveLockSettingRecord>, TransactionStoreError> {
            let records = self.records.lock().unwrap_or_else(|e| unreachable!("{e}"));
            if records.corrupt {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            Ok(records
                .entries
                .iter()
                .rev()
                .find(|r| r.owner() == owner && r.epoch() == epoch)
                .cloned())
        }
        fn request(
            &self,
            owner: &PrincipalId,
            request: &RequestId,
        ) -> Result<Option<ProtectiveLockSettingRecord>, TransactionStoreError> {
            self.integrity_check()?;
            Ok(self
                .records
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .entries
                .iter()
                .find(|r| r.owner() == owner && r.request() == request)
                .cloned())
        }
        fn apply(
            &mut self,
            update: &ProtectiveLockSettingUpdate,
        ) -> Result<ProtectiveLockSettingRecord, TransactionStoreError> {
            if !self.verifier.verify_protective_lock_setting(update) {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            self.integrity_check()?;
            let mut records = self.records.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let record = update.record();
            if records
                .entries
                .iter()
                .rev()
                .find(|r| r.owner() == record.owner() && r.epoch() == record.epoch())
                .map(ProtectiveLockSettingRecord::digest)
                != record.previous()
            {
                return Err(TransactionStoreError::StateConflict);
            }
            records.entries.push(record.clone());
            Ok(record.clone())
        }
        fn integrity_check(&self) -> Result<(), TransactionStoreError> {
            if self
                .records
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .corrupt
            {
                Err(TransactionStoreError::AuthorityRejected)
            } else {
                Ok(())
            }
        }
    }
    struct NativeObserver {
        lock: SessionLockId,
        locker: bool,
        secure: Arc<AtomicBool>,
        sequence: AtomicU64,
    }
    impl Observer for NativeObserver {
        fn observer_id(&self) -> ProviderId {
            id(ProviderId::new(if self.locker {
                "session-locker"
            } else {
                "logind"
            }))
        }
        fn observation_capabilities(&self) -> Vec<Capability> {
            vec![Capability {
                id: id(CapabilityId::new(if self.locker {
                    "session.secure-lock.observe"
                } else {
                    "session.epoch.observe"
                })),
                support: SupportLevel::Supported,
                provider: Some(self.observer_id()),
                reason: None,
            }]
        }
        fn health(&self) -> ProviderHealth {
            ProviderHealth {
                provider: self.observer_id(),
                availability: ProviderAvailability::Available,
                reason: None,
            }
        }
        fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
            Ok(vec![])
        }
        fn observe_authoritative(
            &self,
            resource: &ResourceId,
            capability: &CapabilityId,
        ) -> Result<ObservationEnvelope, ProviderError> {
            let epoch = self.lock.epoch();
            let mut attributes = BTreeMap::from([
                (
                    "boot_id".into(),
                    ObservedValue::Text(epoch.boot().as_str().into()),
                ),
                (
                    "session_id".into(),
                    ObservedValue::Text(epoch.session_id().into()),
                ),
                ("uid".into(), ObservedValue::U64(u64::from(epoch.uid()))),
                (
                    "created_monotonic_us".into(),
                    ObservedValue::U64(epoch.created_monotonic_us()),
                ),
            ]);
            if self.locker {
                attributes.extend([
                    (
                        "security_owner_invocation".into(),
                        ObservedValue::Text(self.lock.security_owner_invocation().as_str().into()),
                    ),
                    (
                        "lock_generation".into(),
                        ObservedValue::U64(self.lock.generation()),
                    ),
                    (
                        "lock_protocol".into(),
                        ObservedValue::Text("ext-session-lock-v1".into()),
                    ),
                    (
                        "secure".into(),
                        ObservedValue::Bool(self.secure.load(Ordering::SeqCst)),
                    ),
                ]);
            } else {
                attributes.extend([
                    ("session_type".into(), ObservedValue::Text("wayland".into())),
                    ("session_class".into(), ObservedValue::Text("user".into())),
                    ("state".into(), ObservedValue::Text("active".into())),
                    ("seat".into(), ObservedValue::Text("seat0".into())),
                    ("active".into(), ObservedValue::Bool(true)),
                    ("remote".into(), ObservedValue::Bool(false)),
                    ("leader_present".into(), ObservedValue::Bool(true)),
                ]);
            }
            Ok(ObservationEnvelope {
                provider: self.observer_id(),
                capability: capability.clone(),
                resource: resource.clone(),
                authority: ObservationAuthority::NativeApi,
                observed_at_unix_ms: id(now()),
                valid_for_ms: 2000,
                sequence: self.sequence.fetch_add(1, Ordering::SeqCst) + 1,
                attributes,
            })
        }
    }
    #[derive(Debug)]
    struct Approver {
        calls: AtomicUsize,
        principal: PrincipalId,
        deny: bool,
        secure: Option<Arc<AtomicBool>>,
        corrupt: Option<Arc<Mutex<Records>>>,
    }
    impl ManagedApprovalAuthorizer for Approver {
        fn authorize(
            &self,
            challenge: &ManagedApprovalChallenge,
        ) -> Result<TrustedHumanApproval, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(challenge.change_key(), "protective_lock.enabled");
            assert_eq!(
                challenge.approval_class(),
                crate::ManagedApprovalClass::SessionOwnerAuthentication
            );
            if self.deny {
                return Err("owner denied".into());
            }
            if let Some(secure) = &self.secure {
                secure.store(false, Ordering::SeqCst);
            }
            if let Some(records) = &self.corrupt {
                records
                    .lock()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .corrupt = true;
            }
            Ok(TrustedHumanApproval::from_authorized_challenge(
                self.principal.clone(),
                challenge,
            ))
        }
    }
    struct Fixture {
        control: ProtectiveLockSettingsControl,
        previews: PlanPreviewControl,
        request: ProtectiveLockConfigurationRequest,
        principal: AuthenticatedPrincipal,
        approver: Approver,
        records: Arc<Mutex<Records>>,
        secure: Arc<AtomicBool>,
    }
    impl Fixture {
        fn new() -> Self {
            let epoch = id(SessionEpoch::new(
                id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
                1000,
                "c2",
                42,
            ));
            let lock = id(SessionLockId::new(
                epoch,
                id(SecurityOwnerInvocationId::new(
                    "98765432-1234-4567-89ab-0123456789ab",
                )),
                7,
            ));
            let records = Arc::new(Mutex::new(Records::default()));
            let secure = Arc::new(AtomicBool::new(true));
            let (signer, verifier) = authority();
            let control = id(ProtectiveLockSettingsControl::new(
                Box::new(Store {
                    records: Arc::clone(&records),
                    verifier,
                }),
                signer,
            ));
            let mut coordinator = ObservationCoordinator::new();
            for locker in [false, true] {
                id(coordinator.register_observer(Box::new(NativeObserver {
                    lock: lock.clone(),
                    locker,
                    secure: Arc::clone(&secure),
                    sequence: AtomicU64::new(0),
                })));
            }
            Self {
                control,
                previews: PlanPreviewControl::new(coordinator),
                request: ProtectiveLockConfigurationRequest {
                    operation_id: "enable".into(),
                    lock,
                    enabled: true,
                },
                principal: id(AuthenticatedPrincipal::new("unix:uid:1000")),
                approver: Approver {
                    calls: AtomicUsize::new(0),
                    principal: id(PrincipalId::new("unix:uid:1000")),
                    deny: false,
                    secure: None,
                    corrupt: None,
                },
                records,
                secure,
            }
        }
        fn configure(&mut self) -> Result<ProtectiveLockConfigurationReceipt, String> {
            self.control.configure_with_clock(
                &mut self.previews,
                &self.principal,
                &self.request,
                &self.approver,
                now,
            )
        }
        fn empty(&self) -> bool {
            self.records
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .entries
                .is_empty()
        }
    }

    #[test]
    fn explicit_owner_enrollment_and_revocation_retain_provenance_and_current_revision() {
        let mut fixture = Fixture::new();
        let enabled = id(fixture.configure());
        assert!(enabled.latest_for_epoch && enabled.record.enabled());
        let setting = id(fixture
            .control
            .current(enabled.record.owner(), enabled.record.epoch()));
        let setting = setting.unwrap_or_else(|| unreachable!());
        assert!(setting.enabled());
        assert_eq!(setting.intent(), enabled.record.intent());
        assert_eq!(
            setting.revision().as_str(),
            format!(
                "policy:protective-lock:v1:{}",
                enabled.record.digest().hex()
            )
        );
        fixture.request.operation_id = "revoke".into();
        fixture.request.enabled = false;
        let revoked = id(fixture.configure());
        assert!(revoked.latest_for_epoch && !revoked.record.enabled());
        assert_eq!(revoked.record.previous(), Some(enabled.record.digest()));
        assert!(
            !id(fixture
                .control
                .current(revoked.record.owner(), revoked.record.epoch()))
            .unwrap_or_else(|| unreachable!())
            .enabled()
        );
    }

    #[test]
    fn public_history_is_owner_scoped_read_only_and_never_restores_consent() {
        let mut fixture = Fixture::new();
        let epoch = fixture.request.lock.epoch().clone();
        assert!(
            id(fixture
                .control
                .recorded_for_epoch(&fixture.principal, &epoch))
            .is_none()
        );
        let enabled = id(fixture.configure());
        let expected = id(enabled.public_receipt());
        assert_eq!(
            id(fixture
                .control
                .request_status(&fixture.principal, enabled.record.request()))
            .public_receipt(),
            Ok(expected)
        );
        fixture.request.operation_id = "revoke".into();
        fixture.request.enabled = false;
        let revoked = id(fixture.configure());
        let calls = fixture.approver.calls.load(Ordering::SeqCst);
        for _ in 0..3 {
            let old = id(fixture
                .control
                .request_status(&fixture.principal, enabled.record.request()));
            assert!(!old.latest_for_epoch && old.record.enabled());
            let latest = id(fixture
                .control
                .recorded_for_epoch(&fixture.principal, &epoch))
            .unwrap_or_else(|| unreachable!());
            assert_eq!(latest, revoked);
        }
        assert_eq!(fixture.approver.calls.load(Ordering::SeqCst), calls);
        for principal in [
            "unix:uid:0",
            "unix:uid:1001",
            "unix:uid:01000",
            "service:system-sleep-protection",
            "agent:helper",
        ] {
            let other = id(AuthenticatedPrincipal::new(principal));
            assert!(
                fixture.control.recorded_for_epoch(&other, &epoch).is_err(),
                "{principal}"
            );
            assert!(
                fixture
                    .control
                    .request_status(&other, enabled.record.request())
                    .is_err(),
                "{principal}"
            );
        }
        for request in [
            "request:v010:session-lock:enable",
            "request:v010:protective-lock-setting:Upper",
            "request:v010:protective-lock-setting:missing",
        ] {
            assert!(
                fixture
                    .control
                    .request_status(&fixture.principal, &id(RequestId::new(request)))
                    .is_err()
            );
        }
        fixture
            .records
            .lock()
            .unwrap_or_else(|e| unreachable!("{e}"))
            .corrupt = true;
        assert!(
            fixture
                .control
                .request_status(&fixture.principal, enabled.record.request())
                .is_err()
        );
        assert!(
            fixture
                .control
                .recorded_for_epoch(&fixture.principal, &epoch)
                .is_err()
        );
    }

    #[test]
    fn exact_historic_retry_is_read_only_and_never_reenables_revoked_permission() {
        let mut fixture = Fixture::new();
        let enabled = id(fixture.configure());
        fixture.request.operation_id = "revoke".into();
        fixture.request.enabled = false;
        let revoked = id(fixture.configure());
        fixture.request.operation_id = "enable".into();
        fixture.request.enabled = true;
        fixture.approver.deny = true;
        fixture.secure.store(false, Ordering::SeqCst);
        let replay = id(fixture.configure());
        assert_eq!(replay.record, enabled.record);
        assert!(!replay.latest_for_epoch);
        assert_eq!(fixture.approver.calls.load(Ordering::SeqCst), 2);
        assert!(
            !id(fixture
                .control
                .current(revoked.record.owner(), revoked.record.epoch()))
            .unwrap_or_else(|| unreachable!())
            .enabled()
        );
        fixture.request.enabled = false;
        assert!(fixture.configure().is_err());
    }

    #[test]
    fn root_other_owner_service_denial_and_wrong_approver_do_not_write() {
        for principal in [
            "unix:uid:0",
            "unix:uid:1001",
            "service:system-sleep-protection",
            "agent:trusted",
        ] {
            let mut fixture = Fixture::new();
            fixture.principal = id(AuthenticatedPrincipal::new(principal));
            assert!(fixture.configure().is_err());
            assert!(fixture.empty());
            assert_eq!(fixture.approver.calls.load(Ordering::SeqCst), 0);
        }
        let mut fixture = Fixture::new();
        fixture.approver.deny = true;
        assert!(fixture.configure().is_err());
        assert!(fixture.empty());
        fixture.approver.deny = false;
        fixture.approver.principal = id(PrincipalId::new("unix:uid:1001"));
        assert!(fixture.configure().is_err());
        assert!(fixture.empty());
    }

    #[test]
    fn uncovered_desktop_and_native_loss_during_approval_never_create_policy_state() {
        let mut fixture = Fixture::new();
        fixture.secure.store(false, Ordering::SeqCst);
        assert!(fixture.configure().is_err());
        assert!(fixture.empty());
        assert_eq!(fixture.approver.calls.load(Ordering::SeqCst), 0);
        let mut fixture = Fixture::new();
        fixture.approver.secure = Some(Arc::clone(&fixture.secure));
        assert!(fixture.configure().is_err());
        assert!(fixture.empty());
        let mut fixture = Fixture::new();
        fixture.approver.corrupt = Some(Arc::clone(&fixture.records));
        assert!(fixture.configure().is_err());
        assert!(fixture.empty());
    }

    #[test]
    fn invalid_operation_identity_is_rejected_before_native_interaction() {
        for operation in ["", "Upper", "-edge", "edge-", "double--dash", "a:b", "a b"] {
            let mut fixture = Fixture::new();
            fixture.request.operation_id = operation.into();
            assert!(fixture.configure().is_err());
            assert!(fixture.empty());
            assert_eq!(fixture.approver.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn fresh_native_samples_cannot_extend_consumed_approval_or_hide_clock_rollback() {
        for final_clock in [0, 3000] {
            let mut fixture = Fixture::new();
            let calls = AtomicUsize::new(0);
            let result = fixture.control.configure_with_clock(
                &mut fixture.previews,
                &fixture.principal,
                &fixture.request,
                &fixture.approver,
                || {
                    let sampled = id(now());
                    if calls.fetch_add(1, Ordering::SeqCst) == 4 {
                        if final_clock == 0 {
                            Ok(0)
                        } else {
                            Ok(sampled + final_clock)
                        }
                    } else {
                        Ok(sampled)
                    }
                },
            );
            assert!(result.is_err());
            assert!(fixture.empty());
            assert_eq!(fixture.approver.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn configuration_is_security_sensitive_local_state_and_never_an_external_effect() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.request.operation_class(),
            OperationClass::LinuraOwnedState
        );
        assert_eq!(fixture.request.risk_floor(), RiskClass::SecuritySensitive);
    }
}
