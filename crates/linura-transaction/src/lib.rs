#![forbid(unsafe_code)]

mod approved_request;
mod protective_lock_setting;
pub use approved_request::{
    ApprovedRequestJournal, MAX_RETAINED_REQUEST_BYTES, RETAINED_REQUEST_FORMAT, RetainedRequest,
};
pub use protective_lock_setting::{
    MAX_PROTECTIVE_LOCK_SETTING_BYTES, ProtectiveLockSettingRecord, ProtectiveLockSettingStore,
    ProtectiveLockSettingUpdate,
};

use std::fmt::{Display, Formatter};

use hmac::{Hmac, KeyInit, Mac};
use linura_core::{
    ApprovalEvidenceId, ApprovalRequestId, CapabilityId, PlanId, PolicyId, PolicyRevisionId,
    PrincipalId, ProviderId, RequestId, ResourceId, RiskClass, ValidationError,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const MAX_AUTHORITY_BINDING_BYTES: usize = 256 * 1024;
pub const MAX_RISK_RULES: usize = 128;
pub const MAX_RISK_RULE_ID_BYTES: usize = 512;
pub const MAX_REVISION_BYTES: usize = 1024;
pub const MAX_TRANSACTION_GENERATIONS: u64 = 64;

const DIGEST_PREFIX: &str = "sha256:";
const ZERO_DIGEST_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactionId(String);

impl TransactionId {
    pub fn new(value: impl Into<String>) -> Result<Self, TransactionValidationError> {
        let value = value.into();
        validate_token("transaction id", &value, 256)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn for_namespace(principal: &PrincipalId, request_id: &RequestId) -> Self {
        let digest = digest_parts(
            "linura.transaction.id.v1",
            [
                principal.as_str().as_bytes(),
                request_id.as_str().as_bytes(),
            ],
        );
        Self(format!("transaction:v1:{}", digest.hex()))
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, TransactionValidationError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix(DIGEST_PREFIX) else {
            return Err(TransactionValidationError::InvalidDigest);
        };
        if hex.len() != 64
            || !hex
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(TransactionValidationError::InvalidDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn zero() -> Self {
        Self(format!("{DIGEST_PREFIX}{ZERO_DIGEST_HEX}"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn hex(&self) -> &str {
        &self.0[DIGEST_PREFIX.len()..]
    }
}

#[must_use]
pub fn digest_bytes(domain: &str, bytes: &[u8]) -> ContentDigest {
    digest_parts(domain, [bytes])
}

#[must_use]
pub fn digest_parts<'a>(domain: &str, parts: impl IntoIterator<Item = &'a [u8]>) -> ContentDigest {
    let mut hasher = Sha256::new();
    put_len_bytes(&mut hasher, domain.as_bytes());
    for part in parts {
        put_len_bytes(&mut hasher, part);
    }
    let digest = hasher.finalize();
    ContentDigest(format!("{DIGEST_PREFIX}{}", hex::encode(digest)))
}

fn put_len_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

fn encode_field(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TransactionValidationError> {
    let len =
        u64::try_from(bytes.len()).map_err(|_| TransactionValidationError::BindingTooLarge)?;
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(bytes);
    if buffer.len() > MAX_AUTHORITY_BINDING_BYTES {
        return Err(TransactionValidationError::BindingTooLarge);
    }
    Ok(())
}

fn encode_str(buffer: &mut Vec<u8>, value: &str) -> Result<(), TransactionValidationError> {
    encode_field(buffer, value.as_bytes())
}

fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::ReadOnly => "read-only",
        RiskClass::UserState => "user-state",
        RiskClass::SystemMutation => "system-mutation",
        RiskClass::SecuritySensitive => "security-sensitive",
        RiskClass::Destructive => "destructive",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalAuthority {
    evidence_id: ApprovalEvidenceId,
    request_id: ApprovalRequestId,
    approver: PrincipalId,
    approval_class: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl ApprovalAuthority {
    pub fn try_new(
        evidence_id: ApprovalEvidenceId,
        request_id: ApprovalRequestId,
        approver: PrincipalId,
        approval_class: impl Into<String>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, TransactionValidationError> {
        let approval_class = approval_class.into();
        validate_token("approval class", &approval_class, 256)?;
        if issued_at_unix_seconds == 0 || expires_at_unix_seconds <= issued_at_unix_seconds {
            return Err(TransactionValidationError::InvalidAuthorization);
        }
        Ok(Self {
            evidence_id,
            request_id,
            approver,
            approval_class,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        })
    }

    #[must_use]
    pub fn evidence_id(&self) -> &ApprovalEvidenceId {
        &self.evidence_id
    }

    #[must_use]
    pub fn request_id(&self) -> &ApprovalRequestId {
        &self.request_id
    }

    #[must_use]
    pub fn approver(&self) -> &PrincipalId {
        &self.approver
    }

    #[must_use]
    pub fn approval_class(&self) -> &str {
        &self.approval_class
    }

    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationBasis {
    PolicyAllow,
    Approval(ApprovalAuthority),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBinding {
    principal: PrincipalId,
    request_id: RequestId,
    plan_id: PlanId,
    request_digest: ContentDigest,
    precondition_digest: ContentDigest,
    observation_digest: ContentDigest,
    provider: ProviderId,
    resource: ResourceId,
    capability: CapabilityId,
    policy_id: PolicyId,
    policy_revision_id: PolicyRevisionId,
    trusted_risk: RiskClass,
    risk_policy_revision: String,
    risk_rule_ids: Vec<String>,
    review_digest: ContentDigest,
    authorization: AuthorizationBasis,
    canonical: Vec<u8>,
    digest: ContentDigest,
}

impl AuthorityBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        principal: PrincipalId,
        request_id: RequestId,
        plan_id: PlanId,
        request_digest: ContentDigest,
        precondition_digest: ContentDigest,
        observation_digest: ContentDigest,
        provider: ProviderId,
        resource: ResourceId,
        capability: CapabilityId,
        policy_id: PolicyId,
        policy_revision_id: PolicyRevisionId,
        trusted_risk: RiskClass,
        risk_policy_revision: impl Into<String>,
        mut risk_rule_ids: Vec<String>,
        review_digest: ContentDigest,
        authorization: AuthorizationBasis,
    ) -> Result<Self, TransactionValidationError> {
        let risk_policy_revision = risk_policy_revision.into();
        validate_token(
            "risk-policy revision",
            &risk_policy_revision,
            MAX_REVISION_BYTES,
        )?;
        if risk_rule_ids.len() > MAX_RISK_RULES {
            return Err(TransactionValidationError::TooManyRiskRules);
        }
        risk_rule_ids.sort();
        if risk_rule_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TransactionValidationError::DuplicateRiskRule);
        }
        for rule in &risk_rule_ids {
            validate_token("risk rule id", rule, MAX_RISK_RULE_ID_BYTES)?;
        }

        let mut canonical = Vec::with_capacity(4096);
        encode_str(&mut canonical, "linura.authority-binding.v1")?;
        encode_str(&mut canonical, principal.as_str())?;
        encode_str(&mut canonical, request_id.as_str())?;
        encode_str(&mut canonical, plan_id.as_str())?;
        encode_str(&mut canonical, request_digest.as_str())?;
        encode_str(&mut canonical, precondition_digest.as_str())?;
        encode_str(&mut canonical, observation_digest.as_str())?;
        encode_str(&mut canonical, provider.as_str())?;
        encode_str(&mut canonical, resource.as_str())?;
        encode_str(&mut canonical, capability.as_str())?;
        encode_str(&mut canonical, policy_id.as_str())?;
        encode_str(&mut canonical, policy_revision_id.as_str())?;
        encode_str(&mut canonical, risk_name(trusted_risk))?;
        encode_str(&mut canonical, &risk_policy_revision)?;
        encode_str(&mut canonical, &risk_rule_ids.len().to_string())?;
        for rule in &risk_rule_ids {
            encode_str(&mut canonical, rule)?;
        }
        encode_str(&mut canonical, review_digest.as_str())?;
        match &authorization {
            AuthorizationBasis::PolicyAllow => {
                encode_str(&mut canonical, "policy-allow")?;
            }
            AuthorizationBasis::Approval(approval) => {
                encode_str(&mut canonical, "approval")?;
                encode_str(&mut canonical, approval.evidence_id.as_str())?;
                encode_str(&mut canonical, approval.request_id.as_str())?;
                encode_str(&mut canonical, approval.approver.as_str())?;
                encode_str(&mut canonical, &approval.approval_class)?;
                encode_str(&mut canonical, &approval.issued_at_unix_seconds.to_string())?;
                encode_str(
                    &mut canonical,
                    &approval.expires_at_unix_seconds.to_string(),
                )?;
            }
        }
        if canonical.len() > MAX_AUTHORITY_BINDING_BYTES {
            return Err(TransactionValidationError::BindingTooLarge);
        }
        let digest = digest_bytes("linura.authority-binding.digest.v1", &canonical);

        Ok(Self {
            principal,
            request_id,
            plan_id,
            request_digest,
            precondition_digest,
            observation_digest,
            provider,
            resource,
            capability,
            policy_id,
            policy_revision_id,
            trusted_risk,
            risk_policy_revision,
            risk_rule_ids,
            review_digest,
            authorization,
            canonical,
            digest,
        })
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    #[must_use]
    pub fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    #[must_use]
    pub fn precondition_digest(&self) -> &ContentDigest {
        &self.precondition_digest
    }

    #[must_use]
    pub fn observation_digest(&self) -> &ContentDigest {
        &self.observation_digest
    }

    #[must_use]
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    #[must_use]
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    #[must_use]
    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    #[must_use]
    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    #[must_use]
    pub fn policy_revision_id(&self) -> &PolicyRevisionId {
        &self.policy_revision_id
    }

    #[must_use]
    pub const fn trusted_risk(&self) -> RiskClass {
        self.trusted_risk
    }

    #[must_use]
    pub fn risk_policy_revision(&self) -> &str {
        &self.risk_policy_revision
    }

    #[must_use]
    pub fn risk_rule_ids(&self) -> &[String] {
        &self.risk_rule_ids
    }

    #[must_use]
    pub fn review_digest(&self) -> &ContentDigest {
        &self.review_digest
    }

    #[must_use]
    pub fn authorization(&self) -> &AuthorizationBasis {
        &self.authorization
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    #[must_use]
    pub fn transaction_id(&self) -> TransactionId {
        TransactionId::for_namespace(&self.principal, &self.request_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionState {
    Prepared,
    Indeterminate,
    Verified,
    Committed,
    Aborted,
    RecoveryBlocked,
}

impl TransactionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Indeterminate => "indeterminate",
            Self::Verified => "verified",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::RecoveryBlocked => "recovery-blocked",
        }
    }

    pub fn parse(value: &str) -> Result<Self, TransactionValidationError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "indeterminate" => Ok(Self::Indeterminate),
            "verified" => Ok(Self::Verified),
            "committed" => Ok(Self::Committed),
            "aborted" => Ok(Self::Aborted),
            "recovery-blocked" => Ok(Self::RecoveryBlocked),
            _ => Err(TransactionValidationError::InvalidState),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionSnapshot {
    pub transaction_id: TransactionId,
    pub principal: PrincipalId,
    pub request_id: RequestId,
    pub current_generation: u64,
    pub state_version: u64,
    pub state: TransactionState,
    pub binding_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareOutcome {
    Created(TransactionSnapshot),
    Existing(TransactionSnapshot),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAnchor {
    pub snapshot: TransactionSnapshot,
    pub request_digest: ContentDigest,
    pub precondition_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCommitMaterial {
    pub snapshot: TransactionSnapshot,
    pub desired_state_digest: ContentDigest,
    pub graph_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
}

const AUTHORITY_MUTATION_KEY_BYTES: usize = 32;
const AUTHORITY_MUTATION_TAG_BYTES: usize = 32;
type AuthorityHmac = Hmac<Sha256>;

/// Root secret used by the trusted composition root to split durable mutation
/// authority into a Control-only signer and a persistence-only verifier.
///
/// The key is deliberately non-`Clone`, redacted from `Debug`, and zeroed on
/// drop. Production callers must provision the same protected 256-bit value on
/// restart; persistence pins only its domain-separated fingerprint.
pub struct TransactionAuthorityKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for TransactionAuthorityKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransactionAuthorityKey([REDACTED])")
    }
}

impl Drop for TransactionAuthorityKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn validate_authority_key_bytes(bytes: &mut [u8]) -> Result<(), TransactionValidationError> {
    if bytes.len() != AUTHORITY_MUTATION_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
        bytes.zeroize();
        return Err(TransactionValidationError::InvalidAuthorityKey);
    }
    Ok(())
}

impl TransactionAuthorityKey {
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, TransactionValidationError> {
        validate_authority_key_bytes(&mut bytes)?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn split(self) -> (TransactionAuthoritySigner, TransactionAuthorityVerifier) {
        let signer = TransactionAuthoritySigner {
            bytes: self.bytes.clone(),
        };
        let verifier = TransactionAuthorityVerifier {
            bytes: self.bytes.clone(),
        };
        (signer, verifier)
    }
}

/// Control-side capability for sealing authority-sensitive durable mutations.
pub struct TransactionAuthoritySigner {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for TransactionAuthoritySigner {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransactionAuthoritySigner([REDACTED])")
    }
}

impl Drop for TransactionAuthoritySigner {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Persistence-side capability. It can validate sealed mutation requests but
/// cannot construct them through the public API.
pub struct TransactionAuthorityVerifier {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for TransactionAuthorityVerifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransactionAuthorityVerifier")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Drop for TransactionAuthorityVerifier {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl TransactionAuthorityVerifier {
    #[must_use]
    pub fn fingerprint(&self) -> ContentDigest {
        digest_bytes(
            "linura.transaction-authority.verifier-fingerprint.v1",
            &self.bytes,
        )
    }

    #[must_use]
    pub fn verify_handoff(&self, request: &HandoffRequest) -> bool {
        verify_authority_tag(
            &self.bytes,
            "linura.transaction-authority.handoff.v1",
            &request.canonical_bytes(),
            &request.authority_tag,
        )
    }

    #[must_use]
    pub fn verify_recovery(&self, request: &RecoveryRequest) -> bool {
        verify_authority_tag(
            &self.bytes,
            "linura.transaction-authority.recovery.v1",
            &request.canonical_bytes(),
            &request.authority_tag,
        )
    }

    #[must_use]
    pub fn verify_commit(&self, request: &CommitRequest) -> bool {
        verify_authority_tag(
            &self.bytes,
            "linura.transaction-authority.commit.v1",
            &request.canonical_bytes(),
            &request.authority_tag,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffRequest {
    transaction_id: TransactionId,
    expected_generation: u64,
    expected_state_version: u64,
    expected_binding_digest: ContentDigest,
    authority_use_digest: ContentDigest,
    authorized_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    authority_tag: [u8; AUTHORITY_MUTATION_TAG_BYTES],
}

impl HandoffRequest {
    #[must_use]
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    #[must_use]
    pub const fn expected_state_version(&self) -> u64 {
        self.expected_state_version
    }

    #[must_use]
    pub fn expected_binding_digest(&self) -> &ContentDigest {
        &self.expected_binding_digest
    }

    #[must_use]
    pub fn authority_use_digest(&self) -> &ContentDigest {
        &self.authority_use_digest
    }

    #[must_use]
    pub const fn authorized_at_unix_ms(&self) -> u64 {
        self.authorized_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut canonical = Vec::with_capacity(256);
        mutation_field(&mut canonical, self.transaction_id.as_str().as_bytes());
        mutation_field(&mut canonical, &self.expected_generation.to_be_bytes());
        mutation_field(&mut canonical, &self.expected_state_version.to_be_bytes());
        mutation_field(
            &mut canonical,
            self.expected_binding_digest.as_str().as_bytes(),
        );
        mutation_field(
            &mut canonical,
            self.authority_use_digest.as_str().as_bytes(),
        );
        mutation_field(&mut canonical, &self.authorized_at_unix_ms.to_be_bytes());
        mutation_field(&mut canonical, &self.expires_at_unix_ms.to_be_bytes());
        canonical
    }
}

impl TransactionAuthoritySigner {
    pub fn authorize_handoff(
        &self,
        snapshot: &TransactionSnapshot,
        authority_use_digest: ContentDigest,
        authorized_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<HandoffRequest, TransactionValidationError> {
        if snapshot.state != TransactionState::Prepared
            || authority_use_digest == ContentDigest::zero()
            || authorized_at_unix_ms == 0
            || expires_at_unix_ms < authorized_at_unix_ms
        {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        let mut request = HandoffRequest {
            transaction_id: snapshot.transaction_id.clone(),
            expected_generation: snapshot.current_generation,
            expected_state_version: snapshot.state_version,
            expected_binding_digest: snapshot.binding_digest.clone(),
            authority_use_digest,
            authorized_at_unix_ms,
            expires_at_unix_ms,
            authority_tag: [0; AUTHORITY_MUTATION_TAG_BYTES],
        };
        request.authority_tag = authority_tag(
            &self.bytes,
            "linura.transaction-authority.handoff.v1",
            &request.canonical_bytes(),
        )?;
        Ok(request)
    }

    pub fn authorize_recovery(
        &self,
        snapshot: &TransactionSnapshot,
        resolution: RecoveryResolution,
        authorized_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<RecoveryRequest, TransactionValidationError> {
        if snapshot.state != TransactionState::Indeterminate
            || authorized_at_unix_ms == 0
            || expires_at_unix_ms < authorized_at_unix_ms
        {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        if let RecoveryResolution::IntendedEffectAbsent { next_binding, .. } = &resolution
            && next_binding.transaction_id() != snapshot.transaction_id
        {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        if let RecoveryResolution::IntendedStateVerified {
            desired_state_digest,
            graph_digest,
            provenance_digest,
            ..
        } = &resolution
            && (desired_state_digest == &ContentDigest::zero()
                || graph_digest == &ContentDigest::zero()
                || provenance_digest == &ContentDigest::zero())
        {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        let mut request = RecoveryRequest {
            transaction_id: snapshot.transaction_id.clone(),
            expected_generation: snapshot.current_generation,
            expected_state_version: snapshot.state_version,
            expected_binding_digest: snapshot.binding_digest.clone(),
            authorized_at_unix_ms,
            expires_at_unix_ms,
            resolution,
            authority_tag: [0; AUTHORITY_MUTATION_TAG_BYTES],
        };
        request.authority_tag = authority_tag(
            &self.bytes,
            "linura.transaction-authority.recovery.v1",
            &request.canonical_bytes(),
        )?;
        Ok(request)
    }

    pub fn authorize_commit(
        &self,
        snapshot: &TransactionSnapshot,
        desired_state_digest: ContentDigest,
        graph_digest: ContentDigest,
        provenance_digest: ContentDigest,
    ) -> Result<CommitRequest, TransactionValidationError> {
        if snapshot.state != TransactionState::Verified
            || desired_state_digest == ContentDigest::zero()
            || graph_digest == ContentDigest::zero()
            || provenance_digest == ContentDigest::zero()
        {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        let mut request = CommitRequest {
            transaction_id: snapshot.transaction_id.clone(),
            expected_generation: snapshot.current_generation,
            expected_state_version: snapshot.state_version,
            expected_binding_digest: snapshot.binding_digest.clone(),
            desired_state_digest,
            graph_digest,
            provenance_digest,
            authority_tag: [0; AUTHORITY_MUTATION_TAG_BYTES],
        };
        request.authority_tag = authority_tag(
            &self.bytes,
            "linura.transaction-authority.commit.v1",
            &request.canonical_bytes(),
        )?;
        Ok(request)
    }
}

fn authority_tag(
    key: &[u8],
    domain: &str,
    canonical: &[u8],
) -> Result<[u8; AUTHORITY_MUTATION_TAG_BYTES], TransactionValidationError> {
    let mut mac = AuthorityHmac::new_from_slice(key)
        .map_err(|_| TransactionValidationError::InvalidAuthorityKey)?;
    mutation_mac_input(&mut mac, domain, canonical);
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0; AUTHORITY_MUTATION_TAG_BYTES];
    tag.copy_from_slice(&bytes);
    Ok(tag)
}

fn verify_authority_tag(
    key: &[u8],
    domain: &str,
    canonical: &[u8],
    tag: &[u8; AUTHORITY_MUTATION_TAG_BYTES],
) -> bool {
    let Ok(mut mac) = AuthorityHmac::new_from_slice(key) else {
        return false;
    };
    mutation_mac_input(&mut mac, domain, canonical);
    mac.verify_slice(tag).is_ok()
}

fn mutation_mac_input(mac: &mut AuthorityHmac, domain: &str, canonical: &[u8]) {
    mac.update(
        &u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    mac.update(domain.as_bytes());
    mac.update(
        &u64::try_from(canonical.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    mac.update(canonical);
}

fn mutation_field(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    buffer.extend_from_slice(bytes);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffCommit {
    pub transaction_id: TransactionId,
    pub generation: u64,
    pub state_version: u64,
    pub binding_digest: ContentDigest,
    pub authority_use_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryResolution {
    IntendedStateVerified {
        observation_digest: ContentDigest,
        desired_state_digest: ContentDigest,
        graph_digest: ContentDigest,
        provenance_digest: ContentDigest,
    },
    IntendedEffectAbsent {
        observation_digest: ContentDigest,
        next_binding: Box<AuthorityBinding>,
    },
    ConflictingState {
        observation_digest: ContentDigest,
    },
    Ambiguous {
        observation_digest: ContentDigest,
    },
}

impl RecoveryResolution {
    fn canonical_fields(&self, canonical: &mut Vec<u8>) {
        match self {
            Self::IntendedStateVerified {
                observation_digest,
                desired_state_digest,
                graph_digest,
                provenance_digest,
            } => {
                mutation_field(canonical, b"intended-state-verified");
                mutation_field(canonical, observation_digest.as_str().as_bytes());
                mutation_field(canonical, desired_state_digest.as_str().as_bytes());
                mutation_field(canonical, graph_digest.as_str().as_bytes());
                mutation_field(canonical, provenance_digest.as_str().as_bytes());
            }
            Self::IntendedEffectAbsent {
                observation_digest,
                next_binding,
            } => {
                mutation_field(canonical, b"intended-effect-absent");
                mutation_field(canonical, observation_digest.as_str().as_bytes());
                mutation_field(canonical, next_binding.digest().as_str().as_bytes());
            }
            Self::ConflictingState { observation_digest } => {
                mutation_field(canonical, b"conflicting-state");
                mutation_field(canonical, observation_digest.as_str().as_bytes());
            }
            Self::Ambiguous { observation_digest } => {
                mutation_field(canonical, b"ambiguous");
                mutation_field(canonical, observation_digest.as_str().as_bytes());
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRequest {
    transaction_id: TransactionId,
    expected_generation: u64,
    expected_state_version: u64,
    expected_binding_digest: ContentDigest,
    authorized_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    resolution: RecoveryResolution,
    authority_tag: [u8; AUTHORITY_MUTATION_TAG_BYTES],
}

impl RecoveryRequest {
    #[must_use]
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    #[must_use]
    pub const fn expected_state_version(&self) -> u64 {
        self.expected_state_version
    }

    #[must_use]
    pub fn expected_binding_digest(&self) -> &ContentDigest {
        &self.expected_binding_digest
    }

    #[must_use]
    pub const fn authorized_at_unix_ms(&self) -> u64 {
        self.authorized_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn resolution(&self) -> &RecoveryResolution {
        &self.resolution
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut canonical = Vec::with_capacity(320);
        mutation_field(&mut canonical, self.transaction_id.as_str().as_bytes());
        mutation_field(&mut canonical, &self.expected_generation.to_be_bytes());
        mutation_field(&mut canonical, &self.expected_state_version.to_be_bytes());
        mutation_field(
            &mut canonical,
            self.expected_binding_digest.as_str().as_bytes(),
        );
        mutation_field(&mut canonical, &self.authorized_at_unix_ms.to_be_bytes());
        mutation_field(&mut canonical, &self.expires_at_unix_ms.to_be_bytes());
        self.resolution.canonical_fields(&mut canonical);
        canonical
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    Verified(TransactionSnapshot),
    Reprepared(TransactionSnapshot),
    Blocked(TransactionSnapshot),
    StillIndeterminate(TransactionSnapshot),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRequest {
    transaction_id: TransactionId,
    expected_generation: u64,
    expected_state_version: u64,
    expected_binding_digest: ContentDigest,
    desired_state_digest: ContentDigest,
    graph_digest: ContentDigest,
    provenance_digest: ContentDigest,
    authority_tag: [u8; AUTHORITY_MUTATION_TAG_BYTES],
}

impl CommitRequest {
    #[must_use]
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    #[must_use]
    pub const fn expected_state_version(&self) -> u64 {
        self.expected_state_version
    }

    #[must_use]
    pub fn expected_binding_digest(&self) -> &ContentDigest {
        &self.expected_binding_digest
    }

    #[must_use]
    pub fn desired_state_digest(&self) -> &ContentDigest {
        &self.desired_state_digest
    }

    #[must_use]
    pub fn graph_digest(&self) -> &ContentDigest {
        &self.graph_digest
    }

    #[must_use]
    pub fn provenance_digest(&self) -> &ContentDigest {
        &self.provenance_digest
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut canonical = Vec::with_capacity(384);
        mutation_field(&mut canonical, self.transaction_id.as_str().as_bytes());
        mutation_field(&mut canonical, &self.expected_generation.to_be_bytes());
        mutation_field(&mut canonical, &self.expected_state_version.to_be_bytes());
        mutation_field(
            &mut canonical,
            self.expected_binding_digest.as_str().as_bytes(),
        );
        mutation_field(
            &mut canonical,
            self.desired_state_digest.as_str().as_bytes(),
        );
        mutation_field(&mut canonical, self.graph_digest.as_str().as_bytes());
        mutation_field(&mut canonical, self.provenance_digest.as_str().as_bytes());
        canonical
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortRequest {
    pub transaction_id: TransactionId,
    pub expected_generation: u64,
    pub expected_state_version: u64,
    pub reason_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionStoreError {
    IdempotencyConflict,
    StateConflict,
    NotFound,
    CapacityExceeded,
    AuthorityRejected,
    Corruption(String),
    UnsupportedSchema(String),
    Storage(String),
}

impl Display for TransactionStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdempotencyConflict => f.write_str("durable request idempotency conflict"),
            Self::StateConflict => f.write_str("durable transaction state/version conflict"),
            Self::NotFound => f.write_str("durable transaction not found"),
            Self::CapacityExceeded => f.write_str("durable transaction capacity exceeded"),
            Self::AuthorityRejected => {
                f.write_str("durable transaction mutation authority rejected")
            }
            Self::Corruption(reason) => write!(f, "durable transaction corruption: {reason}"),
            Self::UnsupportedSchema(reason) => {
                write!(f, "unsupported durable transaction schema: {reason}")
            }
            Self::Storage(reason) => write!(f, "durable transaction storage failure: {reason}"),
        }
    }
}

impl std::error::Error for TransactionStoreError {}

pub trait TransactionStore: std::fmt::Debug {
    fn prepare(
        &mut self,
        binding: &AuthorityBinding,
    ) -> Result<PrepareOutcome, TransactionStoreError>;
    fn handoff(&mut self, request: &HandoffRequest)
    -> Result<HandoffCommit, TransactionStoreError>;
    fn recover(
        &mut self,
        request: &RecoveryRequest,
    ) -> Result<RecoveryOutcome, TransactionStoreError>;
    fn commit(
        &mut self,
        request: &CommitRequest,
    ) -> Result<TransactionSnapshot, TransactionStoreError>;
    fn abort_prepared(
        &mut self,
        request: &AbortRequest,
    ) -> Result<TransactionSnapshot, TransactionStoreError>;
    fn snapshot(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<TransactionSnapshot, TransactionStoreError>;
    fn recovery_anchor(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<RecoveryAnchor, TransactionStoreError>;
    fn verified_commit_material(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<VerifiedCommitMaterial, TransactionStoreError>;
    fn list_state(
        &self,
        state: TransactionState,
    ) -> Result<Vec<TransactionSnapshot>, TransactionStoreError>;
    /// A bounded, authenticated snapshot of one opaque request namespace and
    /// state. Persistence owns query mechanics, never namespace authority or
    /// recovery classification. Excess matches fail rather than truncate.
    fn list_state_in_namespace(
        &self,
        state: TransactionState,
        request_prefix: &str,
        maximum: usize,
    ) -> Result<Vec<TransactionSnapshot>, TransactionStoreError>;
    fn integrity_check(&self) -> Result<(), TransactionStoreError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionValidationError {
    InvalidToken(&'static str),
    TokenTooLong(&'static str),
    InvalidDigest,
    BindingTooLarge,
    TooManyRiskRules,
    DuplicateRiskRule,
    InvalidAuthorization,
    InvalidAuthorityKey,
    InvalidAuthorityMutation,
    InvalidState,
    Core(String),
}

impl Display for TransactionValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken(label) => {
                write!(f, "{label} is empty or contains control characters")
            }
            Self::TokenTooLong(label) => write!(f, "{label} exceeds its UTF-8 byte bound"),
            Self::InvalidDigest => f.write_str("content digest must be sha256:<64 lowercase hex>"),
            Self::BindingTooLarge => write!(
                f,
                "authority binding exceeds {MAX_AUTHORITY_BINDING_BYTES} bytes"
            ),
            Self::TooManyRiskRules => {
                write!(f, "authority binding exceeds {MAX_RISK_RULES} risk rules")
            }
            Self::DuplicateRiskRule => {
                f.write_str("authority binding contains duplicate risk rule")
            }
            Self::InvalidAuthorization => f.write_str("authority authorization basis is invalid"),
            Self::InvalidAuthorityKey => {
                f.write_str("durable transaction authority key must be a non-zero 256-bit secret")
            }
            Self::InvalidAuthorityMutation => {
                f.write_str("durable transaction authority mutation request is invalid")
            }
            Self::InvalidState => f.write_str("durable transaction state is invalid"),
            Self::Core(reason) => write!(f, "invalid core identity: {reason}"),
        }
    }
}

impl std::error::Error for TransactionValidationError {}

impl From<ValidationError> for TransactionValidationError {
    fn from(error: ValidationError) -> Self {
        Self::Core(error.to_string())
    }
}

fn validate_token(
    label: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), TransactionValidationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(TransactionValidationError::InvalidToken(label));
    }
    if value.len() > max_bytes {
        return Err(TransactionValidationError::TokenTooLong(label));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::ValidationError;

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn digest(value: &str) -> ContentDigest {
        digest_bytes("test", value.as_bytes())
    }

    fn binding() -> AuthorityBinding {
        AuthorityBinding::try_new(
            id(PrincipalId::new("uid:1000")),
            id(RequestId::new("request:test")),
            id(PlanId::new("request:test")),
            digest("request"),
            digest("precondition"),
            digest("observation"),
            id(ProviderId::new("systemd")),
            id(ResourceId::new("systemd:unit:test.service")),
            id(CapabilityId::new("systemd.unit.observe")),
            id(PolicyId::new("policy:baseline")),
            id(PolicyRevisionId::new("policy:baseline:v1")),
            RiskClass::SecuritySensitive,
            "risk-policy:v0.4:1",
            vec!["systemd.active-state.security".into()],
            digest("review"),
            AuthorizationBasis::PolicyAllow,
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn transaction_id_is_stable_for_principal_request_namespace() {
        let binding = binding();
        assert_eq!(
            binding.transaction_id(),
            TransactionId::for_namespace(binding.principal(), binding.request_id())
        );
        let other =
            TransactionId::for_namespace(&id(PrincipalId::new("uid:1001")), binding.request_id());
        assert_ne!(binding.transaction_id(), other);
    }

    #[test]
    fn binding_digest_changes_with_authority_material() {
        let original = binding();
        let changed = AuthorityBinding::try_new(
            original.principal().clone(),
            original.request_id().clone(),
            original.plan_id().clone(),
            original.request_digest().clone(),
            original.precondition_digest().clone(),
            digest("different-observation"),
            original.provider().clone(),
            original.resource().clone(),
            original.capability().clone(),
            original.policy_id().clone(),
            original.policy_revision_id().clone(),
            original.trusted_risk(),
            original.risk_policy_revision(),
            original.risk_rule_ids().to_vec(),
            original.review_digest().clone(),
            original.authorization().clone(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(original.digest(), changed.digest());
        assert_ne!(original.canonical_bytes(), changed.canonical_bytes());
    }

    #[test]
    fn risk_rules_are_canonicalized_and_duplicates_fail_closed() {
        let original = binding();
        let reordered = AuthorityBinding::try_new(
            original.principal().clone(),
            original.request_id().clone(),
            original.plan_id().clone(),
            original.request_digest().clone(),
            original.precondition_digest().clone(),
            original.observation_digest().clone(),
            original.provider().clone(),
            original.resource().clone(),
            original.capability().clone(),
            original.policy_id().clone(),
            original.policy_revision_id().clone(),
            original.trusted_risk(),
            original.risk_policy_revision(),
            vec!["z".into(), "a".into()],
            original.review_digest().clone(),
            original.authorization().clone(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            reordered.risk_rule_ids(),
            &["a".to_string(), "z".to_string()]
        );
        assert!(matches!(
            AuthorityBinding::try_new(
                original.principal().clone(),
                original.request_id().clone(),
                original.plan_id().clone(),
                original.request_digest().clone(),
                original.precondition_digest().clone(),
                original.observation_digest().clone(),
                original.provider().clone(),
                original.resource().clone(),
                original.capability().clone(),
                original.policy_id().clone(),
                original.policy_revision_id().clone(),
                original.trusted_risk(),
                original.risk_policy_revision(),
                vec!["dup".into(), "dup".into()],
                original.review_digest().clone(),
                original.authorization().clone(),
            ),
            Err(TransactionValidationError::DuplicateRiskRule)
        ));
    }

    #[test]
    fn rejected_authority_key_material_is_zeroized_before_error() {
        let mut rejected = vec![0xa5; AUTHORITY_MUTATION_KEY_BYTES - 1];
        assert!(matches!(
            validate_authority_key_bytes(&mut rejected),
            Err(TransactionValidationError::InvalidAuthorityKey)
        ));
        assert!(rejected.iter().all(|byte| *byte == 0));
    }
}
