//! S18-6 radio: non-authorizing correlation with the original local login.
//!
//! A root Control process, network provider alias, session string, ordinary
//! Polkit success or this witness cannot issue a radio effect. Only the
//! original, live logind subject is eligible for a future separately protected
//! consent and durable single-dispatch handoff. No native mutation lives here.

use super::*;
use linura_core::{NetworkManagerEpoch, NetworkObservationId};

const MAX_AGE_US: u64 = 5_000_000;
const RADIO_REQUEST_PREFIX: &str = "request:v010:network-radio:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRadioAction {
    NetworkingEnabled,
    WifiEnabled,
}

impl NativeRadioAction {
    #[must_use]
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::NetworkingEnabled => "operation:network.networking.set-enabled",
            Self::WifiEnabled => "operation:network.wifi.set-enabled",
        }
    }

    /// The NetworkManager-owned Polkit action for the actual radio operation.
    /// These may never be chosen by an untrusted request, client or agent.
    #[must_use]
    pub const fn networkmanager_polkit_action(self) -> &'static str {
        match self {
            Self::NetworkingEnabled => "org.freedesktop.NetworkManager.enable-disable-network",
            Self::WifiEnabled => "org.freedesktop.NetworkManager.enable-disable-wifi",
        }
    }

    /// Protected consent is anchored to the exact operation and desired state.
    #[must_use]
    const fn request_slug(self, enabled: bool) -> &'static str {
        match (self, enabled) {
            (Self::NetworkingEnabled, true) => "networking-enable-",
            (Self::NetworkingEnabled, false) => "networking-disable-",
            (Self::WifiEnabled, true) => "wifi-enable-",
            (Self::WifiEnabled, false) => "wifi-disable-",
        }
    }
}

/// Input is only correlation. No fields are native effect authority or
/// instructions for an arbitrary NetworkManager D-Bus method.
#[derive(Clone, Debug)]
pub struct NativeRadioSubjectRequest {
    pub lock: SessionLockId,
    pub network: NetworkManagerEpoch,
    pub observation: NetworkObservationId,
    pub principal: PrincipalId,
    pub seat: String,
    pub action: NativeRadioAction,
    pub desired_enabled: bool,
    pub request: RequestId,
    pub request_digest: ComponentDigest,
    pub observation_digest: ComponentDigest,
    pub review_digest: ComponentDigest,
}

fn valid_request_shape(principal: &str, original_uid: u32, seat: &str, request_id: &str) -> bool {
    if original_uid == 0
        || principal != format!("unix:uid:{original_uid}")
        || !(5..=32).contains(&seat.len())
        || !seat.starts_with("seat")
        || (seat.len() > 5 && seat.as_bytes()[4] == b'0')
        || !seat[4..].bytes().all(|ch| ch.is_ascii_digit())
    {
        return false;
    }
    let Some(slug) = request_id.strip_prefix(RADIO_REQUEST_PREFIX) else {
        return false;
    };
    !slug.is_empty()
        && slug.len() <= 64
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
        && slug
            .bytes()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-')
}

impl NativeRadioSubjectRequest {
    /// Bind the separately protected native consent to the *exact* original
    /// Control review. This does not authenticate NetworkManager's actual
    /// D-Bus sender, issue a Polkit effect permission or spend durable authority.
    pub(super) fn bind_original_approval(
        &self,
        approval: &NativeApprovalRequest,
    ) -> Result<(), String> {
        let action_scope = self
            .request
            .as_str()
            .strip_prefix(RADIO_REQUEST_PREFIX)
            .and_then(|value| value.strip_prefix(self.action.request_slug(self.desired_enabled)))
            .filter(|suffix| !suffix.is_empty());
        if action_scope.is_none()
            || approval.purpose != NativeApprovalPurpose::NetworkRadio
            || approval.transition.is_some()
            || approval.lock != self.lock
            || approval.principal != self.principal
            || approval.request != self.request
            || approval.plan.as_str() != self.request.as_str()
            || approval.request_digest != self.request_digest
            || approval.observation_digest != self.observation_digest
            || approval.review_digest != self.review_digest
        {
            return Err("radio subject is not bound to the exact original native consent".into());
        }
        approval.wire().map(|_| ())
    }

    /// Cross-check the exact original protected approval and durable effect
    /// correlation. The ExecutionBinding is supplied data, not a Control
    /// DispatchPermit; success here never grants native mutation authority.
    pub fn bind_managed_radio_effect(
        &self,
        approval: &NativeApprovalRequest,
        control_principal: &PrincipalId,
        control_request: &RequestId,
        control_transaction_id: &str,
        effect: &linura_provider_sdk::EffectDescriptor,
        binding: &linura_provider_sdk::ExecutionBinding,
    ) -> Result<(), String> {
        self.bind_original_approval(approval)?;
        // The native owner binds the approved original session and request.
        // Only Control may derive the authoritative durable transaction ID.
        if &self.principal != control_principal || &self.request != control_request {
            return Err("native radio owner differs from original Control request".into());
        }
        exact_managed_radio_correlation(
            self.action,
            self.desired_enabled,
            control_transaction_id,
            effect,
            binding,
        )
    }

    fn validate(&self, boot_us: u64) -> Result<(), String> {
        if !valid_request_shape(
            self.principal.as_str(),
            self.lock.epoch().uid(),
            &self.seat,
            self.request.as_str(),
        ) {
            return Err("native radio request is not the original local login".into());
        }
        if self.network.boot() != self.lock.epoch().boot() {
            return Err("native radio request boot is not the login boot".into());
        }
        self.observation
            .require_fresh(&self.network, boot_us, MAX_AGE_US)
            .map_err(|_| "native radio observation is stale or from a different provider".into())
    }
}

fn exact_managed_radio_correlation(
    action: NativeRadioAction,
    enabled: bool,
    control_transaction_id: &str,
    effect: &linura_provider_sdk::EffectDescriptor,
    binding: &linura_provider_sdk::ExecutionBinding,
) -> Result<(), String> {
    let (operation, property) = match action {
        NativeRadioAction::NetworkingEnabled => ("set-networking-enabled", "NetworkingEnabled"),
        NativeRadioAction::WifiEnabled => ("set-wifi-enabled", "WirelessEnabled"),
    };
    let canonical =
        format!("manager=networkmanager:manager\nproperty={property}\nenabled={enabled}\n");
    if control_transaction_id.is_empty()
        || control_transaction_id.len() > 256
        || effect.provider.as_str() != "networkmanager"
        || effect.resource.as_str() != "networkmanager:manager"
        || effect.operation != operation
        || effect.canonical_payload != canonical.as_bytes()
        || binding.transaction_id != control_transaction_id
        || binding.validate_for(effect).is_err()
    {
        return Err("radio effect does not match original review and durable request".into());
    }
    Ok(())
}

/// Sealed proof of subject *correlation*, not human consent. The transport
/// caller must NOT use this as a one-use permission or execution credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRadioSubjectCorrelation {
    subject: NativeAuthenticationSubject,
    network: NetworkManagerEpoch,
    seat: String,
    action: NativeRadioAction,
    requested_enabled: bool,
}

/// Noninteractive, policy-only observation. A positive Polkit decision
/// is NOT authority to issue a NetworkManager mutation as the original user,
/// is NOT human consent, and cannot be replayed as a prepared Control effect.
#[derive(Clone, Debug)]
pub struct NativeRadioPolicyObservation {
    subject: NativeRadioSubjectCorrelation,
    sampled_at: Instant,
    polkit_permitted: bool,
}

impl NativeRadioPolicyObservation {
    #[must_use]
    pub const fn subject(&self) -> &NativeRadioSubjectCorrelation {
        &self.subject
    }

    #[must_use]
    pub const fn polkit_permitted(&self) -> bool {
        self.polkit_permitted
    }

    #[must_use]
    pub fn age(&self) -> Duration {
        self.sampled_at.elapsed()
    }

    /// Explicitly separate a noninteractive policy query from the
    /// original-subject, one-use, durable execution permission.
    #[must_use]
    pub const fn grants_network_mutation(&self) -> bool {
        false
    }
}

fn parse_polkit_result(authorized: bool, challenge: bool) -> Result<bool, String> {
    if authorized && challenge {
        return Err("native NetworkManager policy result is contradictory".into());
    }
    Ok(authorized && !challenge)
}

impl NativeRadioSubjectCorrelation {
    #[must_use]
    pub const fn subject(&self) -> &NativeAuthenticationSubject {
        &self.subject
    }

    #[must_use]
    pub const fn network(&self) -> &NetworkManagerEpoch {
        &self.network
    }

    #[must_use]
    pub fn seat(&self) -> &str {
        &self.seat
    }

    #[must_use]
    pub const fn action(&self) -> NativeRadioAction {
        self.action
    }

    #[must_use]
    pub const fn requested_enabled(&self) -> bool {
        self.requested_enabled
    }

    /// Authenticated user correlation is not authorization or qualified native
    /// recovery. A runtime API must not confuse the two.
    #[must_use]
    pub const fn grants_network_mutation(&self) -> bool {
        false
    }
}

impl NativeSessionChannel {
    /// Repeat native owner, original logind login and real polkitd process
    /// attestations; fail closed on any replacement or expired bounded probe.
    /// Query NetworkManager's *own* fixed Polkit action against the exact
    /// original logind process (PID + kernel start-time + UID), with user
    /// interaction explicitly disabled. This does not issue a native effect,
    /// perform an NM D-Bus call or carry a reusable permit.
    pub fn observe_radio_policy(
        &self,
        request: &NativeRadioSubjectRequest,
        approval: &NativeApprovalRequest,
    ) -> Result<NativeRadioPolicyObservation, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let first = self.observe_original_radio_subject(request, approval)?;
        let daemon = self.authentication_daemon()?;
        let original = first.subject();
        let uid = i32::try_from(original.uid)
            .map_err(|_| "native radio policy UID exceeds Polkit bounds")?;
        let facts = HashMap::from([
            ("pid", zbus::zvariant::Value::U32(original.pid)),
            (
                "start-time",
                zbus::zvariant::Value::U64(original.start_ticks),
            ),
            ("uid", zbus::zvariant::Value::I32(uid)),
        ]);
        let detail = HashMap::<String, String>::new();
        let reply = self.call_with_budget(
            &daemon.unique_name,
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
            "CheckAuthorization",
            &(
                ("unix-process", facts),
                request.action.networkmanager_polkit_action(),
                detail,
                0_u32, // Query only. Never request a second authentication prompt.
                "",
            ),
            owner_reply_budget(started.elapsed())?,
        )?;
        let ((authorized, challenge, _details),): ((bool, bool, HashMap<String, String>),) =
            reply.body().deserialize().map_err(|_| {
                "native NetworkManager policy decision has an invalid D-Bus shape".to_owned()
            })?;
        let permitted = parse_polkit_result(authorized, challenge)?;
        if started.elapsed() >= crate::bus::PROBE_BUDGET
            || self.authentication_daemon()? != daemon
            || self.observe_original_radio_subject(request, approval)? != first
        {
            return Err("NetworkManager policy witness crossed a replaced native subject".into());
        }
        Ok(NativeRadioPolicyObservation {
            subject: first,
            sampled_at: Instant::now(),
            polkit_permitted: permitted,
        })
    }

    pub fn observe_original_radio_subject(
        &self,
        request: &NativeRadioSubjectRequest,
        approval: &NativeApprovalRequest,
    ) -> Result<NativeRadioSubjectCorrelation, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let boot_us = boot_ms()?
            .checked_mul(1000)
            .ok_or("native radio monotonic boot clock overflow")?;
        request.validate(boot_us)?;
        request.bind_original_approval(approval)?;
        let epoch = self.supervised_radio_manager(started)?;
        request
            .network
            .require_same(&epoch)
            .map_err(|_| "native radio NetworkManager source changed".to_owned())?;
        let subject = self.authentication_subject(&request.lock)?;
        let seat = self.native_network_seat(&request.lock, &request.seat, started)?;
        let polkit = self.authentication_daemon()?;
        if request.bind_original_approval(approval).is_err()
            || self.supervised_radio_manager(started)? != epoch
            || self.authentication_subject(&request.lock)? != subject
            || self.native_network_seat(&request.lock, &request.seat, started)? != seat
            || self.authentication_daemon()? != polkit
            || current_boot()? != *request.lock.epoch().boot()
            || started.elapsed() >= crate::bus::PROBE_BUDGET
        {
            return Err("native radio original subject, Polkit daemon or NM changed".into());
        }
        Ok(NativeRadioSubjectCorrelation {
            subject,
            network: epoch,
            seat,
            action: request.action,
            requested_enabled: request.desired_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_request_is_exactly_a_local_user_seat_and_canonical_request() {
        assert!(valid_request_shape(
            "unix:uid:1000",
            1000,
            "seat0",
            "request:v010:network-radio:my-request"
        ));
        for principal in ["unix:uid:0", "unix:uid:1001", "uid:1000"] {
            assert!(!valid_request_shape(
                principal,
                1000,
                "seat0",
                "request:v010:network-radio:my-request"
            ));
        }
        for seat in [
            "", "seat", "seat00", "seat1x", "seat-1", "seat001", "seat0/0",
        ] {
            assert!(!valid_request_shape(
                "unix:uid:1000",
                1000,
                seat,
                "request:v010:network-radio:my-request"
            ));
        }
        for request in [
            "request:v010:network-credential:my-request",
            "request:v010:network-radio:",
            "request:v010:network-radio:-bad",
            "request:v010:network-radio:bad--id",
            "request:v010:network-radio:UPPER",
            "request:v010:network-radio:../bad",
        ] {
            assert!(!valid_request_shape(
                "unix:uid:1000",
                1000,
                "seat0",
                request
            ));
        }
        assert!(!valid_request_shape(
            "unix:uid:0",
            0,
            "seat0",
            "request:v010:network-radio:my-request"
        ));
    }

    #[test]
    fn networkmanager_radio_polkit_actions_are_exact_and_noninterchangeable() {
        assert_eq!(
            NativeRadioAction::NetworkingEnabled.networkmanager_polkit_action(),
            "org.freedesktop.NetworkManager.enable-disable-network"
        );
        assert_eq!(
            NativeRadioAction::WifiEnabled.networkmanager_polkit_action(),
            "org.freedesktop.NetworkManager.enable-disable-wifi"
        );
        assert_eq!(
            NativeRadioAction::WifiEnabled.request_slug(false),
            "wifi-disable-"
        );
        assert_eq!(
            NativeRadioAction::NetworkingEnabled.request_slug(true),
            "networking-enable-"
        );
    }

    #[test]
    fn native_polkit_policy_query_rejects_contradictions_and_never_promotes_challenges() {
        assert_eq!(parse_polkit_result(true, false), Ok(true));
        assert_eq!(parse_polkit_result(false, false), Ok(false));
        assert_eq!(parse_polkit_result(false, true), Ok(false));
        assert!(parse_polkit_result(true, true).is_err());
    }

    #[test]
    fn radio_attempt_shape_rejects_substituted_effect_and_durable_identity() {
        use linura_core::{ProviderId, ResourceId};
        use linura_provider_sdk::{ComponentDigest, EffectDescriptor, ExecutionBinding};
        let effect = EffectDescriptor::new(
            ProviderId::new("networkmanager").unwrap_or_else(|e| unreachable!("{e}")),
            ResourceId::new("networkmanager:manager").unwrap_or_else(|e| unreachable!("{e}")),
            "set-wifi-enabled",
            b"manager=networkmanager:manager\nproperty=WirelessEnabled\nenabled=false\n".to_vec(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let transaction = "transaction:v1:radio-fixture";
        let digest =
            ComponentDigest::parse_hex(&"a".repeat(64)).unwrap_or_else(|e| unreachable!("{e}"));
        let binding = ExecutionBinding::new(transaction, 0, 1, digest, digest, &effect)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let check = |e: &EffectDescriptor, b: &ExecutionBinding, enabled| {
            exact_managed_radio_correlation(
                NativeRadioAction::WifiEnabled,
                enabled,
                transaction,
                e,
                b,
            )
        };
        assert!(check(&effect, &binding, false).is_ok());
        assert!(check(&effect, &binding, true).is_err());
        let mut altered = effect.clone();
        altered.operation = "set-networking-enabled".into();
        assert!(check(&altered, &binding, false).is_err());
        altered = effect.clone();
        altered.canonical_payload.push(b'\n');
        assert!(check(&altered, &binding, false).is_err());
        let mut replaced = binding.clone();
        replaced.transaction_id = "transaction:v1:foreign".into();
        assert!(check(&effect, &replaced, false).is_err());
        assert!(
            exact_managed_radio_correlation(
                NativeRadioAction::WifiEnabled,
                false,
                "transaction:v1:another-durable-request",
                &effect,
                &binding,
            )
            .is_err()
        );
        assert!(
            exact_managed_radio_correlation(
                NativeRadioAction::WifiEnabled,
                false,
                "",
                &effect,
                &binding,
            )
            .is_err()
        );
    }

    #[test]
    fn only_the_two_radio_methods_are_classified() {
        assert_eq!(
            NativeRadioAction::NetworkingEnabled.operation_id(),
            "operation:network.networking.set-enabled"
        );
        assert_eq!(
            NativeRadioAction::WifiEnabled.operation_id(),
            "operation:network.wifi.set-enabled"
        );
    }
}
