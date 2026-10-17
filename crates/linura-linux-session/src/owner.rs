//! Root-supervised native owner discovery and bounded private transport only.
//! Neither these identities nor successful calls mint policy/dispatch authority.
mod sleep_fence;

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linura_core::{
    BootId, PlanId, PrincipalId, RequestId, SecurityOwnerInvocationId, SessionLockId,
    SessionTransition, SessionTransitionId,
};
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};
use linura_provider_sdk::ComponentDigest;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::{NativeSessionChannel, NativeSessionRole};

const SYSTEMD: &str = "org.freedesktop.systemd1";
const MANAGER: &str = "/org/freedesktop/systemd1";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const SERVICE: &str = "org.freedesktop.systemd1.Service";
const IMAGE: &str = "/usr/lib/linura/linura-security-owner";
const FRAGMENT: &str = "/usr/lib/systemd/system/linura-security-owner@.service";
const ENDPOINT: &str = "/org/linura/SecurityOwner1";
const INTERFACE: &str = "org.linura.SecurityOwner1";
const VALID_FOR_MS: u64 = 1_999;
type Properties = HashMap<String, OwnedValue>;
type ExecStart = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
type ApprovalWire = (String, String, String, String, String, String, String, u32);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOwnerIdentity {
    unique_name: String,
    uid: u32,
    pid: u32,
    invocation: SecurityOwnerInvocationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAuthenticationSubject {
    pid: u32,
    start_ticks: u64,
    uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeApprovalPurpose {
    Lock,
    Unlock,
    Suspend,
    Logout,
    Reboot,
    PowerOff,
    EnableProtectiveLock,
    RevokeProtectiveLock,
}

/// Correlation with a canonical Control challenge, not an approval credential.
#[derive(Clone, Debug)]
pub struct NativeApprovalRequest {
    pub lock: SessionLockId,
    pub transition: Option<SessionTransitionId>,
    pub principal: PrincipalId,
    pub request: RequestId,
    pub plan: PlanId,
    pub request_digest: ComponentDigest,
    pub observation_digest: ComponentDigest,
    pub review_digest: ComponentDigest,
    pub purpose: NativeApprovalPurpose,
}

impl NativeApprovalRequest {
    fn wire(&self) -> Result<ApprovalWire, String> {
        let (prefix, resource, purpose) = match (self.purpose, &self.transition) {
            (NativeApprovalPurpose::Lock, None) => (
                "request:v010:session-lock:",
                self.lock.resource_id().map_err(|e| e.to_string())?,
                0,
            ),
            (NativeApprovalPurpose::Unlock, None) => (
                "request:v010:session-lock:",
                self.lock.resource_id().map_err(|e| e.to_string())?,
                1,
            ),
            (
                purpose @ (NativeApprovalPurpose::EnableProtectiveLock
                | NativeApprovalPurpose::RevokeProtectiveLock),
                None,
            ) => (
                "request:v010:protective-lock-setting:",
                self.lock.resource_id().map_err(|e| e.to_string())?,
                if purpose == NativeApprovalPurpose::EnableProtectiveLock {
                    6
                } else {
                    7
                },
            ),
            (purpose, Some(transition)) if transition.lock() == &self.lock => {
                let wire_purpose = match (purpose, transition.transition()) {
                    (NativeApprovalPurpose::Suspend, SessionTransition::Suspend { .. }) => 2,
                    (NativeApprovalPurpose::Logout, SessionTransition::Logout) => 3,
                    (NativeApprovalPurpose::Reboot, SessionTransition::Reboot) => 4,
                    (NativeApprovalPurpose::PowerOff, SessionTransition::PowerOff) => 5,
                    _ => return Err("native approval transition/action mismatch".into()),
                };
                (
                    "request:v010:session-transition:",
                    transition.resource_id().map_err(|e| e.to_string())?,
                    wire_purpose,
                )
            }
            _ => return Err("native approval transition scope is absent or substituted".into()),
        };
        let slug = self
            .request
            .as_str()
            .strip_prefix(prefix)
            .ok_or("native approval requires a registered S17 request")?;
        if slug.is_empty()
            || slug.len() > 64
            || slug.starts_with('-')
            || slug.ends_with('-')
            || slug.contains("--")
            || !slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || self.plan.as_str() != self.request.as_str()
            || self.principal.as_str() != format!("unix:uid:{}", self.lock.epoch().uid())
            || self.lock.epoch().uid() == 0
        {
            return Err(
                "native approval scope is noncanonical or belongs to another principal".into(),
            );
        }
        Ok((
            resource.as_str().into(),
            self.principal.as_str().into(),
            self.request.as_str().into(),
            self.plan.as_str().into(),
            format!("sha256:{}", self.request_digest),
            format!("sha256:{}", self.observation_digest),
            format!("sha256:{}", self.review_digest),
            purpose,
        ))
    }
}

impl NativeSessionChannel {
    fn properties(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        started: Instant,
    ) -> Result<Properties, String> {
        self.call(
            owner,
            path,
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &(interface,),
            started,
        )?
        .body()
        .deserialize()
        .map_err(|_| "native service properties are malformed".into())
    }

    fn supervised_owner(
        &self,
        uid: u32,
        started: Instant,
    ) -> Result<(u32, SecurityOwnerInvocationId), String> {
        if uid == 0 {
            return Err("root graphical sessions are unsupported".into());
        }
        let owner: String = self
            .bus_call("GetNameOwner", &(SYSTEMD,), started)?
            .body()
            .deserialize()
            .map_err(|_| "systemd owner is malformed".to_owned())?;
        if !unique_name(&owner) || self.connection_credentials(&owner, started)?.0 != 0 {
            return Err("native systemd owner is not root".into());
        }
        let name = format!("linura-security-owner@{uid}.service");
        let path: OwnedObjectPath = self
            .call(
                &owner,
                MANAGER,
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(name,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native security owner unit is unavailable".to_owned())?;
        if path.as_str().len() > 256
            || !path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
        {
            return Err("native security owner unit handle is unsupported".into());
        }
        let unit = self.properties(&owner, path.as_str(), UNIT, started)?;
        let service = self.properties(&owner, path.as_str(), SERVICE, started)?;
        let result = bind_supervised(
            uid,
            &unit,
            &service,
            immutable_file(Path::new(FRAGMENT), false),
            immutable_file(Path::new(IMAGE), true),
        )?;
        let fresh: String = self
            .bus_call("GetNameOwner", &(SYSTEMD,), started)?
            .body()
            .deserialize()
            .map_err(|_| "systemd owner recheck is malformed".to_owned())?;
        if fresh != owner {
            return Err("systemd ownership changed during attestation".into());
        }
        Ok(result)
    }

    fn connection_credentials(&self, name: &str, started: Instant) -> Result<(u32, u32), String> {
        let properties: Properties = self
            .bus_call("GetConnectionCredentials", &(name,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native bus credentials are malformed".to_owned())?;
        Ok((
            property(&properties, "UnixUserID")?,
            property(&properties, "ProcessID")?,
        ))
    }

    fn discover(&self, uid: u32, started: Instant) -> Result<NativeOwnerIdentity, String> {
        let (pid, invocation) = self.supervised_owner(uid, started)?;
        let names: Vec<String> = self
            .bus_call("ListNames", &(), started)?
            .body()
            .deserialize()
            .map_err(|_| "native bus names are malformed".to_owned())?;
        if names.len() > 256 {
            return Err("native bus enumeration exceeds its bound".into());
        }
        let mut found = None;
        for name in names.iter().filter(|name| unique_name(name)) {
            // A disappearing connection is a failed probe, not negative evidence.
            if self.connection_credentials(name, started)? == (uid, pid) {
                // Official GLib authentication uses its own connection. Select
                // the private runtime endpoint, not an arbitrary connection
                // from the same (independently attested immutable) process.
                let Ok(reply) = self.call(
                    name,
                    ENDPOINT,
                    "org.freedesktop.DBus.Introspectable",
                    "Introspect",
                    &(),
                    started,
                ) else {
                    continue;
                };
                let xml: String = reply
                    .body()
                    .deserialize()
                    .map_err(|_| "native endpoint introspection is malformed".to_owned())?;
                if xml.len() > 16 * 1024
                    || !xml.contains("<interface name=\"org.linura.SecurityOwner1\">")
                {
                    continue;
                }
                if found.is_some() {
                    return Err("native owner has ambiguous bus connections".into());
                }
                found = Some(name.clone());
            }
        }
        let identity = NativeOwnerIdentity {
            unique_name: found.ok_or("native owner has no authenticated bus connection")?,
            uid,
            pid,
            invocation,
        };
        self.revalidate(&identity, started)?;
        Ok(identity)
    }

    fn revalidate(&self, identity: &NativeOwnerIdentity, started: Instant) -> Result<(), String> {
        if self.supervised_owner(identity.uid, started)?
            != (identity.pid, identity.invocation.clone())
            || self.connection_credentials(&identity.unique_name, started)?
                != (identity.uid, identity.pid)
        {
            return Err("native security owner changed during the operation".into());
        }
        Ok(())
    }

    /// Discover the current generation from native evidence, never a UI hint.
    pub fn observe_current_lock(
        &self,
        uid: u32,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let boot = current_boot()?;
        let identity = self.discover(uid, started)?;
        let reply = self.call(
            &identity.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObserveLock",
            &(),
            started,
        )?;
        require_observation_signature(&reply)?;
        let ((resource, secure, sampled_boot_ms),): ((String, bool, u64),) = reply
            .body()
            .deserialize()
            .map_err(|_| "native lock observation codec mismatch".to_owned())?;
        self.revalidate(&identity, started)?;
        if current_boot()? != boot {
            return Err("native boot changed during observation".into());
        }
        // Read wall time first: time spent between the two clock reads must
        // shorten validity, never freshen the native sample.
        let now_unix_ms = unix_ms()?;
        observation(
            &identity,
            &boot,
            &resource,
            secure,
            sampled_boot_ms,
            boot_ms()?,
            now_unix_ms,
            sequence,
        )
    }

    pub fn observe_lock(
        &self,
        lock: &SessionLockId,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        let observation = self.observe_current_lock(lock.epoch().uid(), sequence)?;
        if observation.resource != lock.resource_id().map_err(|e| e.to_string())? {
            return Err("native lock generation differs from the requested generation".into());
        }
        Ok(observation)
    }

    pub fn authentication_subject(
        &self,
        lock: &SessionLockId,
    ) -> Result<NativeAuthenticationSubject, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let identity = self.discover(lock.epoch().uid(), started)?;
        if identity.invocation != *lock.security_owner_invocation()
            || current_boot()? != *lock.epoch().boot()
        {
            return Err("authentication subject refers to a replaced native owner/boot".into());
        }
        // The separately supervised locker is not itself in the graphical
        // login. Authenticate against that login's freshly attested compositor
        // leader process, where the native listener registered its narrow scope.
        let owner: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native logind owner is unavailable".to_owned())?;
        if self.connection_credentials(&owner, started)?.0 != 0 {
            return Err("native logind owner is not root".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &owner,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "GetSession",
                &(lock.epoch().session_id(),),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native authentication session is unavailable".to_owned())?;
        if path.as_str().len() > 256
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err("native authentication session handle is unsupported".into());
        }
        let facts = self.properties(
            &owner,
            path.as_str(),
            "org.freedesktop.login1.Session",
            started,
        )?;
        let pid = authentication_leader(lock, &facts)?;
        let start_ticks = process_start(pid)?;
        let fresh = self.properties(
            &owner,
            path.as_str(),
            "org.freedesktop.login1.Session",
            started,
        )?;
        if authentication_leader(lock, &fresh)? != pid
            || process_start(pid)? != start_ticks
            || current_boot()? != *lock.epoch().boot()
        {
            return Err("native authentication process/session changed during attestation".into());
        }
        self.revalidate(&identity, started)?;
        let fresh_owner: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.login1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native logind owner recheck failed".to_owned())?;
        if fresh_owner != owner {
            return Err("native logind owner changed during authentication attestation".into());
        }
        Ok(NativeAuthenticationSubject {
            pid,
            start_ticks,
            uid: lock.epoch().uid(),
        })
    }

    /// Authentication is requested on the SAME named Control connection that
    /// armed the exact native scope. Polkit supplies this process identity to
    /// its agent; custom CheckAuthorization details are not forwarded there.
    /// A positive authorization is still not the one-use native approval.
    pub fn authenticate_approval(
        &self,
        request: &NativeApprovalRequest,
        budget: Duration,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        request.wire()?;
        let action = authentication_action(request.purpose)?;
        if budget.is_zero() || budget > crate::bus::INTERACTION_BUDGET {
            return Err("owner authentication purpose or budget is unsupported".into());
        }
        let started = Instant::now();
        let subject = self.authentication_subject(&request.lock)?;
        let daemon = self.authentication_daemon()?;
        let cancellation = format!("linura-s17:{}", request.request.as_str());
        let details = HashMap::<String, String>::new();
        let facts = HashMap::from([
            ("pid", zbus::zvariant::Value::U32(subject.pid)),
            (
                "start-time",
                zbus::zvariant::Value::U64(subject.start_ticks),
            ),
            (
                "uid",
                zbus::zvariant::Value::I32(
                    i32::try_from(subject.uid).map_err(|_| "authentication UID is unsupported")?,
                ),
            ),
        ]);
        let reply = self.call_with_budget(
            &daemon,
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
            "CheckAuthorization",
            &(
                ("unix-process", facts),
                action,
                details,
                1_u32,
                cancellation.as_str(),
            ),
            budget.saturating_sub(started.elapsed()),
        );
        if reply.is_err() {
            // Dropping a local pending reply does not cancel a remote prompt.
            // Cancel only this connection's fixed request, never another caller.
            let _cancelled = self.call(
                &daemon,
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
                "CancelCheckAuthorization",
                &(cancellation,),
                Instant::now(),
            );
        }
        let reply = reply?;
        let ((authorized, challenge, _details),): ((bool, bool, HashMap<String, String>),) = reply
            .body()
            .deserialize()
            .map_err(|_| "native authentication result is malformed".to_owned())?;
        if !authorized
            || challenge
            || started.elapsed() >= budget
            || self.authentication_daemon()? != daemon
            || self.authentication_subject(&request.lock)? != subject
        {
            return Err("native owner authentication was denied, stale or changed identity".into());
        }
        Ok(())
    }

    /// Read native OS permission through the attested SAME-UID owner. Control
    /// cannot inspect vendor actions on a different UID's behalf. This fixed
    /// endpoint cannot prompt, arm approval or dispatch any operation.
    pub fn observe_power_permission(
        &self,
        transition: &SessionTransitionId,
        sequence: u64,
    ) -> Result<ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        if sequence == 0 {
            return Err("native permission observation sequence is invalid".into());
        }
        if transition.transition() == SessionTransition::Logout {
            return Err("logout is not a machine-power permission query".into());
        }
        let started = Instant::now();
        let lock = transition.lock();
        let identity = self.discover(lock.epoch().uid(), started)?;
        let resource = transition.resource_id().map_err(|e| e.to_string())?;
        if identity.invocation != *lock.security_owner_invocation()
            || current_boot()? != *lock.epoch().boot()
        {
            return Err("native permission target has a replaced owner/boot".into());
        }
        let reply = self.call(
            &identity.unique_name,
            ENDPOINT,
            INTERFACE,
            "ObservePowerPermission",
            &(resource.as_str(),),
            started,
        )?;
        if reply.body().signature().to_string() != "(sst)" {
            return Err("native permission observation has a noncanonical signature".into());
        }
        let ((received_resource, availability, sampled_boot_ms),): ((String, String, u64),) = reply
            .body()
            .deserialize()
            .map_err(|_| "native permission reply is malformed".to_owned())?;
        self.revalidate(&identity, started)?;
        if current_boot()? != *lock.epoch().boot() {
            return Err("native permission observation crossed a boot".into());
        }
        let now_unix_ms = unix_ms()?;
        power_permission_observation(
            transition,
            &received_resource,
            &availability,
            sampled_boot_ms,
            boot_ms()?,
            now_unix_ms,
            sequence,
        )
    }

    fn authentication_daemon(&self) -> Result<String, String> {
        let started = Instant::now();
        let owner: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.PolicyKit1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native authentication daemon is unavailable".to_owned())?;
        if !unique_name(&owner) || self.connection_credentials(&owner, started)?.0 != 0 {
            return Err("native authentication daemon has an unsupported identity".into());
        }
        Ok(owner)
    }

    fn approval_call(&self, request: &NativeApprovalRequest, method: &str) -> Result<bool, String> {
        self.require_role(NativeSessionRole::Control)?;
        let wire = request.wire()?;
        let started = Instant::now();
        let identity = self.discover(request.lock.epoch().uid(), started)?;
        if identity.invocation != *request.lock.security_owner_invocation()
            || current_boot()? != *request.lock.epoch().boot()
        {
            return Err("approval refers to a replaced native owner/boot".into());
        }
        let (result,): (bool,) = self
            .call(
                &identity.unique_name,
                ENDPOINT,
                INTERFACE,
                method,
                &(wire,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native approval result is malformed".to_owned())?;
        self.revalidate(&identity, started)?;
        Ok(result)
    }

    pub fn arm_approval(&self, request: &NativeApprovalRequest) -> Result<bool, String> {
        self.approval_call(request, "ArmApproval")
    }
    pub fn consume_approval(&self, request: &NativeApprovalRequest) -> Result<bool, String> {
        self.approval_call(request, "ConsumeApproval")
    }

    pub fn cancel_approval(&self, uid: u32) -> Result<(), String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let identity = self.discover(uid, started)?;
        self.call(
            &identity.unique_name,
            ENDPOINT,
            INTERFACE,
            "CancelApproval",
            &(),
            started,
        )?;
        self.revalidate(&identity, started)
    }

    fn lock_call(
        &self,
        role: NativeSessionRole,
        lock: &SessionLockId,
        method: &str,
        secure: Option<bool>,
    ) -> Result<bool, String> {
        self.require_role(role)?;
        let started = Instant::now();
        let identity = self.discover(lock.epoch().uid(), started)?;
        if identity.invocation != *lock.security_owner_invocation()
            || current_boot()? != *lock.epoch().boot()
        {
            return Err("dispatch/acknowledgement refers to a replaced native owner/boot".into());
        }
        let resource = lock.resource_id().map_err(|e| e.to_string())?;
        let reply = match secure {
            Some(secure) => self.call(
                &identity.unique_name,
                ENDPOINT,
                INTERFACE,
                method,
                &(resource.as_str(), secure),
                started,
            )?,
            None => self.call(
                &identity.unique_name,
                ENDPOINT,
                INTERFACE,
                method,
                &(resource.as_str(),),
                started,
            )?,
        };
        let (result,): (bool,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native lock call result is malformed".to_owned())?;
        self.revalidate(&identity, started)?;
        Ok(result)
    }

    /// Mechanism port for the narrow root executor AFTER durable authorization.
    /// A true reply is dispatch acknowledgement, never independent verification.
    pub fn dispatch_prepared_lock(
        &self,
        lock: &SessionLockId,
        secure: bool,
    ) -> Result<bool, String> {
        self.lock_call(
            NativeSessionRole::Executor,
            lock,
            "DispatchPreparedLock",
            Some(secure),
        )
    }
    pub fn verify_released(&self, lock: &SessionLockId) -> Result<bool, String> {
        self.lock_call(NativeSessionRole::Control, lock, "VerifyReleased", None)
    }
    /// Call only after Control has durably committed the verified release.
    pub fn commit_verified_release(&self, lock: &SessionLockId) -> Result<bool, String> {
        self.lock_call(
            NativeSessionRole::Control,
            lock,
            "CommitVerifiedRelease",
            None,
        )
    }
}

fn authentication_action(purpose: NativeApprovalPurpose) -> Result<&'static str, String> {
    Ok(match purpose {
        NativeApprovalPurpose::Unlock => "org.linura.authority.unlock-session",
        NativeApprovalPurpose::Suspend => "org.linura.authority.suspend-session",
        NativeApprovalPurpose::Logout => "org.linura.authority.logout-session",
        NativeApprovalPurpose::Reboot => "org.linura.authority.reboot-session",
        NativeApprovalPurpose::PowerOff => "org.linura.authority.power-off-session",
        NativeApprovalPurpose::EnableProtectiveLock => {
            "org.linura.authority.enable-protective-lock"
        }
        NativeApprovalPurpose::RevokeProtectiveLock => {
            "org.linura.authority.revoke-protective-lock"
        }
        NativeApprovalPurpose::Lock => return Err("lock confirmation is not a PAM action".into()),
    })
}

#[allow(clippy::too_many_arguments)]
fn power_permission_observation(
    transition: &SessionTransitionId,
    resource: &str,
    availability: &str,
    sampled_boot_ms: u64,
    now_boot_ms: u64,
    now_unix_ms: u64,
    sequence: u64,
) -> Result<ObservationEnvelope, String> {
    let age = now_boot_ms
        .checked_sub(sampled_boot_ms)
        .ok_or("native permission sample is in the future")?;
    let expected = transition.resource_id().map_err(|e| e.to_string())?;
    if sequence == 0
        || sampled_boot_ms == 0
        || age > VALID_FOR_MS
        || resource != expected.as_str()
        || !matches!(availability, "yes" | "no" | "challenge")
        || transition.transition() == SessionTransition::Logout
    {
        return Err("native permission observation is stale, unsupported or substituted".into());
    }
    let lock = transition.lock();
    let observed_at_unix_ms = now_unix_ms
        .checked_sub(age)
        .filter(|ms| *ms != 0)
        .ok_or("native permission wall-clock mapping underflow")?;
    Ok(ObservationEnvelope {
        provider: linura_core::ProviderId::new("polkit").map_err(|e| e.to_string())?,
        resource: transition
            .permission_resource_id()
            .map_err(|e| e.to_string())?,
        capability: linura_core::CapabilityId::new("session.power.permission.observe")
            .map_err(|e| e.to_string())?,
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms,
        valid_for_ms: VALID_FOR_MS,
        sequence,
        attributes: std::collections::BTreeMap::from([
            (
                "permission_query_principal".into(),
                ObservedValue::Text(format!("unix:uid:{}", lock.epoch().uid())),
            ),
            (
                "permission_query_session_epoch".into(),
                ObservedValue::Text(
                    lock.epoch()
                        .resource_id()
                        .map_err(|e| e.to_string())?
                        .as_str()
                        .into(),
                ),
            ),
            (
                "availability".into(),
                ObservedValue::Text(availability.into()),
            ),
        ]),
    })
}

fn property<'a, T>(properties: &'a Properties, name: &str) -> Result<T, String>
where
    T: TryFrom<&'a OwnedValue>,
{
    properties
        .get(name)
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| format!("native service property {name} is absent or has the wrong type"))
}

fn array_property<T>(properties: &Properties, name: &str) -> Result<Vec<T>, String>
where
    for<'a> T: TryFrom<zbus::zvariant::Value<'a>>,
    for<'a> <T as TryFrom<zbus::zvariant::Value<'a>>>::Error: Into<zbus::zvariant::Error>,
{
    let value = properties
        .get(name)
        .ok_or_else(|| format!("native service property {name} is absent"))?
        .try_clone()
        .map_err(|_| "native service property cannot be decoded".to_owned())?;
    Vec::<T>::try_from(value)
        .map_err(|_| format!("native service property {name} has the wrong array type"))
}

fn bind_supervised(
    uid: u32,
    unit: &Properties,
    service: &Properties,
    immutable_fragment: bool,
    immutable_image: bool,
) -> Result<(u32, SecurityOwnerInvocationId), String> {
    let pid: u32 = property(service, "MainPID")?;
    let invocation: Vec<u8> = array_property(unit, "InvocationID")?;
    let drop_ins: Vec<String> = array_property(unit, "DropInPaths")?;
    let launches: Vec<ExecStart> = array_property(service, "ExecStart")?;
    let valid_exec = matches!(launches.as_slice(), [(image, argv, false, started_real, started_mono, 0, 0, launch_pid, 0, 0)]
        if image == IMAGE && argv == &[IMAGE] && *started_real != 0 && *started_mono != 0 && *launch_pid == pid);
    if uid == 0
        || pid == 0
        || property::<&str>(service, "User")? != uid.to_string()
        || property::<&str>(unit, "FragmentPath")? != FRAGMENT
        || !drop_ins.is_empty()
        || property::<&str>(unit, "ActiveState")? != "active"
        || property::<&str>(unit, "SubState")? != "running"
        || invocation.len() != 16
        || invocation.iter().all(|b| *b == 0)
        || !valid_exec
        || !immutable_fragment
        || !immutable_image
    {
        return Err("native owner is not the exact immutable supervised invocation".into());
    }
    let hex: String = invocation
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    Ok((
        pid,
        SecurityOwnerInvocationId::new(uuid).map_err(|e| e.to_string())?,
    ))
}

pub(crate) fn immutable_file(path: &Path, executable: bool) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || executable && metadata.mode() & 0o100 == 0
    {
        return false;
    }
    path.ancestors().skip(1).all(|parent| {
        fs::symlink_metadata(parent)
            .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
    })
}

pub(crate) fn unique_name(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(':') else {
        return false;
    };
    value.len() <= 128
        && suffix.contains('.')
        && suffix
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

fn require_observation_signature(reply: &zbus::Message) -> Result<(), String> {
    // zvariant normalizes the top-level body grouping; this check pins the
    // semantic field types before decoding. Emitted wire grouping is tested
    // independently against the canonical XML contract.
    if reply.body().signature().to_string() != "(sbt)" {
        return Err("native lock observation has a noncanonical wire signature".into());
    }
    Ok(())
}

fn authentication_leader(lock: &SessionLockId, properties: &Properties) -> Result<u32, String> {
    let user_value = properties
        .get("User")
        .ok_or("native authentication owner is absent")?
        .try_clone()
        .map_err(|_| "native authentication owner is malformed".to_owned())?;
    let (uid, _user_path): (u32, OwnedObjectPath) = zbus::zvariant::Value::from(user_value)
        .try_into()
        .map_err(|_| "native authentication owner has the wrong type".to_owned())?;
    let pid: u32 = property(properties, "Leader")?;
    if uid != lock.epoch().uid()
        || uid == 0
        || uid > i32::MAX as u32
        || pid == 0
        || pid > i32::MAX as u32
        || property::<&str>(properties, "Id")? != lock.epoch().session_id()
        || property::<u64>(properties, "TimestampMonotonic")? != lock.epoch().created_monotonic_us()
        || property::<&str>(properties, "Type")? != "wayland"
        || property::<&str>(properties, "Class")? != "user"
        || property::<&str>(properties, "State")? != "active"
        || !property::<bool>(properties, "Active")?
        || property::<bool>(properties, "Remote")?
    {
        return Err(
            "native authentication subject is not the exact active local Wayland session leader"
                .into(),
        );
    }
    Ok(pid)
}

pub(crate) fn process_start(pid: u32) -> Result<u64, String> {
    let mut bytes = Vec::new();
    fs::File::open(format!("/proc/{pid}/stat"))
        .map_err(|_| "native process generation is unavailable".to_owned())?
        .take(4_097)
        .read_to_end(&mut bytes)
        .map_err(|_| "native process generation cannot be read".to_owned())?;
    if bytes.len() > 4_096 {
        return Err("native process generation exceeds its bound".into());
    }
    parse_process_start(
        pid,
        std::str::from_utf8(&bytes)
            .map_err(|_| "native process metadata has invalid encoding".to_owned())?,
    )
}

fn parse_process_start(pid: u32, stat: &str) -> Result<u64, String> {
    if !stat.starts_with(&format!("{pid} (")) {
        return Err("native process metadata belongs to another process".into());
    }
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or("native process metadata is malformed")?;
    let ticks: u64 = fields
        .split_ascii_whitespace()
        .nth(19)
        .ok_or("native process start time is absent")?
        .parse()
        .map_err(|_| "native process start time is malformed".to_owned())?;
    if ticks == 0 {
        return Err("native process start time is unknown".into());
    }
    Ok(ticks)
}

pub(crate) fn current_boot() -> Result<BootId, String> {
    // procfs has a fixed-size kernel-generated field; do not accept a general
    // file path or caller-supplied boot generation.
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| "kernel boot identity is unavailable".to_owned())?;
    BootId::new(value.trim_end_matches('\n')).map_err(|e| e.to_string())
}

pub(crate) fn boot_ms() -> Result<u64, String> {
    let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Boottime)
        .map_err(|_| "native BOOTTIME clock is unavailable".to_owned())?;
    let seconds = u64::try_from(time.tv_sec).map_err(|_| "native clock is negative".to_owned())?;
    let nanos =
        u64::try_from(time.tv_nsec).map_err(|_| "native clock fraction is negative".to_owned())?;
    if nanos >= 1_000_000_000 {
        return Err("native clock fraction is invalid".into());
    }
    seconds
        .checked_mul(1_000)
        .and_then(|ms| ms.checked_add(nanos / 1_000_000))
        .ok_or_else(|| "native clock overflow".into())
}

pub(crate) fn unix_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "wall clock predates its epoch".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "wall clock overflow".into())
}

#[allow(clippy::too_many_arguments)]
fn observation(
    identity: &NativeOwnerIdentity,
    boot: &BootId,
    resource: &str,
    secure: bool,
    sampled_boot_ms: u64,
    now_boot_ms: u64,
    now_unix_ms: u64,
    sequence: u64,
) -> Result<ObservationEnvelope, String> {
    let lock = SessionLockId::from_resource(
        &linura_core::ResourceId::new(resource).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let age = now_boot_ms
        .checked_sub(sampled_boot_ms)
        .ok_or("native sample is in the future")?;
    if sampled_boot_ms == 0
        || age > VALID_FOR_MS
        || lock.epoch().uid() != identity.uid
        || lock.epoch().boot() != boot
        || lock.security_owner_invocation() != &identity.invocation
    {
        return Err("native lock observation is stale or from a replaced session owner".into());
    }
    let observed_at_unix_ms = now_unix_ms
        .checked_sub(age)
        .filter(|ms| *ms != 0)
        .ok_or("native observation wall-clock mapping underflow")?;
    let epoch = lock.epoch();
    Ok(ObservationEnvelope {
        provider: linura_core::ProviderId::new("session-locker").map_err(|e| e.to_string())?,
        capability: linura_core::CapabilityId::new("session.secure-lock.observe")
            .map_err(|e| e.to_string())?,
        resource: lock.resource_id().map_err(|e| e.to_string())?,
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms,
        valid_for_ms: VALID_FOR_MS,
        sequence,
        attributes: [
            ("secure".into(), ObservedValue::Bool(secure)),
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
            (
                "lock_generation".into(),
                ObservedValue::U64(lock.generation()),
            ),
            (
                "security_owner_invocation".into(),
                ObservedValue::Text(identity.invocation.as_str().into()),
            ),
            (
                "lock_protocol".into(),
                ObservedValue::Text("ext-session-lock-v1".into()),
            ),
        ]
        .into(),
    })
}

#[cfg(test)]
mod tests;

mod transition;
