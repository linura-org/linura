//! Fixed native transition mechanism only. Control supplies an already prepared
//! effect through the narrow executor. This adapter neither reviews policy nor
//! retries, recovers, stores intent, chooses a user, or proxies arbitrary APIs.

use super::*;
use async_io::Timer;
use futures_lite::future;

const LOGIND: &str = "org.freedesktop.login1";
const LOGIN_MANAGER: &str = "/org/freedesktop/login1";
const LOGIN_INTERFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
// Native logind flag, NOT an inhibitor bypass. Check even weak inhibitors when
// the native caller is root. No skip, soft-reboot, kexec or interactive fallback.
const ROOT_CHECK_INHIBITORS: u64 = 1;
type SessionRow = (String, u32, String, String, OwnedObjectPath);
type InhibitorRow = (String, String, String, String, u32, u32);

fn power_method(action: SessionTransition) -> Option<&'static str> {
    match action {
        SessionTransition::Suspend { .. } => Some("SuspendWithFlags"),
        SessionTransition::Reboot => Some("RebootWithFlags"),
        SessionTransition::PowerOff => Some("PowerOffWithFlags"),
        SessionTransition::Logout => None,
    }
}

// Only errors known to precede native queuing qualify. Generic AccessDenied,
// Failed, timeout, OperationInProgress and downstream StartUnit errors do not.
// In particular, a lost reply can follow a successfully queued delay operation.
fn definite_power_rejection(name: &str, detail: Option<&str>, sender: &str, owner: &str) -> bool {
    sender == owner
        && unique_name(owner)
        && match name {
            "org.freedesktop.DBus.Error.UnknownMethod"
            | "org.freedesktop.DBus.Error.InvalidArgs"
            | "org.freedesktop.login1.SleepVerbNotSupported" => true,
            "org.freedesktop.DBus.Error.AccessDenied" => {
                detail == Some("Access denied due to active block inhibitor")
            }
            _ => false,
        }
}

impl NativeSessionChannel {
    fn power_call(&self, owner: &str, method: &str) -> Result<Option<zbus::Message>, String> {
        let result = async_io::block_on(future::race(
            async {
                self.connection
                    .inner()
                    .call_method(
                        Some(owner),
                        LOGIN_MANAGER,
                        Some(LOGIN_INTERFACE),
                        method,
                        &(ROOT_CHECK_INHIBITORS,),
                    )
                    .await
            },
            async {
                Timer::after(crate::bus::CALL_BUDGET).await;
                Err(zbus::Error::Failure(
                    "native transition deadline expired".into(),
                ))
            },
        ));
        match result {
            Ok(reply)
                if reply.body().len() <= 1024
                    && reply
                        .header()
                        .sender()
                        .is_some_and(|sender| sender.as_str() == owner) =>
            {
                Ok(Some(reply))
            }
            Err(zbus::Error::MethodError(name, detail, reply))
                if reply.body().len() <= 1024
                    && definite_power_rejection(
                        name.as_str(),
                        detail.as_deref(),
                        reply.header().sender().map_or("", |sender| sender.as_str()),
                        owner,
                    ) =>
            {
                Ok(None)
            }
            _ => Err("native transition acknowledgement is indeterminate".into()),
        }
    }

    fn transition_owner_call(
        &self,
        role: NativeSessionRole,
        target: &SessionTransitionId,
        method: &str,
    ) -> Result<bool, String> {
        self.require_role(role)?;
        let started = Instant::now();
        let identity = self.discover(target.lock().epoch().uid(), started)?;
        if identity.invocation != *target.lock().security_owner_invocation()
            || current_boot()? != *target.lock().epoch().boot()
        {
            return Err("native transition refers to a replaced owner or boot".into());
        }
        let resource = target.resource_id().map_err(|e| e.to_string())?;
        let (accepted,): (bool,) = self
            .call(
                &identity.unique_name,
                ENDPOINT,
                INTERFACE,
                method,
                &(resource.as_str(),),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native transition fence reply is malformed".to_owned())?;
        self.revalidate(&identity, started)?;
        if current_boot()? != *target.lock().epoch().boot() {
            return Err("native transition fence crossed a boot".into());
        }
        Ok(accepted)
    }

    /// Native bookkeeping only, AFTER verified durable suspend commit. The
    /// security owner independently checks kernel cycles and secure coverage.
    pub fn commit_verified_transition(&self, target: &SessionTransitionId) -> Result<bool, String> {
        if !matches!(target.transition(), SessionTransition::Suspend { .. }) {
            return Err("only a completed suspend retains a live native fence".into());
        }
        self.transition_owner_call(
            NativeSessionRole::Control,
            target,
            "CommitVerifiedTransition",
        )
    }

    fn logind_owner(&self, started: Instant) -> Result<String, String> {
        let owner: String = self
            .bus_call("GetNameOwner", &(LOGIND,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native logind owner is unavailable".to_owned())?;
        if !unique_name(&owner) || self.connection_credentials(&owner, started)?.0 != 0 {
            return Err("native logind owner is not root".into());
        }
        Ok(owner)
    }

    fn exact_transition_session(
        &self,
        owner: &str,
        target: &SessionTransitionId,
        started: Instant,
    ) -> Result<(OwnedObjectPath, u32, u64), String> {
        if current_boot()? != *target.lock().epoch().boot() {
            return Err("native transition target boot changed".into());
        }
        let path: OwnedObjectPath = self
            .call(
                owner,
                LOGIN_MANAGER,
                LOGIN_INTERFACE,
                "GetSession",
                &(target.lock().epoch().session_id(),),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native transition session is absent".to_owned())?;
        if path.as_str().len() > 256
            || !path
                .as_str()
                .starts_with("/org/freedesktop/login1/session/")
        {
            return Err("native transition session handle is unsupported".into());
        }
        let properties = self.properties(owner, path.as_str(), SESSION_INTERFACE, started)?;
        let leader = authentication_leader(target.lock(), &properties)?;
        Ok((path, leader, process_start(leader)?))
    }

    fn native_transition_conditions(
        &self,
        owner: &str,
        target: &SessionTransitionId,
        path: &OwnedObjectPath,
        started: Instant,
    ) -> Result<(), String> {
        let properties = self.properties(owner, LOGIN_MANAGER, LOGIN_INTERFACE, started)?;
        if property::<bool>(&properties, "PreparingForSleep")?
            || property::<bool>(&properties, "PreparingForShutdown")?
        {
            return Err("a native machine transition is already in progress".into());
        }
        if target.transition() == SessionTransition::Logout {
            return Ok(());
        }
        let inhibitors: Vec<InhibitorRow> = self
            .call(
                owner,
                LOGIN_MANAGER,
                LOGIN_INTERFACE,
                "ListInhibitors",
                &(),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native inhibitor reply is malformed".to_owned())?;
        require_no_blocking_inhibitors(target.transition(), &inhibitors)?;
        let sessions: Vec<SessionRow> = self
            .call(
                owner,
                LOGIN_MANAGER,
                LOGIN_INTERFACE,
                "ListSessions",
                &(),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native session enumeration is malformed".to_owned())?;
        if sessions.is_empty() || sessions.len() > 16 {
            return Err("native session enumeration exceeds its bound".into());
        }
        let mut found = false;
        let mut seen = std::collections::BTreeSet::new();
        for (id, uid, account, seat, handle) in sessions {
            if id.len() > 64
                || account.len() > 256
                || seat.len() > 64
                || handle.as_str().len() > 256
                || !handle
                    .as_str()
                    .starts_with("/org/freedesktop/login1/session/")
                || !seen.insert(id.clone())
            {
                return Err("native session enumeration is unsupported".into());
            }
            if id == target.lock().epoch().session_id() {
                if uid != target.lock().epoch().uid() || &handle != path || found {
                    return Err("native transition session identity drifted".into());
                }
                found = true;
            } else {
                let properties =
                    self.properties(owner, handle.as_str(), SESSION_INTERFACE, started)?;
                // Revalidate the same class/UID decision as Control, including
                // sessions appearing after the last observed plan or fence.
                if other_session_blocks_machine_power(
                    property::<&str>(&properties, "Class")?,
                    uid,
                    target.lock().epoch().uid(),
                )? {
                    return Err("another native session inhibits machine power".into());
                }
            }
        }
        if !found {
            return Err("native transition session disappeared".into());
        }
        Ok(())
    }

    /// Executor-only fixed OS mechanism. The caller must independently validate
    /// the canonical effect/prepared binding and authorize its supervised
    /// Control sender. A true result acknowledges dispatch, never completion.
    pub fn dispatch_prepared_transition(
        &self,
        target: &SessionTransitionId,
    ) -> Result<bool, String> {
        self.require_role(NativeSessionRole::Executor)?;
        let started = Instant::now();
        let owner = self.logind_owner(started)?;
        let session = self.exact_transition_session(&owner, target, started)?;
        self.native_transition_conditions(&owner, target, &session.0, started)?;
        if self.logind_owner(started)? != owner {
            return Err("native logind changed before fencing".into());
        }
        if !self.transition_owner_call(
            NativeSessionRole::Executor,
            target,
            "FencePreparedTransition",
        )? {
            return Ok(false);
        }
        // No OS method has been called yet. On fresh precondition drift only,
        // the executor can retire its own fence. Lost/failed dispatch replies
        // below MUST leave it armed; there is no retry or timer-based release.
        let recheck = (|| {
            let fresh = Instant::now();
            if self.logind_owner(fresh)? != owner
                || self.exact_transition_session(&owner, target, fresh)? != session
            {
                return Err("native transition session changed across fencing".into());
            }
            self.native_transition_conditions(&owner, target, &session.0, fresh)
        })();
        if recheck.is_err() {
            let cancelled = self.transition_owner_call(
                NativeSessionRole::Executor,
                target,
                "CancelUndispatchedTransition",
            )?;
            return if cancelled {
                Ok(false)
            } else {
                Err("undispatched transition fence could not be retired".into())
            };
        }
        let reply = if let Some(method) = power_method(target.transition()) {
            match self.power_call(&owner, method)? {
                Some(reply) => reply,
                None => {
                    // Authenticated, definite rejection is not ambiguity. Still
                    // refuse to retire coverage across owner/session replacement
                    // or a concurrent native transition. No automatic replay.
                    let fresh = Instant::now();
                    if self.logind_owner(fresh)? != owner
                        || self.exact_transition_session(&owner, target, fresh)? != session
                    {
                        return Err("native identity changed after transition rejection".into());
                    }
                    let properties =
                        self.properties(&owner, LOGIN_MANAGER, LOGIN_INTERFACE, fresh)?;
                    if property::<bool>(&properties, "PreparingForSleep")?
                        || property::<bool>(&properties, "PreparingForShutdown")?
                    {
                        return Err(
                            "another transition prevents retiring the rejected fence".into()
                        );
                    }
                    return if self.transition_owner_call(
                        NativeSessionRole::Executor,
                        target,
                        "CancelUndispatchedTransition",
                    )? {
                        Ok(false)
                    } else {
                        Err("rejected transition fence could not be retired".into())
                    };
                }
            }
        } else {
            // Captured exact session object, not an ambient/current handle or
            // a later re-resolution of a potentially recycled session name.
            self.call(
                &owner,
                session.0.as_str(),
                SESSION_INTERFACE,
                "Terminate",
                &(),
                Instant::now(),
            )?
        };
        let (): () = reply
            .body()
            .deserialize()
            .map_err(|_| "native transition acknowledgement is malformed".to_owned())?;
        Ok(true)
    }
}

fn other_session_blocks_machine_power(
    session_class: &str,
    uid: u32,
    expected_uid: u32,
) -> Result<bool, String> {
    match session_class {
        "user" | "user-early" | "user-incomplete" | "user-light" | "user-early-light"
        | "greeter" | "lock-screen" => Ok(true),
        "manager" | "manager-early" | "background" | "background-light" => Ok(uid != expected_uid),
        _ => Err("native shared-session class is unsupported".into()),
    }
}

fn require_no_blocking_inhibitors(
    action: SessionTransition,
    rows: &[InhibitorRow],
) -> Result<(), String> {
    if rows.len() > 32 {
        return Err("native inhibitor enumeration exceeds its bound".into());
    }
    let relevant = if matches!(action, SessionTransition::Suspend { .. }) {
        "sleep"
    } else {
        "shutdown"
    };
    for (what, who, why, mode, _, _) in rows {
        if [what, who, why, mode]
            .iter()
            .any(|text| text.len() > 512 || text.contains('\0'))
            || !matches!(mode.as_str(), "block" | "block-weak" | "delay")
        {
            return Err("native inhibitor is unsupported".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for kind in what.split(':') {
            if !matches!(
                kind,
                "sleep"
                    | "shutdown"
                    | "idle"
                    | "handle-power-key"
                    | "handle-suspend-key"
                    | "handle-hibernate-key"
                    | "handle-lid-switch"
                    | "handle-reboot-key"
            ) || !seen.insert(kind)
            {
                return Err("native inhibitor scope is unsupported".into());
            }
            if kind == relevant && mode != "delay" {
                return Err("native transition is blocked by an inhibitor".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_authenticated_definite_pre_queue_rejections_can_retire_coverage() {
        let owner = ":1.23";
        for name in [
            "org.freedesktop.DBus.Error.UnknownMethod",
            "org.freedesktop.DBus.Error.InvalidArgs",
            "org.freedesktop.login1.SleepVerbNotSupported",
        ] {
            assert!(definite_power_rejection(name, None, owner, owner));
            assert!(!definite_power_rejection(name, None, ":1.24", owner));
            assert!(!definite_power_rejection(name, None, "", owner));
        }
        assert!(definite_power_rejection(
            "org.freedesktop.DBus.Error.AccessDenied",
            Some("Access denied due to active block inhibitor"),
            owner,
            owner
        ));
        for (name, detail) in [
            ("org.freedesktop.DBus.Error.AccessDenied", None),
            (
                "org.freedesktop.DBus.Error.AccessDenied",
                Some("downstream unit denied"),
            ),
            ("org.freedesktop.DBus.Error.NoReply", None),
            ("org.freedesktop.DBus.Error.Failed", None),
            ("org.freedesktop.login1.OperationInProgress", None),
            ("org.freedesktop.DBus.Error.Disconnected", None),
            ("future-error", None),
        ] {
            assert!(!definite_power_rejection(name, detail, owner, owner));
        }
    }
    #[test]
    fn methods_and_native_flags_are_fixed_and_never_skip_inhibitors() {
        assert_eq!(ROOT_CHECK_INHIBITORS, 0x01);
        assert_eq!(ROOT_CHECK_INHIBITORS & 0x10, 0);
        assert_eq!(
            power_method(SessionTransition::Suspend {
                successful_cycles_before: 10
            }),
            Some("SuspendWithFlags")
        );
        assert_eq!(
            power_method(SessionTransition::Reboot),
            Some("RebootWithFlags")
        );
        assert_eq!(
            power_method(SessionTransition::PowerOff),
            Some("PowerOffWithFlags")
        );
        assert_eq!(power_method(SessionTransition::Logout), None);
    }
    #[test]
    fn executor_revalidates_new_sessions_using_control_class_and_uid_rules() {
        for class in [
            "user",
            "user-early",
            "user-incomplete",
            "user-light",
            "user-early-light",
            "greeter",
            "lock-screen",
        ] {
            for uid in [1000, 1001] {
                assert_eq!(
                    other_session_blocks_machine_power(class, uid, 1000),
                    Ok(true)
                );
            }
        }
        for class in ["manager", "manager-early", "background", "background-light"] {
            assert_eq!(
                other_session_blocks_machine_power(class, 1000, 1000),
                Ok(false)
            );
            assert_eq!(
                other_session_blocks_machine_power(class, 1001, 1000),
                Ok(true)
            );
        }
        for class in ["", "future-class", "greeter-incomplete", "manager-other"] {
            assert!(other_session_blocks_machine_power(class, 1000, 1000).is_err());
        }
    }

    #[test]
    fn native_strong_weak_unknown_and_overflowing_inhibitors_fail_closed() {
        for mode in ["block", "block-weak", "unknown"] {
            let row = (
                "sleep:shutdown".into(),
                "fixture".into(),
                "reason".into(),
                mode.into(),
                1000,
                42,
            );
            for action in [
                SessionTransition::Suspend {
                    successful_cycles_before: 10,
                },
                SessionTransition::Reboot,
                SessionTransition::PowerOff,
            ] {
                assert!(
                    require_no_blocking_inhibitors(action, std::slice::from_ref(&row)).is_err()
                );
            }
        }
        let delay = (
            "sleep:shutdown".into(),
            "fixture".into(),
            "reason".into(),
            "delay".into(),
            1000,
            42,
        );
        assert!(
            require_no_blocking_inhibitors(SessionTransition::Reboot, std::slice::from_ref(&delay))
                .is_ok()
        );
        assert!(
            require_no_blocking_inhibitors(SessionTransition::Reboot, &vec![delay; 33]).is_err()
        );
        for scope in ["", "shutdown:shutdown", "hibernate", "sleep:\0", "future"] {
            let row = (
                scope.into(),
                "fixture".into(),
                "reason".into(),
                "delay".into(),
                1000,
                42,
            );
            assert!(require_no_blocking_inhibitors(SessionTransition::Reboot, &[row]).is_err());
        }
    }
}
