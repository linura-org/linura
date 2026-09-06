#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};
use std::process::Command;
use std::time::Duration;

use linura_core::{ProviderId, ResourceId};
use linura_provider_sdk::{
    ComponentDigest, EffectDescriptor, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
};
use zbus::message::Header;
use zbus::zvariant::OwnedObjectPath;

pub const SERVICE_NAME: &str = "org.linura.Executor.Systemd1";
pub const OBJECT_PATH: &str = "/org/linura/Executor/Systemd1";
pub const INTERFACE_NAME: &str = "org.linura.Executor.Systemd1";
pub const QUALIFICATION_ACTION_ID: &str = "org.linura.executor.systemd.qualify-restart";
pub const QUALIFICATION_UNIT_PREFIX: &str = "linura-v05-qualification-";
pub const MANAGED_ACTION_ID: &str = "org.linura.executor.systemd.set-active-state";
pub const MANAGED_UNIT_PREFIX: &str = "linura-managed-";
const QUALIFICATION_OPERATION: &str = "restart-unit";
const MANAGED_OPERATION: &str = "set-active-state";
const MAX_WIRE_DETAIL_BYTES: usize = 192;
const SYSTEMD_METHOD_TIMEOUT: Duration = Duration::from_secs(5);

pub type ExecutionOutcomeWire = (String, String, String);
pub type QualificationOutcomeWire = ExecutionOutcomeWire;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemdOperation {
    SetUnitEnabled {
        unit: UnitName,
        enabled: bool,
    },
    RestartUnit {
        unit: UnitName,
    },
    SetManagedActiveState {
        unit: ManagedUnitName,
        state: ManagedActiveState,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitName(String);

impl UnitName {
    pub fn parse(value: impl Into<String>) -> Result<Self, UnitNameError> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 {
            return Err(UnitNameError::InvalidLength);
        }
        if !value.ends_with(".service") {
            return Err(UnitNameError::UnsupportedUnitType);
        }
        if !value.is_ascii()
            || value.chars().any(|character| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, ':' | '_' | '.' | '@' | '-'))
            })
        {
            return Err(UnitNameError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for UnitName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitNameError {
    InvalidLength,
    UnsupportedUnitType,
    InvalidCharacter,
}

impl Display for UnitNameError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("systemd unit name has invalid length"),
            Self::UnsupportedUnitType => f.write_str("only systemd .service units are accepted"),
            Self::InvalidCharacter => {
                f.write_str("systemd unit name contains an invalid character")
            }
        }
    }
}

impl std::error::Error for UnitNameError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationUnitName(UnitName);

impl QualificationUnitName {
    pub fn parse(value: impl Into<String>) -> Result<Self, QualificationUnitError> {
        let unit = UnitName::parse(value).map_err(QualificationUnitError::Unit)?;
        validate_reserved_unit(unit.as_str(), QUALIFICATION_UNIT_PREFIX)
            .map_err(|_| QualificationUnitError::InvalidFixtureName)?;
        Ok(Self(unit))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn resource_id(&self) -> Result<ResourceId, ExecutorError> {
        systemd_resource(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationUnitError {
    Unit(UnitNameError),
    WrongNamespace,
    InvalidFixtureName,
}

impl Display for QualificationUnitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit(error) => write!(f, "{error}"),
            Self::WrongNamespace => f.write_str("unit is outside the v0.5 qualification namespace"),
            Self::InvalidFixtureName => f.write_str("qualification fixture name is not canonical"),
        }
    }
}

impl std::error::Error for QualificationUnitError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedUnitName(UnitName);

impl ManagedUnitName {
    pub fn parse(value: impl Into<String>) -> Result<Self, ManagedUnitError> {
        let unit = UnitName::parse(value).map_err(ManagedUnitError::Unit)?;
        if !unit.as_str().starts_with(MANAGED_UNIT_PREFIX) {
            return Err(ManagedUnitError::WrongNamespace);
        }
        validate_reserved_unit(unit.as_str(), MANAGED_UNIT_PREFIX)
            .map_err(|_| ManagedUnitError::InvalidManagedName)?;
        Ok(Self(unit))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn resource_id(&self) -> Result<ResourceId, ExecutorError> {
        systemd_resource(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedUnitError {
    Unit(UnitNameError),
    WrongNamespace,
    InvalidManagedName,
}

impl Display for ManagedUnitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit(error) => write!(f, "{error}"),
            Self::WrongNamespace => f.write_str("unit is outside the linura-managed- namespace"),
            Self::InvalidManagedName => f.write_str("managed unit name is not canonical"),
        }
    }
}

impl std::error::Error for ManagedUnitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedActiveState {
    Active,
    Inactive,
}

impl ManagedActiveState {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "active" => Ok(Self::Active),
            "inactive" => Ok(Self::Inactive),
            _ => Err("managed active state must be exactly active or inactive"),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }

    const fn systemd_method(self) -> &'static str {
        match self {
            Self::Active => "StartUnit",
            Self::Inactive => "StopUnit",
        }
    }
}

#[derive(Debug)]
pub enum ExecutorError {
    Contract(String),
    Transport(String),
}

impl Display for ExecutorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contract(detail) => write!(f, "executor contract error: {detail}"),
            Self::Transport(detail) => write!(f, "executor transport error: {detail}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

#[derive(Clone, Debug, Default)]
pub struct SystemdExecutorService;

#[zbus::interface(name = "org.linura.Executor.Systemd1")]
impl SystemdExecutorService {
    #[allow(clippy::too_many_arguments)]
    async fn qualify_restart(
        &self,
        unit: &str,
        transaction_id: &str,
        generation: u64,
        state_version: u64,
        authority_binding_digest: &str,
        authority_use_digest: &str,
        effect_digest: &str,
        dispatch_digest: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<QualificationOutcomeWire> {
        let sender = authenticated_sender(&header)?;
        authorize_caller(
            &sender,
            QUALIFICATION_ACTION_ID,
            "v0.5 executor qualification",
        )?;

        let unit = match QualificationUnitName::parse(unit) {
            Ok(unit) => unit,
            Err(error) => return Ok(rejected_wire(error.to_string())),
        };
        let effect = match restart_effect(&unit) {
            Ok(effect) => effect,
            Err(error) => return Ok(rejected_wire(error.to_string())),
        };
        let binding = match binding_from_wire(
            transaction_id,
            generation,
            state_version,
            authority_binding_digest,
            authority_use_digest,
            effect_digest,
            dispatch_digest,
        ) {
            Ok(binding) => binding,
            Err(error) => return Ok(rejected_wire(error)),
        };
        if let Err(error) = binding.validate_for(&effect) {
            return Ok(rejected_wire(error.to_string()));
        }

        let proxy = match systemd_manager_proxy(connection).await {
            Ok(proxy) => proxy,
            Err(error) => {
                return Ok(outcome_wire(bounded_outcome(
                    ExecutionDisposition::RejectedBeforeDispatch,
                    binding.dispatch_digest,
                    &format!(
                        "systemd proxy unavailable: {}",
                        bounded_text(&error.to_string())
                    ),
                )?));
            }
        };

        let dispatch: Result<OwnedObjectPath, zbus::Error> =
            proxy.call("RestartUnit", &(unit.as_str(), "replace")).await;
        dispatch_result(
            dispatch,
            binding.dispatch_digest,
            "systemd RestartUnit accepted; authoritative verification required",
        )
    }

    /// v0.6's first supported managed external effect.
    ///
    /// This method is intentionally narrower than generic systemd management:
    /// only canonical `linura-managed-*.service` units and the exact active or
    /// inactive postcondition are accepted. Correlation material is independently
    /// re-derived and checked here, after the trusted caller has consumed
    /// Control's process-local one-shot dispatch permit.
    #[allow(clippy::too_many_arguments)]
    async fn set_managed_active_state(
        &self,
        unit: &str,
        desired_active_state: &str,
        transaction_id: &str,
        generation: u64,
        state_version: u64,
        authority_binding_digest: &str,
        authority_use_digest: &str,
        effect_digest: &str,
        dispatch_digest: &str,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<ExecutionOutcomeWire> {
        let sender = authenticated_sender(&header)?;
        authorize_caller(&sender, MANAGED_ACTION_ID, "v0.6 managed systemd mutation")?;

        let unit = match ManagedUnitName::parse(unit) {
            Ok(unit) => unit,
            Err(error) => return Ok(rejected_wire(error.to_string())),
        };
        let state = match ManagedActiveState::parse(desired_active_state) {
            Ok(state) => state,
            Err(error) => return Ok(rejected_wire(error.into())),
        };
        let effect = match managed_active_state_effect(&unit, state) {
            Ok(effect) => effect,
            Err(error) => return Ok(rejected_wire(error.to_string())),
        };
        let binding = match binding_from_wire(
            transaction_id,
            generation,
            state_version,
            authority_binding_digest,
            authority_use_digest,
            effect_digest,
            dispatch_digest,
        ) {
            Ok(binding) => binding,
            Err(error) => return Ok(rejected_wire(error)),
        };
        if let Err(error) = binding.validate_for(&effect) {
            return Ok(rejected_wire(error.to_string()));
        }

        let proxy = match systemd_manager_proxy(connection).await {
            Ok(proxy) => proxy,
            Err(error) => {
                return Ok(outcome_wire(bounded_outcome(
                    ExecutionDisposition::RejectedBeforeDispatch,
                    binding.dispatch_digest,
                    &format!(
                        "systemd proxy unavailable: {}",
                        bounded_text(&error.to_string())
                    ),
                )?));
            }
        };

        let dispatch: Result<OwnedObjectPath, zbus::Error> = proxy
            .call(state.systemd_method(), &(unit.as_str(), "replace"))
            .await;
        dispatch_result(
            dispatch,
            binding.dispatch_digest,
            &format!(
                "systemd {} accepted for {}; independent authoritative verification required",
                state.systemd_method(),
                unit.as_str()
            ),
        )
    }
}

pub fn serve() -> Result<(), ExecutorError> {
    let _connection = zbus::blocking::connection::Builder::system()
        .map_err(|error| ExecutorError::Transport(error.to_string()))?
        .method_timeout(SYSTEMD_METHOD_TIMEOUT)
        .name(SERVICE_NAME)
        .map_err(|error| ExecutorError::Transport(error.to_string()))?
        .serve_at(OBJECT_PATH, SystemdExecutorService)
        .map_err(|error| ExecutorError::Transport(error.to_string()))?
        .build()
        .map_err(|error| ExecutorError::Transport(error.to_string()))?;
    loop {
        std::thread::park();
    }
}

pub fn restart_effect(unit: &QualificationUnitName) -> Result<EffectDescriptor, ExecutorError> {
    let provider = systemd_provider()?;
    let resource = unit.resource_id()?;
    EffectDescriptor::new(
        provider,
        resource,
        QUALIFICATION_OPERATION,
        unit.as_str().as_bytes().to_vec(),
    )
    .map_err(|error| ExecutorError::Contract(error.to_string()))
}

pub fn managed_active_state_effect(
    unit: &ManagedUnitName,
    state: ManagedActiveState,
) -> Result<EffectDescriptor, ExecutorError> {
    let provider = systemd_provider()?;
    let resource = unit.resource_id()?;
    EffectDescriptor::new(
        provider,
        resource,
        MANAGED_OPERATION,
        format!("unit={}\nactive_state={}\n", unit.as_str(), state.as_str()).into_bytes(),
    )
    .map_err(|error| ExecutorError::Contract(error.to_string()))
}

fn systemd_provider() -> Result<ProviderId, ExecutorError> {
    ProviderId::new("systemd").map_err(|error| ExecutorError::Contract(error.to_string()))
}

fn systemd_resource(unit: &str) -> Result<ResourceId, ExecutorError> {
    ResourceId::new(format!("systemd:unit:{unit}"))
        .map_err(|error| ExecutorError::Contract(error.to_string()))
}

fn validate_reserved_unit(unit: &str, prefix: &str) -> Result<(), ()> {
    let suffix = unit.strip_prefix(prefix).ok_or(())?;
    let slug = suffix.strip_suffix(".service").ok_or(())?;
    if slug.is_empty()
        || slug.len() > 96
        || !slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || slug.starts_with('-')
        || slug.ends_with('-')
        || slug.contains("--")
    {
        return Err(());
    }
    Ok(())
}

async fn systemd_manager_proxy(
    connection: &zbus::Connection,
) -> Result<zbus::Proxy<'_>, zbus::Error> {
    zbus::Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
}

fn binding_from_wire(
    transaction_id: &str,
    generation: u64,
    state_version: u64,
    authority_binding_digest: &str,
    authority_use_digest: &str,
    effect_digest: &str,
    dispatch_digest: &str,
) -> Result<ExecutionBinding, String> {
    Ok(ExecutionBinding {
        transaction_id: transaction_id.into(),
        generation,
        state_version,
        authority_binding_digest: ComponentDigest::parse_hex(authority_binding_digest)
            .map_err(|error| error.to_string())?,
        authority_use_digest: ComponentDigest::parse_hex(authority_use_digest)
            .map_err(|error| error.to_string())?,
        effect_digest: ComponentDigest::parse_hex(effect_digest)
            .map_err(|error| error.to_string())?,
        dispatch_digest: ComponentDigest::parse_hex(dispatch_digest)
            .map_err(|error| error.to_string())?,
    })
}

fn authenticated_sender(header: &Header<'_>) -> zbus::fdo::Result<String> {
    let sender = header.sender().ok_or_else(|| {
        zbus::fdo::Error::AccessDenied("method call has no authenticated D-Bus sender".into())
    })?;
    let sender = sender.as_str();
    if sender.is_empty()
        || sender.len() > 255
        || !sender.starts_with(':')
        || sender.chars().any(char::is_control)
    {
        return Err(zbus::fdo::Error::AccessDenied(
            "method call sender is not a canonical unique bus name".into(),
        ));
    }
    Ok(sender.into())
}

fn authorize_caller(sender: &str, action_id: &str, purpose: &str) -> zbus::fdo::Result<()> {
    let status = Command::new("/usr/bin/pkcheck")
        .args(["--action-id", action_id, "--system-bus-name", sender])
        .status()
        .map_err(|_| {
            zbus::fdo::Error::AccessDenied(format!(
                "{purpose} authorization service is unavailable"
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(zbus::fdo::Error::AccessDenied(format!(
            "caller is not authorized for {purpose}"
        )))
    }
}

fn rejected_wire(detail: String) -> ExecutionOutcomeWire {
    (
        "rejected-before-dispatch".into(),
        String::new(),
        bounded_text(&detail),
    )
}

fn dispatch_result(
    dispatch: Result<OwnedObjectPath, zbus::Error>,
    dispatch_digest: ComponentDigest,
    success_detail: &str,
) -> zbus::fdo::Result<ExecutionOutcomeWire> {
    match dispatch {
        Ok(_job) => Ok(outcome_wire(bounded_outcome(
            ExecutionDisposition::Dispatched,
            dispatch_digest,
            success_detail,
        )?)),
        Err(error) => Ok(outcome_wire(indeterminate_dispatch_outcome(
            dispatch_digest,
            &error,
        )?)),
    }
}

fn indeterminate_dispatch_outcome(
    dispatch_digest: ComponentDigest,
    error: &zbus::Error,
) -> zbus::fdo::Result<ExecutionOutcome> {
    bounded_outcome(
        ExecutionDisposition::Indeterminate,
        dispatch_digest,
        &format!(
            "systemd dispatch outcome is indeterminate: {}",
            bounded_text(&error.to_string())
        ),
    )
}

fn bounded_outcome(
    disposition: ExecutionDisposition,
    dispatch_digest: ComponentDigest,
    detail: &str,
) -> zbus::fdo::Result<ExecutionOutcome> {
    ExecutionOutcome::new(disposition, dispatch_digest, bounded_text(detail))
        .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
}

fn outcome_wire(outcome: ExecutionOutcome) -> ExecutionOutcomeWire {
    (
        match outcome.disposition {
            ExecutionDisposition::RejectedBeforeDispatch => "rejected-before-dispatch",
            ExecutionDisposition::Dispatched => "dispatched",
            ExecutionDisposition::Indeterminate => "indeterminate",
        }
        .into(),
        outcome.dispatch_digest.to_hex(),
        outcome.detail,
    )
}

fn bounded_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_WIRE_DETAIL_BYTES));
    for character in value.chars() {
        if character.is_control() {
            output.push(' ');
        } else {
            output.push(character);
        }
        if output.len() >= MAX_WIRE_DETAIL_BYTES {
            break;
        }
    }
    while !output.is_char_boundary(output.len()) {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_provider_sdk::ExecutionBinding;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        match value {
            Ok(value) => value,
            Err(error) => unreachable!("{error:?}"),
        }
    }

    fn digest(byte: u8) -> ComponentDigest {
        ComponentDigest::from_bytes([byte; 32])
    }

    #[test]
    fn only_service_units_are_accepted_initially() {
        assert!(UnitName::parse("sshd.service").is_ok());
        assert_eq!(
            UnitName::parse("multi-user.target"),
            Err(UnitNameError::UnsupportedUnitType)
        );
    }

    #[test]
    fn suspicious_unit_names_are_rejected() {
        for value in [
            "../../evil.service",
            "bad name.service",
            "bad;name.service",
            "bad$name.service",
            "bad\nname.service",
            "bad\\name.service",
        ] {
            assert!(
                UnitName::parse(value).is_err(),
                "accepted hostile unit: {value}"
            );
        }
    }

    #[test]
    fn qualification_namespace_is_exact_and_canonical() {
        assert!(QualificationUnitName::parse("linura-v05-qualification-restart.service").is_ok());
        for value in [
            "sshd.service",
            "linura-v05-qualification-.service",
            "linura-v05-qualification--bad.service",
            "linura-v05-qualification-Bad.service",
            "linura-v05-qualification-bad--slug.service",
        ] {
            assert!(
                QualificationUnitName::parse(value).is_err(),
                "accepted fixture: {value}"
            );
        }
    }

    #[test]
    fn managed_namespace_is_exact_and_canonical() {
        assert!(ManagedUnitName::parse("linura-managed-web.service").is_ok());
        for value in [
            "sshd.service",
            "linura-managed-.service",
            "linura-managed--bad.service",
            "linura-managed-Bad.service",
            "linura-managed-bad--slug.service",
        ] {
            assert!(
                ManagedUnitName::parse(value).is_err(),
                "accepted managed unit: {value}"
            );
        }
    }

    #[test]
    fn managed_effect_matches_control_canonical_payload() {
        let unit = id(ManagedUnitName::parse("linura-managed-web.service"));
        let active = id(managed_active_state_effect(
            &unit,
            ManagedActiveState::Active,
        ));
        let inactive = id(managed_active_state_effect(
            &unit,
            ManagedActiveState::Inactive,
        ));
        assert_eq!(active.operation, MANAGED_OPERATION);
        assert_eq!(
            active.canonical_payload,
            b"unit=linura-managed-web.service\nactive_state=active\n"
        );
        assert_eq!(
            inactive.canonical_payload,
            b"unit=linura-managed-web.service\nactive_state=inactive\n"
        );
        assert_ne!(active.digest(), inactive.digest());
    }

    #[test]
    fn exact_binding_rejects_effect_substitution() {
        let first = id(QualificationUnitName::parse(
            "linura-v05-qualification-first.service",
        ));
        let second = id(QualificationUnitName::parse(
            "linura-v05-qualification-second.service",
        ));
        let first_effect = id(restart_effect(&first));
        let second_effect = id(restart_effect(&second));
        let binding = id(ExecutionBinding::new(
            "tx:v05-test",
            1,
            1,
            digest(1),
            digest(2),
            &first_effect,
        ));
        assert!(binding.validate_for(&first_effect).is_ok());
        assert!(binding.validate_for(&second_effect).is_err());
    }

    #[test]
    fn managed_binding_rejects_state_and_unit_substitution() {
        let first = id(ManagedUnitName::parse("linura-managed-first.service"));
        let second = id(ManagedUnitName::parse("linura-managed-second.service"));
        let expected = id(managed_active_state_effect(
            &first,
            ManagedActiveState::Active,
        ));
        let changed_state = id(managed_active_state_effect(
            &first,
            ManagedActiveState::Inactive,
        ));
        let changed_unit = id(managed_active_state_effect(
            &second,
            ManagedActiveState::Active,
        ));
        let binding = id(ExecutionBinding::new(
            "transaction:v1:test",
            0,
            2,
            digest(1),
            digest(2),
            &expected,
        ));
        assert!(binding.validate_for(&expected).is_ok());
        assert!(binding.validate_for(&changed_state).is_err());
        assert!(binding.validate_for(&changed_unit).is_err());
    }

    #[test]
    fn wire_binding_rejects_malformed_digests() {
        assert!(
            binding_from_wire(
                "tx",
                1,
                1,
                "bad",
                &"2".repeat(64),
                &"3".repeat(64),
                &"4".repeat(64)
            )
            .is_err()
        );
    }

    #[test]
    fn dispatch_timeout_is_indeterminate_and_bounded() {
        let timeout: zbus::Error = std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "synthetic systemd method timeout",
        )
        .into();
        let outcome = id(indeterminate_dispatch_outcome(digest(9), &timeout));
        assert_eq!(outcome.disposition, ExecutionDisposition::Indeterminate);
        assert_eq!(outcome.dispatch_digest, digest(9));
        assert!(outcome.detail.contains("indeterminate"));
        assert!(outcome.detail.contains("synthetic systemd method timeout"));
        assert!(outcome.detail.len() <= MAX_WIRE_DETAIL_BYTES);
    }

    #[test]
    fn error_text_is_control_free_and_bounded() {
        let bounded = bounded_text(&format!("bad\n{}", "x".repeat(500)));
        assert!(!bounded.chars().any(char::is_control));
        assert!(bounded.len() <= MAX_WIRE_DETAIL_BYTES);
    }
}
