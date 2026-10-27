//! Experimental S21-2 client intent and truthful lifecycle reports. These types
//! contain no principal, policy decision, prepared authority or native handle.
use linura_core::{DisplayLayoutIntent, DisplayLayoutMaterial, RequestId, ResourceId};

pub const DISPLAY_LAYOUT_REQUEST_PREFIX: &str = "request:v010:display-layout:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutRequest {
    operation_id: String,
    material: String,
    reason: String,
}

impl DisplayLayoutRequest {
    pub fn new(
        operation_id: impl Into<String>,
        intent: &DisplayLayoutIntent,
        reason: impl Into<String>,
    ) -> Result<Self, String> {
        Self::from_material(
            operation_id.into(),
            intent.canonical_text().map_err(|e| e.to_string())?,
            reason.into(),
        )
    }

    /// Bounded transport decoding only. Native support and current evidence
    /// must be validated independently inside Control before any authority.
    pub fn from_material(
        operation_id: String,
        material: String,
        reason: String,
    ) -> Result<Self, String> {
        if !valid_operation_id(&operation_id)
            || reason.trim().is_empty()
            || reason.len() > 1024
            || reason.chars().any(char::is_control)
        {
            return Err("display request identity or reason is invalid".into());
        }
        DisplayLayoutMaterial::decode(&material).map_err(|e| e.to_string())?;
        Ok(Self {
            operation_id,
            material,
            reason,
        })
    }
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayLayoutState {
    AwaitingConfirmation,
    Confirmed,
    Restored,
    NotDispatched,
    Indeterminate,
}
impl DisplayLayoutState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingConfirmation => "awaiting-confirmation",
            Self::Confirmed => "confirmed",
            Self::Restored => "restored",
            Self::NotDispatched => "not-dispatched",
            Self::Indeterminate => "indeterminate",
        }
    }
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "awaiting-confirmation" => Some(Self::AwaitingConfirmation),
            "confirmed" => Some(Self::Confirmed),
            "restored" => Some(Self::Restored),
            "not-dispatched" => Some(Self::NotDispatched),
            "indeterminate" => Some(Self::Indeterminate),
            _ => None,
        }
    }
}
/// A lifecycle report at response time. A pending/indeterminate reply is never
/// successful completion; a historical terminal reply is not current evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutReceipt {
    pub request_id: RequestId,
    pub transaction_id: String,
    pub resource: ResourceId,
    pub state: DisplayLayoutState,
    pub confirmation_expires_at_unix_ms: u64,
}
impl DisplayLayoutReceipt {
    /// Report validation only. This is never current-state verification or
    /// execution authority, including for a well-formed terminal report.
    pub fn validate(&self) -> Result<(), String> {
        display_layout_request_id(self.request_id.as_str())?;
        linura_core::DisplayTopologyId::from_resource(&self.resource).map_err(|e| e.to_string())?;
        let transaction = self.transaction_id.strip_prefix("transaction:v1:");
        if transaction.is_none_or(|digest| {
            digest.len() != 64
                || digest.bytes().all(|c| c == b'0')
                || !digest
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }) || self.confirmation_expires_at_unix_ms == 0
            || self.confirmation_expires_at_unix_ms > i64::MAX as u64
        {
            return Err("display lifecycle report has invalid transaction or deadline".into());
        }
        Ok(())
    }
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}

pub fn display_layout_request_id(value: &str) -> Result<RequestId, String> {
    if value.len() > 128
        || !value
            .strip_prefix(DISPLAY_LAYOUT_REQUEST_PREFIX)
            .is_some_and(valid_operation_id)
    {
        return Err("request is outside the S21-2 display namespace".into());
    }
    RequestId::new(value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn material() -> String {
        let lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1";
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        format!(
            "LNDI:1;{lock};LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:0:0:-;LNDL:1;{topology};1:2:enabled:1920:1080:60000:1251:0:0:0:-;"
        )
    }
    #[test]
    fn bounded_intent_does_not_accept_identity_or_command_substitution() {
        assert!(
            DisplayLayoutRequest::from_material(
                "display-1".into(),
                material(),
                "Arrange outputs".into()
            )
            .is_ok()
        );
        for operation in ["", "Display", "display;id", "display\n1"] {
            assert!(
                DisplayLayoutRequest::from_material(
                    operation.into(),
                    material(),
                    "Arrange outputs".into()
                )
                .is_err()
            );
        }
        for reason in ["".into(), "\n".into(), "x".repeat(1025)] {
            assert!(
                DisplayLayoutRequest::from_material("display-1".into(), material(), reason)
                    .is_err()
            );
        }
        for bad in [
            "keyword monitor DP-1,disabled".into(),
            "x".repeat(4097),
            material() + "\n",
        ] {
            assert!(
                DisplayLayoutRequest::from_material(
                    "display-1".into(),
                    bad,
                    "Arrange outputs".into()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn lifecycle_states_remain_distinct_and_unknown_reports_fail_closed() {
        for state in [
            DisplayLayoutState::AwaitingConfirmation,
            DisplayLayoutState::Confirmed,
            DisplayLayoutState::Restored,
            DisplayLayoutState::NotDispatched,
            DisplayLayoutState::Indeterminate,
        ] {
            assert_eq!(DisplayLayoutState::from_wire(state.as_str()), Some(state));
        }
        for unknown in ["success", "pending", "Confirmed", "restored ", ""] {
            assert!(DisplayLayoutState::from_wire(unknown).is_none());
        }
        assert!(display_layout_request_id("request:v010:session-lock:example").is_err());
        assert!(display_layout_request_id("request:v010:display-layout:example").is_ok());
    }
}
