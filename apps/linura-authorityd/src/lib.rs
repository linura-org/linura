#![forbid(unsafe_code)]

//! Concrete authority-service package composition, not a policy or device
//! privilege grant. The separately scoped original-user worker mechanism is
//! compiled here to preserve the inward dependencies of native session and
//! Linux observation crates. It has no trusted handoff issuer or service.

/// Inactive, data-only sealed-Control handoff admission. Does not execute effects.
pub mod backlight_handoff;
pub mod original_user_backlight;
