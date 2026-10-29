#![forbid(unsafe_code)]

//! Concrete bounded native session mechanisms shared only by trusted Control
//! and the narrow session executor composition roots. No planning, policy,
//! approval minting, durable transaction mutation or orchestration lives here.
//! Native transport handles remain adapter details; this crate is forbidden to
//! semantic crates, agent interpreters and the public SDK/UI.

mod account;
mod bus;
mod display_observer;
mod observer;
mod owner;
mod service;
mod sleep_gate;
mod sleep_helper;
mod sleep_observer;

pub use bus::{NativeSessionChannel, NativeSessionRole};
pub use display_observer::NativeDisplayObserver;
pub use observer::{NativeLockObserver, NativePowerPermissionObserver};
pub use owner::{
    NativeApprovalPurpose, NativeApprovalRequest, NativeAuthenticationSubject,
    NativeDisplayContinuation, NativeOwnerIdentity,
};
pub use service::protect_before_native_sleep;
pub use sleep_gate::NativeSleepEntry;
pub use sleep_observer::{
    NativeSleepEntryBinding, NativeSleepEntryGuard, NativeSleepEntryObserver,
};
