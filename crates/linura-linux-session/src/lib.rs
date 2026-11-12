#![forbid(unsafe_code)]

//! Concrete bounded native session mechanisms shared only by trusted Control
//! and the narrow session executor composition roots. No planning, policy,
//! approval minting, durable transaction mutation or orchestration lives here.
//! Native transport handles remain adapter details; this crate is forbidden to
//! semantic crates, agent interpreters and the public SDK/UI.

mod account;
mod bus;
mod display_kernel;
mod display_observer;
mod display_restoration_reservation;
pub use display_restoration_reservation::{
    MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION, NativeDisplayRestorationReservation,
};
mod display_finalization_reservation;
pub use display_finalization_reservation::{
    MAX_NATIVE_DISPLAY_FINALIZATION_RESERVATION, NativeDisplayFinalizationReservation,
};
mod display_retirement_preparation;
pub use display_retirement_preparation::{
    MAX_NATIVE_DISPLAY_RETIREMENT_PREPARATION, NativeDisplayRetirementPreparation,
};
mod display_completion_preparation;
pub use display_completion_preparation::current_commit::{
    MAX_NATIVE_DISPLAY_CURRENT_COMMIT, NativeDisplayCurrentCommitPreparation,
};
pub use display_completion_preparation::power::{
    MAX_NATIVE_DISPLAY_POWER_RETIREMENT, NativeDisplayPowerRetirementPreparation,
};
pub use display_completion_preparation::root_retirement::{
    MAX_NATIVE_DISPLAY_ROOT_RETIREMENT, NativeDisplayRootRetirementPreparation,
};
pub use display_completion_preparation::{
    MAX_NATIVE_DISPLAY_COMPLETION_PREPARATION, NativeDisplayCompletionPreparation,
};
mod original_display_observer;
pub use original_display_observer::NativeOriginalDisplayObserver;
mod observer;
mod owner;
mod service;
mod sleep_gate;
mod sleep_helper;
mod sleep_observer;

pub use bus::{NativeSessionChannel, NativeSessionRole};
pub use display_kernel::{NativeDisplayKernelSubscription, NativeDisplayKernelWitness};
pub use display_observer::NativeDisplayObserver;
pub use observer::{NativeLockObserver, NativePowerPermissionObserver};
pub use owner::{
    NativeApprovalPurpose, NativeApprovalRequest, NativeAuthenticationSubject,
    NativeDisplayApprovalPurpose, NativeDisplayApprovalRequest, NativeDisplayContinuation,
    NativeDisplayDecisionRequest, NativeDisplayPowerFence, NativeDisplayRecoveryCheckpoint,
    NativeDisplayRetiredPowerFence, NativeDisplaySafetyRequest, NativeDisplayStartupPeer,
    NativeDisplayStartupRequest, NativeOwnerIdentity,
};
pub use service::protect_before_native_sleep;
pub use sleep_gate::NativeSleepEntry;
pub use sleep_observer::{
    NativeSleepEntryBinding, NativeSleepEntryGuard, NativeSleepEntryObserver,
};
