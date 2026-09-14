// Semantic implementation sections intentionally share one module namespace.
// This preserves the stable public API and private invariants while keeping
// durability responsibilities reviewable by domain instead of file-size parts.
include!("durable/state.rs");
include!("durable/manifest.rs");
include!("durable/store.rs");
include!("durable/codec.rs");
include!("durable/persistence.rs");
include!("durable/owner_enrollment.rs");
include!("durable/verification.rs");
include!("durable/anchor.rs");
include!("durable/recovery.rs");
include!("durable/tests.rs");
