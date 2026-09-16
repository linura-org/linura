#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod legacy;
pub use legacy::*;

pub mod durable;
