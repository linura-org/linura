#![forbid(unsafe_code)]

//! Canonical top-level Rust crate for Linura.
//!
//! Linura is the intelligent system layer for Linux. This crate establishes
//! the canonical Rust package identity for the project while the supported
//! public integration API remains intentionally narrow.
//!
//! For the current public, non-privileged developer surface, see
//! `linura-sdk` in the Linura repository.

/// Canonical project name.
pub const NAME: &str = "Linura";

/// Canonical project website.
pub const HOMEPAGE: &str = "https://linura.org";

/// Canonical source repository.
pub const REPOSITORY: &str = "https://github.com/linura-org/linura";
