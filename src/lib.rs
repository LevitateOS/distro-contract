//! Trait contracts for the LevitateOS distro family.
//!
//! This crate defines the **interfaces** that distro builders implement.
//! It has near-zero dependencies (just `anyhow` for error types) so that
//! any crate can depend on it without pulling in build infrastructure.
//!
//! # Traits
//!
//! | Trait | Purpose |
//! |-------|---------|
//! | [`KernelInstallConfig`] | Where/how to install kernel and modules |
//! | [`KernelBuildGuard`] | Two-step kernel build confirmation |
//! | [`DistroConfig`] | OS identity, boot, init system |
//! | [`BuildContext`] | Source/staging/output paths |
//! | [`Installable`] | Declarative component installation |
//! | [`DiskImageConfig`] | Disk image building |

pub mod component;
pub mod context;
pub mod disk;
pub mod kernel;

pub use component::{Installable, Op, Phase};
pub use context::{BuildContext, DistroConfig, InitSystem, PackageManager};
pub use disk::{DiskImageConfig, DiskUuids};
pub use kernel::{KernelBuildGuard, KernelGuard, KernelInstallConfig};
