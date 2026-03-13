//! Canonical Stage 00 (00Build) declaration constants.
//!
//! This module is the single source of truth for Stage 00 filenames, required
//! paths, and required declaration values used by loaders and validators.

/// Stage 00 manifest filename used by `distro-variants/<distro>/`.
pub const MANIFEST_FILENAME: &str = "00Build.toml";

/// Stage 00 evidence script required filename prefix.
pub const EVIDENCE_SCRIPT_PREFIX: &str = "00Build-";

/// Required variant-local kconfig path for Stage 00.
pub const REQUIRED_VARIANT_KCONFIG: &str = "kconfig";

/// Required variant-local recipe declaration path for Stage 00.
pub const REQUIRED_VARIANT_RECIPE_DECL: &str = "recipes/kernel.rhai";

/// Baseline required build tools for Stage 00 declaration.
/// human: this doesn't make sense to me: if each distro needs these build tools.. then why put it in the contract?? isn't that just a distro-builder concern??
pub const REQUIRED_BUILD_TOOLS_BASELINE: &[&str] = &[
    "recipe",
    "cargo",
    "make",
    "recuki",
    "ukify",
    "mkfs.erofs",
    "xorriso",
    "reciso",
    "recinit",
    "recstrap",
    "recfstab",
    "recchroot",
];

/// Required recipe lifecycle invocation declaration.
/// human: I don't uderstand this one either.. I think this is overengineered..
pub const REQUIRED_RECIPE_INVOCATION: &str = "recipe install";

/// Required kernel.release output path declaration.
pub const REQUIRED_KERNEL_RELEASE_PATH: &str = "kernel-build/include/config/kernel.release";

/// Required kernel image output path declaration.
pub const REQUIRED_KERNEL_IMAGE_PATH: &str = "staging/boot/vmlinuz";

/// Required kernel modules output path declaration.
pub const REQUIRED_KERNEL_MODULES_PATH: &str = "staging/usr/lib/modules/<kernel.release>";

/// Required module install root declaration (UsrMerge invariant).
pub const REQUIRED_MODULE_INSTALL_PATH: &str = "/usr/lib/modules";

/// Mandatory minimal non-kernel Stage 00 inputs for ISO synthesis.
///
/// These are declared relative to `.artifacts/out/<DistroDir>/`.
pub const REQUIRED_NON_KERNEL_INPUTS_00BUILD_BASELINE: &[&str] = &["s00-overlayfs.erofs"];
