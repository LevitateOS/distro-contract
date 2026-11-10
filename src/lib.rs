//! The variant contract: the schema of `distro/variants/<id>/distro.toml`,
//! its loader and rules, the names derived from it, the registry of products
//! and scenarios, the `.artifacts` layout and run records, and checks of
//! built artifacts against it.

pub mod error;
pub mod install_ux;
pub mod registry;
pub mod runs;
pub mod runtime;
pub mod schema;
mod validate;
pub mod variant;

pub use error::{LoadError, Violation};
pub use runtime::{
    validate_build_runtime, validate_live_boot_runtime, BuildRuntimeArtifacts,
    LiveBootRuntimeArtifacts,
};
pub use registry::{ProductId, ScenarioId, ScenarioInput};
pub use runs::Missing;
pub use schema::{
    ArtifactNames, ConformanceContract, DistroIdentity,
    LiveUkis, PackageBaseContract, RootfsSourceContract,
    SourceContract, CONTRACT_SCHEMA_VERSION, INSTALL_TOOLS, SYSTEM_TUI_APPS, UPDATE_TOOLS,
};
pub use schema::{capabilities_text, locales, system_commands};
pub use validate::WALLPAPERS;
pub use variant::{distro_ids, load, Variant};

/// The profile vocabulary, re-exported for the contract's readers.
pub use distro_profile as profile;
pub use distro_profile::Profile;
