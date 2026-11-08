//! The variant contract: the schema of `distro/variants/<id>/distro.toml`,
//! its loader and rules, the names derived from it, the registry of products
//! and scenarios, and checks of built artifacts against it.

pub mod error;
pub mod registry;
pub mod runtime;
pub mod schema;
pub mod tui_apps;
mod validate;
pub mod variant;

pub use error::{LoadError, Violation};
pub use runtime::{
    validate_build_runtime, validate_live_boot_runtime, BuildRuntimeArtifacts,
    LiveBootRuntimeArtifacts,
};
pub use registry::{ProductId, ScenarioId, ScenarioInput};
pub use schema::{
    ArtifactNames, BuildContract, ConformanceContract, DistroIdentity, InstallDocs,
    InstallUxContract, InstalledContract, KernelBuildContract, LiveContract, LiveService,
    LiveUkis, RecipeOutputKind, RootfsSourceContract, RootfsSourceKind, RpmBaseContract,
    SourceContract, CONTRACT_SCHEMA_VERSION, INSTALLED_TOOLS, LIVE_KERNEL_CMDLINE, LIVE_TOOLS,
};
pub use variant::{distro_ids, load, Variant};

/// The profile vocabulary, re-exported for the contract's readers.
pub use distro_profile as profile;
pub use distro_profile::Profile;
