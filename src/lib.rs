//! The variant contract: the schema of `distro/variants/<id>/distro.toml`,
//! its loader and rules, and checks of built artifacts against it.

pub mod error;
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
pub use schema::{
    ArtifactIdentity, ArtifactTransform, AuthMode, AutomatedLoginScenario, BootPayloadContract,
    BootScenario, BuildContract, ConformanceContract, DistroIdentity, InstallDocs,
    InstallScenario, InstallUxContract, KernelBuildContract, LiveEnvironmentScenario,
    LiveToolsScenario, PayloadProducerContract,
    ProductConfigContract, ProductContract, ProductDecl, RecipeOutputKind, ReleaseContract,
    RootfsMutability, RootfsSourceContract, RootfsSourceKind, RpmBaseContract,
    RuntimeActionContract, RuntimePolicyScenario, ScenarioContract, ScriptEvidence,
    SourceContract, ToolsScenario, TransformContract, CONTRACT_SCHEMA_VERSION,
};
pub use variant::{distro_ids, load, Variant};

/// The profile vocabulary, re-exported for the contract's readers.
pub use distro_profile as profile;
pub use distro_profile::Profile;
