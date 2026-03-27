//! Distro conformance contract schema and validators.
//!
//! This crate is intentionally **conformance-only**:
//! - Defines the canonical conformance declaration schema
//! - Loads canonical variant declarations from the ring/owner manifest family
//! - Validates declaration integrity and anti-gaming rules
//! - Produces deterministic violation reports

mod build_host_legacy;
pub mod error;
pub mod fs_layout;
pub mod runtime;
pub mod schema;
pub mod validate;
pub mod variant;

pub use error::{ConformanceError, ConformanceReport, StageId, Violation, ViolationCode};
pub use runtime::{
    require_valid_build_runtime, require_valid_build_runtime_with_artifacts,
    require_valid_build_runtime_with_split_artifact_roots, require_valid_live_boot_runtime,
    require_valid_live_boot_runtime_with_compatibility_artifact_dir, validate_build_runtime,
    validate_build_runtime_with_artifacts, validate_build_runtime_with_split_artifact_roots,
    validate_live_boot_runtime, validate_live_boot_runtime_with_compatibility_artifact_dir,
    BuildRuntimeArtifacts, LiveBootRuntimeArtifacts,
};
pub use schema::{
    ArtifactIdentity, ArtifactTransform, AuthMode, AutomatedLoginStage, BootPayloadContract,
    BootStage, BuildContract, ConformanceContract, DistroIdentity, InstallDocsFrontend,
    InstallExperience, InstallStage, KernelBuildContract, LiveEnvironmentScenario,
    LiveToolsRuntimeContract, LiveToolsScenario, OpenRcInittab, OverlayContract, OverlayKind,
    PayloadProducerContract, ProductConfigContract, ProductContract, ProductDecl, ReleaseContract,
    ReleaseStage, RootfsMutability, RootfsSourceContract, RootfsSourceKind, RuntimeActionContract,
    RuntimePolicyStage, ScenarioContract, ScriptEvidence, SourceContract, ToolsStage,
    TransformContract, BOOT_REQUIRED_KERNEL_CMDLINE_BASE, BOOT_REQUIRED_LIVE_SERVICES_BASE,
    CONTRACT_SCHEMA_VERSION,
};
pub use validate::{require_valid_contract, validate_contract};
pub use variant::{
    load_variant_contract_bundle_for_distro_from, load_variant_contract_for_distro,
    load_variant_contract_for_distro_from, resolve_variant_owner_paths, LoadedVariantContract,
    VariantContractLoadError, VariantOwnerPaths, VariantPathLayout,
};
