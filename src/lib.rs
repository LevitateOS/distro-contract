//! Distro conformance contract schema and validators.
//!
//! This crate is intentionally **conformance-only**:
//! - Defines Stage 00..Stage 08 declaration schema
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
    require_valid_live_boot_runtime, require_valid_stage_00_runtime,
    require_valid_stage_00_runtime_with_artifacts, require_valid_stage_00_runtime_with_stage_dirs,
    require_valid_stage_01_runtime, validate_live_boot_runtime, validate_stage_00_runtime,
    validate_stage_00_runtime_with_artifacts, validate_stage_00_runtime_with_stage_dirs,
    validate_stage_01_runtime, LiveBootRuntimeArtifacts, Stage00RuntimeArtifacts,
};
pub use schema::{
    ArtifactIdentity, ArtifactTransform, AuthMode, AutomatedLoginStage, BootStage,
    BuildCapabilityStage, BuildContract, ConformanceContract, DistroIdentity, InstallStage,
    KernelBuildContract, ProductContract, ProductDecl, ReleaseContract, ReleaseStage,
    RootfsMutability, RuntimePolicyStage, ScenarioContract, ScriptEvidence, Stage00IsoAssembly,
    Stage00NonKernelInputs, StageContract, ToolsStage, TransformContract, CONTRACT_SCHEMA_VERSION,
    STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE, STAGE_01_REQUIRED_LIVE_SERVICES_BASE,
};
pub use validate::{require_valid_contract, validate_contract};
pub use variant::{
    load_variant_contract_bundle_for_distro_from, load_variant_contract_for_distro,
    load_variant_contract_for_distro_from, LoadedVariantContract, VariantContractLoadError,
};
