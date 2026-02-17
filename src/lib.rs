//! Distro conformance contract schema and validators.
//!
//! This crate is intentionally **conformance-only**:
//! - Defines Stage 00..Stage 08 declaration schema
//! - Loads Stage 00 declarations from `distro-variants/*/00Build.toml`
//! - Validates declaration integrity and anti-gaming rules
//! - Produces deterministic violation reports

pub mod error;
pub mod fs_layout;
pub mod runtime;
pub mod s00_build;
pub mod schema;
pub mod validate;
pub mod variant;

pub use error::{ConformanceError, ConformanceReport, StageId, Violation, ViolationCode};
pub use runtime::{require_valid_stage_00_runtime, validate_stage_00_runtime};
pub use schema::{
    ArtifactIdentity, AuthMode, AutomatedLoginStage, BootStage, BuildCapabilityStage,
    ConformanceContract, DistroIdentity, InstallStage, ReleaseStage, RootfsMutability,
    RuntimePolicyStage, ScriptEvidence, Stage00NonKernelInputs, StageContract, ToolsStage,
    CONTRACT_SCHEMA_VERSION,
};
pub use validate::{require_valid_contract, validate_contract};
pub use variant::{
    load_stage_00_contract_bundle_for_distro_from, load_stage_00_contract_for_distro,
    load_stage_00_contract_for_distro_from, LoadedVariantContract, VariantContractLoadError,
};
