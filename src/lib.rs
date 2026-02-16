//! Distro conformance contract schema and validators.
//!
//! This crate is intentionally **conformance-only**:
//! - Defines CP0..CP8 declaration schema
//! - Loads CP0 declarations from `distro-variants/*/cp0.toml`
//! - Validates declaration integrity and anti-gaming rules
//! - Produces deterministic violation reports

pub mod error;
pub mod runtime;
pub mod schema;
pub mod validate;
pub mod variant;

pub use error::{CheckpointId, ConformanceError, ConformanceReport, Violation, ViolationCode};
pub use runtime::{require_valid_cp0_runtime, validate_cp0_runtime};
pub use schema::{
    ArtifactIdentity, AuthMode, AutomatedLoginCheckpoint, BootCheckpoint,
    BuildCapabilityCheckpoint, CheckpointContract, ConformanceContract, DistroIdentity,
    InstallCheckpoint, ReleaseCheckpoint, RootfsMutability, RuntimePolicyCheckpoint,
    ScriptEvidence, ToolsCheckpoint, CONTRACT_SCHEMA_VERSION,
};
pub use validate::{require_valid_contract, validate_contract};
pub use variant::{
    load_cp0_contract_bundle_for_distro_from, load_cp0_contract_for_distro,
    load_cp0_contract_for_distro_from, LoadedVariantContract, VariantContractLoadError,
};

/// Alias used by external preflight integrations.
pub fn run_preflight(
    contract: &ConformanceContract,
) -> Result<ConformanceReport, ConformanceError> {
    let report = validate_contract(contract);
    if report.passed() {
        Ok(report)
    } else {
        Err(ConformanceError { report })
    }
}
