//! Distro conformance contract schema and validators.
//!
//! This crate is intentionally **conformance-only**:
//! - Defines CP1..CP8 declaration schema
//! - Validates declaration integrity and anti-gaming rules
//! - Produces deterministic violation reports

pub mod error;
pub mod schema;
pub mod validate;

pub use error::{CheckpointId, ConformanceError, ConformanceReport, Violation, ViolationCode};
pub use schema::{
    ArtifactIdentity, AuthMode, AutomatedLoginCheckpoint, BootCheckpoint,
    BuildCapabilityCheckpoint, CheckpointContract, ConformanceContract, DistroIdentity,
    InstallCheckpoint, ReleaseCheckpoint, RootfsMutability, RuntimePolicyCheckpoint,
    ScriptEvidence, ToolsCheckpoint, CONTRACT_SCHEMA_VERSION,
};
pub use validate::{require_valid_contract, validate_contract};

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
