//! Conformance validation errors and reports.

use std::fmt;

/// Stage identifiers for violation attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageId {
    Stage00,
    Stage01,
    Stage02,
    Stage03,
    Stage04,
    Stage05,
    Stage06,
    Stage07,
    Stage08,
}

/// Stable violation codes for machine-readable error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationCode {
    InvalidSchemaVersion,
    MissingValue,
    WhitespaceValue,
    PlaceholderValue,
    InvalidToken,
    DuplicateEntry,
    GenericSuccessPattern,
    PatternSetOverlap,
    MissingStageToolInLiveTools,
    InvalidAuthDeclaration,
    LoginPromptNotInInstalledBootPatterns,
    InvalidPathDeclaration,
    InvalidMetadataKey,
    MissingBaselineMetadata,
    MissingBaselineArtifact,
    InvalidEvidenceDeclaration,
    MissingRequiredBuildTool,
    RecipeKernelOrchestrationRequired,
    InvalidKernelProvenance,
    UnsupportedModuleInstallPath,
    MissingRequiredKernelOutput,
}

/// One contract violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: ViolationCode,
    pub stage: Option<StageId>,
    pub field: String,
    pub message: String,
}

/// Full validation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub distro_id: String,
    pub schema_version: u32,
    pub violations: Vec<Violation>,
}

impl ConformanceReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Error returned when contract validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceError {
    pub report: ConformanceReport,
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "conformance validation failed for '{}' with {} violation(s)",
            self.report.distro_id,
            self.report.violations.len()
        )?;

        for violation in &self.report.violations {
            match violation.stage {
                Some(cp) => {
                    writeln!(
                        f,
                        "- {:?}.{} [{:?}]: {}",
                        cp, violation.field, violation.code, violation.message
                    )?;
                }
                None => {
                    writeln!(
                        f,
                        "- {} [{:?}]: {}",
                        violation.field, violation.code, violation.message
                    )?;
                }
            }
        }

        Ok(())
    }
}

impl std::error::Error for ConformanceError {}
