//! Conformance validation errors and reports.

use std::fmt;

/// Checkpoint identifiers for violation attribution.
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

impl StageId {
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Stage00 => "00Build",
            Self::Stage01 => "01Boot",
            Self::Stage02 => "02LiveTools",
            Self::Stage03 => "03Install",
            Self::Stage04 => "04LoginGate",
            Self::Stage05 => "05Harness",
            Self::Stage06 => "06Runtime",
            Self::Stage07 => "07Update",
            Self::Stage08 => "08Package",
        }
    }
}

impl fmt::Display for StageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical_name())
    }
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

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.stage {
            Some(checkpoint) => write!(
                f,
                "{}.{} [{:?}]: {}",
                checkpoint, self.field, self.code, self.message
            ),
            None => write!(f, "{} [{:?}]: {}", self.field, self.code, self.message),
        }
    }
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
            writeln!(f, "- {}", violation)?;
        }

        Ok(())
    }
}

impl std::error::Error for ConformanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_display_uses_canonical_checkpoint_name() {
        assert_eq!(StageId::Stage01.to_string(), "01Boot");
        assert_eq!(StageId::Stage06.to_string(), "06Runtime");
    }

    #[test]
    fn violation_display_uses_canonical_checkpoint_name() {
        let violation = Violation {
            code: ViolationCode::MissingValue,
            stage: Some(StageId::Stage02),
            field: "scenarios.live_tools.evidence".to_string(),
            message: "missing scenario evidence".to_string(),
        };

        assert_eq!(
            violation.to_string(),
            "02LiveTools.scenarios.live_tools.evidence [MissingValue]: missing scenario evidence"
        );
    }
}
