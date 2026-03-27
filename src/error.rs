//! Conformance validation errors and reports.

use std::fmt;

/// Checkpoint identifiers for violation attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointId {
    Build,
    Boot,
    LiveTools,
    Install,
    LoginGate,
    Harness,
    Runtime,
    Update,
    Package,
}

impl CheckpointId {
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Build => "00Build",
            Self::Boot => "01Boot",
            Self::LiveTools => "02LiveTools",
            Self::Install => "03Install",
            Self::LoginGate => "04LoginGate",
            Self::Harness => "05Harness",
            Self::Runtime => "06Runtime",
            Self::Update => "07Update",
            Self::Package => "08Package",
        }
    }
}

impl fmt::Display for CheckpointId {
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
    MissingRequiredToolInLiveTools,
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
    pub checkpoint: Option<CheckpointId>,
    pub field: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.checkpoint {
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
    fn checkpoint_id_display_uses_canonical_name() {
        assert_eq!(CheckpointId::Boot.to_string(), "01Boot");
        assert_eq!(CheckpointId::Runtime.to_string(), "06Runtime");
    }

    #[test]
    fn violation_display_uses_canonical_checkpoint_name() {
        let violation = Violation {
            code: ViolationCode::MissingValue,
            checkpoint: Some(CheckpointId::LiveTools),
            field: "scenarios.live_tools.evidence".to_string(),
            message: "missing scenario evidence".to_string(),
        };

        assert_eq!(
            violation.to_string(),
            "02LiveTools.scenarios.live_tools.evidence [MissingValue]: missing scenario evidence"
        );
    }
}
