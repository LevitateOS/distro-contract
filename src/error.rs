//! Conformance validation errors and reports.

use std::fmt;

/// Contract owner or runtime scenario associated with a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractScope {
    Build,
    LiveBoot,
    LiveTools,
    Install,
    InstalledBoot,
    AutomatedLogin,
    Runtime,
}

impl ContractScope {
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::LiveBoot => "live-boot",
            Self::LiveTools => "live-tools",
            Self::Install => "install",
            Self::InstalledBoot => "installed-boot",
            Self::AutomatedLogin => "automated-login",
            Self::Runtime => "runtime",
        }
    }
}

impl fmt::Display for ContractScope {
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
    RecipeKernelOrchestrationRequired,
    InvalidKernelProvenance,
    UnsupportedModuleInstallPath,
    MissingRequiredKernelOutput,
}

/// One contract violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: ViolationCode,
    pub scope: Option<ContractScope>,
    pub field: String,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            Some(scope) => write!(
                f,
                "{}.{} [{:?}]: {}",
                scope, self.field, self.code, self.message
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
