//! Filesystem layout validation subsystem.
//!
//! Provides first-class, typed checks for required files/directories/symlinks
//! with deterministic conformance violations.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{StageId, Violation, ViolationCode};

/// Expected filesystem entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    File,
    Directory,
    Symlink,
}

impl LayoutKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }
}

/// One required filesystem entry under a root.
#[derive(Debug, Clone)]
pub struct LayoutRequirement {
    pub field: String,
    pub relative_path: PathBuf,
    pub kind: LayoutKind,
    pub code: ViolationCode,
    pub description: &'static str,
}

impl LayoutRequirement {
    pub fn file(
        field: impl Into<String>,
        relative_path: impl Into<PathBuf>,
        code: ViolationCode,
        description: &'static str,
    ) -> Self {
        Self {
            field: field.into(),
            relative_path: relative_path.into(),
            kind: LayoutKind::File,
            code,
            description,
        }
    }

    pub fn directory(
        field: impl Into<String>,
        relative_path: impl Into<PathBuf>,
        code: ViolationCode,
        description: &'static str,
    ) -> Self {
        Self {
            field: field.into(),
            relative_path: relative_path.into(),
            kind: LayoutKind::Directory,
            code,
            description,
        }
    }

    #[allow(dead_code)]
    pub fn symlink(
        field: impl Into<String>,
        relative_path: impl Into<PathBuf>,
        code: ViolationCode,
        description: &'static str,
    ) -> Self {
        Self {
            field: field.into(),
            relative_path: relative_path.into(),
            kind: LayoutKind::Symlink,
            code,
            description,
        }
    }
}

/// A single failed layout check.
#[derive(Debug, Clone)]
pub struct LayoutFailure {
    pub field: String,
    pub path: PathBuf,
    pub description: &'static str,
}

/// Result of validating a set of layout requirements.
#[derive(Debug, Clone, Default)]
pub struct LayoutReport {
    pub violations: Vec<Violation>,
    pub failures: Vec<LayoutFailure>,
}

impl LayoutReport {
    pub fn has_field_violation(&self, field: &str) -> bool {
        self.violations.iter().any(|v| v.field == field)
    }
}

/// Validate filesystem layout requirements under `root`.
pub fn validate_layout(
    stage: Option<StageId>,
    root: &Path,
    requirements: &[LayoutRequirement],
) -> LayoutReport {
    let mut report = LayoutReport::default();

    for req in requirements {
        let full_path = root.join(&req.relative_path);
        if entry_matches_kind(&full_path, req.kind) {
            continue;
        }

        let actual_kind = detect_kind(&full_path);
        let message = if actual_kind == "missing" {
            format!(
                "missing {}: expected {} at '{}'",
                req.description,
                req.kind.as_str(),
                full_path.display()
            )
        } else {
            format!(
                "invalid {}: expected {} at '{}', found {}",
                req.description,
                req.kind.as_str(),
                full_path.display(),
                actual_kind
            )
        };

        report.violations.push(Violation {
            stage,
            field: req.field.clone(),
            code: req.code,
            message,
        });
        report.failures.push(LayoutFailure {
            field: req.field.clone(),
            path: full_path,
            description: req.description,
        });
    }

    report
}

fn entry_matches_kind(path: &Path, expected: LayoutKind) -> bool {
    match expected {
        LayoutKind::File => fs::metadata(path).map(|m| m.is_file()).unwrap_or(false),
        LayoutKind::Directory => fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false),
        LayoutKind::Symlink => fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false),
    }
}

fn detect_kind(path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_file() {
                "file"
            } else if ft.is_dir() {
                "directory"
            } else if ft.is_symlink() {
                "symlink"
            } else {
                "other"
            }
        }
        Err(_) => "missing",
    }
}
