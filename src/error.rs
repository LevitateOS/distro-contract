//! Contract violations and load errors.

use std::fmt;
use std::path::PathBuf;

/// One problem, under the field (a `distro.toml` path such as
/// `sources.rootfs_source.recipe_script`) or the artifact it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub field: String,
    pub message: String,
}

impl Violation {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Why a variant did not load.
#[derive(Debug)]
pub enum LoadError {
    /// No `distro/variants/<id>/distro.toml`.
    UnknownVariant {
        distro_id: String,
        manifest: PathBuf,
        known: Vec<String>,
    },
    Read {
        manifest: PathBuf,
        source: std::io::Error,
    },
    /// The file is not TOML of the contract's shape (unknown or missing field,
    /// wrong type); the message names the field and line.
    Parse {
        manifest: PathBuf,
        source: toml::de::Error,
    },
    /// The file parsed, and these values break the contract's rules.
    Invalid {
        manifest: PathBuf,
        violations: Vec<Violation>,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVariant {
                distro_id,
                manifest,
                known,
            } => write!(
                f,
                "unknown variant '{distro_id}': no {} (variants: {})",
                manifest.display(),
                known.join(", ")
            ),
            Self::Read { manifest, source } => {
                write!(f, "reading {}: {source}", manifest.display())
            }
            Self::Parse { manifest, source } => {
                write!(f, "parsing {}: {source}", manifest.display())
            }
            Self::Invalid {
                manifest,
                violations,
            } => {
                write!(
                    f,
                    "{} has {} problem(s):",
                    manifest.display(),
                    violations.len()
                )?;
                for violation in violations {
                    write!(f, "\n- {violation}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            _ => None,
        }
    }
}
