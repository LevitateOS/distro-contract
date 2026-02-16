//! Variant-local CP0 contract loader.
//!
//! This module defines the authoritative on-disk CP0 contract format at:
//! `distro-variants/<variant>/cp0.toml`.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::schema::{
    ArtifactIdentity, AuthMode, AutomatedLoginCheckpoint, BootCheckpoint,
    BuildCapabilityCheckpoint, CheckpointContract, ConformanceContract, DistroIdentity,
    InstallCheckpoint, ReleaseCheckpoint, RootfsMutability, RuntimePolicyCheckpoint,
    ScriptEvidence, ToolsCheckpoint,
};

const VARIANTS_DIR: &str = "distro-variants";
const CP0_MANIFEST_FILENAME: &str = "cp0.toml";
const REQUIRED_VARIANT_KCONFIG: &str = "kconfig";
const REQUIRED_VARIANT_RECIPE_DECL: &str = "recipes/kernel.rhai";

/// Loaded variant contract bundle with resolved filesystem paths.
#[derive(Debug, Clone)]
pub struct LoadedVariantContract {
    pub repo_root: PathBuf,
    pub variant_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub contract: ConformanceContract,
}

/// Loader errors for variant-local CP0 declarations.
#[derive(Debug)]
pub enum VariantContractLoadError {
    CurrentDirectoryUnavailable(std::io::Error),
    RepoRootNotFound {
        start: PathBuf,
    },
    VariantDirectoryNotFound {
        distro_id: String,
        path: PathBuf,
    },
    MissingManifestFile {
        path: PathBuf,
    },
    ReadManifestFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    ParseManifestFailed {
        path: PathBuf,
        source: toml::de::Error,
    },
    MissingRequiredFile {
        path: PathBuf,
        description: &'static str,
    },
    InvalidRecipeDeclaration {
        path: PathBuf,
        message: String,
    },
}

impl fmt::Display for VariantContractLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentDirectoryUnavailable(source) => {
                write!(f, "failed to resolve current directory: {source}")
            }
            Self::RepoRootNotFound { start } => write!(
                f,
                "could not locate repository root from '{}': missing '{}' directory in ancestors",
                start.display(),
                VARIANTS_DIR
            ),
            Self::VariantDirectoryNotFound { distro_id, path } => write!(
                f,
                "missing variant directory for '{}': expected '{}'",
                distro_id,
                path.display()
            ),
            Self::MissingManifestFile { path } => write!(
                f,
                "missing CP0 contract manifest: expected '{}'",
                path.display()
            ),
            Self::ReadManifestFailed { path, source } => write!(
                f,
                "failed reading CP0 contract manifest '{}': {}",
                path.display(),
                source
            ),
            Self::ParseManifestFailed { path, source } => write!(
                f,
                "failed parsing CP0 contract manifest '{}': {}",
                path.display(),
                source
            ),
            Self::MissingRequiredFile { path, description } => write!(
                f,
                "missing required CP0 scaffold file ({description}): '{}'",
                path.display()
            ),
            Self::InvalidRecipeDeclaration { path, message } => write!(
                f,
                "invalid CP0 recipe declaration '{}': {}",
                path.display(),
                message
            ),
        }
    }
}

impl std::error::Error for VariantContractLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CurrentDirectoryUnavailable(source) => Some(source),
            Self::ReadManifestFailed { source, .. } => Some(source),
            Self::ParseManifestFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Load a CP0 contract for a distro using current working directory discovery.
pub fn load_cp0_contract_for_distro(
    distro_id: &str,
) -> Result<ConformanceContract, VariantContractLoadError> {
    let cwd =
        std::env::current_dir().map_err(VariantContractLoadError::CurrentDirectoryUnavailable)?;
    load_cp0_contract_for_distro_from(&cwd, distro_id)
}

/// Load a CP0 contract for a distro using `start` as repo-root discovery anchor.
pub fn load_cp0_contract_for_distro_from(
    start: &Path,
    distro_id: &str,
) -> Result<ConformanceContract, VariantContractLoadError> {
    Ok(load_cp0_contract_bundle_for_distro_from(start, distro_id)?.contract)
}

/// Load a CP0 contract bundle (contract + resolved paths) for a distro.
pub fn load_cp0_contract_bundle_for_distro_from(
    start: &Path,
    distro_id: &str,
) -> Result<LoadedVariantContract, VariantContractLoadError> {
    let repo_root = locate_repo_root(start)?;
    load_cp0_contract_bundle_for_distro_at_root(&repo_root, distro_id)
}

fn locate_repo_root(start: &Path) -> Result<PathBuf, VariantContractLoadError> {
    let absolute_start = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(VariantContractLoadError::CurrentDirectoryUnavailable)?
            .join(start)
    };

    for ancestor in absolute_start.ancestors() {
        if ancestor.join(VARIANTS_DIR).is_dir() {
            return Ok(ancestor.to_path_buf());
        }
    }

    Err(VariantContractLoadError::RepoRootNotFound {
        start: absolute_start,
    })
}

fn load_cp0_contract_bundle_for_distro_at_root(
    repo_root: &Path,
    distro_id: &str,
) -> Result<LoadedVariantContract, VariantContractLoadError> {
    let variant_dir = repo_root.join(VARIANTS_DIR).join(distro_id);
    if !variant_dir.is_dir() {
        return Err(VariantContractLoadError::VariantDirectoryNotFound {
            distro_id: distro_id.to_string(),
            path: variant_dir,
        });
    }

    let manifest_path = variant_dir.join(CP0_MANIFEST_FILENAME);
    if !manifest_path.is_file() {
        return Err(VariantContractLoadError::MissingManifestFile {
            path: manifest_path,
        });
    }

    let manifest_raw = fs::read_to_string(&manifest_path).map_err(|source| {
        VariantContractLoadError::ReadManifestFailed {
            path: manifest_path.clone(),
            source,
        }
    })?;
    let manifest: VariantCp0Manifest = toml::from_str(&manifest_raw).map_err(|source| {
        VariantContractLoadError::ParseManifestFailed {
            path: manifest_path.clone(),
            source,
        }
    })?;

    ensure_file_exists(
        &variant_dir.join(REQUIRED_VARIANT_KCONFIG),
        "variant kernel kconfig",
    )?;
    ensure_file_exists(
        &variant_dir.join(REQUIRED_VARIANT_RECIPE_DECL),
        "variant CP0 recipe declaration",
    )?;
    ensure_file_exists(
        &variant_dir.join(&manifest.cp0.evidence.script_path),
        "CP0 evidence script",
    )?;
    ensure_file_exists(
        &repo_root.join(&manifest.cp0.recipe_kernel_script),
        "declared recipe_kernel_script target",
    )?;
    validate_recipe_declaration_content(
        &variant_dir.join(REQUIRED_VARIANT_RECIPE_DECL),
        &manifest.cp0.recipe_kernel_script,
        &manifest.cp0.recipe_kernel_invocation,
    )?;

    Ok(LoadedVariantContract {
        repo_root: repo_root.to_path_buf(),
        variant_dir,
        manifest_path,
        contract: manifest.into_contract(),
    })
}

fn validate_recipe_declaration_content(
    declaration_path: &Path,
    required_script: &str,
    required_invocation: &str,
) -> Result<(), VariantContractLoadError> {
    let raw = fs::read_to_string(declaration_path).map_err(|source| {
        VariantContractLoadError::ReadManifestFailed {
            path: declaration_path.to_path_buf(),
            source,
        }
    })?;

    if !raw.contains(required_script) {
        return Err(VariantContractLoadError::InvalidRecipeDeclaration {
            path: declaration_path.to_path_buf(),
            message: format!("missing required script token '{}'", required_script),
        });
    }
    if !raw.contains(required_invocation) {
        return Err(VariantContractLoadError::InvalidRecipeDeclaration {
            path: declaration_path.to_path_buf(),
            message: format!(
                "missing required invocation token '{}'",
                required_invocation
            ),
        });
    }

    Ok(())
}

fn ensure_file_exists(
    path: &Path,
    description: &'static str,
) -> Result<(), VariantContractLoadError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(VariantContractLoadError::MissingRequiredFile {
            path: path.to_path_buf(),
            description,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantCp0Manifest {
    schema_version: u32,
    identity: VariantIdentity,
    artifacts: VariantArtifacts,
    cp0: VariantCp0Build,
}

impl VariantCp0Manifest {
    fn into_contract(self) -> ConformanceContract {
        ConformanceContract {
            schema_version: self.schema_version,
            identity: DistroIdentity {
                os_name: self.identity.os_name,
                os_id: self.identity.os_id,
                iso_label: self.identity.iso_label,
                os_version: self.identity.os_version,
                default_hostname: self.identity.default_hostname,
            },
            artifacts: ArtifactIdentity {
                rootfs_name: self.artifacts.rootfs_name,
                initramfs_live_output: self.artifacts.initramfs_live_output,
                iso_filename: self.artifacts.iso_filename,
                initramfs_installed_output: self.artifacts.initramfs_installed_output,
            },
            checkpoints: CheckpointContract {
                cp0_build: BuildCapabilityCheckpoint {
                    required_build_tools: self.cp0.required_build_tools,
                    kernel_kconfig_path: self.cp0.kernel_kconfig_path,
                    recipe_kernel_script: self.cp0.recipe_kernel_script,
                    recipe_kernel_invocation: self.cp0.recipe_kernel_invocation,
                    kernel_release_path: self.cp0.kernel_release_path,
                    kernel_image_path: self.cp0.kernel_image_path,
                    kernel_modules_path: self.cp0.kernel_modules_path,
                    kernel_version: self.cp0.kernel_version,
                    kernel_sha256: self.cp0.kernel_sha256,
                    kernel_localversion: self.cp0.kernel_localversion,
                    module_install_path: self.cp0.module_install_path,
                    evidence: ScriptEvidence {
                        script_path: self.cp0.evidence.script_path,
                        pass_marker: self.cp0.evidence.pass_marker,
                    },
                },
                cp1_live_boot: BootCheckpoint {
                    success_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-1-live-boot.sh".to_string(),
                        pass_marker: "CHECKPOINT 1 PASSED".to_string(),
                    },
                },
                cp2_live_tools: ToolsCheckpoint {
                    required_tools: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-2-live-tools.sh".to_string(),
                        pass_marker: "CHECKPOINT 2 PASSED".to_string(),
                    },
                },
                cp3_install: InstallCheckpoint {
                    required_tools: vec!["ignored-in-cp0-phase".to_string()],
                    required_services: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-3-installation.sh".to_string(),
                        pass_marker: "CHECKPOINT 3 PASSED".to_string(),
                    },
                },
                cp4_installed_boot: BootCheckpoint {
                    success_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-4-installed-boot.sh".to_string(),
                        pass_marker: "CHECKPOINT 4 PASSED".to_string(),
                    },
                },
                cp5_automated_login: AutomatedLoginCheckpoint {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("ignored-in-cp0-phase".to_string()),
                    default_password: Some("ignored-in-cp0-phase".to_string()),
                    login_prompt_pattern: "ignored-in-cp0-phase".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-5-automated-login.sh".to_string(),
                        pass_marker: "CHECKPOINT 5 PASSED".to_string(),
                    },
                },
                cp6_installed_tools: ToolsCheckpoint {
                    required_tools: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-6-daily-driver.sh".to_string(),
                        pass_marker: "CHECKPOINT 6 PASSED".to_string(),
                    },
                },
                cp7_runtime_policy: RuntimePolicyCheckpoint {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec![],
                    immutable_required_ro_paths: vec![],
                },
                cp8_release: ReleaseCheckpoint {
                    required_artifacts: vec![],
                    required_metadata: vec![],
                },
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantIdentity {
    os_name: String,
    os_id: String,
    iso_label: String,
    os_version: String,
    default_hostname: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantArtifacts {
    rootfs_name: String,
    initramfs_live_output: String,
    iso_filename: String,
    initramfs_installed_output: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantCp0Build {
    required_build_tools: Vec<String>,
    kernel_kconfig_path: String,
    recipe_kernel_script: String,
    recipe_kernel_invocation: String,
    kernel_release_path: String,
    kernel_image_path: String,
    kernel_modules_path: String,
    kernel_version: String,
    kernel_sha256: String,
    kernel_localversion: String,
    module_install_path: String,
    evidence: VariantEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantEvidence {
    script_path: String,
    pass_marker: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_MANIFEST: &str = r#"schema_version = 3

[identity]
os_name = "LevitateOS"
os_id = "levitateos"
iso_label = "LEVITATEOS"
os_version = "1.0"
default_hostname = "levitateos"

[artifacts]
rootfs_name = "filesystem.erofs"
initramfs_live_output = "initramfs-live.cpio.gz"
iso_filename = "levitateos-x86_64.iso"
initramfs_installed_output = "initramfs-installed.img"

[cp0]
required_build_tools = ["recipe", "cargo", "make", "recuki", "ukify", "mkfs.erofs", "xorriso", "reciso", "recinit", "recstrap", "recfstab", "recchroot"]
kernel_kconfig_path = "kconfig"
recipe_kernel_script = "distro-builder/recipes/linux.rhai"
recipe_kernel_invocation = "recipe install"
kernel_release_path = "kernel-build/include/config/kernel.release"
kernel_image_path = "staging/boot/vmlinuz"
kernel_modules_path = "staging/usr/lib/modules/<kernel.release>"
kernel_version = "6.12.71"
kernel_sha256 = "143e8bc76cc41f831b51aa5e75819bed55bed41f299d35922820f1d2d2b02600"
kernel_localversion = "-levitate"
module_install_path = "/usr/lib/modules"

[cp0.evidence]
script_path = "checkpoint-0-build-capability.sh"
pass_marker = "CHECKPOINT 0 PASSED"
"#;

    fn temp_repo_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "distro-contract-{test_name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp root");
        path
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, content).expect("write file");
    }

    #[test]
    fn loads_variant_cp0_manifest_from_repo_root_ancestor() {
        let repo_root = temp_repo_root("load-ok");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/checkpoint-0-build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/cp0.toml"),
            VALID_MANIFEST,
        );

        let contract =
            load_cp0_contract_for_distro_from(&repo_root.join(".artifacts/out/leviso"), "levitate")
                .expect("load levitate contract");

        assert_eq!(contract.identity.os_name, "LevitateOS");
        assert_eq!(contract.identity.os_id, "levitateos");
        assert_eq!(
            contract.checkpoints.cp0_build.kernel_localversion,
            "-levitate"
        );
        assert_eq!(
            contract.checkpoints.cp0_build.module_install_path,
            "/usr/lib/modules"
        );
        assert_eq!(
            contract.checkpoints.cp0_build.recipe_kernel_script,
            "distro-builder/recipes/linux.rhai"
        );

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn fails_when_variant_manifest_is_missing() {
        let repo_root = temp_repo_root("missing-manifest");
        fs::create_dir_all(repo_root.join("distro-variants/acorn")).expect("create variant dir");

        let err = load_cp0_contract_for_distro_from(&repo_root, "acorn")
            .expect_err("expected missing manifest");
        assert!(matches!(
            err,
            VariantContractLoadError::MissingManifestFile { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn fails_when_recipe_declaration_does_not_reference_required_invocation() {
        let repo_root = temp_repo_root("bad-recipe-decl");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/checkpoint-0-build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/cp0.toml"),
            VALID_MANIFEST,
        );

        let err = load_cp0_contract_for_distro_from(&repo_root, "levitate")
            .expect_err("expected invalid recipe declaration");
        assert!(matches!(
            err,
            VariantContractLoadError::InvalidRecipeDeclaration { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn workspace_cp0_manifests_load_for_all_variants() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("canonicalize workspace root");

        for distro_id in ["levitate", "acorn", "iuppiter", "ralph"] {
            let loaded = load_cp0_contract_bundle_for_distro_from(&repo_root, distro_id)
                .unwrap_or_else(|err| panic!("failed to load {} CP0 manifest: {}", distro_id, err));

            assert_eq!(
                loaded.contract.checkpoints.cp0_build.kernel_kconfig_path,
                "kconfig"
            );
            assert_eq!(
                loaded.contract.checkpoints.cp0_build.recipe_kernel_script,
                "distro-builder/recipes/linux.rhai"
            );
            assert_eq!(
                loaded
                    .contract
                    .checkpoints
                    .cp0_build
                    .recipe_kernel_invocation,
                "recipe install"
            );
            assert_eq!(
                loaded.contract.checkpoints.cp0_build.module_install_path,
                "/usr/lib/modules"
            );
        }
    }
}
