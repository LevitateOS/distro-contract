//! Variant-local Stage 00 contract loader.
//!
//! This module defines the authoritative on-disk 00Build contract format at:
//! `distro-variants/<variant>/00Build.toml`.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{StageId, ViolationCode};
use crate::fs_layout::{validate_layout, LayoutRequirement};
use crate::s00_build::{
    LEGACY_MANIFEST_FILENAME, MANIFEST_FILENAME, REQUIRED_VARIANT_KCONFIG,
    REQUIRED_VARIANT_RECIPE_DECL,
};
use crate::schema::{
    ArtifactIdentity, AuthMode, AutomatedLoginStage, BootStage, BuildCapabilityStage,
    ConformanceContract, DistroIdentity, InstallStage, ReleaseStage, RootfsMutability,
    RuntimePolicyStage, ScriptEvidence, Stage00NonKernelInputs, StageContract, ToolsStage,
};

const VARIANTS_DIR: &str = "distro-variants";

/// Loaded variant contract bundle with resolved filesystem paths.
#[derive(Debug, Clone)]
pub struct LoadedVariantContract {
    pub repo_root: PathBuf,
    pub variant_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub contract: ConformanceContract,
}

/// Loader errors for variant-local Stage 00 declarations.
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
                "missing 00Build contract manifest: expected '{}' (legacy fallback: '{}')",
                path.display(),
                LEGACY_MANIFEST_FILENAME
            ),
            Self::ReadManifestFailed { path, source } => write!(
                f,
                "failed reading Stage 00 contract manifest '{}': {}",
                path.display(),
                source
            ),
            Self::ParseManifestFailed { path, source } => write!(
                f,
                "failed parsing Stage 00 contract manifest '{}': {}",
                path.display(),
                source
            ),
            Self::MissingRequiredFile { path, description } => write!(
                f,
                "missing required Stage 00 scaffold file ({description}): '{}'",
                path.display()
            ),
            Self::InvalidRecipeDeclaration { path, message } => write!(
                f,
                "invalid Stage 00 recipe declaration '{}': {}",
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

/// Load a Stage 00 contract for a distro using current working directory discovery.
pub fn load_stage_00_contract_for_distro(
    distro_id: &str,
) -> Result<ConformanceContract, VariantContractLoadError> {
    let cwd =
        std::env::current_dir().map_err(VariantContractLoadError::CurrentDirectoryUnavailable)?;
    load_stage_00_contract_for_distro_from(&cwd, distro_id)
}

/// Load a Stage 00 contract for a distro using `start` as repo-root discovery anchor.
pub fn load_stage_00_contract_for_distro_from(
    start: &Path,
    distro_id: &str,
) -> Result<ConformanceContract, VariantContractLoadError> {
    Ok(load_stage_00_contract_bundle_for_distro_from(start, distro_id)?.contract)
}

/// Load a Stage 00 contract bundle (contract + resolved paths) for a distro.
pub fn load_stage_00_contract_bundle_for_distro_from(
    start: &Path,
    distro_id: &str,
) -> Result<LoadedVariantContract, VariantContractLoadError> {
    let repo_root = locate_repo_root(start)?;
    load_stage_00_contract_bundle_for_distro_at_root(&repo_root, distro_id)
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

fn load_stage_00_contract_bundle_for_distro_at_root(
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

    let manifest_primary = variant_dir.join(MANIFEST_FILENAME);
    let manifest_legacy = variant_dir.join(LEGACY_MANIFEST_FILENAME);
    let manifest_path = if manifest_primary.is_file() {
        manifest_primary
    } else if manifest_legacy.is_file() {
        manifest_legacy
    } else {
        return Err(VariantContractLoadError::MissingManifestFile {
            path: manifest_primary,
        });
    };

    let manifest_raw = fs::read_to_string(&manifest_path).map_err(|source| {
        VariantContractLoadError::ReadManifestFailed {
            path: manifest_path.clone(),
            source,
        }
    })?;
    let manifest: VariantStage00Manifest = toml::from_str(&manifest_raw).map_err(|source| {
        VariantContractLoadError::ParseManifestFailed {
            path: manifest_path.clone(),
            source,
        }
    })?;

    let variant_layout = validate_layout(
        Some(StageId::Stage00),
        &variant_dir,
        &[
            LayoutRequirement::file(
                "stage_00_build.kernel_kconfig_path",
                REQUIRED_VARIANT_KCONFIG,
                ViolationCode::InvalidPathDeclaration,
                "variant kernel kconfig",
            ),
            LayoutRequirement::file(
                "stage_00_build.recipe_kernel_declaration",
                REQUIRED_VARIANT_RECIPE_DECL,
                ViolationCode::InvalidPathDeclaration,
                "variant Stage 00 recipe declaration",
            ),
            LayoutRequirement::file(
                "stage_00_build.evidence.script_path",
                &manifest.stage_00.evidence.script_path,
                ViolationCode::InvalidEvidenceDeclaration,
                "Stage 00 evidence script",
            ),
        ],
    );
    if let Some(first) = variant_layout.failures.first() {
        return Err(VariantContractLoadError::MissingRequiredFile {
            path: first.path.clone(),
            description: first.description,
        });
    }

    let repo_layout = validate_layout(
        Some(StageId::Stage00),
        repo_root,
        &[LayoutRequirement::file(
            "stage_00_build.recipe_kernel_script",
            &manifest.stage_00.recipe_kernel_script,
            ViolationCode::RecipeKernelOrchestrationRequired,
            "declared recipe_kernel_script target",
        )],
    );
    if let Some(first) = repo_layout.failures.first() {
        return Err(VariantContractLoadError::MissingRequiredFile {
            path: first.path.clone(),
            description: first.description,
        });
    }

    validate_recipe_declaration_content(
        &variant_dir.join(REQUIRED_VARIANT_RECIPE_DECL),
        &manifest.stage_00.recipe_kernel_script,
        &manifest.stage_00.recipe_kernel_invocation,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantStage00Manifest {
    schema_version: u32,
    identity: VariantIdentity,
    artifacts: VariantArtifacts,
    stage_00: VariantStage00Build,
}

impl VariantStage00Manifest {
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
            stages: StageContract {
                stage_00_build: BuildCapabilityStage {
                    required_build_tools: self.stage_00.required_build_tools,
                    kernel_kconfig_path: self.stage_00.kernel_kconfig_path,
                    recipe_kernel_script: self.stage_00.recipe_kernel_script,
                    recipe_kernel_invocation: self.stage_00.recipe_kernel_invocation,
                    kernel_release_path: self.stage_00.kernel_release_path,
                    kernel_image_path: self.stage_00.kernel_image_path,
                    kernel_modules_path: self.stage_00.kernel_modules_path,
                    kernel_version: self.stage_00.kernel_version,
                    kernel_sha256: self.stage_00.kernel_sha256,
                    kernel_localversion: self.stage_00.kernel_localversion,
                    module_install_path: self.stage_00.module_install_path,
                    non_kernel_inputs: Stage00NonKernelInputs {
                        required_for_00build: self.stage_00.non_kernel_inputs.required_for_00build,
                        deferred_to_01boot: self.stage_00.non_kernel_inputs.deferred_to_01boot,
                        deferred_to_02livetools: self
                            .stage_00
                            .non_kernel_inputs
                            .deferred_to_02livetools,
                        deferred_to_03install_plus: self
                            .stage_00
                            .non_kernel_inputs
                            .deferred_to_03install_plus,
                    },
                    evidence: ScriptEvidence {
                        script_path: self.stage_00.evidence.script_path,
                        pass_marker: self.stage_00.evidence.pass_marker,
                    },
                },
                stage_01_live_boot: BootStage {
                    success_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-01-live-boot.sh".to_string(),
                        pass_marker: "STAGE 01 PASSED".to_string(),
                    },
                },
                stage_02_live_tools: ToolsStage {
                    required_tools: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-02-live-tools.sh".to_string(),
                        pass_marker: "STAGE 02 PASSED".to_string(),
                    },
                },
                stage_03_install: InstallStage {
                    required_tools: vec!["ignored-in-stage_00-phase".to_string()],
                    required_services: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-03-installation.sh".to_string(),
                        pass_marker: "STAGE 03 PASSED".to_string(),
                    },
                },
                stage_04_installed_boot: BootStage {
                    success_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-04-installed-boot.sh".to_string(),
                        pass_marker: "STAGE 04 PASSED".to_string(),
                    },
                },
                stage_05_automated_login: AutomatedLoginStage {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("ignored-in-stage_00-phase".to_string()),
                    default_password: Some("ignored-in-stage_00-phase".to_string()),
                    login_prompt_pattern: "ignored-in-stage_00-phase".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "stage-05-automated-login.sh".to_string(),
                        pass_marker: "STAGE 05 PASSED".to_string(),
                    },
                },
                stage_06_installed_tools: ToolsStage {
                    required_tools: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-06-daily-driver.sh".to_string(),
                        pass_marker: "STAGE 06 PASSED".to_string(),
                    },
                },
                stage_07_runtime_policy: RuntimePolicyStage {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec![],
                    immutable_required_ro_paths: vec![],
                },
                stage_08_release: ReleaseStage {
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
struct VariantStage00Build {
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
    non_kernel_inputs: VariantStage00NonKernelInputs,
    evidence: VariantEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantStage00NonKernelInputs {
    required_for_00build: Vec<String>,
    deferred_to_01boot: Vec<String>,
    deferred_to_02livetools: Vec<String>,
    deferred_to_03install_plus: Vec<String>,
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

    const VALID_MANIFEST: &str = r#"schema_version = 4

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

[stage_00]
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

[stage_00.non_kernel_inputs]
required_for_00build = ["filesystem.erofs", "initramfs-live.cpio.gz", "overlayfs.erofs"]
deferred_to_01boot = []
deferred_to_02livetools = []
deferred_to_03install_plus = ["initramfs-installed.img"]

[stage_00.evidence]
script_path = "00Build-build-capability.sh"
pass_marker = "STAGE 00 PASSED"
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
    fn loads_variant_stage_00_manifest_from_repo_root_ancestor() {
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
            &repo_root.join("distro-variants/levitate/00Build-build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/00Build.toml"),
            VALID_MANIFEST,
        );

        let contract = load_stage_00_contract_for_distro_from(
            &repo_root.join(".artifacts/out/levitate"),
            "levitate",
        )
        .expect("load levitate contract");

        assert_eq!(contract.identity.os_name, "LevitateOS");
        assert_eq!(contract.identity.os_id, "levitateos");
        assert_eq!(
            contract.stages.stage_00_build.kernel_localversion,
            "-levitate"
        );
        assert_eq!(
            contract.stages.stage_00_build.module_install_path,
            "/usr/lib/modules"
        );
        assert_eq!(
            contract.stages.stage_00_build.recipe_kernel_script,
            "distro-builder/recipes/linux.rhai"
        );

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn fails_when_variant_manifest_is_missing() {
        let repo_root = temp_repo_root("missing-manifest");
        fs::create_dir_all(repo_root.join("distro-variants/acorn")).expect("create variant dir");

        let err = load_stage_00_contract_for_distro_from(&repo_root, "acorn")
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
            &repo_root.join("distro-variants/levitate/00Build-build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_file(
            &repo_root.join("distro-variants/levitate/00Build.toml"),
            VALID_MANIFEST,
        );

        let err = load_stage_00_contract_for_distro_from(&repo_root, "levitate")
            .expect_err("expected invalid recipe declaration");
        assert!(matches!(
            err,
            VariantContractLoadError::InvalidRecipeDeclaration { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn workspace_stage_00_manifests_load_for_all_variants() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("canonicalize workspace root");

        for distro_id in ["levitate", "acorn", "iuppiter", "ralph"] {
            let loaded = load_stage_00_contract_bundle_for_distro_from(&repo_root, distro_id)
                .unwrap_or_else(|err| {
                    panic!("failed to load {} Stage 00 manifest: {}", distro_id, err)
                });

            assert_eq!(
                loaded.contract.stages.stage_00_build.kernel_kconfig_path,
                "kconfig"
            );
            assert_eq!(
                loaded.contract.stages.stage_00_build.recipe_kernel_script,
                "distro-builder/recipes/linux.rhai"
            );
            assert_eq!(
                loaded
                    .contract
                    .stages
                    .stage_00_build
                    .recipe_kernel_invocation,
                "recipe install"
            );
            assert_eq!(
                loaded.contract.stages.stage_00_build.module_install_path,
                "/usr/lib/modules"
            );
        }
    }
}
