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
use crate::s00_build::{MANIFEST_FILENAME, REQUIRED_VARIANT_KCONFIG, REQUIRED_VARIANT_RECIPE_DECL};
use crate::schema::{
    ArtifactIdentity, ArtifactTransform, AuthMode, AutomatedLoginStage, BootStage,
    BuildCapabilityStage, BuildContract, ConformanceContract, DistroIdentity, InstallStage,
    KernelBuildContract, ProductContract, ProductDecl, ReleaseContract, ReleaseStage,
    RootfsMutability, RuntimePolicyStage, ScenarioContract, ScriptEvidence, Stage00IsoAssembly,
    Stage00NonKernelInputs, StageContract, ToolsStage, TransformContract,
    STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE, STAGE_01_REQUIRED_LIVE_SERVICES_BASE,
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
                "missing 00Build contract manifest: expected '{}'",
                path.display()
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

    let manifest_path = variant_dir.join(MANIFEST_FILENAME);
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
    stage_01: Option<VariantStage01Boot>,
}

impl VariantStage00Manifest {
    fn into_contract(self) -> ConformanceContract {
        let build = build_contract_from_manifest(&self.stage_00);
        let products = product_contract_from_manifest(&self.artifacts);
        let transforms = transform_contract_from_manifest(&self.artifacts, &self.stage_00);
        let scenarios = scenario_contract_from_manifest(self.stage_01.as_ref());
        let release = release_contract_from_manifest(&self.artifacts, &transforms);
        let artifacts = artifact_identity_from_transforms(&transforms);
        let stages = stage_contract_from_model(&build, &transforms, &scenarios, &release);

        ConformanceContract {
            schema_version: self.schema_version,
            identity: DistroIdentity {
                os_name: self.identity.os_name,
                os_id: self.identity.os_id,
                iso_label: self.identity.iso_label,
                os_version: self.identity.os_version,
                default_hostname: self.identity.default_hostname,
            },
            build,
            products,
            transforms,
            scenarios,
            release,
            artifacts,
            stages,
        }
    }
}

fn build_contract_from_manifest(stage_00: &VariantStage00Build) -> BuildContract {
    BuildContract {
        required_build_tools: stage_00.required_build_tools.clone(),
        kernel: KernelBuildContract {
            kconfig_path: stage_00.kernel_kconfig_path.clone(),
            recipe_script: stage_00.recipe_kernel_script.clone(),
            recipe_invocation: stage_00.recipe_kernel_invocation.clone(),
            release_path: stage_00.kernel_release_path.clone(),
            image_path: stage_00.kernel_image_path.clone(),
            modules_path: stage_00.kernel_modules_path.clone(),
            version: stage_00.kernel_version.clone(),
            sha256: stage_00.kernel_sha256.clone(),
            localversion: stage_00.kernel_localversion.clone(),
            module_install_path: stage_00.module_install_path.clone(),
        },
        evidence: ScriptEvidence {
            script_path: stage_00.evidence.script_path.clone(),
            pass_marker: stage_00.evidence.pass_marker.clone(),
        },
    }
}

fn product_contract_from_manifest(artifacts: &VariantArtifacts) -> ProductContract {
    ProductContract {
        rootfs_base: ProductDecl {
            logical_name: "product.rootfs.base".to_string(),
            description: "Canonical base root filesystem tree".to_string(),
        },
        live_overlay: ProductDecl {
            logical_name: "product.payload.live_overlay".to_string(),
            description: "Read-only live overlay payload tree".to_string(),
        },
        boot_live: ProductDecl {
            logical_name: "product.payload.boot.live".to_string(),
            description: "Live boot payload inputs".to_string(),
        },
        boot_installed: (artifacts.initramfs_installed_output.is_some()
            || artifacts
                .installed_uki_outputs
                .as_ref()
                .map(|outputs| !outputs.is_empty())
                .unwrap_or(false)
            || artifacts.disk_image_output.is_some())
        .then_some(ProductDecl {
            logical_name: "product.payload.boot.installed".to_string(),
            description: "Installed-system boot payload inputs".to_string(),
        }),
        kernel_staging: ProductDecl {
            logical_name: "product.kernel.staging".to_string(),
            description: "Kernel image and modules staging product".to_string(),
        },
    }
}

fn transform_contract_from_manifest(
    artifacts: &VariantArtifacts,
    stage_00: &VariantStage00Build,
) -> TransformContract {
    let overlay_output = overlay_output_name(&artifacts.rootfs_name);
    let installed_uki_outputs = artifacts.installed_uki_outputs.clone().unwrap_or_default();

    TransformContract {
        rootfs_image: ArtifactTransform {
            logical_name: "artifact.rootfs.erofs".to_string(),
            dependencies: vec!["product.rootfs.base".to_string()],
            output_names: vec![artifacts.rootfs_name.clone()],
            format: "erofs".to_string(),
            extra_cmdline: None,
        },
        overlay_image: ArtifactTransform {
            logical_name: "artifact.overlay.erofs".to_string(),
            dependencies: vec!["product.payload.live_overlay".to_string()],
            output_names: vec![overlay_output],
            format: "erofs".to_string(),
            extra_cmdline: None,
        },
        initramfs_live: ArtifactTransform {
            logical_name: "artifact.initramfs.live".to_string(),
            dependencies: vec![
                "product.payload.boot.live".to_string(),
                "product.kernel.staging".to_string(),
            ],
            output_names: vec![artifacts.initramfs_live_output.clone()],
            format: "cpio.gz".to_string(),
            extra_cmdline: None,
        },
        initramfs_installed: artifacts.initramfs_installed_output.as_ref().map(|output| {
            ArtifactTransform {
                logical_name: "artifact.initramfs.installed".to_string(),
                dependencies: vec![
                    "product.payload.boot.installed".to_string(),
                    "product.kernel.staging".to_string(),
                ],
                output_names: vec![output.clone()],
                format: "img".to_string(),
                extra_cmdline: None,
            }
        }),
        live_uki: ArtifactTransform {
            logical_name: "artifact.uki.live".to_string(),
            dependencies: vec![
                "product.payload.boot.live".to_string(),
                "product.kernel.staging".to_string(),
            ],
            output_names: vec![
                stage_00.iso_assembly.live_uki_filename.clone(),
                stage_00.iso_assembly.emergency_uki_filename.clone(),
                stage_00.iso_assembly.debug_uki_filename.clone(),
            ],
            format: "uki".to_string(),
            extra_cmdline: Some(stage_00.iso_assembly.live_cmdline.clone()),
        },
        installed_uki: (!installed_uki_outputs.is_empty()).then_some(ArtifactTransform {
            logical_name: "artifact.uki.installed".to_string(),
            dependencies: vec![
                "product.payload.boot.installed".to_string(),
                "product.kernel.staging".to_string(),
            ],
            output_names: installed_uki_outputs,
            format: "uki".to_string(),
            extra_cmdline: None,
        }),
        iso: ArtifactTransform {
            logical_name: "artifact.iso".to_string(),
            dependencies: vec![
                "artifact.rootfs.erofs".to_string(),
                "artifact.overlay.erofs".to_string(),
                "artifact.initramfs.live".to_string(),
                "artifact.uki.live".to_string(),
            ],
            output_names: vec![artifacts.iso_filename.clone()],
            format: "iso".to_string(),
            extra_cmdline: None,
        },
        disk_image: artifacts
            .disk_image_output
            .as_ref()
            .map(|output| ArtifactTransform {
                logical_name: "artifact.disk".to_string(),
                dependencies: vec![
                    "product.rootfs.base".to_string(),
                    "product.kernel.staging".to_string(),
                ],
                output_names: vec![output.clone()],
                format: "img".to_string(),
                extra_cmdline: None,
            }),
    }
}

fn artifact_identity_from_transforms(transforms: &TransformContract) -> ArtifactIdentity {
    ArtifactIdentity {
        rootfs_name: transforms.rootfs_image.output_names[0].clone(),
        initramfs_live_output: transforms.initramfs_live.output_names[0].clone(),
        iso_filename: transforms.iso.output_names[0].clone(),
        initramfs_installed_output: transforms
            .initramfs_installed
            .as_ref()
            .map(|transform| transform.output_names[0].clone()),
        installed_uki_outputs: transforms
            .installed_uki
            .as_ref()
            .map(|transform| transform.output_names.clone())
            .unwrap_or_default(),
        disk_image_output: transforms
            .disk_image
            .as_ref()
            .map(|transform| transform.output_names[0].clone()),
    }
}

fn scenario_contract_from_manifest(stage: Option<&VariantStage01Boot>) -> ScenarioContract {
    let (required_kernel_cmdline, required_live_services) = stage01_defaults_with_manifest(stage);

    ScenarioContract {
        live_boot: stage.map(|_| BootStage {
            success_patterns: vec![],
            fatal_patterns: vec![],
            required_kernel_cmdline,
            required_live_services,
            evidence: ScriptEvidence {
                script_path: "stage-01-live-boot.sh".to_string(),
                pass_marker: "STAGE 01 PASSED".to_string(),
            },
        }),
        live_tools: None,
        install: None,
        installed_boot: None,
        automated_login: None,
        installed_tools: None,
        runtime_policy: None,
    }
}

fn release_contract_from_manifest(
    artifacts: &VariantArtifacts,
    _transforms: &TransformContract,
) -> ReleaseContract {
    let mut primary_outputs = vec![artifacts.iso_filename.clone()];
    if let Some(disk_image_output) = artifacts.disk_image_output.as_ref() {
        primary_outputs.push(disk_image_output.clone());
    }

    let mut supporting_artifacts = vec![
        artifacts.rootfs_name.clone(),
        artifacts.initramfs_live_output.clone(),
    ];
    if let Some(initramfs_installed_output) = artifacts.initramfs_installed_output.as_ref() {
        supporting_artifacts.push(initramfs_installed_output.clone());
    }

    ReleaseContract {
        primary_outputs,
        supporting_artifacts,
        metadata_outputs: vec![],
        metadata_facts: release_metadata_facts_from_manifest(artifacts),
    }
}

fn release_metadata_facts_from_manifest(artifacts: &VariantArtifacts) -> Vec<String> {
    let mut metadata_facts = vec![
        "kernel_source.version".to_string(),
        "kernel_source.sha256".to_string(),
        "kernel_source.localversion".to_string(),
        "artifact.rootfs_name".to_string(),
        "artifact.iso_filename".to_string(),
    ];
    if artifacts.disk_image_output.is_some() {
        metadata_facts.push("artifact.disk_image_filename".to_string());
    }
    metadata_facts
}

fn stage_contract_from_model(
    build: &BuildContract,
    transforms: &TransformContract,
    scenarios: &ScenarioContract,
    release: &ReleaseContract,
) -> StageContract {
    StageContract {
        stage_00_build: BuildCapabilityStage {
            required_build_tools: build.required_build_tools.clone(),
            kernel_kconfig_path: build.kernel.kconfig_path.clone(),
            recipe_kernel_script: build.kernel.recipe_script.clone(),
            recipe_kernel_invocation: build.kernel.recipe_invocation.clone(),
            kernel_release_path: build.kernel.release_path.clone(),
            kernel_image_path: build.kernel.image_path.clone(),
            kernel_modules_path: build.kernel.modules_path.clone(),
            kernel_version: build.kernel.version.clone(),
            kernel_sha256: build.kernel.sha256.clone(),
            kernel_localversion: build.kernel.localversion.clone(),
            module_install_path: build.kernel.module_install_path.clone(),
            non_kernel_inputs: Stage00NonKernelInputs {
                required_for_00build: vec![
                    transforms.rootfs_image.output_names[0].clone(),
                    transforms.initramfs_live.output_names[0].clone(),
                    transforms.overlay_image.output_names[0].clone(),
                ],
                deferred_to_01boot: vec![],
                deferred_to_02livetools: vec![],
                deferred_to_03install_plus: vec![],
            },
            iso_assembly: Stage00IsoAssembly {
                live_uki_filename: transforms.live_uki.output_names[0].clone(),
                emergency_uki_filename: transforms.live_uki.output_names[1].clone(),
                debug_uki_filename: transforms.live_uki.output_names[2].clone(),
                live_cmdline: transforms
                    .live_uki
                    .extra_cmdline
                    .clone()
                    .unwrap_or_default(),
            },
            evidence: build.evidence.clone(),
        },
        stage_01_live_boot: scenarios
            .live_boot
            .clone()
            .unwrap_or_else(compat_default_live_boot_stage),
        stage_02_live_tools: scenarios
            .live_tools
            .clone()
            .unwrap_or_else(compat_default_live_tools_stage),
        stage_03_install: scenarios
            .install
            .clone()
            .unwrap_or_else(compat_default_install_stage),
        stage_04_installed_boot: scenarios
            .installed_boot
            .clone()
            .unwrap_or_else(compat_default_installed_boot_stage),
        stage_05_automated_login: scenarios
            .automated_login
            .clone()
            .unwrap_or_else(compat_default_automated_login_stage),
        stage_06_installed_tools: scenarios
            .installed_tools
            .clone()
            .unwrap_or_else(compat_default_installed_tools_stage),
        stage_07_runtime_policy: scenarios
            .runtime_policy
            .clone()
            .unwrap_or_else(compat_default_runtime_policy_stage),
        stage_08_release: ReleaseStage {
            required_artifacts: release
                .primary_outputs
                .iter()
                .chain(release.supporting_artifacts.iter())
                .cloned()
                .collect(),
            required_metadata: release
                .metadata_outputs
                .iter()
                .chain(release.metadata_facts.iter())
                .cloned()
                .collect(),
        },
    }
}

fn compat_default_live_boot_stage() -> BootStage {
    BootStage {
        success_patterns: vec![],
        fatal_patterns: vec![],
        required_kernel_cmdline: vec![],
        required_live_services: vec![],
        evidence: ScriptEvidence {
            script_path: "stage-01-live-boot.sh".to_string(),
            pass_marker: "STAGE 01 PASSED".to_string(),
        },
    }
}

fn compat_default_live_tools_stage() -> ToolsStage {
    ToolsStage {
        required_tools: vec![],
        evidence: ScriptEvidence {
            script_path: "stage-02-live-tools.sh".to_string(),
            pass_marker: "STAGE 02 PASSED".to_string(),
        },
    }
}

fn compat_default_install_stage() -> InstallStage {
    InstallStage {
        required_tools: vec![],
        required_services: vec![],
        evidence: ScriptEvidence {
            script_path: "stage-03-installation.sh".to_string(),
            pass_marker: "STAGE 03 PASSED".to_string(),
        },
    }
}

fn compat_default_installed_boot_stage() -> BootStage {
    BootStage {
        success_patterns: vec![],
        fatal_patterns: vec![],
        required_kernel_cmdline: vec![],
        required_live_services: vec![],
        evidence: ScriptEvidence {
            script_path: "stage-04-installed-boot.sh".to_string(),
            pass_marker: "STAGE 04 PASSED".to_string(),
        },
    }
}

fn compat_default_automated_login_stage() -> AutomatedLoginStage {
    AutomatedLoginStage {
        auth_mode: AuthMode::DefaultPasswordLogin,
        default_username: None,
        default_password: None,
        login_prompt_pattern: String::new(),
        evidence: ScriptEvidence {
            script_path: "stage-05-automated-login.sh".to_string(),
            pass_marker: "STAGE 05 PASSED".to_string(),
        },
    }
}

fn compat_default_installed_tools_stage() -> ToolsStage {
    ToolsStage {
        required_tools: vec![],
        evidence: ScriptEvidence {
            script_path: "stage-06-daily-driver.sh".to_string(),
            pass_marker: "STAGE 06 PASSED".to_string(),
        },
    }
}

fn compat_default_runtime_policy_stage() -> RuntimePolicyStage {
    RuntimePolicyStage {
        rootfs_mutability: RootfsMutability::Mutable,
        mutable_required_rw_paths: vec![],
        immutable_required_ro_paths: vec![],
    }
}

fn overlay_output_name(rootfs_name: &str) -> String {
    let replaced = rootfs_name.replacen("filesystem.erofs", "overlayfs.erofs", 1);
    if replaced != rootfs_name {
        return replaced;
    }
    "overlayfs.erofs".to_string()
}

fn stage01_defaults_with_manifest(
    stage: Option<&VariantStage01Boot>,
) -> (Vec<String>, Vec<String>) {
    let mut required_kernel_cmdline = stage
        .map(|s| s.required_kernel_cmdline.clone())
        .unwrap_or_default();
    let mut required_live_services = stage
        .map(|s| s.required_live_services.clone())
        .unwrap_or_default();

    merge_required_strings(
        &mut required_kernel_cmdline,
        STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE,
    );
    merge_required_strings(
        &mut required_live_services,
        STAGE_01_REQUIRED_LIVE_SERVICES_BASE,
    );

    (required_kernel_cmdline, required_live_services)
}

fn merge_required_strings(values: &mut Vec<String>, required: &[&str]) {
    for required_item in required {
        if values.iter().any(|existing| existing == required_item) {
            continue;
        }
        values.push((*required_item).to_string());
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
    installed_uki_outputs: Option<Vec<String>>,
    disk_image_output: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
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
    iso_assembly: VariantStage00IsoAssembly,
    evidence: VariantEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantStage01Boot {
    required_kernel_cmdline: Vec<String>,
    required_live_services: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct VariantStage00NonKernelInputs {
    required_for_00build: Vec<String>,
    deferred_to_01boot: Vec<String>,
    deferred_to_02livetools: Vec<String>,
    deferred_to_03install_plus: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantStage00IsoAssembly {
    live_uki_filename: String,
    emergency_uki_filename: String,
    debug_uki_filename: String,
    live_cmdline: String,
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

    const VALID_MANIFEST: &str = r#"schema_version = 6

[identity]
os_name = "LevitateOS"
os_id = "levitateos"
iso_label = "LEVITATEOS"
os_version = "1.0"
default_hostname = "levitateos"

[artifacts]
rootfs_name = "s00-filesystem.erofs"
initramfs_live_output = "s00-initramfs-live.cpio.gz"
iso_filename = "levitateos-x86_64.iso"
initramfs_installed_output = "s00-initramfs-installed.img"
installed_uki_outputs = ["levitateos.efi", "levitateos-recovery.efi"]

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
required_for_00build = ["s00-filesystem.erofs", "s00-initramfs-live.cpio.gz", "s00-overlayfs.erofs"]
deferred_to_01boot = []
deferred_to_02livetools = []
deferred_to_03install_plus = ["s00-initramfs-installed.img"]

[stage_00.iso_assembly]
live_uki_filename = "levitateos-live.efi"
emergency_uki_filename = "levitateos-emergency.efi"
debug_uki_filename = "levitateos-debug.efi"
live_cmdline = "video=1920x1080"

[stage_00.evidence]
script_path = "00Build-build-capability.sh"
pass_marker = "STAGE 00 PASSED"

[stage_01]
required_kernel_cmdline = ["audit=1"]
required_live_services = ["sshd"]
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
            contract.products.rootfs_base.logical_name,
            "product.rootfs.base"
        );
        assert_eq!(
            contract.transforms.iso.output_names,
            vec!["levitateos-x86_64.iso".to_string()]
        );
        assert_eq!(
            contract.artifacts.installed_uki_outputs,
            vec![
                "levitateos.efi".to_string(),
                "levitateos-recovery.efi".to_string(),
            ]
        );
        assert_eq!(contract.artifacts.disk_image_output, None);
        assert_eq!(
            contract.release.primary_outputs,
            vec!["levitateos-x86_64.iso".to_string()]
        );
        assert_eq!(
            contract.release.supporting_artifacts,
            vec![
                "s00-filesystem.erofs".to_string(),
                "s00-initramfs-live.cpio.gz".to_string(),
                "s00-initramfs-installed.img".to_string(),
            ]
        );
        assert!(contract.release.metadata_outputs.is_empty());
        assert_eq!(
            contract.release.metadata_facts,
            vec![
                "kernel_source.version".to_string(),
                "kernel_source.sha256".to_string(),
                "kernel_source.localversion".to_string(),
                "artifact.rootfs_name".to_string(),
                "artifact.iso_filename".to_string(),
            ]
        );
        let live_boot = contract
            .scenarios
            .live_boot
            .as_ref()
            .expect("live boot scenario should exist");
        assert!(live_boot.success_patterns.is_empty());
        assert!(live_boot.fatal_patterns.is_empty());
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
        assert_eq!(
            contract.stages.stage_01_live_boot.required_kernel_cmdline,
            vec!["audit=1".to_string(), "inst.sshd=0".to_string()]
        );
        assert_eq!(
            contract.stages.stage_01_live_boot.required_live_services,
            vec!["sshd".to_string()]
        );
        assert_eq!(
            contract.stages.stage_08_release.required_artifacts,
            vec![
                "levitateos-x86_64.iso".to_string(),
                "s00-filesystem.erofs".to_string(),
                "s00-initramfs-live.cpio.gz".to_string(),
                "s00-initramfs-installed.img".to_string(),
            ]
        );
        assert_eq!(
            contract.stages.stage_08_release.required_metadata,
            vec![
                "kernel_source.version".to_string(),
                "kernel_source.sha256".to_string(),
                "kernel_source.localversion".to_string(),
                "artifact.rootfs_name".to_string(),
                "artifact.iso_filename".to_string(),
            ]
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

            let expected_kernel_recipe = if distro_id == "levitate" {
                "distro-builder/recipes/linux-prebuilt.rhai"
            } else {
                "distro-builder/recipes/linux.rhai"
            };

            assert_eq!(
                loaded.contract.stages.stage_00_build.kernel_kconfig_path,
                "kconfig"
            );
            assert_eq!(
                loaded.contract.stages.stage_00_build.recipe_kernel_script,
                expected_kernel_recipe
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
            match distro_id {
                "levitate" => {
                    assert_eq!(
                        loaded.contract.artifacts.installed_uki_outputs,
                        vec![
                            "levitateos.efi".to_string(),
                            "levitateos-recovery.efi".to_string(),
                        ]
                    );
                    assert_eq!(loaded.contract.artifacts.disk_image_output, None);
                }
                "acorn" => {
                    assert_eq!(
                        loaded.contract.artifacts.installed_uki_outputs,
                        vec![
                            "acornos.efi".to_string(),
                            "acornos-recovery.efi".to_string(),
                        ]
                    );
                    assert_eq!(loaded.contract.artifacts.disk_image_output, None);
                }
                "iuppiter" => {
                    assert_eq!(
                        loaded.contract.artifacts.installed_uki_outputs,
                        vec![
                            "iuppiter.efi".to_string(),
                            "iuppiter-recovery.efi".to_string(),
                        ]
                    );
                    assert_eq!(
                        loaded.contract.artifacts.disk_image_output,
                        Some("iuppiteros-x86_64.img".to_string())
                    );
                    assert_eq!(
                        loaded.contract.release.primary_outputs,
                        vec![
                            "iuppiter-x86_64-s00_build.iso".to_string(),
                            "iuppiteros-x86_64.img".to_string(),
                        ]
                    );
                    assert_eq!(
                        loaded.contract.release.metadata_facts,
                        vec![
                            "kernel_source.version".to_string(),
                            "kernel_source.sha256".to_string(),
                            "kernel_source.localversion".to_string(),
                            "artifact.rootfs_name".to_string(),
                            "artifact.iso_filename".to_string(),
                            "artifact.disk_image_filename".to_string(),
                        ]
                    );
                }
                "ralph" => {
                    assert!(loaded.contract.artifacts.installed_uki_outputs.is_empty());
                    assert_eq!(loaded.contract.artifacts.disk_image_output, None);
                }
                other => panic!("unexpected distro {}", other),
            }
        }
    }

    #[test]
    fn scenario_contract_from_missing_manifest_is_explicitly_partial() {
        let scenarios = scenario_contract_from_manifest(None);
        assert!(scenarios.live_boot.is_none());
        assert!(scenarios.live_tools.is_none());
        assert!(scenarios.install.is_none());
        assert!(scenarios.installed_boot.is_none());
        assert!(scenarios.automated_login.is_none());
        assert!(scenarios.installed_tools.is_none());
        assert!(scenarios.runtime_policy.is_none());
    }

    #[test]
    fn legacy_stage_view_uses_compat_defaults_only_for_absent_scenarios() {
        let build = BuildContract {
            required_build_tools: vec![],
            kernel: KernelBuildContract {
                kconfig_path: "kconfig".to_string(),
                recipe_script: "kernel.rhai".to_string(),
                recipe_invocation: "recipe install kernel.rhai".to_string(),
                release_path: "kernel.release".to_string(),
                image_path: "vmlinuz".to_string(),
                modules_path: "modules".to_string(),
                version: "1.0.0".to_string(),
                sha256: "deadbeef".to_string(),
                localversion: "-test".to_string(),
                module_install_path: "usr/lib/modules".to_string(),
            },
            evidence: ScriptEvidence {
                script_path: "stage-00.sh".to_string(),
                pass_marker: "STAGE 00 PASSED".to_string(),
            },
        };
        let transforms = TransformContract {
            rootfs_image: ArtifactTransform {
                logical_name: "artifact.rootfs.erofs".to_string(),
                dependencies: vec!["product.rootfs.base".to_string()],
                output_names: vec!["filesystem.erofs".to_string()],
                format: "erofs".to_string(),
                extra_cmdline: None,
            },
            overlay_image: ArtifactTransform {
                logical_name: "artifact.overlay.erofs".to_string(),
                dependencies: vec!["product.payload.live_overlay".to_string()],
                output_names: vec!["overlayfs.erofs".to_string()],
                format: "erofs".to_string(),
                extra_cmdline: None,
            },
            initramfs_live: ArtifactTransform {
                logical_name: "artifact.initramfs.live".to_string(),
                dependencies: vec!["product.payload.boot.live".to_string()],
                output_names: vec!["initramfs-live.cpio.gz".to_string()],
                format: "cpio.gz".to_string(),
                extra_cmdline: None,
            },
            initramfs_installed: None,
            live_uki: ArtifactTransform {
                logical_name: "artifact.uki.live".to_string(),
                dependencies: vec![
                    "product.payload.boot.live".to_string(),
                    "product.kernel.staging".to_string(),
                ],
                output_names: vec![
                    "live.efi".to_string(),
                    "live-emergency.efi".to_string(),
                    "live-debug.efi".to_string(),
                ],
                format: "uki".to_string(),
                extra_cmdline: None,
            },
            installed_uki: None,
            iso: ArtifactTransform {
                logical_name: "artifact.iso".to_string(),
                dependencies: vec![
                    "artifact.rootfs.erofs".to_string(),
                    "artifact.overlay.erofs".to_string(),
                    "artifact.initramfs.live".to_string(),
                    "artifact.uki.live".to_string(),
                ],
                output_names: vec!["example.iso".to_string()],
                format: "iso".to_string(),
                extra_cmdline: None,
            },
            disk_image: None,
        };
        let scenarios = ScenarioContract {
            live_boot: Some(BootStage {
                success_patterns: vec!["boot complete".to_string()],
                fatal_patterns: vec![],
                required_kernel_cmdline: vec![],
                required_live_services: vec![],
                evidence: ScriptEvidence {
                    script_path: "stage-01-live-boot.sh".to_string(),
                    pass_marker: "STAGE 01 PASSED".to_string(),
                },
            }),
            live_tools: None,
            install: None,
            installed_boot: None,
            automated_login: None,
            installed_tools: None,
            runtime_policy: None,
        };
        let release = ReleaseContract {
            primary_outputs: vec!["example.iso".to_string()],
            supporting_artifacts: vec![],
            metadata_outputs: vec![],
            metadata_facts: vec![],
        };

        let stages = stage_contract_from_model(&build, &transforms, &scenarios, &release);
        assert_eq!(
            stages.stage_01_live_boot.evidence.script_path,
            "stage-01-live-boot.sh"
        );
        assert_eq!(
            stages.stage_02_live_tools.evidence.script_path,
            "stage-02-live-tools.sh"
        );
    }
}
