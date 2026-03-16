//! Variant-local contract loader.
//!
//! Canonical ownership now lives in the ring/owner manifest family:
//! `identity.toml`, `build-host.toml`, `ring3-sources.toml`,
//! `ring2-products.toml`, `ring1-transforms.toml`, `ring0-release.toml`, and
//! `scenarios.toml`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::build_host_legacy::{REQUIRED_VARIANT_KCONFIG, REQUIRED_VARIANT_RECIPE_DECL};
use crate::error::{StageId, ViolationCode};
use crate::fs_layout::{validate_layout, LayoutRequirement};
use crate::schema::{
    ArtifactIdentity, ArtifactTransform, AuthMode, AutomatedLoginStage, BootStage, BuildContract,
    ConformanceContract, DistroIdentity, InstallStage, KernelBuildContract, ProductContract,
    ProductDecl, ReleaseContract, RootfsMutability, RootfsSourceContract, RootfsSourceKind,
    RuntimePolicyStage, ScenarioContract, ScriptEvidence, SourceContract, ToolsStage,
    TransformContract, STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE, STAGE_01_REQUIRED_LIVE_SERVICES_BASE,
};

const VARIANTS_DIR: &str = "distro-variants";
const IDENTITY_MANIFEST_FILENAME: &str = "identity.toml";
const BUILD_HOST_MANIFEST_FILENAME: &str = "build-host.toml";
const RING3_SOURCES_MANIFEST_FILENAME: &str = "ring3-sources.toml";
const RING2_PRODUCTS_MANIFEST_FILENAME: &str = "ring2-products.toml";
const RING1_TRANSFORMS_MANIFEST_FILENAME: &str = "ring1-transforms.toml";
const RING0_RELEASE_MANIFEST_FILENAME: &str = "ring0-release.toml";
const SCENARIOS_MANIFEST_FILENAME: &str = "scenarios.toml";

/// Loaded variant contract bundle with resolved filesystem paths.
#[derive(Debug, Clone)]
pub struct LoadedVariantContract {
    pub repo_root: PathBuf,
    pub variant_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub contract: ConformanceContract,
}

/// Loader errors for variant-local contract declarations.
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
    PartialRingManifestSet {
        variant_dir: PathBuf,
        present: Vec<String>,
        missing: Vec<String>,
    },
    ReadRingManifestFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    ParseRingManifestFailed {
        path: PathBuf,
        source: toml::de::Error,
    },
    ReadSupportFileFailed {
        path: PathBuf,
        source: std::io::Error,
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
            Self::PartialRingManifestSet {
                variant_dir,
                present,
                missing,
            } => write!(
                f,
                "partial ring-manifest scaffold under '{}': present [{}], missing [{}]",
                variant_dir.display(),
                present.join(", "),
                missing.join(", ")
            ),
            Self::ReadRingManifestFailed { path, source } => write!(
                f,
                "failed reading ring manifest '{}': {}",
                path.display(),
                source
            ),
            Self::ParseRingManifestFailed { path, source } => write!(
                f,
                "failed parsing ring manifest '{}': {}",
                path.display(),
                source
            ),
            Self::ReadSupportFileFailed { path, source } => write!(
                f,
                "failed reading required support file '{}': {}",
                path.display(),
                source
            ),
            Self::MissingRequiredFile { path, description } => write!(
                f,
                "missing required build-host scaffold file ({description}): '{}'",
                path.display()
            ),
            Self::InvalidRecipeDeclaration { path, message } => write!(
                f,
                "invalid build-host recipe declaration '{}': {}",
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
            Self::ReadRingManifestFailed { source, .. } => Some(source),
            Self::ParseRingManifestFailed { source, .. } => Some(source),
            Self::ReadSupportFileFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Load a variant contract for a distro using current working directory discovery.
pub fn load_variant_contract_for_distro(
    distro_id: &str,
) -> Result<ConformanceContract, VariantContractLoadError> {
    let cwd =
        std::env::current_dir().map_err(VariantContractLoadError::CurrentDirectoryUnavailable)?;
    load_variant_contract_for_distro_from(&cwd, distro_id)
}

/// Load a variant contract for a distro using `start` as repo-root discovery anchor.
pub fn load_variant_contract_for_distro_from(
    start: &Path,
    distro_id: &str,
) -> Result<ConformanceContract, VariantContractLoadError> {
    Ok(load_variant_contract_bundle_for_distro_from(start, distro_id)?.contract)
}

/// Load a variant contract bundle (contract + resolved paths) for a distro.
pub fn load_variant_contract_bundle_for_distro_from(
    start: &Path,
    distro_id: &str,
) -> Result<LoadedVariantContract, VariantContractLoadError> {
    let repo_root = locate_repo_root(start)?;
    load_variant_contract_bundle_for_distro_at_root(&repo_root, distro_id)
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

fn load_variant_contract_bundle_for_distro_at_root(
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

    let ring_manifest_bundle = load_ring_manifest_bundle(&variant_dir)?;
    let manifest_path = variant_dir.join(BUILD_HOST_MANIFEST_FILENAME);

    let variant_layout = validate_layout(
        Some(StageId::Stage00),
        &variant_dir,
        &[
            LayoutRequirement::file(
                "build_host.kernel_kconfig_path",
                REQUIRED_VARIANT_KCONFIG,
                ViolationCode::InvalidPathDeclaration,
                "variant kernel kconfig",
            ),
            LayoutRequirement::file(
                "build_host.recipe_kernel_declaration",
                REQUIRED_VARIANT_RECIPE_DECL,
                ViolationCode::InvalidPathDeclaration,
                "variant recipe declaration",
            ),
            LayoutRequirement::file(
                "build_host.evidence.script_path",
                &ring_manifest_bundle
                    .build_host
                    .build_host
                    .evidence
                    .script_path,
                ViolationCode::InvalidEvidenceDeclaration,
                "build evidence script",
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
            "build_host.recipe_kernel_script",
            &ring_manifest_bundle
                .build_host
                .build_host
                .recipe_kernel_script,
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
        &ring_manifest_bundle
            .build_host
            .build_host
            .recipe_kernel_script,
        &ring_manifest_bundle
            .build_host
            .build_host
            .recipe_kernel_invocation,
    )?;
    let contract = contract_from_ring_manifest_bundle(&ring_manifest_bundle);

    Ok(LoadedVariantContract {
        repo_root: repo_root.to_path_buf(),
        variant_dir,
        manifest_path,
        contract,
    })
}

fn validate_recipe_declaration_content(
    declaration_path: &Path,
    required_script: &str,
    required_invocation: &str,
) -> Result<(), VariantContractLoadError> {
    let raw = fs::read_to_string(declaration_path).map_err(|source| {
        VariantContractLoadError::ReadSupportFileFailed {
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

fn contract_from_ring_manifest_bundle(ring: &VariantRingManifestBundle) -> ConformanceContract {
    let identity = identity_from_manifest(&ring.identity.identity);
    let build = build_contract_from_ring_manifest(&ring.build_host.build_host);
    let sources = source_contract_from_ring_manifest(&ring.ring3_sources.ring3_sources);
    let products = product_contract_from_ring_manifest(&ring.ring2_products.ring2_products);
    let transforms = TransformContract {
        rootfs_image: artifact_transform_from_ring_manifest(
            &ring.ring1_transforms.ring1_transforms.rootfs_image,
        ),
        overlay_image: artifact_transform_from_ring_manifest(
            &ring.ring1_transforms.ring1_transforms.overlay_image,
        ),
        initramfs_live: artifact_transform_from_ring_manifest(
            &ring.ring1_transforms.ring1_transforms.initramfs_live,
        ),
        initramfs_installed: ring
            .ring1_transforms
            .ring1_transforms
            .initramfs_installed
            .as_ref()
            .map(artifact_transform_from_ring_manifest),
        live_uki: artifact_transform_from_ring_manifest(
            &ring.ring1_transforms.ring1_transforms.live_uki,
        ),
        installed_uki: ring
            .ring1_transforms
            .ring1_transforms
            .installed_uki
            .as_ref()
            .map(artifact_transform_from_ring_manifest),
        iso: artifact_transform_from_ring_manifest(&ring.ring0_release.ring0_release.iso),
        disk_image: ring
            .ring0_release
            .ring0_release
            .disk_image
            .as_ref()
            .map(artifact_transform_from_ring_manifest),
    };
    let scenarios = scenario_contract_from_ring_manifest(&ring.scenarios.scenarios);
    let release = release_contract_from_ring_manifest(&ring.ring0_release.ring0_release.release);
    let artifacts = artifact_identity_from_transforms(&transforms);

    ConformanceContract {
        schema_version: ring.build_host.schema_version,
        identity,
        build,
        sources,
        products,
        transforms,
        scenarios,
        release,
        artifacts,
    }
}

fn load_ring_manifest_bundle(
    variant_dir: &Path,
) -> Result<VariantRingManifestBundle, VariantContractLoadError> {
    let manifest_specs = [
        ("identity", IDENTITY_MANIFEST_FILENAME),
        ("build_host", BUILD_HOST_MANIFEST_FILENAME),
        ("ring3_sources", RING3_SOURCES_MANIFEST_FILENAME),
        ("ring2_products", RING2_PRODUCTS_MANIFEST_FILENAME),
        ("ring1_transforms", RING1_TRANSFORMS_MANIFEST_FILENAME),
        ("ring0_release", RING0_RELEASE_MANIFEST_FILENAME),
        ("scenarios", SCENARIOS_MANIFEST_FILENAME),
    ];

    let mut present = Vec::new();
    let mut missing = Vec::new();
    for (_, filename) in manifest_specs {
        let path = variant_dir.join(filename);
        if path.is_file() {
            present.push(filename.to_string());
        } else {
            missing.push(filename.to_string());
        }
    }

    if !missing.is_empty() {
        return Err(VariantContractLoadError::PartialRingManifestSet {
            variant_dir: variant_dir.to_path_buf(),
            present,
            missing,
        });
    }

    Ok(VariantRingManifestBundle {
        identity: read_ring_manifest(&variant_dir.join(IDENTITY_MANIFEST_FILENAME))?,
        build_host: read_ring_manifest(&variant_dir.join(BUILD_HOST_MANIFEST_FILENAME))?,
        ring3_sources: read_ring_manifest(&variant_dir.join(RING3_SOURCES_MANIFEST_FILENAME))?,
        ring2_products: read_ring_manifest(&variant_dir.join(RING2_PRODUCTS_MANIFEST_FILENAME))?,
        ring1_transforms: read_ring_manifest(
            &variant_dir.join(RING1_TRANSFORMS_MANIFEST_FILENAME),
        )?,
        ring0_release: read_ring_manifest(&variant_dir.join(RING0_RELEASE_MANIFEST_FILENAME))?,
        scenarios: read_ring_manifest(&variant_dir.join(SCENARIOS_MANIFEST_FILENAME))?,
    })
}

fn read_ring_manifest<T>(path: &Path) -> Result<T, VariantContractLoadError>
where
    T: DeserializeOwned,
{
    let raw = fs::read_to_string(path).map_err(|source| {
        VariantContractLoadError::ReadRingManifestFailed {
            path: path.to_path_buf(),
            source,
        }
    })?;
    toml::from_str(&raw).map_err(|source| VariantContractLoadError::ParseRingManifestFailed {
        path: path.to_path_buf(),
        source,
    })
}

fn identity_from_manifest(identity: &VariantIdentity) -> DistroIdentity {
    DistroIdentity {
        os_name: identity.os_name.clone(),
        os_id: identity.os_id.clone(),
        iso_label: identity.iso_label.clone(),
        os_version: identity.os_version.clone(),
        default_hostname: identity.default_hostname.clone(),
    }
}

fn build_contract_from_ring_manifest(build_host: &VariantBuildHost) -> BuildContract {
    BuildContract {
        required_build_tools: build_host.required_build_tools.clone(),
        kernel: KernelBuildContract {
            kconfig_path: build_host.kernel_kconfig_path.clone(),
            recipe_script: build_host.recipe_kernel_script.clone(),
            recipe_invocation: build_host.recipe_kernel_invocation.clone(),
            release_path: build_host.kernel_release_path.clone(),
            image_path: build_host.kernel_image_path.clone(),
            modules_path: build_host.kernel_modules_path.clone(),
            version: build_host.kernel_version.clone(),
            sha256: build_host.kernel_sha256.clone(),
            localversion: build_host.kernel_localversion.clone(),
            module_install_path: build_host.module_install_path.clone(),
        },
        evidence: ScriptEvidence {
            script_path: build_host.evidence.script_path.clone(),
            pass_marker: build_host.evidence.pass_marker.clone(),
        },
    }
}

fn product_contract_from_ring_manifest(ring2_products: &VariantRing2Products) -> ProductContract {
    ProductContract {
        rootfs_base: ProductDecl {
            logical_name: ring2_products.rootfs_base.logical_name.clone(),
            description: ring2_products.rootfs_base.description.clone(),
            extends: ring2_products.rootfs_base.extends.clone(),
        },
        live_overlay: ProductDecl {
            logical_name: ring2_products.live_overlay.logical_name.clone(),
            description: ring2_products.live_overlay.description.clone(),
            extends: ring2_products.live_overlay.extends.clone(),
        },
        boot_live: ProductDecl {
            logical_name: ring2_products.boot_live.logical_name.clone(),
            description: ring2_products.boot_live.description.clone(),
            extends: ring2_products.boot_live.extends.clone(),
        },
        live_tools: ProductDecl {
            logical_name: ring2_products.live_tools.logical_name.clone(),
            description: ring2_products.live_tools.description.clone(),
            extends: ring2_products.live_tools.extends.clone(),
        },
        boot_installed: ring2_products
            .boot_installed
            .as_ref()
            .map(|product| ProductDecl {
                logical_name: product.logical_name.clone(),
                description: product.description.clone(),
                extends: product.extends.clone(),
            }),
        kernel_staging: ProductDecl {
            logical_name: ring2_products.kernel_staging.logical_name.clone(),
            description: ring2_products.kernel_staging.description.clone(),
            extends: ring2_products.kernel_staging.extends.clone(),
        },
    }
}

fn source_contract_from_ring_manifest(ring3_sources: &VariantRing3Sources) -> SourceContract {
    SourceContract {
        rootfs_source: RootfsSourceContract {
            kind: match ring3_sources.rootfs_source.kind {
                VariantRootfsSourceKind::RecipeRpmDvd => RootfsSourceKind::RecipeRpmDvd,
                VariantRootfsSourceKind::RecipeCustom => RootfsSourceKind::RecipeCustom,
            },
            recipe_script: ring3_sources.rootfs_source.recipe_script.clone(),
            preseed_recipe_script: ring3_sources.rootfs_source.preseed_recipe_script.clone(),
            defines: ring3_sources
                .rootfs_source
                .defines
                .clone()
                .unwrap_or_default(),
        },
    }
}

fn artifact_transform_from_ring_manifest(transform: &VariantRingTransform) -> ArtifactTransform {
    ArtifactTransform {
        logical_name: transform.logical_name.clone(),
        dependencies: transform.dependencies.clone(),
        output_names: transform.output_names.clone(),
        format: transform.format.clone(),
        extra_cmdline: transform.extra_cmdline.clone(),
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

fn scenario_contract_from_ring_manifest(scenarios: &VariantScenarios) -> ScenarioContract {
    let (required_kernel_cmdline, required_live_services) = stage01_defaults_from_values(
        scenarios.live_boot.required_kernel_cmdline.clone(),
        scenarios.live_boot.required_live_services.clone(),
    );

    ScenarioContract {
        live_boot: BootStage {
            success_patterns: scenarios.live_boot.success_patterns.clone(),
            fatal_patterns: scenarios.live_boot.fatal_patterns.clone(),
            required_kernel_cmdline,
            required_live_services,
            evidence: ScriptEvidence {
                script_path: scenarios.live_boot.evidence.script_path.clone(),
                pass_marker: scenarios.live_boot.evidence.pass_marker.clone(),
            },
        },
        live_tools: ToolsStage {
            required_tools: scenarios.live_tools.required_tools.clone(),
            evidence: ScriptEvidence {
                script_path: scenarios.live_tools.evidence.script_path.clone(),
                pass_marker: scenarios.live_tools.evidence.pass_marker.clone(),
            },
        },
        install: InstallStage {
            required_tools: scenarios.install.required_tools.clone(),
            required_services: scenarios.install.required_services.clone(),
            evidence: ScriptEvidence {
                script_path: scenarios.install.evidence.script_path.clone(),
                pass_marker: scenarios.install.evidence.pass_marker.clone(),
            },
        },
        installed_boot: BootStage {
            success_patterns: scenarios.installed_boot.success_patterns.clone(),
            fatal_patterns: scenarios.installed_boot.fatal_patterns.clone(),
            required_kernel_cmdline: scenarios.installed_boot.required_kernel_cmdline.clone(),
            required_live_services: scenarios.installed_boot.required_live_services.clone(),
            evidence: ScriptEvidence {
                script_path: scenarios.installed_boot.evidence.script_path.clone(),
                pass_marker: scenarios.installed_boot.evidence.pass_marker.clone(),
            },
        },
        automated_login: AutomatedLoginStage {
            auth_mode: match scenarios.automated_login.auth_mode {
                VariantAuthMode::DefaultPasswordLogin => AuthMode::DefaultPasswordLogin,
                VariantAuthMode::ProvisionedCredentials => AuthMode::ProvisionedCredentials,
            },
            default_username: scenarios.automated_login.default_username.clone(),
            default_password: scenarios.automated_login.default_password.clone(),
            login_prompt_pattern: scenarios.automated_login.login_prompt_pattern.clone(),
            evidence: ScriptEvidence {
                script_path: scenarios.automated_login.evidence.script_path.clone(),
                pass_marker: scenarios.automated_login.evidence.pass_marker.clone(),
            },
        },
        installed_tools: ToolsStage {
            required_tools: scenarios.installed_tools.required_tools.clone(),
            evidence: ScriptEvidence {
                script_path: scenarios.installed_tools.evidence.script_path.clone(),
                pass_marker: scenarios.installed_tools.evidence.pass_marker.clone(),
            },
        },
        runtime_policy: RuntimePolicyStage {
            rootfs_mutability: match scenarios.runtime_policy.rootfs_mutability {
                VariantRootfsMutability::Mutable => RootfsMutability::Mutable,
                VariantRootfsMutability::Immutable => RootfsMutability::Immutable,
            },
            mutable_required_rw_paths: scenarios.runtime_policy.mutable_required_rw_paths.clone(),
            immutable_required_ro_paths: scenarios
                .runtime_policy
                .immutable_required_ro_paths
                .clone(),
        },
    }
}

fn release_contract_from_ring_manifest(release: &VariantReleaseDecl) -> ReleaseContract {
    ReleaseContract {
        primary_outputs: release.primary_outputs.clone(),
        supporting_artifacts: release.supporting_artifacts.clone(),
        metadata_outputs: release.metadata_outputs.clone(),
        metadata_facts: release.metadata_facts.clone(),
    }
}

fn stage01_defaults_from_values(
    mut required_kernel_cmdline: Vec<String>,
    mut required_live_services: Vec<String>,
) -> (Vec<String>, Vec<String>) {
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantIdentity {
    os_name: String,
    os_id: String,
    iso_label: String,
    os_version: String,
    default_hostname: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantEvidence {
    script_path: String,
    pass_marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VariantRingManifestBundle {
    #[allow(dead_code)]
    identity: VariantIdentityManifest,
    #[allow(dead_code)]
    build_host: VariantBuildHostManifest,
    #[allow(dead_code)]
    ring3_sources: VariantRing3SourcesManifest,
    #[allow(dead_code)]
    ring2_products: VariantRing2ProductsManifest,
    #[allow(dead_code)]
    ring1_transforms: VariantRing1TransformsManifest,
    #[allow(dead_code)]
    ring0_release: VariantRing0ReleaseManifest,
    #[allow(dead_code)]
    scenarios: VariantScenariosManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantIdentityManifest {
    schema_version: u32,
    identity: VariantIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantBuildHostManifest {
    schema_version: u32,
    build_host: VariantBuildHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantBuildHost {
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing3SourcesManifest {
    schema_version: u32,
    ring3_sources: VariantRing3Sources,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing3Sources {
    rootfs_source: VariantRootfsSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRootfsSource {
    kind: VariantRootfsSourceKind,
    recipe_script: String,
    preseed_recipe_script: Option<String>,
    defines: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VariantRootfsSourceKind {
    RecipeRpmDvd,
    RecipeCustom,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing2ProductsManifest {
    schema_version: u32,
    ring2_products: VariantRing2Products,
    ring2_payload_profiles: Option<BTreeMap<String, VariantRing2PayloadProfile>>,
    ring2_runtime_profiles: Option<BTreeMap<String, VariantRing2RuntimeProfile>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing2Products {
    rootfs_base: VariantProductDecl,
    live_overlay: VariantOverlayProductDecl,
    boot_live: VariantProductDecl,
    live_tools: VariantProductDecl,
    boot_installed: Option<VariantProductDecl>,
    kernel_staging: VariantProductDecl,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantProductDecl {
    logical_name: String,
    description: String,
    extends: Option<String>,
    payload_profile: Option<String>,
    runtime_profiles: Option<Vec<String>>,
    runtime_profiles_ux: Option<Vec<String>>,
    runtime_profiles_automated_ssh: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing2PayloadProfile {
    producers: Vec<VariantRing2PayloadProducer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VariantRing2PayloadProducer {
    CopyTree {
        source: String,
        destination: String,
    },
    CopySymlink {
        source: String,
        destination: String,
    },
    CopyFile {
        source: String,
        destination: String,
        #[serde(default)]
        optional: bool,
    },
    WriteText {
        path: String,
        content: String,
        mode: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VariantInstallDocsFrontend {
    PlainText,
    BunBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing2RuntimeProfile {
    actions: Vec<VariantRing2RuntimeAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VariantRing2RuntimeAction {
    ToolPayloadWorkspaceBinary {
        package: String,
        binary: Option<String>,
        target: Option<String>,
    },
    RootfsWorkspaceBinary {
        package: String,
        binary: Option<String>,
        target: Option<String>,
        destination: String,
    },
    ApkPackages {
        packages: Vec<String>,
    },
    IuppiterDarPayload {
        target: Option<String>,
    },
    InstallModePayload {
        interactive_shell: String,
        ux_docs_frontend: VariantInstallDocsFrontend,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantOverlayProductDecl {
    logical_name: String,
    description: String,
    extends: Option<String>,
    overlay_kind: String,
    issue_message: Option<String>,
    openrc_inittab: Option<String>,
    profile_overlay: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing1TransformsManifest {
    schema_version: u32,
    ring1_transforms: VariantRing1Transforms,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing1Transforms {
    rootfs_image: VariantRingTransform,
    overlay_image: VariantRingTransform,
    initramfs_live: VariantRingTransform,
    initramfs_installed: Option<VariantRingTransform>,
    live_uki: VariantRingTransform,
    installed_uki: Option<VariantRingTransform>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRingTransform {
    logical_name: String,
    dependencies: Vec<String>,
    output_names: Vec<String>,
    format: String,
    extra_cmdline: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing0ReleaseManifest {
    schema_version: u32,
    ring0_release: VariantRing0Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRing0Release {
    iso: VariantRingTransform,
    disk_image: Option<VariantRingTransform>,
    release: VariantReleaseDecl,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantReleaseDecl {
    primary_outputs: Vec<String>,
    supporting_artifacts: Vec<String>,
    metadata_outputs: Vec<String>,
    metadata_facts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantScenariosManifest {
    schema_version: u32,
    scenarios: VariantScenarios,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantScenarios {
    live_boot: VariantBootScenario,
    live_environment: VariantLiveEnvironmentScenario,
    live_tools: VariantLiveToolsScenario,
    install: VariantInstallScenario,
    installed_boot: VariantBootScenario,
    automated_login: VariantAutomatedLoginScenario,
    installed_tools: VariantInstalledToolsScenario,
    runtime_policy: VariantRuntimePolicyScenario,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantBootScenario {
    success_patterns: Vec<String>,
    fatal_patterns: Vec<String>,
    required_kernel_cmdline: Vec<String>,
    required_live_services: Vec<String>,
    evidence: VariantEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantLiveEnvironmentScenario {
    required_services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantLiveToolsScenario {
    required_tools: Vec<String>,
    install_experience: String,
    evidence: VariantEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantInstallScenario {
    required_tools: Vec<String>,
    required_services: Vec<String>,
    evidence: VariantEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantAutomatedLoginScenario {
    auth_mode: VariantAuthMode,
    default_username: Option<String>,
    default_password: Option<String>,
    login_prompt_pattern: String,
    evidence: VariantEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantInstalledToolsScenario {
    required_tools: Vec<String>,
    evidence: VariantEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VariantAuthMode {
    DefaultPasswordLogin,
    ProvisionedCredentials,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRuntimePolicyScenario {
    rootfs_mutability: VariantRootfsMutability,
    mutable_required_rw_paths: Vec<String>,
    immutable_required_ro_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VariantRootfsMutability {
    Mutable,
    Immutable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CONTRACT_SCHEMA_VERSION;

    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_IDENTITY_RING_MANIFEST: &str = r#"schema_version = 6

[identity]
os_name = "LevitateOS"
os_id = "levitateos"
iso_label = "LEVITATEOS"
os_version = "1.0"
default_hostname = "levitateos"
"#;

    const VALID_BUILD_HOST_RING_MANIFEST: &str = r#"schema_version = 6

[build_host]
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

[build_host.evidence]
script_path = "build-capability.sh"
pass_marker = "BUILD CAPABILITY PASSED"
"#;

    const VALID_RING3_SOURCES_MANIFEST: &str = r#"schema_version = 6

[ring3_sources.rootfs_source]
kind = "recipe_rpm_dvd"
recipe_script = "distro-builder/recipes/fedora-stage01-rootfs.rhai"
preseed_recipe_script = "distro-builder/recipes/fedora-preseed-iso.rhai"
"#;

    const VALID_RING2_PRODUCTS_MANIFEST: &str = r#"schema_version = 6

[ring2_products.rootfs_base]
logical_name = "product.rootfs.base"
description = "Canonical base root filesystem tree"

[ring2_products.live_overlay]
logical_name = "product.payload.live_overlay"
description = "Read-only live overlay payload tree"
overlay_kind = "systemd"

[ring2_products.boot_live]
logical_name = "product.payload.boot.live"
description = "Live boot payload inputs"
extends = "product.rootfs.base"
payload_profile = "boot_baseline"

[ring2_products.live_tools]
logical_name = "product.payload.live_tools"
description = "Live tools payload tree"
extends = "product.payload.boot.live"
runtime_profiles = ["live_tools_common"]
runtime_profiles_ux = ["live_tools_ux"]

[ring2_products.boot_installed]
logical_name = "product.payload.boot.installed"
description = "Installed-system boot payload inputs"
extends = "product.rootfs.base"
payload_profile = "boot_baseline"

[ring2_payload_profiles.boot_baseline]
[[ring2_payload_profiles.boot_baseline.producers]]
kind = "write_text"
path = ".live-payload-role"
content = "rootfs\n"

[ring2_runtime_profiles.live_tools_common]
[[ring2_runtime_profiles.live_tools_common.actions]]
kind = "tool_payload_workspace_binary"
package = "recstrap"

[[ring2_runtime_profiles.live_tools_common.actions]]
kind = "tool_payload_workspace_binary"
package = "recfstab"

[[ring2_runtime_profiles.live_tools_common.actions]]
kind = "tool_payload_workspace_binary"
package = "recchroot"

[[ring2_runtime_profiles.live_tools_common.actions]]
kind = "install_mode_payload"
interactive_shell = "/bin/bash"
ux_docs_frontend = "bun_bundle"

[ring2_runtime_profiles.live_tools_ux]
[[ring2_runtime_profiles.live_tools_ux.actions]]
kind = "rootfs_workspace_binary"
package = "stage02-split-pane"
binary = "levitate-install-docs-split"
destination = "usr/local/bin/levitate-install-docs-split"

[ring2_products.kernel_staging]
logical_name = "product.kernel.staging"
description = "Kernel image and modules staging product"
"#;

    const VALID_RING1_TRANSFORMS_MANIFEST: &str = r#"schema_version = 6

[ring1_transforms.rootfs_image]
logical_name = "artifact.rootfs.erofs"
dependencies = ["product.rootfs.base"]
output_names = ["filesystem.erofs"]
format = "erofs"

[ring1_transforms.overlay_image]
logical_name = "artifact.overlay.erofs"
dependencies = ["product.payload.live_overlay"]
output_names = ["overlayfs.erofs"]
format = "erofs"

[ring1_transforms.initramfs_live]
logical_name = "artifact.initramfs.live"
dependencies = ["product.payload.boot.live", "product.kernel.staging"]
output_names = ["initramfs-live.cpio.gz"]
format = "cpio.gz"

[ring1_transforms.initramfs_installed]
logical_name = "artifact.initramfs.installed"
dependencies = ["product.payload.boot.installed", "product.kernel.staging"]
output_names = ["initramfs-installed.img"]
format = "img"

[ring1_transforms.live_uki]
logical_name = "artifact.uki.live"
dependencies = ["product.payload.boot.live", "product.kernel.staging"]
output_names = ["levitateos-live.efi", "levitateos-emergency.efi", "levitateos-debug.efi"]
format = "uki"
extra_cmdline = "video=1920x1080"

[ring1_transforms.installed_uki]
logical_name = "artifact.uki.installed"
dependencies = ["product.payload.boot.installed", "product.kernel.staging"]
output_names = ["levitateos.efi", "levitateos-recovery.efi"]
format = "uki"
"#;

    const VALID_RING0_RELEASE_MANIFEST: &str = r#"schema_version = 6

[ring0_release.iso]
logical_name = "artifact.iso"
dependencies = ["artifact.rootfs.erofs", "artifact.overlay.erofs", "artifact.initramfs.live", "artifact.uki.live"]
output_names = ["levitateos-x86_64.iso"]
format = "iso"

[ring0_release.release]
primary_outputs = ["levitateos-x86_64.iso"]
supporting_artifacts = ["filesystem.erofs", "initramfs-live.cpio.gz", "initramfs-installed.img"]
metadata_outputs = []
metadata_facts = ["kernel_source.version", "kernel_source.sha256", "kernel_source.localversion", "artifact.rootfs_name", "artifact.iso_filename"]
"#;

    const VALID_SCENARIOS_MANIFEST: &str = r#"schema_version = 6

[scenarios.live_boot]
success_patterns = []
fatal_patterns = []
required_kernel_cmdline = ["audit=1"]
required_live_services = ["sshd"]

[scenarios.live_boot.evidence]
script_path = "live-boot.sh"
pass_marker = "STAGE 01 PASSED"

[scenarios.live_environment]
required_services = ["sshd", "auditd"]

[scenarios.live_tools]
required_tools = ["bash"]
install_experience = "ux"

[scenarios.live_tools.evidence]
script_path = "live-tools.sh"
pass_marker = "STAGE 02 PASSED"

[scenarios.install]
required_tools = ["recstrap"]
required_services = ["sshd", "auditd"]

[scenarios.install.evidence]
script_path = "install.sh"
pass_marker = "STAGE 03 PASSED"

[scenarios.installed_boot]
success_patterns = ["example login:"]
fatal_patterns = []
required_kernel_cmdline = []
required_live_services = []

[scenarios.installed_boot.evidence]
script_path = "installed-boot.sh"
pass_marker = "STAGE 04 PASSED"

[scenarios.automated_login]
auth_mode = "default_password_login"
default_username = "example"
default_password = "example"
login_prompt_pattern = "example login:"

[scenarios.automated_login.evidence]
script_path = "automated-login.sh"
pass_marker = "STAGE 05 PASSED"

[scenarios.installed_tools]
required_tools = ["sudo"]

[scenarios.installed_tools.evidence]
script_path = "installed-tools.sh"
pass_marker = "STAGE 06 PASSED"

[scenarios.runtime_policy]
rootfs_mutability = "mutable"
mutable_required_rw_paths = []
immutable_required_ro_paths = []
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

    fn write_full_ring_scaffold(variant_dir: &Path) {
        write_file(
            &variant_dir.join(IDENTITY_MANIFEST_FILENAME),
            VALID_IDENTITY_RING_MANIFEST,
        );
        write_file(
            &variant_dir.join(BUILD_HOST_MANIFEST_FILENAME),
            VALID_BUILD_HOST_RING_MANIFEST,
        );
        write_file(
            &variant_dir.join(RING3_SOURCES_MANIFEST_FILENAME),
            VALID_RING3_SOURCES_MANIFEST,
        );
        write_file(
            &variant_dir.join(RING2_PRODUCTS_MANIFEST_FILENAME),
            VALID_RING2_PRODUCTS_MANIFEST,
        );
        write_file(
            &variant_dir.join(RING1_TRANSFORMS_MANIFEST_FILENAME),
            VALID_RING1_TRANSFORMS_MANIFEST,
        );
        write_file(
            &variant_dir.join(RING0_RELEASE_MANIFEST_FILENAME),
            VALID_RING0_RELEASE_MANIFEST,
        );
        write_file(
            &variant_dir.join(SCENARIOS_MANIFEST_FILENAME),
            VALID_SCENARIOS_MANIFEST,
        );
    }

    #[test]
    fn loads_variant_contract_from_repo_root_ancestor() {
        let repo_root = temp_repo_root("load-ok");
        let variant_dir = repo_root.join("distro-variants/levitate");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &variant_dir.join("kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &variant_dir.join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir.join("build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_full_ring_scaffold(&variant_dir);

        let contract = load_variant_contract_for_distro_from(
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
                "filesystem.erofs".to_string(),
                "initramfs-live.cpio.gz".to_string(),
                "initramfs-installed.img".to_string(),
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
        let live_boot = &contract.scenarios.live_boot;
        assert!(live_boot.success_patterns.is_empty());
        assert!(live_boot.fatal_patterns.is_empty());
        assert_eq!(
            contract.scenarios.live_tools.required_tools,
            vec!["bash".to_string()]
        );
        assert_eq!(
            contract.scenarios.install.required_services,
            vec!["sshd".to_string(), "auditd".to_string()]
        );
        assert_eq!(
            contract.scenarios.installed_boot.success_patterns,
            vec!["example login:".to_string()]
        );
        assert_eq!(
            contract.scenarios.automated_login.default_username,
            Some("example".to_string())
        );
        assert_eq!(
            contract.scenarios.installed_tools.required_tools,
            vec!["sudo".to_string()]
        );
        assert_eq!(
            contract.scenarios.runtime_policy.rootfs_mutability,
            RootfsMutability::Mutable
        );
        assert_eq!(contract.build.kernel.localversion, "-levitate");
        assert_eq!(
            contract.build.kernel.module_install_path,
            "/usr/lib/modules"
        );
        assert_eq!(
            contract.build.kernel.recipe_script,
            "distro-builder/recipes/linux.rhai"
        );
        assert_eq!(
            contract.scenarios.live_boot.required_kernel_cmdline,
            vec!["audit=1".to_string(), "inst.sshd=0".to_string()]
        );
        assert_eq!(
            contract.scenarios.live_boot.required_live_services,
            vec!["sshd".to_string()]
        );
        assert_eq!(
            contract
                .release
                .primary_outputs
                .iter()
                .chain(contract.release.supporting_artifacts.iter())
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "levitateos-x86_64.iso".to_string(),
                "filesystem.erofs".to_string(),
                "initramfs-live.cpio.gz".to_string(),
                "initramfs-installed.img".to_string(),
            ]
        );
        assert_eq!(
            contract
                .release
                .metadata_outputs
                .iter()
                .chain(contract.release.metadata_facts.iter())
                .cloned()
                .collect::<Vec<_>>(),
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
    fn full_ring_scaffold_parses_and_loads_canonical_contract() {
        let repo_root = temp_repo_root("ring-load");
        let variant_dir = repo_root.join("distro-variants/levitate");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &variant_dir.join("kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &variant_dir.join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir.join("build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_full_ring_scaffold(&variant_dir);
        let ring_bundle = load_ring_manifest_bundle(&variant_dir).expect("parse ring scaffold");
        assert_eq!(ring_bundle.identity.identity.os_id, "levitateos");
        assert_eq!(
            ring_bundle.build_host.build_host.kernel_localversion,
            "-levitate"
        );
        assert_eq!(
            ring_bundle
                .ring3_sources
                .ring3_sources
                .rootfs_source
                .recipe_script,
            "distro-builder/recipes/fedora-stage01-rootfs.rhai"
        );
        assert_eq!(
            ring_bundle
                .ring2_products
                .ring2_products
                .live_overlay
                .overlay_kind,
            "systemd"
        );
        assert_eq!(
            ring_bundle
                .ring2_products
                .ring2_products
                .live_tools
                .runtime_profiles
                .as_ref()
                .expect("live tools runtime profiles should parse"),
            &vec!["live_tools_common".to_string()]
        );
        assert!(ring_bundle
            .ring2_products
            .ring2_runtime_profiles
            .as_ref()
            .expect("ring2 runtime profiles should parse")
            .contains_key("live_tools_common"));
        assert_eq!(
            ring_bundle
                .ring0_release
                .ring0_release
                .release
                .primary_outputs,
            vec!["levitateos-x86_64.iso".to_string()]
        );
        assert_eq!(
            ring_bundle.scenarios.scenarios.live_tools.required_tools,
            vec!["bash".to_string()]
        );
        assert_eq!(
            ring_bundle
                .scenarios
                .scenarios
                .live_tools
                .install_experience,
            "ux"
        );
        assert_eq!(
            ring_bundle
                .scenarios
                .scenarios
                .automated_login
                .login_prompt_pattern,
            "example login:"
        );
        assert_eq!(
            ring_bundle
                .scenarios
                .scenarios
                .runtime_policy
                .rootfs_mutability,
            VariantRootfsMutability::Mutable
        );

        let loaded = load_variant_contract_bundle_for_distro_from(&repo_root, "levitate")
            .expect("load levitate contract with ring scaffold");
        assert_eq!(
            loaded.manifest_path,
            variant_dir.join(BUILD_HOST_MANIFEST_FILENAME)
        );
        assert_eq!(loaded.contract.identity.os_name, "LevitateOS");
        assert_eq!(
            loaded.contract.sources.rootfs_source.recipe_script,
            "distro-builder/recipes/fedora-stage01-rootfs.rhai"
        );
        assert_eq!(
            loaded.contract.transforms.iso.output_names,
            vec!["levitateos-x86_64.iso".to_string()]
        );

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn fails_when_ring_manifest_family_is_missing() {
        let repo_root = temp_repo_root("missing-manifest");
        fs::create_dir_all(repo_root.join("distro-variants/acorn")).expect("create variant dir");

        let err = load_variant_contract_for_distro_from(&repo_root, "acorn")
            .expect_err("expected missing manifest");
        assert!(matches!(
            err,
            VariantContractLoadError::PartialRingManifestSet { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn partial_ring_scaffold_fails_fast() {
        let repo_root = temp_repo_root("partial-ring");
        let variant_dir = repo_root.join("distro-variants/levitate");
        fs::create_dir_all(&variant_dir).expect("create variant dir");
        write_file(
            &variant_dir.join(IDENTITY_MANIFEST_FILENAME),
            VALID_IDENTITY_RING_MANIFEST,
        );
        write_file(
            &variant_dir.join(BUILD_HOST_MANIFEST_FILENAME),
            VALID_BUILD_HOST_RING_MANIFEST,
        );

        let err =
            load_ring_manifest_bundle(&variant_dir).expect_err("partial ring scaffold should fail");
        assert!(matches!(
            err,
            VariantContractLoadError::PartialRingManifestSet { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn fails_when_recipe_declaration_does_not_reference_required_invocation() {
        let repo_root = temp_repo_root("bad-recipe-decl");
        let variant_dir = repo_root.join("distro-variants/levitate");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &variant_dir.join("kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_full_ring_scaffold(&variant_dir);
        write_file(
            &variant_dir.join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n",
        );
        write_file(
            &variant_dir.join("build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );

        let err = load_variant_contract_for_distro_from(&repo_root, "levitate")
            .expect_err("expected invalid recipe declaration");
        assert!(matches!(
            err,
            VariantContractLoadError::InvalidRecipeDeclaration { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn workspace_variant_contracts_load_for_all_variants() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("canonicalize workspace root");

        for distro_id in ["levitate", "acorn", "iuppiter", "ralph"] {
            let loaded = load_variant_contract_bundle_for_distro_from(&repo_root, distro_id)
                .unwrap_or_else(|err| {
                    panic!("failed to load {} variant contract: {}", distro_id, err)
                });

            let expected_kernel_recipe = if distro_id == "levitate" {
                "distro-builder/recipes/linux-prebuilt.rhai"
            } else {
                "distro-builder/recipes/linux.rhai"
            };

            assert_eq!(loaded.contract.build.kernel.kconfig_path, "kconfig");
            assert_eq!(
                loaded.contract.build.kernel.recipe_script,
                expected_kernel_recipe
            );
            assert_eq!(
                loaded.contract.build.kernel.recipe_invocation,
                "recipe install"
            );
            assert_eq!(
                loaded.contract.build.kernel.module_install_path,
                "/usr/lib/modules"
            );
            match distro_id {
                "levitate" | "ralph" => {
                    assert_eq!(
                        loaded.contract.sources.rootfs_source.kind,
                        RootfsSourceKind::RecipeRpmDvd
                    );
                }
                "acorn" | "iuppiter" => {
                    assert_eq!(
                        loaded.contract.sources.rootfs_source.kind,
                        RootfsSourceKind::RecipeCustom
                    );
                }
                _ => unreachable!(),
            }
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
                            "iuppiter-x86_64.iso".to_string(),
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
    fn workspace_levitate_ring_scaffold_is_complete_and_parseable() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("canonicalize workspace root");
        let variant_dir = repo_root.join("distro-variants/levitate");

        let ring_bundle =
            load_ring_manifest_bundle(&variant_dir).expect("parse levitate ring scaffold");

        assert_eq!(ring_bundle.identity.identity.os_id, "levitateos");
        assert_eq!(
            ring_bundle.ring0_release.ring0_release.iso.output_names,
            vec!["levitateos-x86_64.iso".to_string()]
        );
    }

    #[test]
    fn workspace_ring_scaffolds_are_complete_and_parseable_for_all_variants() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("canonicalize workspace root");

        for distro_id in ["levitate", "ralph", "acorn", "iuppiter"] {
            let variant_dir = repo_root.join("distro-variants").join(distro_id);
            let ring_bundle = load_ring_manifest_bundle(&variant_dir).unwrap_or_else(|err| {
                panic!("failed to parse {} ring scaffold: {}", distro_id, err)
            });

            assert_eq!(ring_bundle.identity.schema_version, CONTRACT_SCHEMA_VERSION);
            assert_eq!(
                ring_bundle.build_host.schema_version,
                CONTRACT_SCHEMA_VERSION
            );
            assert_eq!(
                ring_bundle.ring3_sources.schema_version,
                CONTRACT_SCHEMA_VERSION
            );
            assert_eq!(
                ring_bundle.ring2_products.schema_version,
                CONTRACT_SCHEMA_VERSION
            );
            assert_eq!(
                ring_bundle.ring1_transforms.schema_version,
                CONTRACT_SCHEMA_VERSION
            );
            assert_eq!(
                ring_bundle.ring0_release.schema_version,
                CONTRACT_SCHEMA_VERSION
            );
            assert_eq!(
                ring_bundle.scenarios.schema_version,
                CONTRACT_SCHEMA_VERSION
            );
        }
    }

    #[test]
    fn stage_view_uses_canonical_scenarios_without_fallback() {
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
            live_boot: BootStage {
                success_patterns: vec!["boot complete".to_string()],
                fatal_patterns: vec![],
                required_kernel_cmdline: vec![],
                required_live_services: vec![],
                evidence: ScriptEvidence {
                    script_path: "live-boot.sh".to_string(),
                    pass_marker: "STAGE 01 PASSED".to_string(),
                },
            },
            live_tools: ToolsStage {
                required_tools: vec!["bash".to_string()],
                evidence: ScriptEvidence {
                    script_path: "live-tools.sh".to_string(),
                    pass_marker: "STAGE 02 PASSED".to_string(),
                },
            },
            install: InstallStage {
                required_tools: vec!["recstrap".to_string()],
                required_services: vec!["sshd".to_string()],
                evidence: ScriptEvidence {
                    script_path: "install.sh".to_string(),
                    pass_marker: "STAGE 03 PASSED".to_string(),
                },
            },
            installed_boot: BootStage {
                success_patterns: vec!["example login:".to_string()],
                fatal_patterns: vec![],
                required_kernel_cmdline: vec![],
                required_live_services: vec![],
                evidence: ScriptEvidence {
                    script_path: "installed-boot.sh".to_string(),
                    pass_marker: "STAGE 04 PASSED".to_string(),
                },
            },
            automated_login: AutomatedLoginStage {
                auth_mode: AuthMode::DefaultPasswordLogin,
                default_username: Some("example".to_string()),
                default_password: Some("example".to_string()),
                login_prompt_pattern: "example login:".to_string(),
                evidence: ScriptEvidence {
                    script_path: "automated-login.sh".to_string(),
                    pass_marker: "STAGE 05 PASSED".to_string(),
                },
            },
            installed_tools: ToolsStage {
                required_tools: vec!["sudo".to_string()],
                evidence: ScriptEvidence {
                    script_path: "installed-tools.sh".to_string(),
                    pass_marker: "STAGE 06 PASSED".to_string(),
                },
            },
            runtime_policy: RuntimePolicyStage {
                rootfs_mutability: RootfsMutability::Mutable,
                mutable_required_rw_paths: vec![],
                immutable_required_ro_paths: vec![],
            },
        };
        let release = ReleaseContract {
            primary_outputs: vec!["example.iso".to_string()],
            supporting_artifacts: vec![],
            metadata_outputs: vec![],
            metadata_facts: vec![],
        };
        let product = |logical_name: &str| ProductDecl {
            logical_name: logical_name.to_string(),
            description: logical_name.to_string(),
            extends: None,
        };
        let contract = ConformanceContract {
            schema_version: CONTRACT_SCHEMA_VERSION,
            identity: DistroIdentity {
                os_name: "ExampleOS".to_string(),
                os_id: "exampleos".to_string(),
                iso_label: "EXAMPLEOS".to_string(),
                os_version: "1.0".to_string(),
                default_hostname: "example".to_string(),
            },
            build,
            sources: SourceContract {
                rootfs_source: RootfsSourceContract {
                    kind: RootfsSourceKind::RecipeRpmDvd,
                    recipe_script: "distro-builder/recipes/fedora-stage01-rootfs.rhai".to_string(),
                    preseed_recipe_script: Some(
                        "distro-builder/recipes/fedora-preseed-iso.rhai".to_string(),
                    ),
                    defines: BTreeMap::new(),
                },
            },
            products: ProductContract {
                rootfs_base: product("product.rootfs.base"),
                live_overlay: product("product.payload.live_overlay"),
                boot_live: product("product.payload.boot.live"),
                live_tools: product("product.payload.live_tools"),
                boot_installed: None,
                kernel_staging: product("product.kernel.staging"),
            },
            artifacts: artifact_identity_from_transforms(&transforms),
            transforms,
            scenarios,
            release,
        };
        assert_eq!(
            contract.scenarios.live_boot.evidence.script_path,
            "live-boot.sh"
        );
        assert_eq!(
            contract.scenarios.live_tools.evidence.script_path,
            "live-tools.sh"
        );
        assert_eq!(
            contract.scenarios.installed_boot.success_patterns,
            vec!["example login:".to_string()]
        );
        assert_eq!(
            contract.scenarios.automated_login.default_username,
            Some("example".to_string())
        );
    }
}
