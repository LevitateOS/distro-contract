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
    ArtifactIdentity, ArtifactTransform, AuthMode, AutomatedLoginStage, BootPayloadContract,
    BootStage, BuildContract, ConformanceContract, DistroIdentity, InstallDocsFrontend,
    InstallExperience, InstallStage, KernelBuildContract, LiveEnvironmentScenario,
    LiveToolsRuntimeContract, LiveToolsScenario, OpenRcInittab, OverlayContract, OverlayKind,
    PayloadProducerContract, ProductConfigContract, ProductContract, ProductDecl, ReleaseContract,
    RootfsMutability, RootfsSourceContract, RootfsSourceKind, RuntimeActionContract,
    RuntimePolicyStage, ScenarioContract, ScriptEvidence, SourceContract, ToolsStage,
    TransformContract, BOOT_REQUIRED_KERNEL_CMDLINE_BASE, BOOT_REQUIRED_LIVE_SERVICES_BASE,
};

const VARIANTS_DIR: &str = "distro-variants";
const IDENTITY_MANIFEST_FILENAME: &str = "identity.toml";
const BUILD_HOST_MANIFEST_FILENAME: &str = "build-host.toml";
const RING3_SOURCES_MANIFEST_FILENAME: &str = "ring3-sources.toml";
const RING2_PRODUCTS_MANIFEST_FILENAME: &str = "ring2-products.toml";
const RING1_TRANSFORMS_MANIFEST_FILENAME: &str = "ring1-transforms.toml";
const RING0_RELEASE_MANIFEST_FILENAME: &str = "ring0-release.toml";
const SCENARIOS_MANIFEST_FILENAME: &str = "scenarios.toml";
const IDENTITY_OWNER_DIR: &str = "identity";
const BUILD_HOST_OWNER_DIR: &str = "build-host";
const RING3_OWNER_DIR: &str = "ring3";
const RING2_OWNER_DIR: &str = "ring2";
const RING1_OWNER_DIR: &str = "ring1";
const RING0_OWNER_DIR: &str = "ring0";
const SCENARIOS_OWNER_DIR: &str = "scenarios";
const RING0_HOOKS_DIR: &str = "hooks";
const BUILD_RELEASE_HOOK_FILENAME: &str = "build-release.sh";
const BOOT_RELEASE_HOOK_FILENAME: &str = "boot-release.sh";
const LIVE_TOOLS_RELEASE_HOOK_FILENAME: &str = "live-tools-release.sh";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantPathLayout {
    FlatRoot,
    OwnerDirectories,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantOwnerPaths {
    pub variant_dir: PathBuf,
    pub manifest_layout: VariantPathLayout,
    pub build_host_support_layout: VariantPathLayout,
    pub ring0_hooks_layout: VariantPathLayout,
    pub identity_manifest: PathBuf,
    pub build_host_manifest: PathBuf,
    pub ring3_sources_manifest: PathBuf,
    pub ring2_products_manifest: PathBuf,
    pub ring1_transforms_manifest: PathBuf,
    pub ring0_release_manifest: PathBuf,
    pub scenarios_manifest: PathBuf,
    pub build_host_support_root: PathBuf,
    pub ring0_hooks_dir: PathBuf,
}

impl VariantOwnerPaths {
    pub fn build_host_declared_path(&self, declared_relative: &str) -> PathBuf {
        self.build_host_support_root.join(declared_relative)
    }

    pub fn build_host_recipe_declaration_path(&self) -> PathBuf {
        self.build_host_declared_path(REQUIRED_VARIANT_RECIPE_DECL)
    }

    pub fn ring0_hook_path(&self, hook_filename: &str) -> PathBuf {
        self.ring0_hooks_dir.join(hook_filename)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedManifestPaths(
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
);

/// Loaded variant contract bundle with resolved filesystem paths.
#[derive(Debug, Clone)]
pub struct LoadedVariantContract {
    pub repo_root: PathBuf,
    pub variant_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub paths: VariantOwnerPaths,
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
    DuplicateOwnerPath {
        component: &'static str,
        flat_path: PathBuf,
        owner_path: PathBuf,
    },
    MixedOwnerLayout {
        component: &'static str,
        variant_dir: PathBuf,
        flat_present: Vec<String>,
        owner_present: Vec<String>,
        missing: Vec<String>,
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
    InvalidRing2Declaration {
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
            Self::DuplicateOwnerPath {
                component,
                flat_path,
                owner_path,
            } => write!(
                f,
                "conflicting variant path ownership for {}: both flat path '{}' and owner-directory path '{}' exist",
                component,
                flat_path.display(),
                owner_path.display()
            ),
            Self::MixedOwnerLayout {
                component,
                variant_dir,
                flat_present,
                owner_present,
                missing,
            } => write!(
                f,
                "mixed flat/owner-directory layout for {} under '{}': flat-present [{}], owner-present [{}], missing [{}]",
                component,
                variant_dir.display(),
                flat_present.join(", "),
                owner_present.join(", "),
                missing.join(", ")
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
            Self::InvalidRing2Declaration { path, message } => write!(
                f,
                "invalid Ring 2 declaration '{}': {}",
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

    let paths = resolve_variant_owner_paths(&variant_dir)?;
    let ring_manifest_bundle = load_ring_manifest_bundle(&paths)?;
    let manifest_path = paths.build_host_manifest.clone();

    let variant_layout = validate_layout(
        Some(StageId::Stage00),
        &paths.build_host_support_root,
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
        &paths.build_host_recipe_declaration_path(),
        &ring_manifest_bundle
            .build_host
            .build_host
            .recipe_kernel_script,
        &ring_manifest_bundle
            .build_host
            .build_host
            .recipe_kernel_invocation,
    )?;
    let contract = contract_from_ring_manifest_bundle(repo_root, &paths, &ring_manifest_bundle)?;

    Ok(LoadedVariantContract {
        repo_root: repo_root.to_path_buf(),
        variant_dir,
        manifest_path,
        paths,
        contract,
    })
}

pub fn resolve_variant_owner_paths(
    variant_dir: &Path,
) -> Result<VariantOwnerPaths, VariantContractLoadError> {
    let variant_dir = variant_dir.to_path_buf();
    let (manifest_layout, manifest_paths) = resolve_manifest_paths(&variant_dir)?;
    let ResolvedManifestPaths(
        identity_manifest,
        build_host_manifest_path,
        ring3_sources_manifest,
        ring2_products_manifest,
        ring1_transforms_manifest,
        ring0_release_manifest,
        scenarios_manifest,
    ) = manifest_paths;
    let build_host_manifest: VariantBuildHostManifest =
        read_ring_manifest(&build_host_manifest_path)?;
    let (build_host_support_layout, build_host_support_root) = resolve_group_root(
        "build-host support files",
        &variant_dir,
        &[
            ("build_host.kernel_kconfig_path", REQUIRED_VARIANT_KCONFIG),
            (
                "build_host.recipe_kernel_declaration",
                REQUIRED_VARIANT_RECIPE_DECL,
            ),
            (
                "build_host.evidence.script_path",
                build_host_manifest.build_host.evidence.script_path.as_str(),
            ),
        ],
        &variant_dir,
        &variant_dir.join(BUILD_HOST_OWNER_DIR),
        manifest_layout,
    )?;
    let (ring0_hooks_layout, ring0_hooks_dir) = resolve_group_root(
        "ring0 release hooks",
        &variant_dir,
        &[
            ("ring0 hook", BUILD_RELEASE_HOOK_FILENAME),
            ("ring0 hook", BOOT_RELEASE_HOOK_FILENAME),
            ("ring0 hook", LIVE_TOOLS_RELEASE_HOOK_FILENAME),
        ],
        &variant_dir,
        &variant_dir.join(RING0_OWNER_DIR).join(RING0_HOOKS_DIR),
        manifest_layout,
    )?;

    Ok(VariantOwnerPaths {
        variant_dir,
        manifest_layout,
        build_host_support_layout,
        ring0_hooks_layout,
        identity_manifest,
        build_host_manifest: build_host_manifest_path,
        ring3_sources_manifest,
        ring2_products_manifest,
        ring1_transforms_manifest,
        ring0_release_manifest,
        scenarios_manifest,
        build_host_support_root,
        ring0_hooks_dir,
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

fn contract_from_ring_manifest_bundle(
    repo_root: &Path,
    paths: &VariantOwnerPaths,
    ring: &VariantRingManifestBundle,
) -> Result<ConformanceContract, VariantContractLoadError> {
    let identity = identity_from_manifest(&ring.identity.identity);
    let build = build_contract_from_ring_manifest(&ring.build_host.build_host);
    let sources = source_contract_from_ring_manifest(&ring.ring3_sources.ring3_sources);
    let products = product_contract_from_ring_manifest(&ring.ring2_products.ring2_products);
    let product_config = product_config_contract_from_ring_manifest(
        repo_root,
        &paths.ring2_products_manifest,
        &ring.ring2_products,
    )?;
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

    Ok(ConformanceContract {
        schema_version: ring.build_host.schema_version,
        identity,
        build,
        sources,
        products,
        product_config,
        transforms,
        scenarios,
        release,
        artifacts,
    })
}

fn load_ring_manifest_bundle(
    paths: &VariantOwnerPaths,
) -> Result<VariantRingManifestBundle, VariantContractLoadError> {
    Ok(VariantRingManifestBundle {
        identity: read_ring_manifest(&paths.identity_manifest)?,
        build_host: read_ring_manifest(&paths.build_host_manifest)?,
        ring3_sources: read_ring_manifest(&paths.ring3_sources_manifest)?,
        ring2_products: read_ring_manifest(&paths.ring2_products_manifest)?,
        ring1_transforms: read_ring_manifest(&paths.ring1_transforms_manifest)?,
        ring0_release: read_ring_manifest(&paths.ring0_release_manifest)?,
        scenarios: read_ring_manifest(&paths.scenarios_manifest)?,
    })
}

fn resolve_manifest_paths(
    variant_dir: &Path,
) -> Result<(VariantPathLayout, ResolvedManifestPaths), VariantContractLoadError> {
    let manifest_specs = [
        ("identity", IDENTITY_OWNER_DIR, IDENTITY_MANIFEST_FILENAME),
        (
            "build_host",
            BUILD_HOST_OWNER_DIR,
            BUILD_HOST_MANIFEST_FILENAME,
        ),
        (
            "ring3_sources",
            RING3_OWNER_DIR,
            RING3_SOURCES_MANIFEST_FILENAME,
        ),
        (
            "ring2_products",
            RING2_OWNER_DIR,
            RING2_PRODUCTS_MANIFEST_FILENAME,
        ),
        (
            "ring1_transforms",
            RING1_OWNER_DIR,
            RING1_TRANSFORMS_MANIFEST_FILENAME,
        ),
        (
            "ring0_release",
            RING0_OWNER_DIR,
            RING0_RELEASE_MANIFEST_FILENAME,
        ),
        (
            "scenarios",
            SCENARIOS_OWNER_DIR,
            SCENARIOS_MANIFEST_FILENAME,
        ),
    ];

    let mut flat_present = Vec::new();
    let mut owner_present = Vec::new();
    let mut missing = Vec::new();
    let mut resolved = Vec::new();

    for (component, owner_dir, filename) in manifest_specs {
        let flat_path = variant_dir.join(filename);
        let owner_path = variant_dir.join(owner_dir).join(filename);
        let flat_exists = flat_path.is_file();
        let owner_exists = owner_path.is_file();

        if flat_exists && owner_exists {
            return Err(VariantContractLoadError::DuplicateOwnerPath {
                component,
                flat_path,
                owner_path,
            });
        }

        match (flat_exists, owner_exists) {
            (true, false) => {
                flat_present.push(filename.to_string());
                resolved.push(flat_path);
            }
            (false, true) => {
                owner_present.push(format!("{owner_dir}/{filename}"));
                resolved.push(owner_path);
            }
            (false, false) => missing.push(filename.to_string()),
            (true, true) => unreachable!("duplicate manifest paths handled above"),
        }
    }

    let layout = if missing.is_empty() && owner_present.is_empty() {
        VariantPathLayout::FlatRoot
    } else if missing.is_empty() && flat_present.is_empty() {
        VariantPathLayout::OwnerDirectories
    } else if flat_present.is_empty() && owner_present.is_empty() {
        return Err(VariantContractLoadError::PartialRingManifestSet {
            variant_dir: variant_dir.to_path_buf(),
            present: Vec::new(),
            missing,
        });
    } else if !flat_present.is_empty() && owner_present.is_empty() {
        return Err(VariantContractLoadError::PartialRingManifestSet {
            variant_dir: variant_dir.to_path_buf(),
            present: flat_present,
            missing,
        });
    } else if flat_present.is_empty() && !owner_present.is_empty() {
        return Err(VariantContractLoadError::PartialRingManifestSet {
            variant_dir: variant_dir.to_path_buf(),
            present: owner_present,
            missing,
        });
    } else {
        return Err(VariantContractLoadError::MixedOwnerLayout {
            component: "ring manifests",
            variant_dir: variant_dir.to_path_buf(),
            flat_present,
            owner_present,
            missing,
        });
    };

    let mut resolved_iter = resolved.into_iter();
    Ok((
        layout,
        ResolvedManifestPaths(
            resolved_iter.next().expect("identity manifest path"),
            resolved_iter.next().expect("build-host manifest path"),
            resolved_iter.next().expect("ring3 manifest path"),
            resolved_iter.next().expect("ring2 manifest path"),
            resolved_iter.next().expect("ring1 manifest path"),
            resolved_iter.next().expect("ring0 manifest path"),
            resolved_iter.next().expect("scenarios manifest path"),
        ),
    ))
}

fn resolve_group_root(
    component: &'static str,
    variant_dir: &Path,
    entries: &[(&'static str, &str)],
    flat_root: &Path,
    owner_root: &Path,
    default_layout: VariantPathLayout,
) -> Result<(VariantPathLayout, PathBuf), VariantContractLoadError> {
    let mut flat_present = Vec::new();
    let mut owner_present = Vec::new();
    let mut missing = Vec::new();

    for (label, relative_path) in entries {
        let flat_path = flat_root.join(relative_path);
        let owner_path = owner_root.join(relative_path);
        let flat_exists = flat_path.is_file();
        let owner_exists = owner_path.is_file();

        if flat_exists && owner_exists {
            return Err(VariantContractLoadError::DuplicateOwnerPath {
                component: *label,
                flat_path,
                owner_path,
            });
        }

        match (flat_exists, owner_exists) {
            (true, false) => flat_present.push(relative_path.to_string()),
            (false, true) => owner_present.push(relative_path.to_string()),
            (false, false) => missing.push(relative_path.to_string()),
            (true, true) => unreachable!("duplicate owner paths handled above"),
        }
    }

    if flat_present.len() == entries.len() && owner_present.is_empty() {
        return Ok((VariantPathLayout::FlatRoot, flat_root.to_path_buf()));
    }
    if owner_present.len() == entries.len() && flat_present.is_empty() {
        return Ok((
            VariantPathLayout::OwnerDirectories,
            owner_root.to_path_buf(),
        ));
    }
    if flat_present.is_empty() && owner_present.is_empty() {
        return Ok((
            default_layout,
            match default_layout {
                VariantPathLayout::FlatRoot => flat_root.to_path_buf(),
                VariantPathLayout::OwnerDirectories => owner_root.to_path_buf(),
            },
        ));
    }
    Err(VariantContractLoadError::MixedOwnerLayout {
        component,
        variant_dir: variant_dir.to_path_buf(),
        flat_present,
        owner_present,
        missing,
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

fn product_config_contract_from_ring_manifest(
    _repo_root: &Path,
    manifest_path: &Path,
    ring2_manifest: &VariantRing2ProductsManifest,
) -> Result<ProductConfigContract, VariantContractLoadError> {
    Ok(ProductConfigContract {
        live_overlay: overlay_contract_from_ring_manifest(
            manifest_path,
            &ring2_manifest.ring2_products.live_overlay,
        )?,
        boot_live: BootPayloadContract {
            producers: payload_producers_for_product(
                manifest_path,
                &ring2_manifest.ring2_products.boot_live,
                ring2_manifest.ring2_payload_profiles.as_ref(),
            )?,
        },
        boot_installed: ring2_manifest
            .ring2_products
            .boot_installed
            .as_ref()
            .map(|product| {
                payload_producers_for_product(
                    manifest_path,
                    product,
                    ring2_manifest.ring2_payload_profiles.as_ref(),
                )
                .map(|producers| BootPayloadContract { producers })
            })
            .transpose()?,
        live_tools: live_tools_runtime_contract_from_ring_manifest(
            manifest_path,
            &ring2_manifest.ring2_products.live_tools,
            ring2_manifest.ring2_runtime_profiles.as_ref(),
        )?,
    })
}

fn overlay_contract_from_ring_manifest(
    manifest_path: &Path,
    ring_overlay: &VariantOverlayProductDecl,
) -> Result<OverlayContract, VariantContractLoadError> {
    let kind = match ring_overlay
        .overlay_kind
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "systemd" => OverlayKind::Systemd,
        "openrc" => OverlayKind::OpenRc,
        other => {
            return Err(invalid_ring2(
                manifest_path,
                format!(
                    "unsupported overlay_kind '{}' (expected 'systemd' or 'openrc')",
                    other
                ),
            ))
        }
    };

    let openrc_inittab = match kind {
        OverlayKind::Systemd => None,
        OverlayKind::OpenRc => Some(parse_openrc_inittab_contract(
            manifest_path,
            ring_overlay.openrc_inittab.as_deref(),
        )?),
    };

    if ring_overlay.seed_overlay.is_some() && ring_overlay.legacy_profile_overlay.is_some() {
        return Err(invalid_ring2(
            manifest_path,
            "ring2_products.live_overlay may not declare both seed_overlay and profile_overlay; use seed_overlay only",
        ));
    }

    let (seed_overlay_raw, seed_overlay_field) = match (
        ring_overlay.seed_overlay.as_deref(),
        ring_overlay.legacy_profile_overlay.as_deref(),
    ) {
        (Some(raw), None) => (Some(raw), "ring2_products.live_overlay.seed_overlay"),
        (None, Some(raw)) => (Some(raw), "ring2_products.live_overlay.profile_overlay"),
        (None, None) => (None, "ring2_products.live_overlay.seed_overlay"),
        (Some(_), Some(_)) => unreachable!("checked above"),
    };

    let seed_overlay = seed_overlay_raw
        .map(|raw| normalize_relative_string(raw, seed_overlay_field, manifest_path))
        .transpose()?;

    Ok(OverlayContract {
        kind,
        issue_message: ring_overlay.issue_message.clone(),
        openrc_inittab,
        seed_overlay,
    })
}

fn parse_openrc_inittab_contract(
    manifest_path: &Path,
    raw: Option<&str>,
) -> Result<OpenRcInittab, VariantContractLoadError> {
    let raw = raw.ok_or_else(|| {
        invalid_ring2(
            manifest_path,
            "openrc_inittab is required when ring2_products.live_overlay.overlay_kind = 'openrc'",
        )
    })?;

    match raw.trim().to_ascii_lowercase().as_str() {
        "desktop_with_serial" => Ok(OpenRcInittab::DesktopWithSerial),
        "serial_only" => Ok(OpenRcInittab::SerialOnly),
        other => Err(invalid_ring2(
            manifest_path,
            format!(
                "unsupported openrc_inittab '{}' (expected 'desktop_with_serial' or 'serial_only')",
                other
            ),
        )),
    }
}

fn payload_producers_for_product(
    manifest_path: &Path,
    product: &VariantProductDecl,
    payload_profiles: Option<&BTreeMap<String, VariantRing2PayloadProfile>>,
) -> Result<Vec<PayloadProducerContract>, VariantContractLoadError> {
    let profile_name = product.payload_profile.as_deref().ok_or_else(|| {
        invalid_ring2(
            manifest_path,
            format!("missing payload_profile for '{}'", product.logical_name),
        )
    })?;
    let profile_name = normalize_non_empty_string(
        profile_name,
        "ring2_products.*.payload_profile",
        manifest_path,
    )?;

    let profiles = payload_profiles.ok_or_else(|| {
        invalid_ring2(
            manifest_path,
            format!(
                "missing ring2_payload_profiles section required by payload_profile '{}'",
                profile_name
            ),
        )
    })?;

    let profile = profiles.get(profile_name.as_str()).ok_or_else(|| {
        invalid_ring2(
            manifest_path,
            format!(
                "unknown payload profile '{}' referenced by '{}'",
                profile_name, product.logical_name
            ),
        )
    })?;

    if profile.producers.is_empty() {
        return Err(invalid_ring2(
            manifest_path,
            format!(
                "payload profile '{}' must declare at least one producer",
                profile_name
            ),
        ));
    }

    profile
        .producers
        .iter()
        .map(|producer| payload_producer_contract_from_ring_manifest(producer, manifest_path))
        .collect()
}

fn payload_producer_contract_from_ring_manifest(
    producer: &VariantRing2PayloadProducer,
    manifest_path: &Path,
) -> Result<PayloadProducerContract, VariantContractLoadError> {
    Ok(match producer {
        VariantRing2PayloadProducer::CopyTree {
            source,
            destination,
        } => PayloadProducerContract::CopyTree {
            source: normalize_relative_string(source, "source", manifest_path)?,
            destination: normalize_relative_string(destination, "destination", manifest_path)?,
        },
        VariantRing2PayloadProducer::CopySymlink {
            source,
            destination,
        } => PayloadProducerContract::CopySymlink {
            source: normalize_relative_string(source, "source", manifest_path)?,
            destination: normalize_relative_string(destination, "destination", manifest_path)?,
        },
        VariantRing2PayloadProducer::CopyFile {
            source,
            destination,
            optional,
        } => PayloadProducerContract::CopyFile {
            source: normalize_relative_string(source, "source", manifest_path)?,
            destination: normalize_relative_string(destination, "destination", manifest_path)?,
            optional: *optional,
        },
        VariantRing2PayloadProducer::WriteText {
            path,
            content,
            mode,
        } => PayloadProducerContract::WriteText {
            path: normalize_relative_string(path, "path", manifest_path)?,
            content: content.clone(),
            mode: *mode,
        },
    })
}

fn live_tools_runtime_contract_from_ring_manifest(
    manifest_path: &Path,
    live_tools: &VariantProductDecl,
    runtime_profiles: Option<&BTreeMap<String, VariantRing2RuntimeProfile>>,
) -> Result<LiveToolsRuntimeContract, VariantContractLoadError> {
    Ok(LiveToolsRuntimeContract {
        common_actions: runtime_actions_for_profile_group(
            manifest_path,
            &live_tools.logical_name,
            live_tools.runtime_profiles.as_deref(),
            runtime_profiles,
            "ring2_products.live_tools.runtime_profiles",
        )?,
        ux_actions: runtime_actions_for_profile_group(
            manifest_path,
            &live_tools.logical_name,
            live_tools.runtime_profiles_ux.as_deref(),
            runtime_profiles,
            "ring2_products.live_tools.runtime_profiles_ux",
        )?,
        automated_ssh_actions: runtime_actions_for_profile_group(
            manifest_path,
            &live_tools.logical_name,
            live_tools.runtime_profiles_automated_ssh.as_deref(),
            runtime_profiles,
            "ring2_products.live_tools.runtime_profiles_automated_ssh",
        )?,
    })
}

fn runtime_actions_for_profile_group(
    manifest_path: &Path,
    logical_name: &str,
    profile_names: Option<&[String]>,
    runtime_profiles: Option<&BTreeMap<String, VariantRing2RuntimeProfile>>,
    field: &str,
) -> Result<Vec<RuntimeActionContract>, VariantContractLoadError> {
    let Some(profile_names) = profile_names else {
        return Ok(Vec::new());
    };

    let profiles = runtime_profiles.ok_or_else(|| {
        invalid_ring2(
            manifest_path,
            format!(
                "missing ring2_runtime_profiles section required by {}",
                field
            ),
        )
    })?;

    let mut actions = Vec::new();
    for profile_name in profile_names {
        let profile_name = normalize_non_empty_string(profile_name, field, manifest_path)?;
        let profile = profiles.get(profile_name.as_str()).ok_or_else(|| {
            invalid_ring2(
                manifest_path,
                format!(
                    "unknown runtime profile '{}' referenced by '{}'",
                    profile_name, logical_name
                ),
            )
        })?;
        if profile.actions.is_empty() {
            return Err(invalid_ring2(
                manifest_path,
                format!(
                    "runtime profile '{}' must declare at least one action",
                    profile_name
                ),
            ));
        }
        for action in &profile.actions {
            actions.push(runtime_action_contract_from_ring_manifest(
                action,
                manifest_path,
            )?);
        }
    }

    Ok(actions)
}

fn runtime_action_contract_from_ring_manifest(
    action: &VariantRing2RuntimeAction,
    manifest_path: &Path,
) -> Result<RuntimeActionContract, VariantContractLoadError> {
    Ok(match action {
        VariantRing2RuntimeAction::ToolPayloadWorkspaceBinary {
            package,
            binary,
            target,
        } => RuntimeActionContract::ToolPayloadWorkspaceBinary {
            package: normalize_non_empty_string(package, "package", manifest_path)?,
            binary: binary
                .as_deref()
                .map(|raw| normalize_non_empty_string(raw, "binary", manifest_path))
                .transpose()?,
            target: target
                .as_deref()
                .map(|raw| normalize_non_empty_string(raw, "target", manifest_path))
                .transpose()?,
        },
        VariantRing2RuntimeAction::RootfsWorkspaceBinary {
            package,
            binary,
            target,
            destination,
        } => RuntimeActionContract::RootfsWorkspaceBinary {
            package: normalize_non_empty_string(package, "package", manifest_path)?,
            binary: binary
                .as_deref()
                .map(|raw| normalize_non_empty_string(raw, "binary", manifest_path))
                .transpose()?,
            target: target
                .as_deref()
                .map(|raw| normalize_non_empty_string(raw, "target", manifest_path))
                .transpose()?,
            destination: normalize_relative_string(destination, "destination", manifest_path)?,
        },
        VariantRing2RuntimeAction::ApkPackages { packages } => {
            let packages = packages
                .iter()
                .map(|package| normalize_non_empty_string(package, "packages", manifest_path))
                .collect::<Result<Vec<_>, _>>()?;
            if packages.is_empty() {
                return Err(invalid_ring2(
                    manifest_path,
                    "runtime action 'apk_packages' must declare at least one package",
                ));
            }
            RuntimeActionContract::ApkPackages { packages }
        }
        VariantRing2RuntimeAction::IuppiterDarPayload { target } => {
            RuntimeActionContract::IuppiterDarPayload {
                target: target
                    .as_deref()
                    .map(|raw| normalize_non_empty_string(raw, "target", manifest_path))
                    .transpose()?,
            }
        }
        VariantRing2RuntimeAction::InstallModePayload {
            interactive_shell,
            ux_docs_frontend,
        } => RuntimeActionContract::InstallModePayload {
            interactive_shell: normalize_absolute_string(
                interactive_shell,
                "interactive_shell",
                manifest_path,
            )?,
            ux_docs_frontend: match ux_docs_frontend {
                VariantInstallDocsFrontend::PlainText => InstallDocsFrontend::PlainText,
                VariantInstallDocsFrontend::BunBundle => InstallDocsFrontend::BunBundle,
            },
        },
    })
}

fn normalize_non_empty_string(
    raw: &str,
    field: &str,
    manifest_path: &Path,
) -> Result<String, VariantContractLoadError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(invalid_ring2(
            manifest_path,
            format!("field '{}' must not be empty", field),
        ));
    }
    Ok(value.to_string())
}

fn normalize_relative_string(
    raw: &str,
    field: &str,
    manifest_path: &Path,
) -> Result<String, VariantContractLoadError> {
    let value = normalize_non_empty_string(raw, field, manifest_path)?;
    let path = Path::new(&value);
    if path.is_absolute() {
        return Err(invalid_ring2(
            manifest_path,
            format!(
                "field '{}' must be relative, got '{}'",
                field,
                path.display()
            ),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid_ring2(
            manifest_path,
            format!(
                "field '{}' must not traverse parents, got '{}'",
                field,
                path.display()
            ),
        ));
    }
    Ok(value)
}

fn normalize_absolute_string(
    raw: &str,
    field: &str,
    manifest_path: &Path,
) -> Result<String, VariantContractLoadError> {
    let value = normalize_non_empty_string(raw, field, manifest_path)?;
    let path = Path::new(&value);
    if !path.is_absolute() {
        return Err(invalid_ring2(
            manifest_path,
            format!(
                "field '{}' must be absolute, got '{}'",
                field,
                path.display()
            ),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid_ring2(
            manifest_path,
            format!(
                "field '{}' must not traverse parents, got '{}'",
                field,
                path.display()
            ),
        ));
    }
    Ok(value)
}

fn invalid_ring2(manifest_path: &Path, message: impl Into<String>) -> VariantContractLoadError {
    VariantContractLoadError::InvalidRing2Declaration {
        path: manifest_path.to_path_buf(),
        message: message.into(),
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
    let (required_kernel_cmdline, required_live_services) = merge_live_boot_required_defaults(
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
        live_environment: LiveEnvironmentScenario {
            required_services: scenarios.live_environment.required_services.clone(),
        },
        live_tools: LiveToolsScenario {
            required_tools: scenarios.live_tools.required_tools.clone(),
            install_experience: match scenarios.live_tools.install_experience {
                VariantInstallExperience::Ux => InstallExperience::Ux,
                VariantInstallExperience::AutomatedSsh => InstallExperience::AutomatedSsh,
            },
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

fn merge_live_boot_required_defaults(
    mut required_kernel_cmdline: Vec<String>,
    mut required_live_services: Vec<String>,
) -> (Vec<String>, Vec<String>) {
    merge_required_strings(
        &mut required_kernel_cmdline,
        BOOT_REQUIRED_KERNEL_CMDLINE_BASE,
    );
    merge_required_strings(
        &mut required_live_services,
        BOOT_REQUIRED_LIVE_SERVICES_BASE,
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
    seed_overlay: Option<String>,
    #[serde(rename = "profile_overlay")]
    legacy_profile_overlay: Option<String>,
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
    install_experience: VariantInstallExperience,
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
kernel_kconfig_path = "kernel/kconfig"
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
script_path = "evidence/build-capability.sh"
pass_marker = "BUILD CAPABILITY PASSED"
"#;

    const VALID_RING3_SOURCES_MANIFEST: &str = r#"schema_version = 6

[ring3_sources.rootfs_source]
kind = "recipe_rpm_dvd"
recipe_script = "distro-builder/recipes/fedora-dvd-source-rootfs.rhai"
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
package = "install-split-pane"
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
pass_marker = "LIVE BOOT PASSED"

[scenarios.live_environment]
required_services = ["sshd", "auditd"]

[scenarios.live_tools]
required_tools = ["bash"]
install_experience = "ux"

[scenarios.live_tools.evidence]
script_path = "live-tools.sh"
pass_marker = "LIVE TOOLS PASSED"

[scenarios.install]
required_tools = ["recstrap"]
required_services = ["sshd", "auditd"]

[scenarios.install.evidence]
script_path = "install.sh"
pass_marker = "INSTALL PASSED"

[scenarios.installed_boot]
success_patterns = ["example login:"]
fatal_patterns = []
required_kernel_cmdline = []
required_live_services = []

[scenarios.installed_boot.evidence]
script_path = "installed-boot.sh"
pass_marker = "INSTALLED BOOT PASSED"

[scenarios.automated_login]
auth_mode = "default_password_login"
default_username = "example"
default_password = "example"
login_prompt_pattern = "example login:"

[scenarios.automated_login.evidence]
script_path = "automated-login.sh"
pass_marker = "AUTOMATED LOGIN PASSED"

[scenarios.installed_tools]
required_tools = ["sudo"]

[scenarios.installed_tools.evidence]
script_path = "installed-tools.sh"
pass_marker = "INSTALLED TOOLS PASSED"

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

    fn write_full_ring_scaffold_owner_dirs(variant_dir: &Path) {
        write_file(
            &variant_dir
                .join(IDENTITY_OWNER_DIR)
                .join(IDENTITY_MANIFEST_FILENAME),
            VALID_IDENTITY_RING_MANIFEST,
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join(BUILD_HOST_MANIFEST_FILENAME),
            VALID_BUILD_HOST_RING_MANIFEST,
        );
        write_file(
            &variant_dir
                .join(RING3_OWNER_DIR)
                .join(RING3_SOURCES_MANIFEST_FILENAME),
            VALID_RING3_SOURCES_MANIFEST,
        );
        write_file(
            &variant_dir
                .join(RING2_OWNER_DIR)
                .join(RING2_PRODUCTS_MANIFEST_FILENAME),
            VALID_RING2_PRODUCTS_MANIFEST,
        );
        write_file(
            &variant_dir
                .join(RING1_OWNER_DIR)
                .join(RING1_TRANSFORMS_MANIFEST_FILENAME),
            VALID_RING1_TRANSFORMS_MANIFEST,
        );
        write_file(
            &variant_dir
                .join(RING0_OWNER_DIR)
                .join(RING0_RELEASE_MANIFEST_FILENAME),
            VALID_RING0_RELEASE_MANIFEST,
        );
        write_file(
            &variant_dir
                .join(SCENARIOS_OWNER_DIR)
                .join(SCENARIOS_MANIFEST_FILENAME),
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
            &variant_dir.join("build-host").join("kernel/kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &variant_dir.join("build-host").join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir
                .join("build-host")
                .join("evidence/build-capability.sh"),
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
            &variant_dir.join("kernel/kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &variant_dir.join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir.join("evidence/build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_full_ring_scaffold(&variant_dir);
        let paths = resolve_variant_owner_paths(&variant_dir).expect("resolve flat variant paths");
        let ring_bundle = load_ring_manifest_bundle(&paths).expect("parse ring scaffold");
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
            "distro-builder/recipes/fedora-dvd-source-rootfs.rhai"
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
            VariantInstallExperience::Ux
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
        assert_eq!(loaded.paths.manifest_layout, VariantPathLayout::FlatRoot);
        assert_eq!(
            loaded.paths.build_host_support_layout,
            VariantPathLayout::FlatRoot
        );
        assert_eq!(loaded.contract.identity.os_name, "LevitateOS");
        assert_eq!(
            loaded.contract.sources.rootfs_source.recipe_script,
            "distro-builder/recipes/fedora-dvd-source-rootfs.rhai"
        );
        assert_eq!(
            loaded.contract.transforms.iso.output_names,
            vec!["levitateos-x86_64.iso".to_string()]
        );

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn owner_directory_ring_scaffold_parses_and_loads_canonical_contract() {
        let repo_root = temp_repo_root("owner-dir-ring-load");
        let variant_dir = repo_root.join("distro-variants/levitate");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("kernel/kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("evidence/build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_full_ring_scaffold_owner_dirs(&variant_dir);

        let paths = resolve_variant_owner_paths(&variant_dir).expect("resolve owner-dir paths");
        assert_eq!(paths.manifest_layout, VariantPathLayout::OwnerDirectories);
        assert_eq!(
            paths.build_host_manifest,
            variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join(BUILD_HOST_MANIFEST_FILENAME)
        );

        let ring_bundle = load_ring_manifest_bundle(&paths).expect("parse owner-dir ring scaffold");
        assert_eq!(ring_bundle.identity.identity.os_id, "levitateos");

        let loaded = load_variant_contract_bundle_for_distro_from(&repo_root, "levitate")
            .expect("load owner-dir levitate contract");
        assert_eq!(
            loaded.manifest_path,
            variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join(BUILD_HOST_MANIFEST_FILENAME)
        );
        assert_eq!(
            loaded.paths.manifest_layout,
            VariantPathLayout::OwnerDirectories
        );
        assert_eq!(
            loaded.paths.build_host_support_layout,
            VariantPathLayout::OwnerDirectories
        );
        assert_eq!(loaded.contract.identity.os_name, "LevitateOS");

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

        let err = resolve_variant_owner_paths(&variant_dir)
            .expect_err("partial ring scaffold should fail");
        assert!(matches!(
            err,
            VariantContractLoadError::PartialRingManifestSet { .. }
        ));

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn duplicate_ring_manifest_paths_fail_loudly() {
        let repo_root = temp_repo_root("duplicate-ring-manifest");
        let variant_dir = repo_root.join("distro-variants/levitate");
        write_full_ring_scaffold(&variant_dir);
        write_file(
            &variant_dir
                .join(IDENTITY_OWNER_DIR)
                .join(IDENTITY_MANIFEST_FILENAME),
            VALID_IDENTITY_RING_MANIFEST,
        );

        let err = resolve_variant_owner_paths(&variant_dir)
            .expect_err("duplicate manifest ownership should fail");
        assert!(matches!(
            err,
            VariantContractLoadError::DuplicateOwnerPath {
                component: "identity",
                ..
            }
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
            &variant_dir.join("kernel/kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_full_ring_scaffold(&variant_dir);
        write_file(
            &variant_dir.join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n",
        );
        write_file(
            &variant_dir.join("evidence/build-capability.sh"),
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
    fn legacy_profile_overlay_key_maps_to_seed_overlay_contract() {
        let repo_root = temp_repo_root("legacy-profile-overlay-key");
        let variant_dir = repo_root.join("distro-variants/acorn");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("kernel/kconfig"),
            "CONFIG_LOCALVERSION=\"-acorn\"\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("evidence/build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_full_ring_scaffold_owner_dirs(&variant_dir);
        write_file(
            &variant_dir
                .join(RING2_OWNER_DIR)
                .join(RING2_PRODUCTS_MANIFEST_FILENAME),
            &VALID_RING2_PRODUCTS_MANIFEST.replacen(
                "overlay_kind = \"systemd\"",
                "overlay_kind = \"openrc\"\nopenrc_inittab = \"serial_only\"\nprofile_overlay = \"ring2/overlays/live\"",
                1,
            ),
        );

        let contract =
            load_variant_contract_for_distro_from(&repo_root, "acorn").expect("load acorn");

        assert_eq!(
            contract.product_config.live_overlay.seed_overlay,
            Some("ring2/overlays/live".to_string())
        );

        fs::remove_dir_all(repo_root).expect("cleanup temp root");
    }

    #[test]
    fn rejects_overlay_manifest_that_declares_both_seed_and_profile_overlay_keys() {
        let repo_root = temp_repo_root("conflicting-overlay-keys");
        let variant_dir = repo_root.join("distro-variants/acorn");

        write_file(
            &repo_root.join("distro-builder/recipes/linux.rhai"),
            "// shared kernel recipe placeholder\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("kernel/kconfig"),
            "CONFIG_LOCALVERSION=\"-acorn\"\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("recipes/kernel.rhai"),
            "let required_kernel_recipe = \"distro-builder/recipes/linux.rhai\";\n\
             let required_invocation = \"recipe install\";\n",
        );
        write_file(
            &variant_dir
                .join(BUILD_HOST_OWNER_DIR)
                .join("evidence/build-capability.sh"),
            "#!/bin/sh\nexit 0\n",
        );
        write_full_ring_scaffold_owner_dirs(&variant_dir);
        write_file(
            &variant_dir
                .join(RING2_OWNER_DIR)
                .join(RING2_PRODUCTS_MANIFEST_FILENAME),
            &VALID_RING2_PRODUCTS_MANIFEST.replacen(
                "overlay_kind = \"systemd\"",
                "overlay_kind = \"openrc\"\nopenrc_inittab = \"serial_only\"\nseed_overlay = \"ring2/overlays/live\"\nprofile_overlay = \"ring2/overlays/legacy\"",
                1,
            ),
        );

        let err = load_variant_contract_for_distro_from(&repo_root, "acorn")
            .expect_err("conflicting overlay keys should fail");

        assert!(matches!(
            err,
            VariantContractLoadError::InvalidRing2Declaration { .. }
        ));
        assert!(err
            .to_string()
            .contains("both seed_overlay and profile_overlay"));

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

            assert_eq!(loaded.contract.build.kernel.kconfig_path, "kernel/kconfig");
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

        let paths = resolve_variant_owner_paths(&variant_dir).expect("resolve levitate paths");
        let ring_bundle = load_ring_manifest_bundle(&paths).expect("parse levitate ring scaffold");

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
            let paths = resolve_variant_owner_paths(&variant_dir).unwrap_or_else(|err| {
                panic!("failed to resolve {} variant paths: {}", distro_id, err)
            });
            let ring_bundle = load_ring_manifest_bundle(&paths).unwrap_or_else(|err| {
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
                kconfig_path: "kernel/kconfig".to_string(),
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
                script_path: "evidence/build-capability.sh".to_string(),
                pass_marker: "BUILD CAPABILITY PASSED".to_string(),
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
                    pass_marker: "LIVE BOOT PASSED".to_string(),
                },
            },
            live_environment: LiveEnvironmentScenario {
                required_services: vec!["sshd".to_string(), "auditd".to_string()],
            },
            live_tools: LiveToolsScenario {
                required_tools: vec!["bash".to_string()],
                install_experience: InstallExperience::Ux,
                evidence: ScriptEvidence {
                    script_path: "live-tools.sh".to_string(),
                    pass_marker: "LIVE TOOLS PASSED".to_string(),
                },
            },
            install: InstallStage {
                required_tools: vec!["recstrap".to_string()],
                required_services: vec!["sshd".to_string()],
                evidence: ScriptEvidence {
                    script_path: "install.sh".to_string(),
                    pass_marker: "INSTALL PASSED".to_string(),
                },
            },
            installed_boot: BootStage {
                success_patterns: vec!["example login:".to_string()],
                fatal_patterns: vec![],
                required_kernel_cmdline: vec![],
                required_live_services: vec![],
                evidence: ScriptEvidence {
                    script_path: "installed-boot.sh".to_string(),
                    pass_marker: "INSTALLED BOOT PASSED".to_string(),
                },
            },
            automated_login: AutomatedLoginStage {
                auth_mode: AuthMode::DefaultPasswordLogin,
                default_username: Some("example".to_string()),
                default_password: Some("example".to_string()),
                login_prompt_pattern: "example login:".to_string(),
                evidence: ScriptEvidence {
                    script_path: "automated-login.sh".to_string(),
                    pass_marker: "AUTOMATED LOGIN PASSED".to_string(),
                },
            },
            installed_tools: ToolsStage {
                required_tools: vec!["sudo".to_string()],
                evidence: ScriptEvidence {
                    script_path: "installed-tools.sh".to_string(),
                    pass_marker: "INSTALLED TOOLS PASSED".to_string(),
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
        let product_config = ProductConfigContract {
            live_overlay: OverlayContract {
                kind: OverlayKind::Systemd,
                issue_message: None,
                openrc_inittab: None,
                seed_overlay: None,
            },
            boot_live: BootPayloadContract {
                producers: vec![PayloadProducerContract::WriteText {
                    path: ".live-payload-role".to_string(),
                    content: "rootfs\n".to_string(),
                    mode: None,
                }],
            },
            boot_installed: None,
            live_tools: LiveToolsRuntimeContract {
                common_actions: vec![RuntimeActionContract::InstallModePayload {
                    interactive_shell: "/bin/bash".to_string(),
                    ux_docs_frontend: InstallDocsFrontend::PlainText,
                }],
                ux_actions: vec![],
                automated_ssh_actions: vec![],
            },
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
                    recipe_script: "distro-builder/recipes/fedora-dvd-source-rootfs.rhai"
                        .to_string(),
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
            product_config,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VariantInstallExperience {
    Ux,
    AutomatedSsh,
}
