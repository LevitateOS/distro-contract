//! The loader: `distro/variants/<id>/distro.toml`, read once, validated once.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::LoadError;
use crate::schema::{ArtifactIdentity, ConformanceContract, TransformContract};

const VARIANTS_DIR: &str = "distro/variants";
const MANIFEST: &str = "distro.toml";

/// A loaded, validated variant.
#[derive(Debug, Clone)]
pub struct Variant {
    /// The variant id: its directory name under `distro/variants`.
    pub id: String,
    pub repo_root: PathBuf,
    /// `distro/variants/<id>`.
    pub dir: PathBuf,
    /// `distro/variants/<id>/distro.toml`.
    pub manifest: PathBuf,
    pub contract: ConformanceContract,
}

impl Variant {
    /// A file beside `distro.toml` (`kconfig`, `keys/...`, `hooks/...`).
    pub fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.dir.join(relative)
    }
}

/// Load and validate the variant `distro_id` of the checkout at `repo_root`.
pub fn load(repo_root: &Path, distro_id: &str) -> Result<Variant, LoadError> {
    let dir = repo_root.join(VARIANTS_DIR).join(distro_id);
    let manifest = dir.join(MANIFEST);
    if !is_variant_id(distro_id) || !manifest.is_file() {
        return Err(LoadError::UnknownVariant {
            distro_id: distro_id.to_string(),
            manifest,
            known: distro_ids(repo_root),
        });
    }
    let text = fs::read_to_string(&manifest).map_err(|source| LoadError::Read {
        manifest: manifest.clone(),
        source,
    })?;
    let mut contract: ConformanceContract =
        toml::from_str(&text).map_err(|source| LoadError::Parse {
            manifest: manifest.clone(),
            source,
        })?;
    let violations = crate::validate::validate(&contract, repo_root, &dir);
    if !violations.is_empty() {
        return Err(LoadError::Invalid {
            manifest,
            violations,
        });
    }
    contract.artifacts = artifact_identity(&contract.transforms);
    Ok(Variant {
        id: distro_id.to_string(),
        repo_root: repo_root.to_path_buf(),
        dir,
        manifest,
        contract,
    })
}

/// The variant ids of the checkout at `repo_root`: the directories under
/// `distro/variants` that hold a `distro.toml`, sorted.
pub fn distro_ids(repo_root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(repo_root.join(VARIANTS_DIR)) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().join(MANIFEST).is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|id| is_variant_id(id))
        .collect();
    ids.sort();
    ids
}

/// A variant id is one plain path component.
fn is_variant_id(id: &str) -> bool {
    !id.is_empty() && !id.contains(['/', '\\']) && id != "." && id != ".."
}

fn artifact_identity(transforms: &TransformContract) -> ArtifactIdentity {
    ArtifactIdentity {
        rootfs_name: transforms.rootfs_image.output().to_string(),
        initramfs_live_output: transforms.initramfs_live.output().to_string(),
        iso_filename: transforms.iso.output().to_string(),
        initramfs_installed_output: transforms
            .initramfs_installed
            .as_ref()
            .map(|t| t.output().to_string()),
        installed_uki_outputs: transforms
            .installed_uki
            .as_ref()
            .map(|t| t.output_names.clone())
            .unwrap_or_default(),
        disk_image_output: transforms.disk_image.as_ref().map(|t| t.output().to_string()),
    }
}
