//! The loader: `distro/variants/<id>/distro.toml`, read once, validated once.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::LoadError;
use crate::schema::{ArtifactNames, ConformanceContract};

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
    /// A file beside `distro.toml` (`kconfig`, `keys/...`).
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
    derive_names(&mut contract);
    let violations = crate::validate::validate(&contract, repo_root, &dir);
    if !violations.is_empty() {
        return Err(LoadError::Invalid {
            manifest,
            violations,
        });
    }
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

/// The names that follow from the variant id and `os_id`, so no file spells them.
fn derive_names(contract: &mut ConformanceContract) {
    let os_id = contract.identity.os_id.clone();
    contract.identity.iso_label = os_id.to_ascii_uppercase();
    contract.identity.default_hostname = os_id.clone();
    contract.identity.login_prompt = format!("{os_id} login:");
    contract.artifacts = ArtifactNames::derive(&os_id, contract.installed.initramfs);
    let source = &mut contract.sources.rootfs_source;
    if contract.profile.packages == distro_profile::PackageBackend::Rpm {
        source.rpm_base = Some(crate::schema::RpmBaseContract {
            fedora_release: source.base.release.parse().unwrap_or(0),
            signing_key: source.base.signing_key.clone(),
            packages: source.base.packages.clone(),
        });
    }
}
