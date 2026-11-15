//! The installed-system release set a system part publishes and its ISO
//! carries: `release.json`, naming what the build produced (the system's
//! identity, the sources it was built from, its kernel, and the size and
//! SHA-256 of its rootfs image, kernel and installed initramfs). The combiner
//! verifies the set before writing the ISO; preflight checks it again.
use anyhow::{ensure, Result};
use distro_profile::{Flavour, InitSystem, Libc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

pub const MANIFEST: &str = "release.json";
pub const MAX_MANIFEST: usize = 1024 * 1024;
const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub distro: String,
    pub architecture: Architecture,
    pub init: InitSystem,
    pub libc: Libc,
    pub flavour: Flavour,
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// The member's path in the release directory and on the ISO.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifacts {
    pub rootfs: Artifact,
    pub kernel: Artifact,
    pub initramfs: Artifact,
}
impl Artifacts {
    pub fn all(&self) -> [&Artifact; 3] {
        [&self.rootfs, &self.kernel, &self.initramfs]
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    pub release: String,
    pub modules_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub identity: Identity,
    pub sources_sha256: String,
    pub kernel: Kernel,
    pub artifacts: Artifacts,
}
impl ReleaseManifest {
    pub fn new(
        identity: Identity,
        sources_sha256: String,
        kernel: Kernel,
        artifacts: Artifacts,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            identity,
            sources_sha256,
            kernel,
            artifacts,
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_MANIFEST,
            "release manifest exceeds 1 MiB"
        );
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported release manifest version {} (expected {SCHEMA_VERSION}); build the release again",
            self.schema_version
        );
        token(&self.identity.distro)?;
        token(&self.kernel.release)?;
        ensure!(
            !self.identity.version.trim().is_empty() && self.identity.version.len() <= 128,
            "invalid release identity"
        );
        hash(&self.sources_sha256)?;
        hash(&self.kernel.modules_sha256)?;
        let mut names = BTreeSet::new();
        for artifact in self.artifacts.all() {
            relative(&artifact.path)?;
            hash(&artifact.sha256)?;
            ensure!(
                artifact.size > 0 && artifact.size <= 64 * 1024 * 1024 * 1024,
                "invalid release payload size"
            );
            ensure!(
                names.insert(&artifact.path) && artifact.path != MANIFEST,
                "duplicate/reserved release member"
            );
        }
        Ok(())
    }
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn hash(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA256"
    );
    Ok(())
}
pub fn relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && !path.contains(['\\', '\0'])
            && Path::new(path)
                .components()
                .all(|p| matches!(p, Component::Normal(_)))
            && path
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != ".."),
        "unsafe release member"
    );
    Ok(())
}
fn token(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
        "invalid release token"
    );
    Ok(())
}
