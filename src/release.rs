//! The installed-system release set, identical on media and online. Signatures
//! cover exact manifest bytes; the configured distribution key is the authority.
use anyhow::{ensure, Context, Result};
use distro_profile::{Flavour, InitSystem, Libc};
use levitate_recipe::target::{Entry, Manifest};
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

pub const MANIFEST: &str = "release.json";
pub const SIGNATURE: &str = "release.sig";
pub const INVENTORY: &str = "system-inventory.json";
pub const SOURCE_CONFIG: &str = "usr/lib/recab/update-source.json";
pub const MAX_MANIFEST: usize = 1024 * 1024;
pub const MAX_INVENTORY: u64 = 64 * 1024 * 1024;
pub const STATE_MAJOR: u32 = 2;
pub const STATE_MINOR: u32 = 3;
pub const BOOT_PROTOCOL: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSource {
    /// HTTPS index, or loopback HTTP for local fixtures. Acquisition is Recipe (P08).
    pub index: String,
    pub recipe: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// Distribution release key: 32 raw Ed25519 bytes as lowercase hex.
    pub ed25519: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub channel: String,
    /// Release ordering is a publishing decision, never inferred from a version
    /// string or a build clock. Zero disables release production.
    pub sequence: u64,
    pub source: Option<UpdateSource>,
    pub trust: Option<Trust>,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.channel.is_empty()
            && self.sequence == 0
            && self.source.is_none()
            && self.trust.is_none()
        {
            return Ok(());
        }
        token(&self.channel)?;
        ensure!(self.sequence > 0, "release sequence must be positive");
        if let Some(source) = &self.source {
            ensure!(
                source.index.len() <= 4096 && !source.index.chars().any(char::is_whitespace),
                "invalid update index URL"
            );
            let url = url::Url::parse(&source.index)?;
            let loopback = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                Some(url::Host::Domain("localhost")) => true,
                _ => false,
            };
            ensure!(
                (url.scheme() == "https" || (url.scheme() == "http" && loopback))
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "update index must use HTTPS (or loopback HTTP) without credentials/fragment"
            );
            relative(&source.recipe)?;
            ensure!(
                self.trust.is_some(),
                "an online source requires a distribution release key"
            );
        }
        if let Some(trust) = &self.trust {
            ensure!(
                hex::decode(&trust.ed25519)?.len() == 32,
                "release key must be 32 Ed25519 bytes"
            );
            ensure!(
                trust
                    .ed25519
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "release key must use lowercase hex"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}
impl Architecture {
    pub fn machine(&self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::Aarch64 => 183,
        }
    }
    pub fn native(&self) -> bool {
        matches!(
            (self, std::env::consts::ARCH),
            (Self::X86_64, "x86_64") | (Self::Aarch64, "aarch64")
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub distro: String,
    pub architecture: Architecture,
    pub init: InitSystem,
    pub libc: Libc,
    pub flavour: Flavour,
    pub channel: String,
    pub sequence: u64,
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Canonical media-relative member, also resolved against the online base URL.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifacts {
    pub rootfs: Artifact,
    pub inventory: Artifact,
    pub kernel: Artifact,
    pub initramfs: Artifact,
}
impl Artifacts {
    pub fn all(&self) -> [&Artifact; 4] {
        [&self.rootfs, &self.inventory, &self.kernel, &self.initramfs]
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
pub struct Compatibility {
    pub minimum_recab: String,
    pub state_major: u32,
    pub state_minor: u32,
    pub boot_protocol: u32,
}
impl Compatibility {
    pub fn check(&self, recab: &str) -> Result<()> {
        ensure!(
            semver::Version::parse(recab)? >= semver::Version::parse(&self.minimum_recab)?,
            "release requires a newer recab runtime"
        );
        ensure!(
            self.state_major == STATE_MAJOR
                && self.state_minor <= STATE_MINOR
                && self.boot_protocol == BOOT_PROTOCOL,
            "incompatible release state/boot protocol"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub identity: Identity,
    pub sources_sha256: String,
    pub compatibility: Compatibility,
    pub kernel: Kernel,
    pub artifacts: Artifacts,
}
impl ReleaseManifest {
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
            self.schema_version == 1,
            "unsupported release manifest version"
        );
        token(&self.identity.distro)?;
        token(&self.identity.channel)?;
        token(&self.kernel.release)?;
        ensure!(
            self.identity.sequence > 0
                && !self.identity.version.trim().is_empty()
                && self.identity.version.len() <= 128,
            "invalid release identity"
        );
        hash(&self.sources_sha256)?;
        hash(&self.kernel.modules_sha256)?;
        semver::Version::parse(&self.compatibility.minimum_recab)?;
        let mut names = BTreeSet::new();
        for artifact in self.artifacts.all() {
            relative(&artifact.path)?;
            ensure!(
                !artifact.path.contains([':', '?', '#', '%'])
                    && !artifact.path.chars().any(char::is_whitespace),
                "release payload path is not URL-relative"
            );
            hash(&artifact.sha256)?;
            ensure!(
                artifact.size > 0 && artifact.size <= 64 * 1024 * 1024 * 1024,
                "invalid release payload size"
            );
            ensure!(
                names.insert(&artifact.path)
                    && ![MANIFEST, SIGNATURE].contains(&artifact.path.as_str()),
                "duplicate/reserved release member"
            );
        }
        ensure!(
            self.artifacts.inventory.size <= MAX_INVENTORY
                && self.artifacts.kernel.size <= 512 * 1024 * 1024
                && self.artifacts.initramfs.size <= 512 * 1024 * 1024,
            "release artifact exceeds bound"
        );
        Ok(())
    }
    pub fn matches(&self, installed: &Identity) -> Result<()> {
        let n = &self.identity;
        let o = installed;
        ensure!(
            n.distro == o.distro,
            "release distro differs from installed system"
        );
        ensure!(
            n.architecture == o.architecture,
            "release architecture differs from installed system"
        );
        ensure!(
            n.init == o.init && n.libc == o.libc && n.flavour == o.flavour,
            "release init/libc/flavour differs from installed system"
        );
        ensure!(
            n.channel == o.channel,
            "release channel differs from installed system"
        );
        // Import can cache the current release; selecting a downgrade is a
        // separate future apply decision, never an implicit discovery result.
        ensure!(
            n.sequence >= o.sequence,
            "release sequence is older than installed baseline"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemInventory {
    pub schema_version: u32,
    pub entries: BTreeMap<String, Entry>,
}
impl SystemInventory {
    pub fn from_target(target: Manifest) -> Result<Self> {
        ensure!(
            target.removals.is_empty(),
            "release rootfs must be a complete tree, not a removal payload"
        );
        let mut entries = target.entries;
        entries.retain(|path, e| inventory_path(path, &e.kind));
        let value = Self {
            schema_version: 1,
            entries,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_INVENTORY,
            "release inventory exceeds bound"
        );
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.entries.get("").is_some_and(|e| e.kind == "dir"),
            "invalid release inventory root/version"
        );
        ensure!(
            self.entries.len() <= 1_000_000,
            "release inventory exceeds entry bound"
        );
        for (path, e) in &self.entries {
            if !path.is_empty() {
                relative(path)?;
            }
            ensure!(
                inventory_path(path, &e.kind),
                "excluded release inventory path: {path}"
            );
            ensure!(
                e.user.is_none() && e.group.is_none() && e.mode <= 0o7777,
                "unresolved/invalid intended metadata"
            );
            if path == SOURCE_CONFIG {
                ensure!(
                    e.kind == "file" && e.uid == 0 && e.mode & 0o022 == 0,
                    "release policy needs intended root ownership and protected regular-file permissions"
                );
            }
            ensure!(
                ["file", "dir", "symlink", "hardlink"].contains(&e.kind.as_str()),
                "unsupported inventory kind"
            );
            if matches!(e.kind.as_str(), "file" | "hardlink") {
                hash(
                    e.sha256
                        .as_deref()
                        .context("inventory content digest missing")?,
                )?;
            }
            if e.kind == "symlink" {
                ensure!(
                    e.link
                        .as_ref()
                        .is_some_and(|l| !l.contains('\0') && l.len() <= 4096),
                    "invalid inventory symlink"
                );
            }
            if e.kind == "hardlink" {
                let first = self
                    .entries
                    .get(e.link.as_ref().context("hardlink target missing")?)
                    .context("hardlink outside release inventory")?;
                ensure!(
                    first.kind == "file"
                        && first.sha256 == e.sha256
                        && first.mode == e.mode
                        && first.uid == e.uid
                        && first.gid == e.gid
                        && first.xattrs == e.xattrs,
                    "inconsistent release hardlink"
                );
            }
            for (n, v) in &e.xattrs {
                ensure!(
                    !n.is_empty()
                        && !n.contains(['\0', '\n', '='])
                        && hex::decode(v)?.len() <= 65536,
                    "invalid inventory xattr"
                );
            }
            if !path.is_empty() {
                if let Some(parent) = Path::new(path).parent() {
                    let name = parent.to_str().context("inventory path must be UTF-8")?;
                    ensure!(
                        self.entries.get(name).is_some_and(|e| e.kind == "dir"),
                        "missing/non-directory inventory parent: {path}"
                    );
                }
            }
        }
        Ok(())
    }
}
pub fn inventory_path(path: &str, kind: &str) -> bool {
    if [
        levitate_recipe::target::MANIFEST,
        "usr/lib/recab/generation.json",
        "usr/lib/recab/boot-generation",
    ]
    .contains(&path)
    {
        return false;
    }
    let first = path.split('/').next().unwrap_or("");
    let excluded = [
        "boot",
        "var",
        "home",
        "root",
        "proc",
        "sys",
        "dev",
        "run",
        "tmp",
        "lost+found",
    ]
    .contains(&first);
    !excluded || (path == first && kind == "symlink")
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
pub fn verify_signature(bytes: &[u8], signature: &[u8], trust: &Trust) -> Result<()> {
    let key = hex::decode(&trust.ed25519)?;
    ensure!(
        key.len() == 32 && signature.len() == 64,
        "invalid release signing key/signature length"
    );
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(bytes, signature)
        .map_err(|_| anyhow::anyhow!("release signature verification failed"))
}
pub fn sign(bytes: &[u8], pkcs8: &[u8], trust: &Trust) -> Result<Vec<u8>> {
    // OpenSSL emits PKCS#8 v1 without an embedded public key. Accept v1/v2,
    // then require the derived public key to match configured distribution trust.
    let key = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 release key"))?;
    ensure!(
        hex::encode(key.public_key().as_ref()) == trust.ed25519,
        "signing key differs from configured distribution key"
    );
    Ok(key.sign(bytes).as_ref().to_vec())
}

/// Local image-writer provenance, not a second release manifest or trust root.
/// It binds the exact mkfs tar input's metadata/content inventory to its output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsProvenance {
    pub schema_version: u32,
    pub rootfs_sha256: String,
    pub inventory: SystemInventory,
}
pub fn provenance_path(image: &Path) -> std::path::PathBuf {
    let mut name = image.as_os_str().to_os_string();
    name.push(".release.json");
    name.into()
}
impl SystemInventory {
    /// Read the image writer's actual tar bytes, not staging inode ownership or
    /// a second walk of paths that may have changed since the tar was written.
    pub fn from_tar(input: impl std::io::Read) -> Result<Self> {
        let mut archive = tar::Archive::new(input);
        let mut entries = BTreeMap::<String, Entry>::new();
        for item in archive.entries()? {
            let mut item = item?;
            let path = item
                .path()?
                .components()
                .filter_map(|c| match c {
                    Component::CurDir => None,
                    Component::Normal(n) => Some(
                        n.to_str()
                            .map(str::to_owned)
                            .context("non-UTF8 release path"),
                    ),
                    _ => Some(Err(anyhow::anyhow!("unsafe image tar member"))),
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            let kind = match item.header().entry_type() {
                t if t.is_file() => "file",
                t if t.is_dir() => "dir",
                t if t.is_symlink() => "symlink",
                t if t.is_hard_link() => "hardlink",
                _ => anyhow::bail!("unsupported image tar inode"),
            };
            if !inventory_path(&path, kind) {
                continue;
            }
            let mut entry = Entry {
                kind: kind.into(),
                mode: item.header().mode()?,
                uid: u32::try_from(item.header().uid()?)?,
                gid: u32::try_from(item.header().gid()?)?,
                user: None,
                group: None,
                xattrs: BTreeMap::new(),
                link: None,
                sha256: None,
            };
            if let Some(attrs) = item.pax_extensions()? {
                for attr in attrs {
                    let attr = attr?;
                    if let Some(name) = attr.key()?.strip_prefix("SCHILY.xattr.") {
                        entry
                            .xattrs
                            .insert(name.into(), hex::encode(attr.value_bytes()));
                    }
                }
            }
            if kind == "file" {
                let mut hash = Sha256::new();
                std::io::copy(&mut item, &mut hash)?;
                entry.sha256 = Some(hex::encode(hash.finalize()));
            }
            if kind == "symlink" || kind == "hardlink" {
                entry.link = Some(
                    item.link_name()?
                        .context("tar link target missing")?
                        .to_str()
                        .context("non-UTF8 tar link")?
                        .to_owned(),
                );
            }
            if kind == "hardlink" {
                entry.sha256 = entries
                    .get(entry.link.as_ref().unwrap())
                    .and_then(|e| e.sha256.clone());
            }
            ensure!(
                entries.insert(path, entry).is_none(),
                "duplicate image tar path"
            );
        }
        let value = Self {
            schema_version: 1,
            entries,
        };
        value.validate()?;
        Ok(value)
    }
}

pub const INDEX: &str = "index.json";
pub const INDEX_SIGNATURE: &str = "index.sig";
pub const ACQUISITION_RECIPE: &str = "usr/share/recab/update-acquire.rhai";
/// The only network authority the installed acquisition recipe needs.
pub fn endpoint(index: &str) -> Result<String> {
    let url = url::Url::parse(index)?;
    Ok(format!(
        "{}:{}",
        url.host_str().context("update source host missing")?,
        url.port_or_known_default()
            .context("update source port missing")?
    ))
}
impl Policy {
    /// Variant recipes are repository paths; installed policy uses the packaged,
    /// configured acquisition recipe rather than referring back to a checkout.
    pub fn installed(&self) -> Self {
        let mut policy = self.clone();
        if let Some(source) = &mut policy.source {
            source.recipe = ACQUISITION_RECIPE.into();
        }
        policy
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub identity: Identity,
    pub manifest: Artifact,
    pub signature: Artifact,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndex {
    pub schema_version: u32,
    pub sequence: u64,
    pub channel: String,
    pub releases: Vec<IndexEntry>,
}
impl ReleaseIndex {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_MANIFEST, "release index exceeds 1 MiB");
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.sequence > 0 && self.releases.len() <= 256,
            "invalid release index version/sequence/entry count"
        );
        token(&self.channel)?;
        let mut identities = BTreeSet::new();
        for entry in &self.releases {
            let identity = &entry.identity;
            token(&identity.distro)?;
            token(&identity.channel)?;
            ensure!(
                identity.channel == self.channel
                    && identity.sequence > 0
                    && !identity.version.is_empty(),
                "release index identity/channel mismatch"
            );
            ensure!(
                identities.insert(serde_json::to_vec(&(
                    &identity.distro,
                    &identity.architecture,
                    identity.init,
                    identity.libc,
                    identity.flavour
                ))?),
                "duplicate indexed release profile"
            );
            for artifact in [&entry.manifest, &entry.signature] {
                relative(&artifact.path)?;
                hash(&artifact.sha256)?;
                ensure!(
                    !artifact.path.contains([':', '?', '#', '%'])
                        && !artifact.path.chars().any(char::is_whitespace),
                    "unsafe index member URL"
                );
            }
            ensure!(
                entry.manifest.size > 0
                    && entry.manifest.size <= MAX_MANIFEST as u64
                    && entry.signature.size == 64,
                "invalid indexed metadata size"
            );
            ensure!(
                Path::new(&entry.manifest.path).file_name() == Some(std::ffi::OsStr::new(MANIFEST))
                    && Path::new(&entry.signature.path).file_name()
                        == Some(std::ffi::OsStr::new(SIGNATURE))
                    && Path::new(&entry.manifest.path).parent()
                        == Path::new(&entry.signature.path).parent(),
                "indexed manifest/signature must be one release set"
            );
        }
        Ok(())
    }
}
