//! Production metadata authentication and delivery, shared by publisher and reader.
//! This extends discovery, not the canonical system manifest or the A/B engine.
use super::{
    Architecture, Identity, IndexEntry, ReleaseManifest, Trust, digest, hash, relative, sign,
    token, verify_signature,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const AUTHORITY_FILE: &str = "release-keys.json";
pub const MAX_AUTHORITY: usize = 64 * 1024;
pub const MAX_PART: u64 = 1024 * 1024 * 1024;
pub const MAX_PARTS: usize = 64;
pub const MAX_INDEX_AGE: u64 = 14 * 24 * 60 * 60;
pub const MAX_AUTHORITY_AGE: u64 = 365 * 24 * 60 * 60;
pub const CLOCK_TOLERANCE: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    Candidate,
    Stable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningRole {
    Release,
    Index,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootAnchor {
    /// Original trust lineage. Root rotation never resets its durable floors.
    pub lineage: String,
    pub version: u64,
    pub key: Trust,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionPolicy {
    pub schema_version: u32,
    pub root: RootAnchor,
    pub audience: Audience,
    /// Canonical HTTPS origin/path prefix for metadata; no implicit redirects.
    pub metadata_base: String,
    /// Exact repository release-download prefix, not all of github.com.
    pub asset_prefix: String,
    pub redirect_origins: Vec<String>,
}

fn https(value: &str) -> Result<url::Url> {
    ensure!(
        value.len() <= 4096 && !value.chars().any(char::is_whitespace),
        "invalid production URL"
    );
    let u = url::Url::parse(value)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none(),
        "production URLs require HTTPS without credentials or fragment"
    );
    Ok(u)
}
fn prefix(value: &str) -> Result<url::Url> {
    let u = https(value)?;
    ensure!(
        u.query().is_none() && u.path().ends_with('/') && !u.path().contains('%'),
        "production prefix must end in / without query/escapes"
    );
    ensure!(u.as_str() == value, "production prefix must be canonical");
    Ok(u)
}
fn under(value: &str, base: &str) -> Result<url::Url> {
    let u = https(value)?;
    let base = prefix(base)?;
    ensure!(
        u.origin() == base.origin()
            && u.path().starts_with(base.path())
            && u.query().is_none()
            && !u.path().contains('%')
            && u.as_str() == value,
        "URL leaves configured publication prefix"
    );
    Ok(u)
}
impl ProductionPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 2 && self.root.version > 0,
            "unsupported production policy/root version"
        );
        hash(&self.root.lineage)?;
        self.root.key.validate()?;
        if self.root.version == 1 {
            ensure!(
                self.root.lineage == self.root.key.id()?,
                "initial trust lineage must identify its root key"
            );
        }
        prefix(&self.metadata_base)?;
        prefix(&self.asset_prefix)?;
        ensure!(
            self.redirect_origins.len() <= 4,
            "too many release redirect origins"
        );
        let mut origins = BTreeSet::new();
        for s in &self.redirect_origins {
            let u = https(s)?;
            ensure!(
                u.origin().ascii_serialization() == *s && origins.insert(s),
                "redirect grants must be distinct canonical HTTPS origins"
            );
        }
        Ok(())
    }
    pub fn metadata_url(&self, value: &str) -> Result<()> {
        under(value, &self.metadata_base)?;
        Ok(())
    }
    pub fn asset_url(&self, value: &str) -> Result<()> {
        under(value, &self.asset_prefix)?;
        Ok(())
    }
    /// All URLs, including redirects, remain within installed authority.
    pub fn request_origins(&self, value: &str) -> Result<Vec<String>> {
        if self.metadata_url(value).is_ok() {
            return Ok(vec![https(value)?.origin().ascii_serialization()]);
        }
        self.asset_url(value)?;
        let mut out = vec![https(value)?.origin().ascii_serialization()];
        for origin in &self.redirect_origins {
            if !out.contains(origin) {
                out.push(origin.clone());
            }
        }
        Ok(out)
    }
    pub fn feed_id(&self, identity: &Identity) -> Result<String> {
        ensure!(
            identity.architecture == Architecture::X86_64,
            "production execution supports x86_64 only"
        );
        Ok(digest(&serde_json::to_vec(&(
            &self.root.lineage,
            &identity.distro,
            &identity.channel,
            self.audience,
            &identity.architecture,
            identity.init,
            identity.libc,
            identity.flavour,
        ))?))
    }
}

impl Trust {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.ed25519.len() == 64
                && self
                    .ed25519
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "release key must be 32 lowercase-hex Ed25519 bytes"
        );
        Ok(())
    }
    pub fn id(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(&hex::decode(&self.ed25519)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTransition {
    pub version: u64,
    pub previous: Trust,
    pub successor: Trust,
    pub previous_signature: Vec<u8>,
    pub successor_signature: Vec<u8>,
}
impl RootTransition {
    pub fn message(&self, lineage: &str) -> Result<Vec<u8>> {
        let mut b = b"recab-root-transition-v1\n".to_vec();
        b.extend(serde_json::to_vec(&(
            lineage,
            self.version,
            &self.previous,
            &self.successor,
        ))?);
        Ok(b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDelegation {
    pub schema_version: u32,
    pub version: u64,
    pub root_version: u64,
    /// Only the offline root may start a new index epoch after signer compromise.
    pub index_epoch: u64,
    pub distro: String,
    pub channel: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub release_keys: Vec<Trust>,
    pub index_keys: Vec<Trust>,
    pub revoked: BTreeSet<String>,
}
fn window(issued: u64, expires: u64, limit: u64) -> Result<()> {
    ensure!(
        issued > 0 && expires > issued && expires - issued <= limit,
        "invalid metadata validity window"
    );
    Ok(())
}
fn fresh(issued: u64, expires: u64, now: u64) -> Result<()> {
    ensure!(
        issued <= now.saturating_add(CLOCK_TOLERANCE),
        "metadata issue time is in the future; check the system clock"
    );
    ensure!(
        now < expires,
        "metadata expired; refresh the feed or check the system clock"
    );
    Ok(())
}
impl KeyDelegation {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.version > 0
                && self.root_version > 0
                && self.index_epoch > 0,
            "unsupported key delegation version"
        );
        token(&self.distro)?;
        token(&self.channel)?;
        window(self.issued_at, self.expires_at, MAX_AUTHORITY_AGE)?;
        ensure!(
            !self.release_keys.is_empty()
                && self.release_keys.len() <= 4
                && !self.index_keys.is_empty()
                && self.index_keys.len() <= 4
                && self.revoked.len() <= 64,
            "invalid signing-role key count"
        );
        let mut ids = BTreeSet::new();
        for k in self.release_keys.iter().chain(&self.index_keys) {
            let id = k.id()?;
            ensure!(
                ids.insert(id.clone()),
                "signing roles must use distinct keys"
            );
            ensure!(
                !self.revoked.contains(&id),
                "revoked key remains in an active signing role"
            );
        }
        for id in &self.revoked {
            hash(id)?;
        }
        Ok(())
    }
    pub fn keys(&self, role: SigningRole) -> &[Trust] {
        match role {
            SigningRole::Release => &self.release_keys,
            SigningRole::Index => &self.index_keys,
        }
    }
}

/// Exact signed document bytes plus the bounded, dual-signed root succession.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityProof {
    pub document: String,
    pub signature: Vec<u8>,
    pub transitions: Vec<RootTransition>,
}
pub struct VerifiedAuthority {
    delegation: KeyDelegation,
    digest: String,
}
impl AuthorityProof {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_AUTHORITY,
            "key delegation proof exceeds bound"
        );
        Ok(serde_json::from_slice(bytes)?)
    }
    pub fn verify(
        &self,
        policy: &ProductionPolicy,
        distro: &str,
        channel: &str,
        now: u64,
    ) -> Result<VerifiedAuthority> {
        self.verify_inner(policy, distro, channel, Some(now))
    }
    /// Signature/lineage verification for renewing an expired authorization or
    /// checking an already accepted offline proof. Does not authorize discovery.
    pub fn verify_archived(
        &self,
        policy: &ProductionPolicy,
        distro: &str,
        channel: &str,
    ) -> Result<VerifiedAuthority> {
        self.verify_inner(policy, distro, channel, None)
    }
    fn verify_inner(
        &self,
        policy: &ProductionPolicy,
        distro: &str,
        channel: &str,
        now: Option<u64>,
    ) -> Result<VerifiedAuthority> {
        policy.validate()?;
        ensure!(
            self.document.len() <= 16384 && self.transitions.len() <= 32,
            "key delegation/transition chain exceeds bound"
        );
        let mut root = policy.root.key.clone();
        let mut version = policy.root.version;
        let mut roots = BTreeSet::from([root.id()?]);
        for transition in &self.transitions {
            transition.successor.validate()?;
            ensure!(
                roots.insert(transition.successor.id()?),
                "root transition reuses a previous root"
            );
            ensure!(
                version.checked_add(1) == Some(transition.version)
                    && transition.previous == root
                    && transition.successor != root,
                "root transition is not the next dual-signed successor"
            );
            let message = transition.message(&policy.root.lineage)?;
            verify_signature(&message, &transition.previous_signature, &root)?;
            verify_signature(
                &message,
                &transition.successor_signature,
                &transition.successor,
            )?;
            root = transition.successor.clone();
            version = transition.version;
        }
        verify_signature(self.document.as_bytes(), &self.signature, &root)?;
        let delegation: KeyDelegation = serde_json::from_str(&self.document)?;
        delegation.validate()?;
        ensure!(
            delegation.root_version == version
                && delegation.distro == distro
                && delegation.channel == channel,
            "delegation root/distro/channel mismatch"
        );
        ensure!(
            !delegation
                .release_keys
                .iter()
                .chain(&delegation.index_keys)
                .any(|key| key.id().is_ok_and(|id| roots.contains(&id))),
            "root key cannot be an operational signer"
        );
        if let Some(now) = now {
            fresh(delegation.issued_at, delegation.expires_at, now)?;
        }
        Ok(VerifiedAuthority {
            delegation,
            digest: digest(self.document.as_bytes()),
        })
    }
}
impl VerifiedAuthority {
    pub fn delegation(&self) -> &KeyDelegation {
        &self.delegation
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn require_current(&self, now: u64) -> Result<()> {
        fresh(self.delegation.issued_at, self.delegation.expires_at, now)
    }
    pub fn verify(&self, role: SigningRole, bytes: &[u8], signature: &[u8]) -> Result<Trust> {
        for key in self.delegation.keys(role) {
            if verify_signature(bytes, signature, key).is_ok() {
                return Ok(key.clone());
            }
        }
        anyhow::bail!("signature is not authorized for the {role:?} role")
    }
    pub fn sign(
        &self,
        role: SigningRole,
        bytes: &[u8],
        private_key: &[u8],
        now: u64,
    ) -> Result<Vec<u8>> {
        self.require_current(now)?;
        for key in self.delegation.keys(role) {
            if let Ok(sig) = sign(bytes, private_key, key) {
                return Ok(sig);
            }
        }
        anyhow::bail!("private key is not authorized for the {role:?} role")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPart {
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
    pub url: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEntry {
    pub release: IndexEntry,
    pub parts: BTreeMap<String, Vec<TransportPart>>,
}
impl ProductionEntry {
    pub fn validate(&self, policy: &ProductionPolicy) -> Result<()> {
        ensure!(
            self.release.identity.architecture == Architecture::X86_64,
            "production release must be x86_64"
        );
        ensure!(
            self.parts.len() == 4,
            "transport must describe exactly four system artifacts"
        );
        for (name, parts) in &self.parts {
            relative(name)?;
            ensure!(
                name != AUTHORITY_FILE && !name.starts_with(&format!("{AUTHORITY_FILE}/")),
                "transport artifact collides with release authority"
            );
            ensure!(
                !parts.is_empty() && parts.len() <= MAX_PARTS,
                "invalid transport part count"
            );
            let mut offset = 0u64;
            for part in parts {
                ensure!(
                    part.offset == offset && part.size > 0 && part.size <= MAX_PART,
                    "non-contiguous or oversized transport part"
                );
                offset = offset
                    .checked_add(part.size)
                    .context("transport size overflow")?;
                hash(&part.sha256)?;
                policy.asset_url(&part.url)?;
            }
        }
        Ok(())
    }
    pub fn for_manifest(
        &self,
        manifest: &ReleaseManifest,
        policy: &ProductionPolicy,
    ) -> Result<()> {
        self.validate(policy)?;
        ensure!(
            self.release.identity == manifest.identity,
            "indexed release identity differs from manifest"
        );
        for artifact in manifest.artifacts.all() {
            let parts = self
                .parts
                .get(&artifact.path)
                .context("artifact is missing its signed transport")?;
            let end = parts.last().context("empty transport")?;
            ensure!(
                end.offset.checked_add(end.size) == Some(artifact.size),
                "transport size differs from system manifest"
            );
            if parts.len() == 1 {
                ensure!(
                    parts[0].sha256 == artifact.sha256,
                    "single-part digest differs from manifest"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndexV2 {
    pub schema_version: u32,
    pub sequence: u64,
    pub index_epoch: u64,
    pub channel: String,
    pub audience: Audience,
    pub issued_at: u64,
    pub expires_at: u64,
    pub releases: Vec<ProductionEntry>,
}
impl ReleaseIndexV2 {
    pub fn parse(bytes: &[u8], policy: &ProductionPolicy) -> Result<Self> {
        ensure!(
            bytes.len() <= super::MAX_MANIFEST,
            "release index exceeds bound"
        );
        let index: Self = serde_json::from_slice(bytes)?;
        index.validate(policy)?;
        Ok(index)
    }
    pub fn validate(&self, policy: &ProductionPolicy) -> Result<()> {
        policy.validate()?;
        ensure!(
            self.schema_version == 2 && self.index_epoch > 0 && self.audience == policy.audience,
            "production index version/audience mismatch"
        );
        window(self.issued_at, self.expires_at, MAX_INDEX_AGE)?;
        // Reuse the existing identity, duplicate-profile and metadata-path rules.
        super::ReleaseIndex {
            schema_version: 1,
            sequence: self.sequence,
            channel: self.channel.clone(),
            releases: self.releases.iter().map(|v| v.release.clone()).collect(),
        }
        .validate()?;
        for entry in &self.releases {
            entry.validate(policy)?;
        }
        Ok(())
    }
    pub fn authenticate(
        bytes: &[u8],
        signature: &[u8],
        authority: &VerifiedAuthority,
        policy: &ProductionPolicy,
        now: u64,
    ) -> Result<Self> {
        // Archived proofs authenticate cached bytes, not fresh online metadata.
        authority.require_current(now)?;
        authority.verify(SigningRole::Index, bytes, signature)?;
        let index = Self::parse(bytes, policy)?;
        ensure!(
            index.channel == authority.delegation.channel
                && index.index_epoch == authority.delegation.index_epoch,
            "index and delegation channel differ"
        );
        fresh(index.issued_at, index.expires_at, now)?;
        Ok(index)
    }
}

/// Floors are persisted by the reader before exposing newly authenticated data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackFloor {
    pub root_version: u64,
    pub authority_version: u64,
    pub authority_digest: String,
    #[serde(default)]
    pub index_epoch: u64,
    pub index_sequence: u64,
    pub index_digest: String,
    pub release: Option<(u64, String)>,
    pub signed_time: u64,
}
impl RollbackFloor {
    pub fn authority(&mut self, authority: &VerifiedAuthority) -> Result<()> {
        let d = authority.delegation();
        ensure!(
            d.root_version >= self.root_version && d.version >= self.authority_version,
            "delegation/root rollback refused"
        );
        ensure!(
            d.version != self.authority_version || self.authority_digest == authority.digest(),
            "delegation equivocation refused"
        );
        ensure!(
            d.index_epoch >= self.index_epoch,
            "index epoch rollback refused"
        );
        if d.index_epoch > self.index_epoch {
            // A root-authorized epoch recovers a poisoned metadata counter;
            // accepted system release floors and signed time are preserved.
            self.index_epoch = d.index_epoch;
            self.index_sequence = 0;
            self.index_digest.clear();
        }
        self.root_version = d.root_version;
        self.authority_version = d.version;
        self.authority_digest = authority.digest().into();
        Ok(())
    }
    pub fn index(&mut self, index: &ReleaseIndexV2, raw: &[u8], now: u64) -> Result<()> {
        let digest = digest(raw);
        ensure!(
            index.index_epoch == self.index_epoch,
            "index epoch differs from accepted root authorization"
        );
        ensure!(
            now.saturating_add(CLOCK_TOLERANCE) >= self.signed_time,
            "system clock moved behind accepted signed time"
        );
        ensure!(
            index.sequence >= self.index_sequence
                && (index.sequence != self.index_sequence || digest == self.index_digest),
            "index rollback/equivocation refused"
        );
        self.index_sequence = index.sequence;
        self.index_digest = digest;
        self.signed_time = self.signed_time.max(index.issued_at);
        Ok(())
    }
    pub fn release(&mut self, sequence: u64, id: &str) -> Result<()> {
        hash(id)?;
        if let Some((previous, digest)) = &self.release {
            ensure!(
                sequence >= *previous && (sequence != *previous || id == digest),
                "release rollback/equivocation refused"
            );
        }
        self.release = Some((sequence, id.into()));
        Ok(())
    }
}
