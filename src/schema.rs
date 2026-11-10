//! The variant contract: these types are the shape of `distro/variants/<id>/distro.toml`.

use distro_profile::Profile;

use crate::registry::ProductId;
use serde::Deserialize;

/// The `schema_version` every `distro.toml` declares.
pub const CONTRACT_SCHEMA_VERSION: u32 = 8;

/// Identity metadata for a distro contract.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistroIdentity {
    pub os_name: String,
    pub os_id: String,
    /// `os_id` in capitals; derived when the contract loads (not in the file).
    #[serde(skip)]
    pub iso_label: String,
    pub os_version: String,
    /// The OS's website (os-release `HOME_URL`, and the browser's homepage);
    /// an OS without one of its own leaves it out.
    #[serde(default)]
    pub home_url: Option<String>,
    /// `os_id`; derived when the contract loads (not in the file).
    #[serde(skip)]
    pub default_hostname: String,
    /// `<default_hostname> login:`, the installed system's login prompt; derived
    /// when the contract loads (not in the file).
    #[serde(skip)]
    pub login_prompt: String,
}

/// The live UKIs, by role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveUkis {
    /// The default boot entry.
    pub live: String,
    /// Boots to the live init's emergency shell.
    pub emergency: String,
    /// Boots with the live init's debug output.
    pub debug: String,
}

/// The file names of a variant's build outputs, derived from `os_id` when the
/// contract loads (not in the file).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactNames {
    pub rootfs: String,
    pub overlay: String,
    pub initramfs_live: String,
    /// The installed system's own initramfs, which the ISO carries.
    pub initramfs_installed: String,
    pub live_uki: LiveUkis,
    /// The name an ISO is published under: `<os_id>-x86_64.iso`.
    pub release_iso: String,
    /// `<os_id>-x86_64`.
    iso_stem: String,
}

impl ArtifactNames {
    pub(crate) fn derive(os_id: &str) -> Self {
        let iso_stem = format!("{os_id}-x86_64");
        Self {
            rootfs: "filesystem.erofs".to_string(),
            overlay: "overlayfs.erofs".to_string(),
            initramfs_live: "initramfs-live.cpio.gz".to_string(),
            initramfs_installed: "initramfs-installed.img".to_string(),
            live_uki: LiveUkis {
                live: format!("{os_id}-live.efi"),
                emergency: format!("{os_id}-emergency.efi"),
                debug: format!("{os_id}-debug.efi"),
            },
            release_iso: format!("{iso_stem}.iso"),
            iso_stem,
        }
    }

    /// A release product's ISO: `<os_id>-x86_64-<product>.iso`.
    pub fn iso(&self, product: ProductId) -> String {
        format!("{}-{}.iso", self.iso_stem, product.name())
    }
}

/// What the rootfs takes from its base distribution, the same shape for
/// every package backend (`profile.packages`). `cargo xtask base lock
/// <distro>` resolves the packages and their dependencies from the release
/// into the backend's lock, which the rootfs recipes import.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageBaseContract {
    /// The release: Fedora's number (`45`) or Alpine's branch (`v3.24`).
    pub release: String,
    /// The key the release signs its packages with, relative to the variant
    /// directory.
    pub signing_key: String,
    /// What the system wants. Both locks add the dependencies (requires and
    /// provides), so only the top-level packages are named.
    pub packages: Vec<String>,
    /// Capabilities the image supplies itself, so the rpm lock does not pull
    /// a package for them (Fedora's `system-release` would add fedora-release,
    /// which ships its own os-release).
    #[serde(default)]
    pub provided_elsewhere: Vec<String>,
}

/// Rootfs source policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsSourceContract {
    pub recipe_script: String,
    /// Downloads the base's locked packages.
    pub preseed_recipe_script: String,
    pub base: PackageBaseContract,
}

/// Source ownership.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceContract {
    pub rootfs_source: RootfsSourceContract,
}

/// The graphical desktop of the desktop system, the rootfs of the
/// `live-desktop` product (`profile.desktop` names which: Plasma or LXQt).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopContract {
    /// What the desktop wants from the base release, beside the base
    /// packages. `cargo xtask base lock` locks their dependencies minus the
    /// base lock's packages in the desktop lock.
    pub packages: Vec<String>,
    /// The display manager's unit (systemd) or service (OpenRC); the desktop
    /// system enables it and boots to the graphical target.
    pub display_manager: String,
    /// Downloads the desktop lock's packages, which the rootfs recipe
    /// installs over the base lock's when it builds the desktop system.
    pub preseed_recipe_script: String,
}

/// A variant's whole contract: the shape of its `distro.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub identity: DistroIdentity,
    /// The base facts the variant differs in.
    pub profile: Profile,
    pub sources: SourceContract,
    pub desktop: DesktopContract,
    /// Derived from `identity` when the contract loads.
    #[serde(skip)]
    pub artifacts: ArtifactNames,
}

/// What every system provides, live and installed, on every variant:
/// `capabilities.txt`, which the rootfs producers also read.
const CAPABILITIES: &str = include_str!("../capabilities.txt");

/// `capabilities.txt` itself: the rootfs recipes' `capabilities` input.
pub fn capabilities_text() -> &'static str {
    CAPABILITIES
}

fn capabilities(kind: &'static str) -> impl Iterator<Item = &'static str> {
    CAPABILITIES.lines().filter_map(move |line| {
        let (entry, name) = line.trim().split_once(' ')?;
        (entry == kind).then(|| name.trim())
    })
}

/// The commands every system's rootfs has (`command` in `capabilities.txt`).
pub fn system_commands() -> impl Iterator<Item = &'static str> {
    capabilities("command")
}

/// The UTF-8 locales every system has (`locale` in `capabilities.txt`), as
/// `<language>_<TERRITORY>`.
pub fn locales() -> impl Iterator<Item = &'static str> {
    capabilities("locale")
}

/// The install tools the live ISO adds to the installed system's commands.
pub const INSTALL_TOOLS: &[&str] = &["recpart", "recstrap", "recfstab", "recchroot", "recsetup"];

/// The workspace tools the installed system has (A/B updates).
pub const UPDATE_TOOLS: &[&str] = &["recab", "recstrap"];

/// The TUI apps (under `tui/apps`, by `bin` name) the installed system carries as
/// commands, on every distro; the builder compiles them into the system rootfs.
pub const SYSTEM_TUI_APPS: &[&str] = &["recab-tui"];

impl ConformanceContract {
    /// The init system's units every live boot runs: sshd. (NetworkManager and
    /// the rest are the installed system's, which `installed-system.rhai`
    /// enables.)
    pub fn live_service_units(&self) -> Vec<String> {
        vec!["sshd".to_string()]
    }

    /// The commands the installed system has: its privilege tool, the update
    /// tools, its TUI apps and every system's commands.
    pub fn installed_tools(&self) -> Vec<String> {
        std::iter::once(self.profile.privilege.as_str())
            .chain(UPDATE_TOOLS.iter().copied())
            .chain(SYSTEM_TUI_APPS.iter().copied())
            .chain(system_commands())
            .map(|tool| tool.to_string())
            .collect()
    }

    /// The commands the live-tools ISO has: the install tools, then the
    /// installed system's.
    pub fn live_tools(&self) -> Vec<String> {
        let installed = self.installed_tools();
        INSTALL_TOOLS
            .iter()
            .map(|tool| tool.to_string())
            .filter(|tool| !installed.contains(tool))
            .chain(installed.iter().cloned())
            .collect()
    }
}
