//! The variant contract: these types are the shape of `distro/variants/<id>/distro.toml`.

use std::collections::BTreeMap;

use distro_profile::{InitSystem, Profile};

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
    /// The installed system's own initramfs, which the ISO carries, when the
    /// variant's installed system boots through one (`installed.initramfs`).
    pub initramfs_installed: Option<String>,
    pub live_uki: LiveUkis,
    /// The name an ISO is published under: `<os_id>-x86_64.iso`.
    pub release_iso: String,
    /// `<os_id>-x86_64`.
    iso_stem: String,
}

impl ArtifactNames {
    pub(crate) fn derive(os_id: &str, installed_initramfs: bool) -> Self {
        let iso_stem = format!("{os_id}-x86_64");
        Self {
            rootfs: "filesystem.erofs".to_string(),
            overlay: "overlayfs.erofs".to_string(),
            initramfs_live: "initramfs-live.cpio.gz".to_string(),
            initramfs_installed: installed_initramfs.then(|| "initramfs-installed.img".to_string()),
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

/// How the rootfs source is acquired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsSourceKind {
    /// A locked set of RPMs from a Fedora release and its updates (`rpm_base`).
    RecipeRpmSet,
    RecipeCustom,
}

/// The RPMs a `recipe_rpm_set` rootfs takes from its Fedora base. The exact
/// builds are locked by `cargo xtask base lock`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpmBaseContract {
    pub fedora_release: u32,
    /// The release's RPM signing key, relative to the variant directory.
    pub signing_key: String,
    pub packages: Vec<String>,
}

/// Filesystem kinds required by a recipe consumer's named output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeOutputKind {
    File,
    Directory,
}

/// Rootfs source policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsSourceContract {
    pub storage_max_objects: Option<u64>,
    pub memory_mib: Option<u64>,
    pub preseed_memory_mib: Option<u64>,
    #[serde(default)]
    pub network_hosts: Vec<String>,
    #[serde(default)]
    pub preseed_network_hosts: Vec<String>,
    /// Recipe inputs by name: repo-relative files.
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
    pub kind: RootfsSourceKind,
    pub recipe_script: String,
    pub preseed_recipe_script: Option<String>,
    #[serde(default)]
    pub preseed_outputs: BTreeMap<String, RecipeOutputKind>,
    #[serde(default)]
    pub defines: BTreeMap<String, String>,
    pub rpm_base: Option<RpmBaseContract>,
}

/// Source ownership.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceContract {
    pub rootfs_source: RootfsSourceContract,
}

/// The live ISO's install screen: a shell beside the install docs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallUxContract {
    /// Consoles whose getty starts the install screen (`tty1`, `ttyS0`). A serial
    /// console runs it only when the boot asks for it; otherwise it gets the shell.
    pub consoles: Vec<String>,
    /// Absolute path of the shell beside the docs, and of the login shell that
    /// takes over when the install screen ends.
    pub shell: String,
    pub docs: InstallDocs,
    /// TUI apps under `tui/apps`, by name, that the live ISO carries besides the docs
    /// app: each is a command on PATH, for the shell beside the docs.
    #[serde(default)]
    pub apps: Vec<String>,
    /// The TUI app the install screen runs in place of the bare shell (it opens the
    /// shell itself on request), by name; it ships like the other apps.
    pub hub: Option<String>,
}

/// The docs the install screen shows: a TUI app under `tui/apps`, by its `bin` name,
/// started with `args` and opened at `page` (with the flag its manifest's
/// `inspect.pages.arg` names) or at its first page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallDocs {
    pub app: String,
    pub page: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

/// A service the live system runs besides the installed system's (the live
/// system is the installed rootfs plus the live overlay, so it runs what the
/// installed system runs: time sync, audit, D-Bus, the network). Every live
/// system runs sshd; the init system names the units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveService {
    Ssh,
    Network,
}

impl LiveService {
    /// The units (systemd) or services (OpenRC) that provide it.
    pub fn units(self, init: InitSystem) -> &'static [&'static str] {
        match (self, init) {
            (Self::Ssh, _) => &["sshd"],
            (Self::Network, InitSystem::Systemd) => &["NetworkManager"],
            (Self::Network, InitSystem::Openrc) => &["networking", "dhcpcd"],
        }
    }
}

/// What the live system has that the shared lists do not give every variant.
/// Each list holds only this variant's additions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveContract {
    /// Services the live system runs besides sshd.
    #[serde(default)]
    pub services: Vec<LiveService>,
    /// Kernel command line tokens of every live boot besides the shared ones
    /// and the init system's.
    #[serde(default)]
    pub kernel_cmdline: Vec<String>,
}

/// How the installed system differs from every variant's.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledContract {
    /// The installed system boots through its own initramfs, built from the
    /// rootfs it installs (`initramfs-installed.img`, which the ISO carries).
    pub initramfs: bool,
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
    pub install_ux: InstallUxContract,
    pub live: LiveContract,
    pub installed: InstalledContract,
    /// Derived from `identity` and `installed` when the contract loads.
    #[serde(skip)]
    pub artifacts: ArtifactNames,
}

/// Kernel command line tokens of every live boot of every variant. `audit=1`
/// keeps the audit trail from the first process; `inst.sshd=0` keeps
/// Anaconda's sshd off port 22 where its unit exists.
pub const LIVE_KERNEL_CMDLINE: &[&str] = &["console=ttyS0,115200n8", "console=tty0", "audit=1", "inst.sshd=0"];

/// What every system provides, live and installed, on every variant:
/// `capabilities.txt`, which the rootfs producers also read.
const CAPABILITIES: &str = include_str!("../capabilities.txt");

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

/// The live kernel command line every variant of `init` has: the shared
/// tokens, then the init system's.
pub(crate) fn shared_live_cmdline(init: InitSystem) -> impl Iterator<Item = &'static str> {
    let init_tokens: &[&str] = match init {
        InitSystem::Systemd => &["systemd.show_status=0", "rd.systemd.show_status=0"],
        InitSystem::Openrc => &[],
    };
    LIVE_KERNEL_CMDLINE.iter().chain(init_tokens).copied()
}

impl ConformanceContract {
    /// The services every live boot runs: sshd, then the variant's.
    pub fn live_services(&self) -> Vec<LiveService> {
        std::iter::once(LiveService::Ssh)
            .chain(self.live.services.iter().copied())
            .collect()
    }

    /// The init system's units for `live_services`, sorted.
    pub fn live_service_units(&self) -> Vec<String> {
        let mut units: Vec<String> = self
            .live_services()
            .into_iter()
            .flat_map(|service| service.units(self.profile.init))
            .map(|unit| unit.to_string())
            .collect();
        units.sort();
        units
    }

    /// Every live boot's kernel command line: the shared tokens, the init
    /// system's, then the variant's.
    pub fn live_kernel_cmdline(&self) -> Vec<String> {
        shared_live_cmdline(self.profile.init)
            .map(|token| token.to_string())
            .chain(self.live.kernel_cmdline.iter().cloned())
            .collect()
    }

    /// The commands the installed system has: its privilege tool, the update
    /// tools and every system's commands.
    pub fn installed_tools(&self) -> Vec<String> {
        std::iter::once(self.profile.privilege.as_str())
            .chain(UPDATE_TOOLS.iter().copied())
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
