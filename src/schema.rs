//! The variant contract: these types are the shape of `distro/variants/<id>/distro.toml`.

use distro_profile::Profile;

use crate::registry::ProductId;
use serde::Deserialize;

/// The `schema_version` every `distro.toml` declares.
pub const CONTRACT_SCHEMA_VERSION: u32 = 12;

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

    /// An ISO product's file: the release product is
    /// `<os_id>-x86_64.iso`, a test product `<os_id>-x86_64-<product>.iso`.
    pub fn iso(&self, product: ProductId) -> String {
        if product == ProductId::Release {
            self.release_iso.clone()
        } else {
            format!("{}-{}.iso", self.iso_stem, product.name())
        }
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

/// The variant's default software set and what its group recipes are locked
/// and built from. The system image is the base alone; the default set is
/// installed through Recipe during the installation (recsetup's software
/// step), from the release medium, which carries these recipes and every
/// package they pin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopContract {
    /// The default set: group recipes of the public catalogue (`recipes/`,
    /// by name), installed into every target in this order by
    /// `recipe --system --root <target> install`; their `deps` come with them.
    pub recipes: Vec<String>,
    /// Downloads the desktop lock: every package the group recipes' seeds
    /// need beyond the base lock (`cargo xtask base lock` resolves them; `base
    /// groups` shares them out into the recipes' pins). The release medium's
    /// package cache is filled from what it downloads.
    pub preseed_recipe_script: String,
    /// What compiling the desktop apps (`tools/gui/`) needs from the base
    /// release beside the base packages: the compiler, CMake and Qt's
    /// development files. `cargo xtask base lock` locks their dependencies
    /// minus the base lock's packages in the apps-build lock, in the same run
    /// as the desktop lock, so both name the same Qt. None of these packages
    /// is in an image; the compiled apps are published as a prebuilt tree that
    /// the `rec-apps` recipe pins.
    pub apps_build_packages: Vec<String>,
    /// Downloads the apps-build lock's packages.
    pub apps_build_preseed_recipe_script: String,
    /// Makes the root the desktop apps are compiled in: the base lock's and
    /// the apps-build lock's packages as one root image.
    pub apps_build_root_recipe_script: String,
    /// A display server compiled from source instead of taken from a
    /// package: the OS recipe that compiles it in the apps-build root, whose
    /// tree the builder publishes as the prebuilt family `display-server`.
    /// AcornOS names XLibre here (Alpine has no package for it).
    #[serde(default)]
    pub display_server_recipe_script: Option<String>,
}

/// One mode's colours, each `#RRGGBB`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Palette {
    pub surface: String,
    pub surface_raised: String,
    pub surface_sunken: String,
    pub text: String,
    pub text_secondary: String,
    pub text_muted: String,
    pub rule: String,
    pub hairline: String,
    pub accent: String,
    pub highlight: String,
    pub band: String,
    pub on_band: String,
    pub ok: String,
    pub warn: String,
    pub bad: String,
}

/// A variant's colours in both modes; the mode it starts in is
/// `profile.appearance`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LookContract {
    pub light: Palette,
    pub dark: Palette,
}

/// A variant's whole contract: the shape of its `distro.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub identity: DistroIdentity,
    /// The base facts the variant differs in.
    pub profile: Profile,
    /// The colours in each mode.
    pub look: LookContract,
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
/// recab is one: the A/B boot step puts it into an A/B target from here.
pub const INSTALL_TOOLS: &[&str] = &["recpart", "recstrap", "recfstab", "recchroot", "recsetup", "recab"];

/// Every file of the recab desktop app, as the compiled desktop apps' tree
/// holds them. Only an A/B system has the app: the release medium carries
/// these files in recsetup's A/B-only tree (`install_tools::AB_ONLY_TREE`,
/// at these paths below it), and the A/B boot step copies them into the
/// target. A mutable install never has them.
pub const AB_DESKTOP_APP_FILES: &[&str] = &[
    "usr/bin/recab-gui",
    "usr/share/applications/org.levitateos.recab.desktop",
    "usr/share/icons/hicolor/scalable/apps/org.levitateos.recab.svg",
    "usr/share/polkit-1/actions/org.levitateos.recab.policy",
];

impl ConformanceContract {
    /// The init system's units every live boot runs: sshd. (NetworkManager
    /// comes with the `network` group the live overlay carries, whose own
    /// configuration enables it.)
    pub fn live_service_units(&self) -> Vec<String> {
        vec!["sshd".to_string()]
    }

    /// The commands every installed system has, A/B or mutable: its privilege
    /// tool and every system's commands. An A/B install also has recab, which
    /// its boot step puts there.
    pub fn installed_tools(&self) -> Vec<String> {
        std::iter::once(self.profile.privilege.as_str())
            .chain(system_commands())
            .map(|tool| tool.to_string())
            .collect()
    }

    /// The commands the test-install-base ISO has: the install tools, then the
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
