//! The products a variant builds and the scenarios that test them, each named
//! once. The builder, xtask and install-tests read these; none spells a
//! product or scenario name of its own.

use distro_profile::Flavour;

/// A product: its flavour's system tree plus an overlay, which the builder
/// prepares and, for a release product, combines into a bootable ISO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProductId {
    TestBaseRootfs,
    TestLiveSsh,
    TestInstallBase,
    Release,
    TestInstalledBoot,
}

impl ProductId {
    /// Every product. Each is its flavour's system plus an overlay; the
    /// builder makes both as cached parts, so no product is built on another.
    pub const ALL: [ProductId; 5] = [
        ProductId::TestBaseRootfs,
        ProductId::TestLiveSsh,
        ProductId::TestInstallBase,
        ProductId::Release,
        ProductId::TestInstalledBoot,
    ];

    /// The name the CLIs take, and the product's release directory.
    pub fn name(self) -> &'static str {
        match self {
            Self::TestBaseRootfs => "test-base-rootfs",
            Self::TestLiveSsh => "test-live-ssh",
            Self::TestInstallBase => "test-install-base",
            Self::Release => "release",
            Self::TestInstalledBoot => "test-installed-boot",
        }
    }

    /// How the product is called in boot banners and boot menus.
    pub fn title(self) -> &'static str {
        match self {
            Self::TestBaseRootfs => "Test Base Rootfs",
            Self::TestLiveSsh => "Test Live SSH",
            Self::TestInstallBase => "Test Install Base",
            Self::Release => "Release",
            Self::TestInstalledBoot => "Test Installed Boot",
        }
    }

    /// The system the product's rootfs is, and so what an ISO of it
    /// installs and recab stages from it: the base system, or the base
    /// system with the variant's desktop (`[desktop]` of its contract).
    pub fn flavour(self) -> Flavour {
        match self {
            Self::Release => Flavour::Desktop,
            _ => Flavour::Base,
        }
    }

    /// Whether the product is built into an ISO; test-installed-boot is
    /// only prepared.
    pub fn is_iso(self) -> bool {
        self != Self::TestInstalledBoot
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|product| product.name() == name)
    }

    /// The products built into an ISO.
    pub fn iso_products() -> impl Iterator<Item = ProductId> {
        Self::ALL.into_iter().filter(|product| product.is_iso())
    }

    /// The scenarios whose input includes this product's ISO, in run order.
    pub fn scenarios(self) -> impl Iterator<Item = ScenarioId> {
        ScenarioId::ALL
            .into_iter()
            .filter(move |scenario| scenario.input().iso == Some(self))
    }

    /// The scenario to run after building this product: the first that
    /// takes its ISO.
    pub fn next_scenario(self) -> Option<ScenarioId> {
        self.scenarios().next()
    }

    /// `test-base-rootfs | test-live-ssh | ...` over `products`.
    pub fn list(products: impl IntoIterator<Item = ProductId>) -> String {
        products
            .into_iter()
            .map(ProductId::name)
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

impl std::fmt::Display for ProductId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What a scenario consumes. Scenarios run independently: each needs only
/// its inputs to exist, never another scenario's pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScenarioInput {
    /// The release product whose latest ISO the scenario uses.
    pub iso: Option<ProductId>,
    /// Whether it boots the disk of the latest successful install run.
    pub install_run: bool,
}

/// A named check of built products, run by install-tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScenarioId {
    BuildPreflight,
    TestLiveSsh,
    TestInstallBase,
    Install,
    TestInstalledBoot,
    AutomatedLogin,
    Runtime,
    OtherRoot,
    DesktopBoot,
}

impl ScenarioId {
    /// Every scenario, in run order. Every variant has every scenario;
    /// `test all` runs those [`in_test_all`](Self::in_test_all).
    pub const ALL: [ScenarioId; 9] = [
        ScenarioId::BuildPreflight,
        ScenarioId::TestLiveSsh,
        ScenarioId::TestInstallBase,
        ScenarioId::Install,
        ScenarioId::TestInstalledBoot,
        ScenarioId::AutomatedLogin,
        ScenarioId::Runtime,
        ScenarioId::OtherRoot,
        ScenarioId::DesktopBoot,
    ];

    /// The name the CLIs take, and the scenario's state and output key.
    pub fn key(self) -> &'static str {
        match self {
            Self::BuildPreflight => "build-preflight",
            Self::TestLiveSsh => "test-live-ssh",
            Self::TestInstallBase => "test-install-base",
            Self::Install => "install",
            Self::TestInstalledBoot => "test-installed-boot",
            Self::AutomatedLogin => "automated-login",
            Self::Runtime => "runtime",
            Self::OtherRoot => "other-root",
            Self::DesktopBoot => "desktop-boot",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::BuildPreflight => "Build Preflight",
            Self::TestLiveSsh => "Test Live SSH",
            Self::TestInstallBase => "Test Install Base",
            Self::Install => "Install",
            Self::TestInstalledBoot => "Test Installed Boot",
            Self::AutomatedLogin => "Automated Login",
            Self::Runtime => "Runtime",
            Self::OtherRoot => "Other Root",
            Self::DesktopBoot => "Desktop Boot",
        }
    }

    /// What the scenario checks, in a line.
    pub fn summary(self) -> &'static str {
        match self {
            Self::BuildPreflight => {
                "the test-base-rootfs ISO and the kernel match the contract, before any VM"
            }
            Self::TestLiveSsh => "the test-live-ssh ISO boots and takes an SSH login",
            Self::TestInstallBase => "the test-install-base ISO has its tools and its install screen",
            Self::Install => {
                "the selected base/desktop installer ISO installs the chosen layout; an A/B install has root B a copy of root A, A the boot default and the recab-started service enabled, a mutable install has no recab"
            }
            Self::TestInstalledBoot => "the installed disk boots",
            Self::AutomatedLogin => "root logs in on the installed system",
            Self::Runtime => {
                "the installed tools execute a native Recipe/Ginux worker without activating system packages"
            }
            Self::OtherRoot => {
                "on an A/B install, a change written into the unlocked other root boots with boot-other and becomes the default after it started; copy makes the roots equal; an other root that does not finish starting falls back to the previous root"
            }
            Self::DesktopBoot => {
                "the release ISO boots to the installer with the desktop system and apps it installs"
            }
        }
    }

    /// Installed checks select the exact requested system flavour; live-only
    /// scenarios retain the product whose capability they explicitly exercise.
    pub fn input_for(self, flavour: Flavour) -> ScenarioInput {
        if flavour == Flavour::Desktop && matches!(self, Self::Install | Self::BuildPreflight) {
            ScenarioInput {
                iso: Some(ProductId::Release),
                install_run: false,
            }
        } else {
            self.input()
        }
    }
    pub fn input(self) -> ScenarioInput {
        let iso = |product| ScenarioInput {
            iso: Some(product),
            install_run: false,
        };
        match self {
            Self::BuildPreflight => iso(ProductId::TestBaseRootfs),
            Self::TestLiveSsh => iso(ProductId::TestLiveSsh),
            Self::TestInstallBase | Self::Install => iso(ProductId::TestInstallBase),
            Self::DesktopBoot => iso(ProductId::Release),
            Self::TestInstalledBoot | Self::AutomatedLogin | Self::Runtime | Self::OtherRoot => {
                ScenarioInput {
                    iso: None,
                    install_run: true,
                }
            }
        }
    }

    /// Whether `cargo xtask run` can boot the scenario's input for you: a
    /// scenario that only boots its input, an ISO or the installed disk.
    pub fn is_runnable(self) -> bool {
        matches!(
            self,
            Self::TestLiveSsh | Self::TestInstallBase | Self::TestInstalledBoot | Self::DesktopBoot
        )
    }

    /// Whether `test all` runs the scenario. desktop-boot does not: its
    /// input, the release ISO, is a build of its own (the desktop's
    /// packages, a 2.6 GB tree, about 6 GiB of build memory) that the base
    /// loop never makes, so `test all` would always report it missing. It
    /// runs by name: `cargo xtask test desktop-boot <distro>`.
    pub fn in_test_all(self) -> bool {
        self != Self::DesktopBoot
    }
}

impl std::fmt::Display for ScenarioId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.key())
    }
}
