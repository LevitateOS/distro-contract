//! The products a variant builds and the scenarios that test them, each named
//! once. The builder, xtask and install-tests read these; none spells a
//! product or scenario name of its own.

use distro_profile::Flavour;

/// A product: a rootfs tree plus layers, which the builder prepares and,
/// for a release product, assembles into a bootable ISO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProductId {
    BaseRootfs,
    LiveBoot,
    LiveTools,
    LiveDesktop,
    InstalledBoot,
}

impl ProductId {
    /// Every product, parents before the products built on them.
    pub const ALL: [ProductId; 5] = [
        ProductId::BaseRootfs,
        ProductId::LiveBoot,
        ProductId::LiveTools,
        ProductId::LiveDesktop,
        ProductId::InstalledBoot,
    ];

    /// The name the CLIs take, and the product's release directory.
    pub fn name(self) -> &'static str {
        match self {
            Self::BaseRootfs => "base-rootfs",
            Self::LiveBoot => "live-boot",
            Self::LiveTools => "live-tools",
            Self::LiveDesktop => "live-desktop",
            Self::InstalledBoot => "installed-boot",
        }
    }

    /// How the product is called in boot banners and boot menus.
    pub fn title(self) -> &'static str {
        match self {
            Self::BaseRootfs => "Base Rootfs",
            Self::LiveBoot => "Live Boot",
            Self::LiveTools => "Live Tools",
            Self::LiveDesktop => "Live Desktop",
            Self::InstalledBoot => "Installed Boot",
        }
    }

    /// The system the product's rootfs is, and so what an ISO of it
    /// installs and recab stages from it: the base system, or the base
    /// system with the variant's desktop (`[desktop]` of its contract).
    pub fn flavour(self) -> Flavour {
        match self {
            Self::LiveDesktop => Flavour::Desktop,
            _ => Flavour::Base,
        }
    }

    /// The product whose rootfs this one starts from, unchanged. A product
    /// without one builds the system of its [`flavour`](Self::flavour) from
    /// the variant's rootfs recipe: base-rootfs the base system, live-desktop
    /// the desktop system (the base and desktop locks in one tree, so the
    /// desktop packages' setup runs over the whole system). A parent always
    /// has its child's flavour.
    pub fn parent(self) -> Option<ProductId> {
        match self {
            Self::BaseRootfs | Self::LiveDesktop => None,
            Self::LiveBoot | Self::InstalledBoot => Some(Self::BaseRootfs),
            Self::LiveTools => Some(Self::LiveBoot),
        }
    }

    /// Whether the product is built into a release ISO; installed-boot is
    /// only prepared.
    pub fn is_release(self) -> bool {
        self != Self::InstalledBoot
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|product| product.name() == name)
    }

    /// The release products.
    pub fn releases() -> impl Iterator<Item = ProductId> {
        Self::ALL.into_iter().filter(|product| product.is_release())
    }

    /// This product's ancestors, oldest first, then the product itself.
    pub fn chain(self) -> Vec<ProductId> {
        let mut chain = vec![self];
        while let Some(parent) = chain.last().and_then(|product| product.parent()) {
            chain.push(parent);
        }
        chain.reverse();
        chain
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

    /// `base-rootfs | live-boot | ...` over `products`.
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
    LiveBoot,
    LiveTools,
    Install,
    InstalledBoot,
    AutomatedLogin,
    Runtime,
    AbUpdate,
    DesktopBoot,
}

impl ScenarioId {
    /// Every scenario, in run order. Every variant has every scenario;
    /// `test all` runs those [`in_test_all`](Self::in_test_all).
    pub const ALL: [ScenarioId; 9] = [
        ScenarioId::BuildPreflight,
        ScenarioId::LiveBoot,
        ScenarioId::LiveTools,
        ScenarioId::Install,
        ScenarioId::InstalledBoot,
        ScenarioId::AutomatedLogin,
        ScenarioId::Runtime,
        ScenarioId::AbUpdate,
        ScenarioId::DesktopBoot,
    ];

    /// The name the CLIs take, and the scenario's state and output key.
    pub fn key(self) -> &'static str {
        match self {
            Self::BuildPreflight => "build-preflight",
            Self::LiveBoot => "live-boot",
            Self::LiveTools => "live-tools",
            Self::Install => "install",
            Self::InstalledBoot => "installed-boot",
            Self::AutomatedLogin => "automated-login",
            Self::Runtime => "runtime",
            Self::AbUpdate => "ab-update",
            Self::DesktopBoot => "desktop-boot",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::BuildPreflight => "Build Preflight",
            Self::LiveBoot => "Live Boot",
            Self::LiveTools => "Live Tools",
            Self::Install => "Install",
            Self::InstalledBoot => "Installed Boot",
            Self::AutomatedLogin => "Automated Login",
            Self::Runtime => "Runtime",
            Self::AbUpdate => "A/B Update",
            Self::DesktopBoot => "Desktop Boot",
        }
    }

    /// What the scenario checks, in a line.
    pub fn summary(self) -> &'static str {
        match self {
            Self::BuildPreflight => {
                "the base-rootfs ISO and the kernel match the contract, before any VM"
            }
            Self::LiveBoot => "the live-boot ISO boots and takes an SSH login",
            Self::LiveTools => "the live-tools ISO has its tools and its install screen",
            Self::Install => {
                "the live-tools ISO installs identical personalized A/B systems with both slots bootable"
            }
            Self::InstalledBoot => "the installed disk boots",
            Self::AutomatedLogin => "root logs in on the installed system",
            Self::Runtime => {
                "the installed tools execute a native Recipe/Ginux worker without activating system packages"
            }
            Self::AbUpdate => {
                "equivalent initial A/B systems, signed updates preserving X, metadata and independent profiles, failed/healthy trials both ways, reverse Y and measured write avoidance with retained boot logs"
            }
            Self::DesktopBoot => {
                "the live-desktop ISO boots into the desktop with no failed service and with its desktop apps"
            }
        }
    }

    pub fn input(self) -> ScenarioInput {
        let iso = |product| ScenarioInput {
            iso: Some(product),
            install_run: false,
        };
        match self {
            Self::BuildPreflight => iso(ProductId::BaseRootfs),
            Self::LiveBoot => iso(ProductId::LiveBoot),
            Self::LiveTools | Self::Install => iso(ProductId::LiveTools),
            Self::DesktopBoot => iso(ProductId::LiveDesktop),
            Self::InstalledBoot | Self::AutomatedLogin | Self::Runtime => ScenarioInput {
                iso: None,
                install_run: true,
            },
            // The install and an explicit --update-fixture ISO supply old/new
            // release inputs. Never restage the same latest ISO as an update.
            Self::AbUpdate => ScenarioInput {
                iso: None,
                install_run: true,
            },
        }
    }

    /// Whether `cargo xtask run` can boot the scenario's input for you: a
    /// scenario that only boots its input, an ISO or the installed disk.
    pub fn is_runnable(self) -> bool {
        matches!(
            self,
            Self::LiveBoot | Self::LiveTools | Self::InstalledBoot | Self::DesktopBoot
        )
    }

    /// Whether `test all` runs the scenario. desktop-boot does not: its
    /// input, the live-desktop ISO, is a build of its own (the desktop's
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
