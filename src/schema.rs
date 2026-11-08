//! The variant contract: these types are the shape of `distro/variants/<id>/distro.toml`.

use std::collections::BTreeMap;

use distro_profile::Profile;
use serde::Deserialize;

/// The `schema_version` every `distro.toml` declares.
pub const CONTRACT_SCHEMA_VERSION: u32 = 7;

/// Automated login policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Automated login uses deterministic distro-provided credentials.
    DefaultPasswordLogin,
    /// Automated login credentials are provisioned out-of-band.
    ProvisionedCredentials,
}

/// Runtime-policy rootfs model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsMutability {
    /// Writable install model.
    Mutable,
    /// Read-only/immutable install model.
    Immutable,
}

/// A scenario's on-ISO script and the marker its output must contain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptEvidence {
    /// On-ISO scenario script filename (for example `live-tools.sh`).
    pub script_path: String,
    /// Marker the script prints when it passes: its name in capitals plus `PASSED`.
    pub pass_marker: String,
}

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
}

/// Artifact names, derived from the transforms when the contract loads (not in the file).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactIdentity {
    pub rootfs_name: String,
    pub initramfs_live_output: String,
    pub iso_filename: String,
    pub initramfs_installed_output: Option<String>,
    pub installed_uki_outputs: Vec<String>,
    pub disk_image_output: Option<String>,
}

/// What the variant pins about its build: the kernel. The kernel's
/// configuration is `kconfig` beside `distro.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildContract {
    pub kernel: KernelBuildContract,
}

/// Kernel source pin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelBuildContract {
    pub version: String,
    pub sha256: String,
    /// `CONFIG_LOCALVERSION` of `kconfig`: `-` and the variant id; derived when
    /// the contract loads (not in the file).
    #[serde(skip)]
    pub localversion: String,
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

/// Product declaration with a stable logical identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductDecl {
    pub logical_name: String,
    pub description: String,
    /// Immediate parent product in the product composition DAG, if any.
    pub extends: Option<String>,
}

/// The products a variant builds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductContract {
    pub rootfs_base: ProductDecl,
    pub live_overlay: ProductDecl,
    pub boot_live: ProductDecl,
    pub live_tools: ProductDecl,
    pub boot_installed: Option<ProductDecl>,
    pub kernel_staging: ProductDecl,
}

/// One step that shapes a boot payload from the rootfs (paths are relative
/// to the rootfs and the payload).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PayloadProducerContract {
    CopyTree {
        source: String,
        destination: String,
    },
    CopySymlink {
        source: String,
        destination: String,
    },
    CopyFile {
        source: String,
        destination: String,
        #[serde(default)]
        optional: bool,
    },
    WriteText {
        path: String,
        content: String,
        mode: Option<u32>,
    },
}

/// A boot payload's producers, in order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootPayloadContract {
    pub producers: Vec<PayloadProducerContract>,
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

/// A workspace binary the live-tools product carries, built for the
/// profile's libc.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeActionContract {
    ToolPayloadWorkspaceBinary {
        package: String,
        binary: Option<String>,
    },
    RootfsWorkspaceBinary {
        package: String,
        binary: Option<String>,
        /// Path in the rootfs.
        destination: String,
    },
}

/// How the builder assembles the products.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductConfigContract {
    pub boot_live: BootPayloadContract,
    /// Present exactly when `products.boot_installed` is.
    pub boot_installed: Option<BootPayloadContract>,
    #[serde(default)]
    pub live_tools_actions: Vec<RuntimeActionContract>,
    pub install_ux: InstallUxContract,
}

/// Artifact transform declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTransform {
    pub logical_name: String,
    /// Immediate dependency identities in the build graph: product or
    /// upstream artifact logical names.
    pub dependencies: Vec<String>,
    pub output_names: Vec<String>,
    pub format: String,
    pub extra_cmdline: Option<String>,
}

impl ArtifactTransform {
    /// The transform's output file name (validation guarantees exactly one,
    /// except for the UKI transforms).
    pub fn output(&self) -> &str {
        &self.output_names[0]
    }
}

/// The artifacts built from the products.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformContract {
    pub rootfs_image: ArtifactTransform,
    pub overlay_image: ArtifactTransform,
    pub initramfs_live: ArtifactTransform,
    pub initramfs_installed: Option<ArtifactTransform>,
    /// Outputs in order: live, emergency, debug.
    pub live_uki: ArtifactTransform,
    pub installed_uki: Option<ArtifactTransform>,
    pub iso: ArtifactTransform,
    pub disk_image: Option<ArtifactTransform>,
}

/// Validation and runtime scenarios (not build-graph owners).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioContract {
    pub live_boot: BootScenario,
    pub live_environment: LiveEnvironmentScenario,
    pub live_tools: LiveToolsScenario,
    pub install: InstallScenario,
    pub installed_boot: BootScenario,
    pub automated_login: AutomatedLoginScenario,
    pub installed_tools: ToolsScenario,
    pub runtime_policy: RuntimePolicyScenario,
}

/// Release outputs and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseContract {
    /// The ISO output, then the disk image output if there is one.
    pub primary_outputs: Vec<String>,
    pub supporting_artifacts: Vec<String>,
    pub metadata_outputs: Vec<String>,
    pub metadata_facts: Vec<String>,
}

/// Boot-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootScenario {
    /// Console lines that mean the boot succeeded (the serial test protocol's
    /// readiness marker always does).
    pub success_patterns: Vec<String>,
    /// Console lines that mean the boot failed.
    pub fatal_patterns: Vec<String>,
    /// Console lines that report a failed service: recorded, not fatal.
    #[serde(default)]
    pub service_failure_patterns: Vec<String>,
    /// Required kernel cmdline tokens for booting this scenario.
    pub required_kernel_cmdline: Vec<String>,
    /// Required live services that must be available in this scenario.
    pub required_live_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Shared live-environment service requirements.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveEnvironmentScenario {
    pub required_services: Vec<String>,
}

/// Tool-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsScenario {
    pub required_tools: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Live-tools scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveToolsScenario {
    pub required_tools: Vec<String>,
    /// Serial console lines that mean the live system is up when the serial
    /// console runs the install UX instead of a shell (login prompt, issue).
    #[serde(default)]
    pub serial_ready_patterns: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Install-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallScenario {
    pub required_tools: Vec<String>,
    pub required_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Automated-login scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomatedLoginScenario {
    pub auth_mode: AuthMode,
    pub default_username: Option<String>,
    pub default_password: Option<String>,
    /// `<os_id> login:`; derived when the contract loads (not in the file).
    #[serde(skip)]
    pub login_prompt_pattern: String,
    pub evidence: ScriptEvidence,
}

/// Runtime-policy scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicyScenario {
    pub rootfs_mutability: RootfsMutability,
    pub mutable_required_rw_paths: Vec<String>,
    pub immutable_required_ro_paths: Vec<String>,
}

/// A variant's whole contract: the shape of its `distro.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub identity: DistroIdentity,
    /// The base facts the variant differs in.
    pub profile: Profile,
    pub build: BuildContract,
    pub sources: SourceContract,
    pub products: ProductContract,
    pub product_config: ProductConfigContract,
    pub transforms: TransformContract,
    pub scenarios: ScenarioContract,
    pub release: ReleaseContract,
    /// Derived from `transforms` when the contract loads.
    #[serde(skip)]
    pub artifacts: ArtifactIdentity,
}
