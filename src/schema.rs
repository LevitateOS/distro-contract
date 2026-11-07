//! Conformance contract schema for distro ownership and scenario declarations.

use std::collections::BTreeMap;

/// Contract schema version enforced by validators.
pub const CONTRACT_SCHEMA_VERSION: u32 = 6;

/// Shared live-boot kernel cmdline invariants required across all distros.
pub const BOOT_REQUIRED_KERNEL_CMDLINE_BASE: &[&str] = &["audit=1", "inst.sshd=0"];

/// Shared live-boot services that must be present across all distros.
pub const BOOT_REQUIRED_LIVE_SERVICES_BASE: &[&str] = &["sshd"];

/// Automated login policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// Automated login uses deterministic distro-provided credentials.
    DefaultPasswordLogin,
    /// Automated login credentials are provisioned out-of-band.
    ProvisionedCredentials,
}

/// Runtime-policy rootfs model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootfsMutability {
    /// Writable install model.
    Mutable,
    /// Read-only/immutable install model.
    Immutable,
}

/// Shared script evidence declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptEvidence {
    /// On-ISO scenario script filename (for example `live-tools.sh`).
    pub script_path: String,
    /// Required PASS marker emitted by script output.
    pub pass_marker: String,
}

/// Identity metadata for a distro contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroIdentity {
    pub os_name: String,
    pub os_id: String,
    pub iso_label: String,
    pub os_version: String,
    pub default_hostname: String,
}

/// Artifact naming metadata used by release conformance checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIdentity {
    pub rootfs_name: String,
    pub initramfs_live_output: String,
    pub iso_filename: String,
    pub initramfs_installed_output: Option<String>,
    pub installed_uki_outputs: Vec<String>,
    pub disk_image_output: Option<String>,
}

/// Minimal build-system ownership model.
///
/// Captures build-host prerequisites and kernel ownership independently of
/// product composition and runtime scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildContract {
    pub required_build_tools: Vec<String>,
    pub kernel: KernelBuildContract,
    pub evidence: ScriptEvidence,
}

/// Kernel build/product declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBuildContract {
    pub kconfig_path: String,
    pub recipe_script: String,
    pub recipe_invocation: String,
    pub release_path: String,
    pub image_path: String,
    pub modules_path: String,
    pub version: String,
    pub sha256: String,
    pub localversion: String,
    pub module_install_path: String,
}

/// Ring 3 source acquisition kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootfsSourceKind {
    /// A locked set of RPMs from a Fedora release and its updates (`rpm_base`).
    RecipeRpmSet,
    RecipeCustom,
}

/// The RPMs a `recipe_rpm_set` rootfs takes from its Fedora base. The exact
/// builds are locked by `cargo xtask base lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmBaseContract {
    pub fedora_release: u32,
    /// The release's RPM signing key, relative to the variant directory.
    pub signing_key: String,
    pub packages: Vec<String>,
}

/// Filesystem kinds required by a recipe consumer's named output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipeOutputKind {
    File,
    Directory,
}

/// Canonical rootfs source policy declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsSourceContract {
    pub storage_max_objects: Option<u64>,
    pub memory_mib: Option<u64>,
    pub preseed_memory_mib: Option<u64>,
    pub network_hosts: Vec<String>,
    pub preseed_network_hosts: Vec<String>,
    pub inputs: BTreeMap<String, String>,
    pub kind: RootfsSourceKind,
    pub recipe_script: String,
    pub preseed_recipe_script: Option<String>,
    pub preseed_outputs: BTreeMap<String, RecipeOutputKind>,
    pub defines: BTreeMap<String, String>,
    pub rpm_base: Option<RpmBaseContract>,
}

/// Canonical source ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceContract {
    pub rootfs_source: RootfsSourceContract,
}

/// Product declaration with a stable logical identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductDecl {
    pub logical_name: String,
    pub description: String,
    /// Immediate parent product in the Ring 2 composition DAG, if any.
    pub extends: Option<String>,
}

/// Canonical product ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductContract {
    pub rootfs_base: ProductDecl,
    pub live_overlay: ProductDecl,
    pub boot_live: ProductDecl,
    pub live_tools: ProductDecl,
    pub boot_installed: Option<ProductDecl>,
    pub kernel_staging: ProductDecl,
}

/// Supported overlay implementation for live boot products.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverlayKind {
    Systemd,
    OpenRc,
}

/// Canonical live-overlay execution policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayContract {
    pub kind: OverlayKind,
}

/// Canonical rootfs producer declaration for boot payload shaping.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        optional: bool,
    },
    WriteText {
        path: String,
        content: String,
        mode: Option<u32>,
    },
}

/// Resolved boot payload producer set for a Ring 2 product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPayloadContract {
    pub producers: Vec<PayloadProducerContract>,
}

/// The live ISO's install screen (`[install_ux]` in the variant's products.toml):
/// a shell beside the install docs.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub apps: Vec<String>,
}

/// What the install screen shows as docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDocs {
    /// A TUI app under `tui/apps`, by its `bin` name, opened at `page` (with the
    /// flag its manifest's `inspect.pages.arg` names) or at its first page.
    TuiApp { app: String, page: Option<String> },
    /// A text file, resolved to a path on the build host.
    Text(std::path::PathBuf),
}

/// Canonical live-tools runtime action declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeActionContract {
    ToolPayloadWorkspaceBinary {
        package: String,
        binary: Option<String>,
        target: Option<String>,
    },
    RootfsWorkspaceBinary {
        package: String,
        binary: Option<String>,
        target: Option<String>,
        destination: String,
    },
}

/// Canonical Ring 2 execution config used by the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductConfigContract {
    pub live_overlay: OverlayContract,
    pub boot_live: BootPayloadContract,
    pub boot_installed: Option<BootPayloadContract>,
    pub live_tools_actions: Vec<RuntimeActionContract>,
    pub install_ux: InstallUxContract,
}

/// Artifact transform declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTransform {
    pub logical_name: String,
    /// Immediate dependency identities in the build graph.
    ///
    /// These may be product logical names or upstream artifact logical names.
    pub dependencies: Vec<String>,
    pub output_names: Vec<String>,
    pub format: String,
    pub extra_cmdline: Option<String>,
}

/// Canonical transform ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformContract {
    pub rootfs_image: ArtifactTransform,
    pub overlay_image: ArtifactTransform,
    pub initramfs_live: ArtifactTransform,
    pub initramfs_installed: Option<ArtifactTransform>,
    pub live_uki: ArtifactTransform,
    pub installed_uki: Option<ArtifactTransform>,
    pub iso: ArtifactTransform,
    pub disk_image: Option<ArtifactTransform>,
}

/// Scenario ownership.
///
/// These are validation/runtime scenarios, not build-graph owners.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Release ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseContract {
    pub primary_outputs: Vec<String>,
    pub supporting_artifacts: Vec<String>,
    pub metadata_outputs: Vec<String>,
    pub metadata_facts: Vec<String>,
}

/// Boot-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootScenario {
    /// Console lines that mean the boot succeeded (the serial test protocol's
    /// readiness marker always does).
    pub success_patterns: Vec<String>,
    /// Console lines that mean the boot failed.
    pub fatal_patterns: Vec<String>,
    /// Console lines that report a failed service: recorded, not fatal.
    pub service_failure_patterns: Vec<String>,
    /// Required kernel cmdline tokens for booting this scenario.
    pub required_kernel_cmdline: Vec<String>,
    /// Required live services that must be available in this scenario.
    pub required_live_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Shared live-environment service requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEnvironmentScenario {
    pub required_services: Vec<String>,
}

/// Tool-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsScenario {
    pub required_tools: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Live-tools scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveToolsScenario {
    pub required_tools: Vec<String>,
    /// Serial console lines that mean the live system is up when the serial
    /// console runs the install UX instead of a shell (login prompt, issue).
    pub serial_ready_patterns: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Install-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallScenario {
    pub required_tools: Vec<String>,
    pub required_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Automated-login scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomatedLoginScenario {
    pub auth_mode: AuthMode,
    pub default_username: Option<String>,
    pub default_password: Option<String>,
    pub login_prompt_pattern: String,
    pub evidence: ScriptEvidence,
}

/// Runtime-policy scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyScenario {
    pub rootfs_mutability: RootfsMutability,
    pub mutable_required_rw_paths: Vec<String>,
    pub immutable_required_ro_paths: Vec<String>,
}

/// Complete distro conformance declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub identity: DistroIdentity,
    pub build: BuildContract,
    pub sources: SourceContract,
    pub products: ProductContract,
    pub product_config: ProductConfigContract,
    pub transforms: TransformContract,
    pub scenarios: ScenarioContract,
    pub release: ReleaseContract,
    pub artifacts: ArtifactIdentity,
}
