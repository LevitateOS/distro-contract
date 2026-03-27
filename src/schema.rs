//! Conformance contract schema for distro ownership and scenario declarations.

use std::collections::BTreeMap;

/// Contract schema version enforced by validators.
pub const CONTRACT_SCHEMA_VERSION: u32 = 6;

/// Shared live-boot kernel cmdline invariants required across all distros.
pub const BOOT_REQUIRED_KERNEL_CMDLINE_BASE: &[&str] = &["audit=1", "inst.sshd=0"];

/// Shared live-boot services that must be present across all distros.
pub const BOOT_REQUIRED_LIVE_SERVICES_BASE: &[&str] = &["sshd"];

/// Canonical install interaction mode for live-tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallExperience {
    Ux,
    AutomatedSsh,
}

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
/// This is the filesystem-first replacement for treating the build checkpoint as
/// the canonical aggregate owner. It captures build prerequisites and kernel
/// ownership without implying that "checkpoint" is the architecture.
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
    RecipeRpmDvd,
    RecipeCustom,
}

/// Canonical rootfs source policy declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsSourceContract {
    pub kind: RootfsSourceKind,
    pub recipe_script: String,
    pub preseed_recipe_script: Option<String>,
    pub defines: BTreeMap<String, String>,
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

/// Supported OpenRC `/etc/inittab` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenRcInittab {
    DesktopWithSerial,
    SerialOnly,
}

/// Canonical live-overlay execution policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayContract {
    pub kind: OverlayKind,
    pub issue_message: Option<String>,
    pub openrc_inittab: Option<OpenRcInittab>,
    pub seed_overlay: Option<String>,
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

/// Canonical install-docs frontend selection for live-tools runtime payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallDocsFrontend {
    PlainText,
    BunBundle,
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
    ApkPackages {
        packages: Vec<String>,
    },
    IuppiterDarPayload {
        target: Option<String>,
    },
    InstallModePayload {
        interactive_shell: String,
        ux_docs_frontend: InstallDocsFrontend,
    },
}

/// Resolved live-tools runtime policy by install-experience branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveToolsRuntimeContract {
    pub common_actions: Vec<RuntimeActionContract>,
    pub ux_actions: Vec<RuntimeActionContract>,
    pub automated_ssh_actions: Vec<RuntimeActionContract>,
}

/// Canonical Ring 2 execution config used by the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductConfigContract {
    pub live_overlay: OverlayContract,
    pub boot_live: BootPayloadContract,
    pub boot_installed: Option<BootPayloadContract>,
    pub live_tools: LiveToolsRuntimeContract,
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
    pub live_boot: BootCheckpoint,
    pub live_environment: LiveEnvironmentScenario,
    pub live_tools: LiveToolsScenario,
    pub install: InstallCheckpoint,
    pub installed_boot: BootCheckpoint,
    pub automated_login: AutomatedLoginCheckpoint,
    pub installed_tools: ToolsCheckpoint,
    pub runtime_policy: RuntimePolicyCheckpoint,
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
pub struct BootCheckpoint {
    pub success_patterns: Vec<String>,
    pub fatal_patterns: Vec<String>,
    /// Required kernel cmdline tokens for booting this checkpoint.
    pub required_kernel_cmdline: Vec<String>,
    /// Required live services that must be available at this checkpoint.
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
pub struct ToolsCheckpoint {
    pub required_tools: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Live-tools scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveToolsScenario {
    pub required_tools: Vec<String>,
    pub install_experience: InstallExperience,
    pub evidence: ScriptEvidence,
}

/// Install-scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCheckpoint {
    pub required_tools: Vec<String>,
    pub required_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Automated-login scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomatedLoginCheckpoint {
    pub auth_mode: AuthMode,
    pub default_username: Option<String>,
    pub default_password: Option<String>,
    pub login_prompt_pattern: String,
    pub evidence: ScriptEvidence,
}

/// Runtime-policy scenario declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyCheckpoint {
    pub rootfs_mutability: RootfsMutability,
    pub mutable_required_rw_paths: Vec<String>,
    pub immutable_required_ro_paths: Vec<String>,
}

/// Release validation declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCheckpoint {
    pub required_artifacts: Vec<String>,
    pub required_metadata: Vec<String>,
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
