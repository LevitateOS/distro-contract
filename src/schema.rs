//! Conformance contract schema for distro stage declarations.

/// Contract schema version enforced by validators.
pub const CONTRACT_SCHEMA_VERSION: u32 = 6;

/// Shared Stage 01 kernel cmdline invariants required for deterministic live boot.
pub const STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE: &[&str] = &["audit=1", "inst.sshd=0"];

/// Shared Stage 01 live services that must be present across all distros.
pub const STAGE_01_REQUIRED_LIVE_SERVICES_BASE: &[&str] = &["sshd"];

/// Stage 05 authentication policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// Stage 05 automation uses deterministic distro-provided credentials.
    DefaultPasswordLogin,
    /// Stage 05 credentials are provisioned out-of-band.
    ProvisionedCredentials,
}

/// Stage 07 rootfs model.
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
/// This is the filesystem-first replacement for treating Stage 00 as the
/// canonical aggregate owner. It captures build prerequisites and kernel
/// ownership without implying that "stage" is the architecture.
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
    pub live_boot: BootStage,
    pub live_tools: ToolsStage,
    pub install: InstallStage,
    pub installed_boot: BootStage,
    pub automated_login: AutomatedLoginStage,
    pub installed_tools: ToolsStage,
    pub runtime_policy: RuntimePolicyStage,
}

/// Release ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseContract {
    pub primary_outputs: Vec<String>,
    pub supporting_artifacts: Vec<String>,
    pub metadata_outputs: Vec<String>,
    pub metadata_facts: Vec<String>,
}

/// Stage 01/Stage 04 boot declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootStage {
    pub success_patterns: Vec<String>,
    pub fatal_patterns: Vec<String>,
    /// Required kernel cmdline tokens for booting this stage.
    pub required_kernel_cmdline: Vec<String>,
    /// Required live services that must be available at this stage.
    pub required_live_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Stage 02/Stage 06 tool declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsStage {
    pub required_tools: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Stage 03 install declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallStage {
    pub required_tools: Vec<String>,
    pub required_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// Stage 05 automated login declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomatedLoginStage {
    pub auth_mode: AuthMode,
    pub default_username: Option<String>,
    pub default_password: Option<String>,
    pub login_prompt_pattern: String,
    pub evidence: ScriptEvidence,
}

/// Stage 07 runtime policy declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyStage {
    pub rootfs_mutability: RootfsMutability,
    pub mutable_required_rw_paths: Vec<String>,
    pub immutable_required_ro_paths: Vec<String>,
}

/// Stage 08 release declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseStage {
    pub required_artifacts: Vec<String>,
    pub required_metadata: Vec<String>,
}

/// Stage-scoped non-kernel input partition for 00Build.
///
/// All entries are relative paths under `.artifacts/out/<distro>/`.
/// Stage 00 validators require a minimal bootable subset in
/// `required_for_00build`, while deferred buckets are declared ownership for
/// later runtime stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage00NonKernelInputs {
    pub required_for_00build: Vec<String>,
    pub deferred_to_01boot: Vec<String>,
    pub deferred_to_02livetools: Vec<String>,
    pub deferred_to_03install_plus: Vec<String>,
}

/// Stage 00 ISO assembly parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage00IsoAssembly {
    /// UKI filename used for normal live boot.
    pub live_uki_filename: String,
    /// UKI filename used for emergency mode.
    pub emergency_uki_filename: String,
    /// UKI filename used for debug mode.
    pub debug_uki_filename: String,
    /// Additional live UKI cmdline tokens (may be empty).
    pub live_cmdline: String,
}

/// Stage 00 build-capability declaration.
///
/// Stage 00 is intentionally non-runtime: it validates build-system/kernel provenance
/// invariants and required build tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildCapabilityStage {
    /// Build tooling that must exist in the declared build pipeline.
    pub required_build_tools: Vec<String>,
    /// Kernel config input path (relative to distro root).
    pub kernel_kconfig_path: String,
    /// Required Recipe Rhai kernel script path.
    pub recipe_kernel_script: String,
    /// Required recipe invocation pattern.
    pub recipe_kernel_invocation: String,
    /// Expected kernel release output path (relative to `.artifacts/out/<DistroDir>/`).
    pub kernel_release_path: String,
    /// Expected installed kernel image path (relative to `.artifacts/out/<DistroDir>/`).
    pub kernel_image_path: String,
    /// Expected installed modules path pattern.
    pub kernel_modules_path: String,
    /// Declared kernel source version.
    pub kernel_version: String,
    /// Declared kernel source tarball sha256.
    pub kernel_sha256: String,
    /// Declared kernel localversion suffix.
    pub kernel_localversion: String,
    /// Declared kernel modules install root.
    pub module_install_path: String,
    /// Stage-scoped non-kernel artifact input partition.
    pub non_kernel_inputs: Stage00NonKernelInputs,
    /// Stage 00 ISO assembly parameters.
    pub iso_assembly: Stage00IsoAssembly,
    /// Evidence declaration for Stage 00 checks.
    pub evidence: ScriptEvidence,
}

/// Stage 00..Stage 08 aggregate declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageContract {
    pub stage_00_build: BuildCapabilityStage,
    pub stage_01_live_boot: BootStage,
    pub stage_02_live_tools: ToolsStage,
    pub stage_03_install: InstallStage,
    pub stage_04_installed_boot: BootStage,
    pub stage_05_automated_login: AutomatedLoginStage,
    pub stage_06_installed_tools: ToolsStage,
    pub stage_07_runtime_policy: RuntimePolicyStage,
    pub stage_08_release: ReleaseStage,
}

/// Complete distro conformance declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub identity: DistroIdentity,
    pub build: BuildContract,
    pub products: ProductContract,
    pub transforms: TransformContract,
    pub scenarios: ScenarioContract,
    pub release: ReleaseContract,
    pub artifacts: ArtifactIdentity,
    pub stages: StageContract,
}
