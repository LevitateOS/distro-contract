//! Conformance contract schema for distro stage declarations.

/// Contract schema version enforced by validators.
pub const CONTRACT_SCHEMA_VERSION: u32 = 4;

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
    /// On-ISO stage script filename (for example `stage-02-live-tools.sh`).
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
}

/// Stage 01/Stage 04 boot declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootStage {
    pub success_patterns: Vec<String>,
    pub fatal_patterns: Vec<String>,
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
    pub artifacts: ArtifactIdentity,
    pub stages: StageContract,
}
