//! Conformance contract schema for distro checkpoint declarations.

/// Contract schema version enforced by validators.
pub const CONTRACT_SCHEMA_VERSION: u32 = 3;

/// CP5 authentication policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// CP5 automation uses deterministic distro-provided credentials.
    DefaultPasswordLogin,
    /// CP5 credentials are provisioned out-of-band.
    ProvisionedCredentials,
}

/// CP7 rootfs model.
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
    /// On-ISO checkpoint script filename (for example `checkpoint-2-live-tools.sh`).
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

/// CP1/CP4 boot declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCheckpoint {
    pub success_patterns: Vec<String>,
    pub fatal_patterns: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// CP2/CP6 tool declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsCheckpoint {
    pub required_tools: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// CP3 install declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCheckpoint {
    pub required_tools: Vec<String>,
    pub required_services: Vec<String>,
    pub evidence: ScriptEvidence,
}

/// CP5 automated login declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomatedLoginCheckpoint {
    pub auth_mode: AuthMode,
    pub default_username: Option<String>,
    pub default_password: Option<String>,
    pub login_prompt_pattern: String,
    pub evidence: ScriptEvidence,
}

/// CP7 runtime policy declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyCheckpoint {
    pub rootfs_mutability: RootfsMutability,
    pub mutable_required_rw_paths: Vec<String>,
    pub immutable_required_ro_paths: Vec<String>,
}

/// CP8 release declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCheckpoint {
    pub required_artifacts: Vec<String>,
    pub required_metadata: Vec<String>,
}

/// CP0 build-capability declaration.
///
/// CP0 is intentionally non-runtime: it validates build-system/kernel provenance
/// invariants and required build tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildCapabilityCheckpoint {
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
    /// Evidence declaration for CP0 checks.
    pub evidence: ScriptEvidence,
}

/// CP0..CP8 aggregate declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointContract {
    pub cp0_build: BuildCapabilityCheckpoint,
    pub cp1_live_boot: BootCheckpoint,
    pub cp2_live_tools: ToolsCheckpoint,
    pub cp3_install: InstallCheckpoint,
    pub cp4_installed_boot: BootCheckpoint,
    pub cp5_automated_login: AutomatedLoginCheckpoint,
    pub cp6_installed_tools: ToolsCheckpoint,
    pub cp7_runtime_policy: RuntimePolicyCheckpoint,
    pub cp8_release: ReleaseCheckpoint,
}

/// Complete distro conformance declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub identity: DistroIdentity,
    pub artifacts: ArtifactIdentity,
    pub checkpoints: CheckpointContract,
}
