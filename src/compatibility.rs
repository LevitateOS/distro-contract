//! Legacy stage-shaped compatibility types and facades.

use std::path::Path;

use crate::error::{ConformanceError, ConformanceReport};
use crate::runtime::BuildRuntimeArtifacts;
use crate::schema::{
    AutomatedLoginStage, BootStage, ConformanceContract, InstallStage, ReleaseStage,
    RuntimePolicyStage, ScriptEvidence, ToolsStage,
};

/// Stage-scoped non-kernel input partition for 00Build.
///
/// All entries are relative paths under `.artifacts/out/<distro>/`.
/// Stage 00 validators require a minimal bootable subset in
/// `required_for_00build`, while deferred buckets are compatibility-only.
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
    pub live_uki_filename: String,
    pub emergency_uki_filename: String,
    pub debug_uki_filename: String,
    pub live_cmdline: String,
}

/// Stage 00 build-capability declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildCapabilityStage {
    pub required_build_tools: Vec<String>,
    pub kernel_kconfig_path: String,
    pub recipe_kernel_script: String,
    pub recipe_kernel_invocation: String,
    pub kernel_release_path: String,
    pub kernel_image_path: String,
    pub kernel_modules_path: String,
    pub kernel_version: String,
    pub kernel_sha256: String,
    pub kernel_localversion: String,
    pub module_install_path: String,
    pub non_kernel_inputs: Stage00NonKernelInputs,
    pub iso_assembly: Stage00IsoAssembly,
    pub evidence: ScriptEvidence,
}

/// Stage 00..Stage 08 aggregate compatibility declaration.
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

fn build_stage_from_contract(contract: &ConformanceContract) -> BuildCapabilityStage {
    let build = &contract.build;
    let kernel = &build.kernel;
    let mut required_for_00build = Vec::new();
    for outputs in [
        &contract.transforms.rootfs_image.output_names,
        &contract.transforms.initramfs_live.output_names,
        &contract.transforms.overlay_image.output_names,
    ] {
        if let Some(output) = outputs.first() {
            required_for_00build.push(output.clone());
        }
    }

    let live_uki_output = |index: usize| {
        contract
            .transforms
            .live_uki
            .output_names
            .get(index)
            .cloned()
            .unwrap_or_default()
    };

    BuildCapabilityStage {
        required_build_tools: build.required_build_tools.clone(),
        kernel_kconfig_path: kernel.kconfig_path.clone(),
        recipe_kernel_script: kernel.recipe_script.clone(),
        recipe_kernel_invocation: kernel.recipe_invocation.clone(),
        kernel_release_path: kernel.release_path.clone(),
        kernel_image_path: kernel.image_path.clone(),
        kernel_modules_path: kernel.modules_path.clone(),
        kernel_version: kernel.version.clone(),
        kernel_sha256: kernel.sha256.clone(),
        kernel_localversion: kernel.localversion.clone(),
        module_install_path: kernel.module_install_path.clone(),
        non_kernel_inputs: Stage00NonKernelInputs {
            required_for_00build,
            deferred_to_01boot: vec![],
            deferred_to_02livetools: vec![],
            deferred_to_03install_plus: vec![],
        },
        iso_assembly: Stage00IsoAssembly {
            live_uki_filename: live_uki_output(0),
            emergency_uki_filename: live_uki_output(1),
            debug_uki_filename: live_uki_output(2),
            live_cmdline: contract
                .transforms
                .live_uki
                .extra_cmdline
                .clone()
                .unwrap_or_default(),
        },
        evidence: build.evidence.clone(),
    }
}

/// Build the legacy stage-shaped compatibility view from canonical owners.
pub fn stage_view(contract: &ConformanceContract) -> StageContract {
    StageContract {
        stage_00_build: build_stage_from_contract(contract),
        stage_01_live_boot: contract.scenarios.live_boot.clone(),
        stage_02_live_tools: contract.scenarios.live_tools.clone(),
        stage_03_install: contract.scenarios.install.clone(),
        stage_04_installed_boot: contract.scenarios.installed_boot.clone(),
        stage_05_automated_login: contract.scenarios.automated_login.clone(),
        stage_06_installed_tools: contract.scenarios.installed_tools.clone(),
        stage_07_runtime_policy: contract.scenarios.runtime_policy.clone(),
        stage_08_release: ReleaseStage {
            required_artifacts: contract
                .release
                .primary_outputs
                .iter()
                .chain(contract.release.supporting_artifacts.iter())
                .cloned()
                .collect(),
            required_metadata: contract
                .release
                .metadata_outputs
                .iter()
                .chain(contract.release.metadata_facts.iter())
                .cloned()
                .collect(),
        },
    }
}

impl ConformanceContract {
    /// Derive the legacy stage-shaped compatibility view from canonical owners.
    pub fn compatibility_stage_view(&self) -> StageContract {
        stage_view(self)
    }
}

#[deprecated(note = "use crate::runtime::BuildRuntimeArtifacts")]
pub type Stage00RuntimeArtifacts = BuildRuntimeArtifacts;

#[deprecated(note = "use crate::runtime::validate_build_runtime")]
pub fn validate_stage_00_runtime(
    contract: &ConformanceContract,
    variant_dir: &Path,
    artifact_dir: &Path,
) -> ConformanceReport {
    crate::runtime::validate_build_runtime(contract, variant_dir, artifact_dir)
}

#[deprecated(note = "use crate::runtime::validate_build_runtime_with_stage_dirs")]
pub fn validate_stage_00_runtime_with_stage_dirs(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    stage_artifact_dir: &Path,
) -> ConformanceReport {
    crate::runtime::validate_build_runtime_with_stage_dirs(
        contract,
        variant_dir,
        kernel_artifact_dir,
        stage_artifact_dir,
    )
}

#[deprecated(note = "use crate::runtime::validate_build_runtime_with_artifacts")]
pub fn validate_stage_00_runtime_with_artifacts(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifacts: &BuildRuntimeArtifacts,
) -> ConformanceReport {
    crate::runtime::validate_build_runtime_with_artifacts(
        contract,
        variant_dir,
        kernel_artifact_dir,
        artifacts,
    )
}

#[deprecated(note = "use crate::runtime::require_valid_build_runtime")]
pub fn require_valid_stage_00_runtime(
    contract: &ConformanceContract,
    variant_dir: &Path,
    artifact_dir: &Path,
) -> Result<(), ConformanceError> {
    crate::runtime::require_valid_build_runtime(contract, variant_dir, artifact_dir)
}

#[deprecated(note = "use crate::runtime::require_valid_build_runtime_with_artifacts")]
pub fn require_valid_stage_00_runtime_with_artifacts(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifacts: &BuildRuntimeArtifacts,
) -> Result<(), ConformanceError> {
    crate::runtime::require_valid_build_runtime_with_artifacts(
        contract,
        variant_dir,
        kernel_artifact_dir,
        artifacts,
    )
}

#[deprecated(note = "use crate::runtime::require_valid_build_runtime_with_stage_dirs")]
pub fn require_valid_stage_00_runtime_with_stage_dirs(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    stage_artifact_dir: &Path,
) -> Result<(), ConformanceError> {
    crate::runtime::require_valid_build_runtime_with_stage_dirs(
        contract,
        variant_dir,
        kernel_artifact_dir,
        stage_artifact_dir,
    )
}

#[deprecated(note = "use crate::runtime::validate_live_boot_runtime_with_stage_dir")]
pub fn validate_stage_01_runtime(
    contract: &ConformanceContract,
    stage_artifact_dir: &Path,
    stage_artifact_tag: &str,
) -> ConformanceReport {
    crate::runtime::validate_live_boot_runtime_with_stage_dir(
        contract,
        stage_artifact_dir,
        stage_artifact_tag,
    )
}

#[deprecated(note = "use crate::runtime::require_valid_live_boot_runtime_with_stage_dir")]
pub fn require_valid_stage_01_runtime(
    contract: &ConformanceContract,
    stage_artifact_dir: &Path,
    stage_artifact_tag: &str,
) -> Result<(), ConformanceError> {
    crate::runtime::require_valid_live_boot_runtime_with_stage_dir(
        contract,
        stage_artifact_dir,
        stage_artifact_tag,
    )
}
