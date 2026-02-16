//! Contract validation engine.
//!
//! Current phase: Stage 00-only enforcement.
//! Stage 01-Stage 08 declarations may exist in the schema, but this validator only
//! executes Stage 00 build-capability conformance checks.

use std::collections::HashSet;

use crate::error::{StageId, ConformanceError, ConformanceReport, Violation, ViolationCode};
use crate::schema::{ConformanceContract, CONTRACT_SCHEMA_VERSION};

const PLACEHOLDER_TOKENS: &[&str] = &[
    "todo",
    "tbd",
    "placeholder",
    "dummy",
    "fixme",
    "changeme",
    "none",
    "n/a",
    "unknown",
];

const STAGE_00_REQUIRED_BUILD_TOOLS_BASELINE: &[&str] = &[
    "recipe",
    "cargo",
    "make",
    "recuki",
    "ukify",
    "mkfs.erofs",
    "xorriso",
    "reciso",
    "recinit",
    "recstrap",
    "recfstab",
    "recchroot",
];

const STAGE_00_REQUIRED_RECIPE_KERNEL_SCRIPT: &str = "distro-builder/recipes/linux.rhai";
const STAGE_00_REQUIRED_RECIPE_INVOCATION: &str = "recipe install";
const STAGE_00_REQUIRED_KERNEL_RELEASE_PATH: &str = "kernel-build/include/config/kernel.release";
const STAGE_00_REQUIRED_KERNEL_IMAGE_PATH: &str = "staging/boot/vmlinuz";
const STAGE_00_REQUIRED_KERNEL_MODULES_PATH: &str = "staging/usr/lib/modules/<kernel.release>";
const STAGE_00_REQUIRED_MODULE_INSTALL_PATH: &str = "/usr/lib/modules";

fn push_violation(
    violations: &mut Vec<Violation>,
    stage: Option<StageId>,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    violations.push(Violation {
        stage,
        field: field.into(),
        code,
        message: message.into(),
    });
}

fn is_placeholder_token(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    PLACEHOLDER_TOKENS.contains(&lowered.as_str())
}

fn validate_non_empty_trimmed(
    violations: &mut Vec<Violation>,
    stage: Option<StageId>,
    field: &str,
    value: &str,
) -> bool {
    if value.trim().is_empty() {
        push_violation(
            violations,
            stage,
            field,
            ViolationCode::MissingValue,
            format!("{field} must be non-empty"),
        );
        return false;
    }
    if value != value.trim() {
        push_violation(
            violations,
            stage,
            field,
            ViolationCode::WhitespaceValue,
            format!("{field} must not include leading/trailing whitespace"),
        );
        return false;
    }
    if is_placeholder_token(value) {
        push_violation(
            violations,
            stage,
            field,
            ViolationCode::PlaceholderValue,
            format!("{field} must not be a placeholder token"),
        );
        return false;
    }

    true
}

fn validate_unique_values(
    violations: &mut Vec<Violation>,
    stage: Option<StageId>,
    field: &str,
    values: &[String],
) {
    if values.is_empty() {
        push_violation(
            violations,
            stage,
            field,
            ViolationCode::MissingValue,
            format!("{field} must be non-empty"),
        );
        return;
    }

    let mut seen = HashSet::new();
    for value in values {
        validate_non_empty_trimmed(violations, stage, field, value);
        if !seen.insert(value) {
            push_violation(
                violations,
                stage,
                field,
                ViolationCode::DuplicateEntry,
                format!("{field} contains duplicate value '{value}'"),
            );
        }
    }
}

fn is_command_token(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

fn validate_command_entries(
    violations: &mut Vec<Violation>,
    stage: Option<StageId>,
    field: &str,
    values: &[String],
) {
    validate_unique_values(violations, stage, field, values);

    for value in values {
        if !is_command_token(value) {
            push_violation(
                violations,
                stage,
                field,
                ViolationCode::InvalidToken,
                format!("{field} value '{value}' is not a valid command token"),
            );
        }
    }
}

fn validate_evidence(
    violations: &mut Vec<Violation>,
    stage: StageId,
    field_prefix: &str,
    script_path: &str,
    pass_marker: &str,
    expected_script_prefix: &str,
) {
    let script_field = format!("{field_prefix}.script_path");
    let marker_field = format!("{field_prefix}.pass_marker");

    let script_ok =
        validate_non_empty_trimmed(violations, Some(stage), &script_field, script_path);
    let marker_ok =
        validate_non_empty_trimmed(violations, Some(stage), &marker_field, pass_marker);

    if script_ok {
        if script_path.contains('/') || script_path.contains('\\') {
            push_violation(
                violations,
                Some(stage),
                &script_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{script_field} must be a script filename, not a path"),
            );
        }
        if !script_path.starts_with(expected_script_prefix) || !script_path.ends_with(".sh") {
            push_violation(
                violations,
                Some(stage),
                &script_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!(
                    "{script_field} must start with '{expected_script_prefix}' and end with '.sh'"
                ),
            );
        }
    }

    if marker_ok {
        let lowered = pass_marker.to_ascii_uppercase();
        if !lowered.contains("STAGE") || !lowered.contains("PASS") {
            push_violation(
                violations,
                Some(stage),
                &marker_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{marker_field} must contain STAGE and PASS tokens"),
            );
        }
    }
}

fn is_relative_contract_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains("//")
        && !value.contains("/../")
        && !value.starts_with("../")
        && !value.ends_with("/..")
}

fn is_kernel_version_token(value: &str) -> bool {
    let mut saw_dot = false;
    for c in value.chars() {
        if c == '.' {
            saw_dot = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return false;
        }
    }
    saw_dot
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_stage_00_build(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let stage_00 = &contract.stages.stage_00_build;

    validate_command_entries(
        violations,
        Some(StageId::Stage00),
        "stage_00_build.required_build_tools",
        &stage_00.required_build_tools,
    );
    let stage_00_tools: HashSet<&str> = stage_00
        .required_build_tools
        .iter()
        .map(String::as_str)
        .collect();
    for tool in STAGE_00_REQUIRED_BUILD_TOOLS_BASELINE {
        if !stage_00_tools.contains(tool) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                "stage_00_build.required_build_tools",
                ViolationCode::MissingRequiredBuildTool,
                format!("stage_00_build.required_build_tools must include '{tool}'"),
            );
        }
    }

    let kconfig_field = "stage_00_build.kernel_kconfig_path";
    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
        kconfig_field,
        &stage_00.kernel_kconfig_path,
    ) && stage_00.kernel_kconfig_path != "kconfig"
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
            kconfig_field,
            ViolationCode::InvalidPathDeclaration,
            "stage_00_build.kernel_kconfig_path must be exactly 'kconfig'",
        );
    }

    for (field, value) in [
        (
            "stage_00_build.recipe_kernel_script",
            stage_00.recipe_kernel_script.as_str(),
        ),
        (
            "stage_00_build.recipe_kernel_invocation",
            stage_00.recipe_kernel_invocation.as_str(),
        ),
        (
            "stage_00_build.kernel_release_path",
            stage_00.kernel_release_path.as_str(),
        ),
        (
            "stage_00_build.kernel_image_path",
            stage_00.kernel_image_path.as_str(),
        ),
        (
            "stage_00_build.kernel_modules_path",
            stage_00.kernel_modules_path.as_str(),
        ),
    ] {
        if validate_non_empty_trimmed(violations, Some(StageId::Stage00), field, value)
            && !is_relative_contract_path(value)
        {
            push_violation(
                violations,
                Some(StageId::Stage00),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} must be a relative normalized path"),
            );
        }
    }

    if stage_00.recipe_kernel_script != STAGE_00_REQUIRED_RECIPE_KERNEL_SCRIPT {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.recipe_kernel_script",
            ViolationCode::RecipeKernelOrchestrationRequired,
            format!(
                "stage_00_build.recipe_kernel_script must be '{}'",
                STAGE_00_REQUIRED_RECIPE_KERNEL_SCRIPT
            ),
        );
    }
    if stage_00.recipe_kernel_invocation != STAGE_00_REQUIRED_RECIPE_INVOCATION {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.recipe_kernel_invocation",
            ViolationCode::RecipeKernelOrchestrationRequired,
            format!(
                "stage_00_build.recipe_kernel_invocation must be '{}'",
                STAGE_00_REQUIRED_RECIPE_INVOCATION
            ),
        );
    }

    if stage_00.kernel_release_path != STAGE_00_REQUIRED_KERNEL_RELEASE_PATH {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.kernel_release_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "stage_00_build.kernel_release_path must be '{}'",
                STAGE_00_REQUIRED_KERNEL_RELEASE_PATH
            ),
        );
    }
    if stage_00.kernel_image_path != STAGE_00_REQUIRED_KERNEL_IMAGE_PATH {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.kernel_image_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "stage_00_build.kernel_image_path must be '{}'",
                STAGE_00_REQUIRED_KERNEL_IMAGE_PATH
            ),
        );
    }
    if stage_00.kernel_modules_path != STAGE_00_REQUIRED_KERNEL_MODULES_PATH {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.kernel_modules_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "stage_00_build.kernel_modules_path must be '{}'",
                STAGE_00_REQUIRED_KERNEL_MODULES_PATH
            ),
        );
    }

    if stage_00.module_install_path != STAGE_00_REQUIRED_MODULE_INSTALL_PATH {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.module_install_path",
            ViolationCode::UnsupportedModuleInstallPath,
            format!(
                "stage_00_build.module_install_path must be '{}' to enforce cross-distro consistency",
                STAGE_00_REQUIRED_MODULE_INSTALL_PATH
            ),
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
        "stage_00_build.kernel_version",
        &stage_00.kernel_version,
    ) && !is_kernel_version_token(&stage_00.kernel_version)
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.kernel_version",
            ViolationCode::InvalidKernelProvenance,
            "stage_00_build.kernel_version must be digits/dot format (for example 6.12.71)",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
        "stage_00_build.kernel_sha256",
        &stage_00.kernel_sha256,
    ) && !is_sha256_hex(&stage_00.kernel_sha256)
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.kernel_sha256",
            ViolationCode::InvalidKernelProvenance,
            "stage_00_build.kernel_sha256 must be a 64-character hex SHA256",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
        "stage_00_build.kernel_localversion",
        &stage_00.kernel_localversion,
    ) && (stage_00.kernel_localversion.len() < 2
        || !stage_00.kernel_localversion.starts_with('-')
        || stage_00
            .kernel_localversion
            .chars()
            .skip(1)
            .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_'))
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
            "stage_00_build.kernel_localversion",
            ViolationCode::InvalidKernelProvenance,
            "stage_00_build.kernel_localversion must be '-' followed by lowercase alnum/underscore",
        );
    }

    validate_evidence(
        violations,
        StageId::Stage00,
        "stage_00_build.evidence",
        &stage_00.evidence.script_path,
        &stage_00.evidence.pass_marker,
        "stage-00-",
    );
}

/// Validate a conformance contract and return a full report.
///
/// Stage 00-only phase:
/// - validates schema version
/// - validates identity token shape
/// - validates Stage 00 build-capability declaration
/// - does not execute Stage 01-Stage 08 runtime stage validation
pub fn validate_contract(contract: &ConformanceContract) -> ConformanceReport {
    let mut violations = Vec::new();

    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        push_violation(
            &mut violations,
            None,
            "schema_version",
            ViolationCode::InvalidSchemaVersion,
            format!(
                "schema_version must be {}, got {}",
                CONTRACT_SCHEMA_VERSION, contract.schema_version
            ),
        );
    }

    validate_non_empty_trimmed(
        &mut violations,
        None,
        "identity.os_name",
        &contract.identity.os_name,
    );
    validate_non_empty_trimmed(
        &mut violations,
        None,
        "identity.os_id",
        &contract.identity.os_id,
    );
    validate_non_empty_trimmed(
        &mut violations,
        None,
        "identity.iso_label",
        &contract.identity.iso_label,
    );
    validate_non_empty_trimmed(
        &mut violations,
        None,
        "identity.os_version",
        &contract.identity.os_version,
    );
    validate_non_empty_trimmed(
        &mut violations,
        None,
        "identity.default_hostname",
        &contract.identity.default_hostname,
    );

    if !contract
        .identity
        .os_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        push_violation(
            &mut violations,
            None,
            "identity.os_id",
            ViolationCode::InvalidToken,
            "identity.os_id must be lowercase alphanumeric/underscore",
        );
    }

    validate_stage_00_build(&mut violations, contract);

    ConformanceReport {
        distro_id: contract.identity.os_id.clone(),
        schema_version: contract.schema_version,
        violations,
    }
}

/// Validate a contract and return an error if any violations are present.
pub fn require_valid_contract(contract: &ConformanceContract) -> Result<(), ConformanceError> {
    let report = validate_contract(contract);
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    fn valid_contract() -> ConformanceContract {
        ConformanceContract {
            schema_version: CONTRACT_SCHEMA_VERSION,
            identity: DistroIdentity {
                os_name: "ExampleOS".to_string(),
                os_id: "exampleos".to_string(),
                iso_label: "EXAMPLEOS".to_string(),
                os_version: "1.0".to_string(),
                default_hostname: "example".to_string(),
            },
            artifacts: ArtifactIdentity {
                rootfs_name: "exampleos.erofs".to_string(),
                initramfs_live_output: "initramfs-live.cpio.gz".to_string(),
                iso_filename: "exampleos.iso".to_string(),
                initramfs_installed_output: Some("initramfs-installed.img".to_string()),
            },
            stages: StageContract {
                stage_00_build: BuildCapabilityStage {
                    required_build_tools: vec![
                        "recipe".to_string(),
                        "cargo".to_string(),
                        "make".to_string(),
                        "recuki".to_string(),
                        "ukify".to_string(),
                        "mkfs.erofs".to_string(),
                        "xorriso".to_string(),
                        "reciso".to_string(),
                        "recinit".to_string(),
                        "recstrap".to_string(),
                        "recfstab".to_string(),
                        "recchroot".to_string(),
                    ],
                    kernel_kconfig_path: "kconfig".to_string(),
                    recipe_kernel_script: "distro-builder/recipes/linux.rhai".to_string(),
                    recipe_kernel_invocation: "recipe install".to_string(),
                    kernel_release_path: "kernel-build/include/config/kernel.release".to_string(),
                    kernel_image_path: "staging/boot/vmlinuz".to_string(),
                    kernel_modules_path: "staging/usr/lib/modules/<kernel.release>".to_string(),
                    kernel_version: "6.12.71".to_string(),
                    kernel_sha256:
                        "143e8bc76cc41f831b51aa5e75819bed55bed41f299d35922820f1d2d2b02600"
                            .to_string(),
                    kernel_localversion: "-exampleos".to_string(),
                    module_install_path: "/usr/lib/modules".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "stage-00-build-capability.sh".to_string(),
                        pass_marker: "STAGE 00 PASSED".to_string(),
                    },
                },
                stage_01_live_boot: BootStage {
                    success_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-01-live-boot.sh".to_string(),
                        pass_marker: "STAGE 01 PASSED".to_string(),
                    },
                },
                stage_02_live_tools: ToolsStage {
                    required_tools: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-02-live-tools.sh".to_string(),
                        pass_marker: "STAGE 02 PASSED".to_string(),
                    },
                },
                stage_03_install: InstallStage {
                    required_tools: vec!["ignored-in-stage_00-phase".to_string()],
                    required_services: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-03-installation.sh".to_string(),
                        pass_marker: "STAGE 03 PASSED".to_string(),
                    },
                },
                stage_04_installed_boot: BootStage {
                    success_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-04-installed-boot.sh".to_string(),
                        pass_marker: "STAGE 04 PASSED".to_string(),
                    },
                },
                stage_05_automated_login: AutomatedLoginStage {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("ignored".to_string()),
                    default_password: Some("ignored".to_string()),
                    login_prompt_pattern: "ignored-in-stage_00-phase".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "stage-05-automated-login.sh".to_string(),
                        pass_marker: "STAGE 05 PASSED".to_string(),
                    },
                },
                stage_06_installed_tools: ToolsStage {
                    required_tools: vec!["ignored-in-stage_00-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-06-daily-driver.sh".to_string(),
                        pass_marker: "STAGE 06 PASSED".to_string(),
                    },
                },
                stage_07_runtime_policy: RuntimePolicyStage {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec![],
                    immutable_required_ro_paths: vec![],
                },
                stage_08_release: ReleaseStage {
                    required_artifacts: vec![],
                    required_metadata: vec![],
                },
            },
        }
    }

    #[test]
    fn valid_contract_passes() {
        let report = validate_contract(&valid_contract());
        assert!(report.passed(), "violations: {:#?}", report.violations);
    }

    #[test]
    fn stage_00_requires_recipe_rhai_kernel_orchestration() {
        let mut contract = valid_contract();
        contract.stages.stage_00_build.recipe_kernel_script = "linux.rhai".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::RecipeKernelOrchestrationRequired));
    }

    #[test]
    fn stage_00_requires_baseline_build_tools() {
        let mut contract = valid_contract();
        contract
            .stages
            .stage_00_build
            .required_build_tools
            .retain(|tool| tool != "xorriso");

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingRequiredBuildTool));
    }

    #[test]
    fn stage_00_requires_usrmerge_module_install_path() {
        let mut contract = valid_contract();
        contract.stages.stage_00_build.module_install_path = "/lib/modules".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UnsupportedModuleInstallPath));
    }
}
