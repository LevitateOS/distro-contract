//! Contract validation engine.
//!
//! Current phase: CP0-only enforcement.
//! CP1-CP8 declarations may exist in the schema, but this validator only
//! executes CP0 build-capability conformance checks.

use std::collections::HashSet;

use crate::error::{CheckpointId, ConformanceError, ConformanceReport, Violation, ViolationCode};
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

const CP0_REQUIRED_BUILD_TOOLS_BASELINE: &[&str] = &[
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

const CP0_REQUIRED_RECIPE_KERNEL_SCRIPT: &str = "distro-builder/recipes/linux.rhai";
const CP0_REQUIRED_RECIPE_INVOCATION: &str = "recipe install";
const CP0_REQUIRED_KERNEL_RELEASE_PATH: &str = "kernel-build/include/config/kernel.release";
const CP0_REQUIRED_KERNEL_IMAGE_PATH: &str = "staging/boot/vmlinuz";
const CP0_REQUIRED_KERNEL_MODULES_PATH: &str = "staging/usr/lib/modules/<kernel.release>";
const CP0_REQUIRED_MODULE_INSTALL_PATH: &str = "/usr/lib/modules";

fn push_violation(
    violations: &mut Vec<Violation>,
    checkpoint: Option<CheckpointId>,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    violations.push(Violation {
        checkpoint,
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
    checkpoint: Option<CheckpointId>,
    field: &str,
    value: &str,
) -> bool {
    if value.trim().is_empty() {
        push_violation(
            violations,
            checkpoint,
            field,
            ViolationCode::MissingValue,
            format!("{field} must be non-empty"),
        );
        return false;
    }
    if value != value.trim() {
        push_violation(
            violations,
            checkpoint,
            field,
            ViolationCode::WhitespaceValue,
            format!("{field} must not include leading/trailing whitespace"),
        );
        return false;
    }
    if is_placeholder_token(value) {
        push_violation(
            violations,
            checkpoint,
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
    checkpoint: Option<CheckpointId>,
    field: &str,
    values: &[String],
) {
    if values.is_empty() {
        push_violation(
            violations,
            checkpoint,
            field,
            ViolationCode::MissingValue,
            format!("{field} must be non-empty"),
        );
        return;
    }

    let mut seen = HashSet::new();
    for value in values {
        validate_non_empty_trimmed(violations, checkpoint, field, value);
        if !seen.insert(value) {
            push_violation(
                violations,
                checkpoint,
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
    checkpoint: Option<CheckpointId>,
    field: &str,
    values: &[String],
) {
    validate_unique_values(violations, checkpoint, field, values);

    for value in values {
        if !is_command_token(value) {
            push_violation(
                violations,
                checkpoint,
                field,
                ViolationCode::InvalidToken,
                format!("{field} value '{value}' is not a valid command token"),
            );
        }
    }
}

fn validate_evidence(
    violations: &mut Vec<Violation>,
    checkpoint: CheckpointId,
    field_prefix: &str,
    script_path: &str,
    pass_marker: &str,
    expected_script_prefix: &str,
) {
    let script_field = format!("{field_prefix}.script_path");
    let marker_field = format!("{field_prefix}.pass_marker");

    let script_ok =
        validate_non_empty_trimmed(violations, Some(checkpoint), &script_field, script_path);
    let marker_ok =
        validate_non_empty_trimmed(violations, Some(checkpoint), &marker_field, pass_marker);

    if script_ok {
        if script_path.contains('/') || script_path.contains('\\') {
            push_violation(
                violations,
                Some(checkpoint),
                &script_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{script_field} must be a script filename, not a path"),
            );
        }
        if !script_path.starts_with(expected_script_prefix) || !script_path.ends_with(".sh") {
            push_violation(
                violations,
                Some(checkpoint),
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
        if !lowered.contains("CHECKPOINT") || !lowered.contains("PASS") {
            push_violation(
                violations,
                Some(checkpoint),
                &marker_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{marker_field} must contain CHECKPOINT and PASS tokens"),
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

fn validate_cp0_build(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let cp0 = &contract.checkpoints.cp0_build;

    validate_command_entries(
        violations,
        Some(CheckpointId::Cp0),
        "cp0_build.required_build_tools",
        &cp0.required_build_tools,
    );
    let cp0_tools: HashSet<&str> = cp0
        .required_build_tools
        .iter()
        .map(String::as_str)
        .collect();
    for tool in CP0_REQUIRED_BUILD_TOOLS_BASELINE {
        if !cp0_tools.contains(tool) {
            push_violation(
                violations,
                Some(CheckpointId::Cp0),
                "cp0_build.required_build_tools",
                ViolationCode::MissingRequiredBuildTool,
                format!("cp0_build.required_build_tools must include '{tool}'"),
            );
        }
    }

    let kconfig_field = "cp0_build.kernel_kconfig_path";
    if validate_non_empty_trimmed(
        violations,
        Some(CheckpointId::Cp0),
        kconfig_field,
        &cp0.kernel_kconfig_path,
    ) && cp0.kernel_kconfig_path != "kconfig"
    {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            kconfig_field,
            ViolationCode::InvalidPathDeclaration,
            "cp0_build.kernel_kconfig_path must be exactly 'kconfig'",
        );
    }

    for (field, value) in [
        (
            "cp0_build.recipe_kernel_script",
            cp0.recipe_kernel_script.as_str(),
        ),
        (
            "cp0_build.recipe_kernel_invocation",
            cp0.recipe_kernel_invocation.as_str(),
        ),
        (
            "cp0_build.kernel_release_path",
            cp0.kernel_release_path.as_str(),
        ),
        (
            "cp0_build.kernel_image_path",
            cp0.kernel_image_path.as_str(),
        ),
        (
            "cp0_build.kernel_modules_path",
            cp0.kernel_modules_path.as_str(),
        ),
    ] {
        if validate_non_empty_trimmed(violations, Some(CheckpointId::Cp0), field, value)
            && !is_relative_contract_path(value)
        {
            push_violation(
                violations,
                Some(CheckpointId::Cp0),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} must be a relative normalized path"),
            );
        }
    }

    if cp0.recipe_kernel_script != CP0_REQUIRED_RECIPE_KERNEL_SCRIPT {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.recipe_kernel_script",
            ViolationCode::RecipeKernelOrchestrationRequired,
            format!(
                "cp0_build.recipe_kernel_script must be '{}'",
                CP0_REQUIRED_RECIPE_KERNEL_SCRIPT
            ),
        );
    }
    if cp0.recipe_kernel_invocation != CP0_REQUIRED_RECIPE_INVOCATION {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.recipe_kernel_invocation",
            ViolationCode::RecipeKernelOrchestrationRequired,
            format!(
                "cp0_build.recipe_kernel_invocation must be '{}'",
                CP0_REQUIRED_RECIPE_INVOCATION
            ),
        );
    }

    if cp0.kernel_release_path != CP0_REQUIRED_KERNEL_RELEASE_PATH {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.kernel_release_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "cp0_build.kernel_release_path must be '{}'",
                CP0_REQUIRED_KERNEL_RELEASE_PATH
            ),
        );
    }
    if cp0.kernel_image_path != CP0_REQUIRED_KERNEL_IMAGE_PATH {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.kernel_image_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "cp0_build.kernel_image_path must be '{}'",
                CP0_REQUIRED_KERNEL_IMAGE_PATH
            ),
        );
    }
    if cp0.kernel_modules_path != CP0_REQUIRED_KERNEL_MODULES_PATH {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.kernel_modules_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "cp0_build.kernel_modules_path must be '{}'",
                CP0_REQUIRED_KERNEL_MODULES_PATH
            ),
        );
    }

    if cp0.module_install_path != CP0_REQUIRED_MODULE_INSTALL_PATH {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.module_install_path",
            ViolationCode::UnsupportedModuleInstallPath,
            format!(
                "cp0_build.module_install_path must be '{}' to enforce cross-distro consistency",
                CP0_REQUIRED_MODULE_INSTALL_PATH
            ),
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(CheckpointId::Cp0),
        "cp0_build.kernel_version",
        &cp0.kernel_version,
    ) && !is_kernel_version_token(&cp0.kernel_version)
    {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.kernel_version",
            ViolationCode::InvalidKernelProvenance,
            "cp0_build.kernel_version must be digits/dot format (for example 6.12.71)",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(CheckpointId::Cp0),
        "cp0_build.kernel_sha256",
        &cp0.kernel_sha256,
    ) && !is_sha256_hex(&cp0.kernel_sha256)
    {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.kernel_sha256",
            ViolationCode::InvalidKernelProvenance,
            "cp0_build.kernel_sha256 must be a 64-character hex SHA256",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(CheckpointId::Cp0),
        "cp0_build.kernel_localversion",
        &cp0.kernel_localversion,
    ) && (cp0.kernel_localversion.len() < 2
        || !cp0.kernel_localversion.starts_with('-')
        || cp0
            .kernel_localversion
            .chars()
            .skip(1)
            .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_'))
    {
        push_violation(
            violations,
            Some(CheckpointId::Cp0),
            "cp0_build.kernel_localversion",
            ViolationCode::InvalidKernelProvenance,
            "cp0_build.kernel_localversion must be '-' followed by lowercase alnum/underscore",
        );
    }

    validate_evidence(
        violations,
        CheckpointId::Cp0,
        "cp0_build.evidence",
        &cp0.evidence.script_path,
        &cp0.evidence.pass_marker,
        "checkpoint-0-",
    );
}

/// Validate a conformance contract and return a full report.
///
/// CP0-only phase:
/// - validates schema version
/// - validates identity token shape
/// - validates CP0 build-capability declaration
/// - does not execute CP1-CP8 runtime checkpoint validation
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

    validate_cp0_build(&mut violations, contract);

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
            checkpoints: CheckpointContract {
                cp0_build: BuildCapabilityCheckpoint {
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
                        script_path: "checkpoint-0-build-capability.sh".to_string(),
                        pass_marker: "CHECKPOINT 0 PASSED".to_string(),
                    },
                },
                cp1_live_boot: BootCheckpoint {
                    success_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-1-live-boot.sh".to_string(),
                        pass_marker: "CHECKPOINT 1 PASSED".to_string(),
                    },
                },
                cp2_live_tools: ToolsCheckpoint {
                    required_tools: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-2-live-tools.sh".to_string(),
                        pass_marker: "CHECKPOINT 2 PASSED".to_string(),
                    },
                },
                cp3_install: InstallCheckpoint {
                    required_tools: vec!["ignored-in-cp0-phase".to_string()],
                    required_services: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-3-installation.sh".to_string(),
                        pass_marker: "CHECKPOINT 3 PASSED".to_string(),
                    },
                },
                cp4_installed_boot: BootCheckpoint {
                    success_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    fatal_patterns: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-4-installed-boot.sh".to_string(),
                        pass_marker: "CHECKPOINT 4 PASSED".to_string(),
                    },
                },
                cp5_automated_login: AutomatedLoginCheckpoint {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("ignored".to_string()),
                    default_password: Some("ignored".to_string()),
                    login_prompt_pattern: "ignored-in-cp0-phase".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-5-automated-login.sh".to_string(),
                        pass_marker: "CHECKPOINT 5 PASSED".to_string(),
                    },
                },
                cp6_installed_tools: ToolsCheckpoint {
                    required_tools: vec!["ignored-in-cp0-phase".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-6-daily-driver.sh".to_string(),
                        pass_marker: "CHECKPOINT 6 PASSED".to_string(),
                    },
                },
                cp7_runtime_policy: RuntimePolicyCheckpoint {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec![],
                    immutable_required_ro_paths: vec![],
                },
                cp8_release: ReleaseCheckpoint {
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
    fn cp0_requires_recipe_rhai_kernel_orchestration() {
        let mut contract = valid_contract();
        contract.checkpoints.cp0_build.recipe_kernel_script = "linux.rhai".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::RecipeKernelOrchestrationRequired));
    }

    #[test]
    fn cp0_requires_baseline_build_tools() {
        let mut contract = valid_contract();
        contract
            .checkpoints
            .cp0_build
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
    fn cp0_requires_usrmerge_module_install_path() {
        let mut contract = valid_contract();
        contract.checkpoints.cp0_build.module_install_path = "/lib/modules".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UnsupportedModuleInstallPath));
    }
}
