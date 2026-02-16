//! Contract validation engine.

use std::collections::HashSet;

use crate::error::{CheckpointId, ConformanceError, ConformanceReport, Violation, ViolationCode};
use crate::schema::{AuthMode, ConformanceContract, RootfsMutability, CONTRACT_SCHEMA_VERSION};

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

const GENERIC_BOOT_SUCCESS_PATTERNS: &[&str] = &[
    "login:",
    "___prompt___",
    "___shell_ready___",
    "multi-user.target",
    "[autologin]",
    "welcome",
];

const CP8_REQUIRED_METADATA_BASELINE: &[&str] = &[
    "kernel_source.version",
    "kernel_source.sha256",
    "kernel_source.localversion",
    "artifact.rootfs_name",
    "artifact.iso_filename",
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

fn is_service_token(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '@'))
}

fn validate_service_entries(
    violations: &mut Vec<Violation>,
    checkpoint: Option<CheckpointId>,
    field: &str,
    values: &[String],
) {
    validate_unique_values(violations, checkpoint, field, values);

    for value in values {
        if !is_service_token(value) {
            push_violation(
                violations,
                checkpoint,
                field,
                ViolationCode::InvalidToken,
                format!("{field} value '{value}' is not a valid service token"),
            );
        }
    }
}

fn is_generic_success_pattern(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    if GENERIC_BOOT_SUCCESS_PATTERNS.contains(&lowered.as_str()) {
        return true;
    }

    lowered == "login" || lowered == "ready"
}

fn validate_boot_patterns(
    violations: &mut Vec<Violation>,
    checkpoint: CheckpointId,
    success_field: &str,
    success_patterns: &[String],
    fatal_field: &str,
    fatal_patterns: &[String],
) {
    validate_unique_values(
        violations,
        Some(checkpoint),
        success_field,
        success_patterns,
    );
    validate_unique_values(violations, Some(checkpoint), fatal_field, fatal_patterns);

    for pattern in success_patterns {
        if is_generic_success_pattern(pattern) {
            push_violation(
                violations,
                Some(checkpoint),
                success_field,
                ViolationCode::GenericSuccessPattern,
                format!(
                    "{success_field} contains generic boot pass marker '{pattern}' (must be distro-specific)"
                ),
            );
        }
    }

    let fatal_set: HashSet<&str> = fatal_patterns.iter().map(String::as_str).collect();
    for pattern in success_patterns {
        if fatal_set.contains(pattern.as_str()) {
            push_violation(
                violations,
                Some(checkpoint),
                success_field,
                ViolationCode::PatternSetOverlap,
                format!("{success_field} and {fatal_field} overlap at '{pattern}'"),
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

fn validate_absolute_paths(
    violations: &mut Vec<Violation>,
    checkpoint: CheckpointId,
    field: &str,
    paths: &[String],
) {
    validate_unique_values(violations, Some(checkpoint), field, paths);

    for value in paths {
        if !value.starts_with('/') {
            push_violation(
                violations,
                Some(checkpoint),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} value '{value}' must be an absolute path"),
            );
        }
        if value.contains("//") || value.contains("/../") || value.ends_with("/..") {
            push_violation(
                violations,
                Some(checkpoint),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} value '{value}' contains invalid path traversal"),
            );
        }
    }
}

fn validate_artifact_filename(violations: &mut Vec<Violation>, field: &str, value: &str) {
    if !validate_non_empty_trimmed(violations, None, field, value) {
        return;
    }

    if value.contains('/') || value.contains('\\') || value.contains("..") {
        push_violation(
            violations,
            None,
            field,
            ViolationCode::InvalidToken,
            format!("{field} must be a file name, got '{value}'"),
        );
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
    ) {
        if cp0.kernel_kconfig_path != "kconfig" {
            push_violation(
                violations,
                Some(CheckpointId::Cp0),
                kconfig_field,
                ViolationCode::InvalidPathDeclaration,
                "cp0_build.kernel_kconfig_path must be exactly 'kconfig'",
            );
        }
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
    ) {
        if !cp0.kernel_localversion.starts_with('-')
            || cp0
                .kernel_localversion
                .chars()
                .skip(1)
                .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_')
        {
            push_violation(
                violations,
                Some(CheckpointId::Cp0),
                "cp0_build.kernel_localversion",
                ViolationCode::InvalidKernelProvenance,
                "cp0_build.kernel_localversion must be '-' followed by lowercase alnum/underscore",
            );
        }
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

fn validate_metadata_key(key: &str) -> bool {
    let mut parts = key.split('.');
    let Some(first) = parts.next() else {
        return false;
    };

    if !matches!(
        first,
        "kernel_source" | "artifact" | "runtime" | "boot" | "qemu" | "tarball" | "checkpoint"
    ) {
        return false;
    }

    let mut saw_subkey = false;
    for part in parts {
        saw_subkey = true;
        if part.is_empty()
            || !part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return false;
        }
    }

    saw_subkey
}

/// Validate a conformance contract and return a full report.
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

    validate_artifact_filename(
        &mut violations,
        "artifacts.rootfs_name",
        &contract.artifacts.rootfs_name,
    );
    validate_artifact_filename(
        &mut violations,
        "artifacts.initramfs_live_output",
        &contract.artifacts.initramfs_live_output,
    );
    validate_artifact_filename(
        &mut violations,
        "artifacts.iso_filename",
        &contract.artifacts.iso_filename,
    );
    if let Some(value) = &contract.artifacts.initramfs_installed_output {
        validate_artifact_filename(
            &mut violations,
            "artifacts.initramfs_installed_output",
            value,
        );
    }

    validate_cp0_build(&mut violations, contract);

    let cp1 = &contract.checkpoints.cp1_live_boot;
    validate_boot_patterns(
        &mut violations,
        CheckpointId::Cp1,
        "cp1_live_boot.success_patterns",
        &cp1.success_patterns,
        "cp1_live_boot.fatal_patterns",
        &cp1.fatal_patterns,
    );
    validate_evidence(
        &mut violations,
        CheckpointId::Cp1,
        "cp1_live_boot.evidence",
        &cp1.evidence.script_path,
        &cp1.evidence.pass_marker,
        "checkpoint-1-",
    );

    let cp2 = &contract.checkpoints.cp2_live_tools;
    validate_command_entries(
        &mut violations,
        Some(CheckpointId::Cp2),
        "cp2_live_tools.required_tools",
        &cp2.required_tools,
    );
    validate_evidence(
        &mut violations,
        CheckpointId::Cp2,
        "cp2_live_tools.evidence",
        &cp2.evidence.script_path,
        &cp2.evidence.pass_marker,
        "checkpoint-2-",
    );

    let cp3 = &contract.checkpoints.cp3_install;
    validate_command_entries(
        &mut violations,
        Some(CheckpointId::Cp3),
        "cp3_install.required_tools",
        &cp3.required_tools,
    );
    validate_service_entries(
        &mut violations,
        Some(CheckpointId::Cp3),
        "cp3_install.required_services",
        &cp3.required_services,
    );
    validate_evidence(
        &mut violations,
        CheckpointId::Cp3,
        "cp3_install.evidence",
        &cp3.evidence.script_path,
        &cp3.evidence.pass_marker,
        "checkpoint-3-",
    );

    let cp2_tool_set: HashSet<&str> = cp2.required_tools.iter().map(String::as_str).collect();
    for tool in &cp3.required_tools {
        if !cp2_tool_set.contains(tool.as_str()) {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp3),
                "cp3_install.required_tools",
                ViolationCode::MissingCheckpointToolInLiveTools,
                format!(
                    "cp3_install.required_tools includes '{tool}' which is not declared in cp2_live_tools.required_tools"
                ),
            );
        }
    }

    let cp4 = &contract.checkpoints.cp4_installed_boot;
    validate_boot_patterns(
        &mut violations,
        CheckpointId::Cp4,
        "cp4_installed_boot.success_patterns",
        &cp4.success_patterns,
        "cp4_installed_boot.fatal_patterns",
        &cp4.fatal_patterns,
    );
    validate_evidence(
        &mut violations,
        CheckpointId::Cp4,
        "cp4_installed_boot.evidence",
        &cp4.evidence.script_path,
        &cp4.evidence.pass_marker,
        "checkpoint-4-",
    );

    let cp5 = &contract.checkpoints.cp5_automated_login;
    let login_prompt_ok = validate_non_empty_trimmed(
        &mut violations,
        Some(CheckpointId::Cp5),
        "cp5_automated_login.login_prompt_pattern",
        &cp5.login_prompt_pattern,
    );

    if login_prompt_ok {
        let lowered = cp5.login_prompt_pattern.to_ascii_lowercase();
        if lowered == "login:" || !lowered.contains("login") {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp5),
                "cp5_automated_login.login_prompt_pattern",
                ViolationCode::GenericSuccessPattern,
                "cp5 login prompt must be distro-specific and include login marker",
            );
        }
    }

    match cp5.auth_mode {
        AuthMode::DefaultPasswordLogin => {
            let username_ok = cp5.default_username.as_ref().is_some_and(|v| {
                validate_non_empty_trimmed(
                    &mut violations,
                    Some(CheckpointId::Cp5),
                    "cp5_automated_login.default_username",
                    v,
                )
            });
            let password_ok = cp5.default_password.as_ref().is_some_and(|v| {
                validate_non_empty_trimmed(
                    &mut violations,
                    Some(CheckpointId::Cp5),
                    "cp5_automated_login.default_password",
                    v,
                )
            });

            if !username_ok || !password_ok {
                push_violation(
                    &mut violations,
                    Some(CheckpointId::Cp5),
                    "cp5_automated_login.auth_mode",
                    ViolationCode::InvalidAuthDeclaration,
                    "DefaultPasswordLogin mode requires non-empty default_username and default_password",
                );
            }
        }
        AuthMode::ProvisionedCredentials => {
            if cp5.default_username.is_some() || cp5.default_password.is_some() {
                push_violation(
                    &mut violations,
                    Some(CheckpointId::Cp5),
                    "cp5_automated_login.auth_mode",
                    ViolationCode::InvalidAuthDeclaration,
                    "ProvisionedCredentials mode must not expose default_username/default_password",
                );
            }
        }
    }

    if !cp4
        .success_patterns
        .iter()
        .any(|value| value == &cp5.login_prompt_pattern)
    {
        push_violation(
            &mut violations,
            Some(CheckpointId::Cp5),
            "cp5_automated_login.login_prompt_pattern",
            ViolationCode::LoginPromptNotInInstalledBootPatterns,
            "cp5 login prompt must be included in cp4 installed boot success patterns",
        );
    }

    validate_evidence(
        &mut violations,
        CheckpointId::Cp5,
        "cp5_automated_login.evidence",
        &cp5.evidence.script_path,
        &cp5.evidence.pass_marker,
        "checkpoint-5-",
    );

    let cp6 = &contract.checkpoints.cp6_installed_tools;
    validate_command_entries(
        &mut violations,
        Some(CheckpointId::Cp6),
        "cp6_installed_tools.required_tools",
        &cp6.required_tools,
    );
    validate_evidence(
        &mut violations,
        CheckpointId::Cp6,
        "cp6_installed_tools.evidence",
        &cp6.evidence.script_path,
        &cp6.evidence.pass_marker,
        "checkpoint-6-",
    );

    let cp7 = &contract.checkpoints.cp7_runtime_policy;
    match cp7.rootfs_mutability {
        RootfsMutability::Mutable => {
            if !cp7.immutable_required_ro_paths.is_empty() {
                push_violation(
                    &mut violations,
                    Some(CheckpointId::Cp7),
                    "cp7_runtime_policy.immutable_required_ro_paths",
                    ViolationCode::InvalidPathDeclaration,
                    "mutable rootfs contracts must not define immutable_required_ro_paths",
                );
            }
            validate_absolute_paths(
                &mut violations,
                CheckpointId::Cp7,
                "cp7_runtime_policy.mutable_required_rw_paths",
                &cp7.mutable_required_rw_paths,
            );
        }
        RootfsMutability::Immutable => {
            if !cp7.mutable_required_rw_paths.is_empty() {
                push_violation(
                    &mut violations,
                    Some(CheckpointId::Cp7),
                    "cp7_runtime_policy.mutable_required_rw_paths",
                    ViolationCode::InvalidPathDeclaration,
                    "immutable rootfs contracts must not define mutable_required_rw_paths",
                );
            }
            validate_absolute_paths(
                &mut violations,
                CheckpointId::Cp7,
                "cp7_runtime_policy.immutable_required_ro_paths",
                &cp7.immutable_required_ro_paths,
            );
        }
    }

    let cp8 = &contract.checkpoints.cp8_release;
    validate_unique_values(
        &mut violations,
        Some(CheckpointId::Cp8),
        "cp8_release.required_artifacts",
        &cp8.required_artifacts,
    );
    for artifact in &cp8.required_artifacts {
        if artifact.contains('\\')
            || artifact.contains("..")
            || artifact.trim() != artifact
            || artifact.trim().is_empty()
        {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp8),
                "cp8_release.required_artifacts",
                ViolationCode::InvalidToken,
                format!(
                    "cp8_release.required_artifacts value '{artifact}' is not a stable artifact id"
                ),
            );
        }
    }

    let cp8_artifacts: HashSet<&str> = cp8.required_artifacts.iter().map(String::as_str).collect();
    for required in [
        contract.artifacts.rootfs_name.as_str(),
        contract.artifacts.initramfs_live_output.as_str(),
        contract.artifacts.iso_filename.as_str(),
    ] {
        if !cp8_artifacts.contains(required) {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp8),
                "cp8_release.required_artifacts",
                ViolationCode::MissingBaselineArtifact,
                format!("cp8_release.required_artifacts must include '{required}'"),
            );
        }
    }
    if let Some(value) = &contract.artifacts.initramfs_installed_output {
        if !cp8_artifacts.contains(value.as_str()) {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp8),
                "cp8_release.required_artifacts",
                ViolationCode::MissingBaselineArtifact,
                format!("cp8_release.required_artifacts must include '{value}'"),
            );
        }
    }

    validate_unique_values(
        &mut violations,
        Some(CheckpointId::Cp8),
        "cp8_release.required_metadata",
        &cp8.required_metadata,
    );
    let cp8_metadata: HashSet<&str> = cp8.required_metadata.iter().map(String::as_str).collect();

    for key in &cp8.required_metadata {
        if !validate_metadata_key(key) {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp8),
                "cp8_release.required_metadata",
                ViolationCode::InvalidMetadataKey,
                format!("cp8_release.required_metadata key '{key}' is invalid"),
            );
        }
    }

    for key in CP8_REQUIRED_METADATA_BASELINE {
        if !cp8_metadata.contains(key) {
            push_violation(
                &mut violations,
                Some(CheckpointId::Cp8),
                "cp8_release.required_metadata",
                ViolationCode::MissingBaselineMetadata,
                format!("cp8_release.required_metadata must include '{key}'"),
            );
        }
    }

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
                    success_patterns: vec!["ExampleOS Live Ready".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-1-live-boot.sh".to_string(),
                        pass_marker: "CHECKPOINT 1 PASSED".to_string(),
                    },
                },
                cp2_live_tools: ToolsCheckpoint {
                    required_tools: vec!["recstrap".to_string(), "mount".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-2-live-tools.sh".to_string(),
                        pass_marker: "CHECKPOINT 2 PASSED".to_string(),
                    },
                },
                cp3_install: InstallCheckpoint {
                    required_tools: vec!["recstrap".to_string(), "mount".to_string()],
                    required_services: vec!["networking".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-3-installation.sh".to_string(),
                        pass_marker: "CHECKPOINT 3 PASSED".to_string(),
                    },
                },
                cp4_installed_boot: BootCheckpoint {
                    success_patterns: vec!["exampleos login:".to_string()],
                    fatal_patterns: vec!["VFS: Cannot open root device".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-4-installed-boot.sh".to_string(),
                        pass_marker: "CHECKPOINT 4 PASSED".to_string(),
                    },
                },
                cp5_automated_login: AutomatedLoginCheckpoint {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("example".to_string()),
                    default_password: Some("example".to_string()),
                    login_prompt_pattern: "exampleos login:".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-5-automated-login.sh".to_string(),
                        pass_marker: "CHECKPOINT 5 PASSED".to_string(),
                    },
                },
                cp6_installed_tools: ToolsCheckpoint {
                    required_tools: vec!["sudo".to_string(), "ip".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "checkpoint-6-daily-driver.sh".to_string(),
                        pass_marker: "CHECKPOINT 6 PASSED".to_string(),
                    },
                },
                cp7_runtime_policy: RuntimePolicyCheckpoint {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec!["/etc".to_string(), "/var".to_string()],
                    immutable_required_ro_paths: vec![],
                },
                cp8_release: ReleaseCheckpoint {
                    required_artifacts: vec![
                        "exampleos.erofs".to_string(),
                        "initramfs-live.cpio.gz".to_string(),
                        "initramfs-installed.img".to_string(),
                        "exampleos.iso".to_string(),
                    ],
                    required_metadata: vec![
                        "kernel_source.version".to_string(),
                        "kernel_source.sha256".to_string(),
                        "kernel_source.localversion".to_string(),
                        "artifact.rootfs_name".to_string(),
                        "artifact.iso_filename".to_string(),
                    ],
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
    fn generic_boot_pattern_fails() {
        let mut contract = valid_contract();
        contract.checkpoints.cp1_live_boot.success_patterns = vec!["login:".to_string()];

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::GenericSuccessPattern));
    }

    #[test]
    fn cp3_tools_must_exist_in_cp2() {
        let mut contract = valid_contract();
        contract
            .checkpoints
            .cp3_install
            .required_tools
            .push("recchroot".to_string());

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingCheckpointToolInLiveTools));
    }

    #[test]
    fn cp5_login_prompt_must_match_cp4_patterns() {
        let mut contract = valid_contract();
        contract
            .checkpoints
            .cp5_automated_login
            .login_prompt_pattern = "example login:".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::LoginPromptNotInInstalledBootPatterns));
    }

    #[test]
    fn evidence_script_must_be_filename_with_checkpoint_prefix() {
        let mut contract = valid_contract();
        contract.checkpoints.cp2_live_tools.evidence.script_path =
            "scripts/checkpoint-2-live-tools.sh".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::InvalidEvidenceDeclaration));
    }

    #[test]
    fn cp8_requires_baseline_metadata_and_artifacts() {
        let mut contract = valid_contract();
        contract
            .checkpoints
            .cp8_release
            .required_metadata
            .retain(|key| key != "kernel_source.sha256");
        contract
            .checkpoints
            .cp8_release
            .required_artifacts
            .retain(|artifact| artifact != "exampleos.erofs");

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingBaselineMetadata));
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingBaselineArtifact));
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
