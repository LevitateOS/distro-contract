//! Contract validation engine.
//!
//! Validates canonical build, source, transform, release, and scenario owners.

use std::collections::HashSet;

use crate::build_host::{
    EVIDENCE_SCRIPT_PREFIX, REQUIRED_KERNEL_IMAGE_PATH,
    REQUIRED_KERNEL_MODULES_PATH, REQUIRED_KERNEL_RELEASE_PATH, REQUIRED_MODULE_INSTALL_PATH,
    REQUIRED_RECIPE_INVOCATION, REQUIRED_VARIANT_KCONFIG,
};
use crate::error::{ConformanceError, ConformanceReport, ContractScope, Violation, ViolationCode};
use crate::schema::{
    ConformanceContract, RootfsSourceKind, BOOT_REQUIRED_KERNEL_CMDLINE_BASE,
    BOOT_REQUIRED_LIVE_SERVICES_BASE, CONTRACT_SCHEMA_VERSION,
};

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
const FORBIDDEN_BUILD_ROOTFS_TOKEN: &str = "squashfs";
const BUILD_REQUIRED_TOOLS_FIELD: &str = "build.required_build_tools";
const BUILD_KERNEL_KCONFIG_FIELD: &str = "build.kernel.kconfig_path";
const BUILD_KERNEL_RECIPE_SCRIPT_FIELD: &str = "build.kernel.recipe_script";
const BUILD_KERNEL_RECIPE_INVOCATION_FIELD: &str = "build.kernel.recipe_invocation";
const BUILD_KERNEL_RELEASE_FIELD: &str = "build.kernel.release_path";
const BUILD_KERNEL_IMAGE_FIELD: &str = "build.kernel.image_path";
const BUILD_KERNEL_MODULES_FIELD: &str = "build.kernel.modules_path";
const BUILD_KERNEL_VERSION_FIELD: &str = "build.kernel.version";
const BUILD_KERNEL_SHA256_FIELD: &str = "build.kernel.sha256";
const BUILD_KERNEL_LOCALVERSION_FIELD: &str = "build.kernel.localversion";
const BUILD_KERNEL_MODULE_INSTALL_FIELD: &str = "build.kernel.module_install_path";
const BUILD_EVIDENCE_FIELD: &str = "build.evidence";
const ROOTFS_SOURCE_KIND_FIELD: &str = "sources.rootfs_source.kind";
const ROOTFS_SOURCE_RECIPE_SCRIPT_FIELD: &str = "sources.rootfs_source.recipe_script";
const ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD: &str =
    "sources.rootfs_source.preseed_recipe_script";
const ROOTFS_SOURCE_DEFINES_FIELD: &str = "sources.rootfs_source.defines";
const BUILD_RUNTIME_REQUIRED_INPUTS_FIELD: &str = "transforms.build_runtime.required_inputs";
const LIVE_UKI_PRIMARY_OUTPUT_FIELD: &str = "transforms.live_uki.output_names[0]";
const LIVE_UKI_EMERGENCY_OUTPUT_FIELD: &str = "transforms.live_uki.output_names[1]";
const LIVE_UKI_DEBUG_OUTPUT_FIELD: &str = "transforms.live_uki.output_names[2]";
const LIVE_UKI_EXTRA_CMDLINE_FIELD: &str = "transforms.live_uki.extra_cmdline";
const LIVE_BOOT_EVIDENCE_FIELD: &str = "scenarios.live_boot.evidence";
const LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD: &str = "scenarios.live_boot.required_kernel_cmdline";
const LIVE_BOOT_REQUIRED_SERVICES_FIELD: &str = "scenarios.live_boot.required_live_services";
const LIVE_ENVIRONMENT_REQUIRED_SERVICES_FIELD: &str =
    "scenarios.live_environment.required_services";
const LIVE_TOOLS_EVIDENCE_FIELD: &str = "scenarios.live_tools.evidence";
const INSTALL_EVIDENCE_FIELD: &str = "scenarios.install.evidence";
const INSTALLED_BOOT_EVIDENCE_FIELD: &str = "scenarios.installed_boot.evidence";
const AUTOMATED_LOGIN_EVIDENCE_FIELD: &str = "scenarios.automated_login.evidence";
const INSTALLED_TOOLS_EVIDENCE_FIELD: &str = "scenarios.installed_tools.evidence";

fn push_violation(
    violations: &mut Vec<Violation>,
    scope: Option<ContractScope>,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    violations.push(Violation {
        scope,
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
    scope: Option<ContractScope>,
    field: &str,
    value: &str,
) -> bool {
    if value.trim().is_empty() {
        push_violation(
            violations,
            scope,
            field,
            ViolationCode::MissingValue,
            format!("{field} must be non-empty"),
        );
        return false;
    }
    if value != value.trim() {
        push_violation(
            violations,
            scope,
            field,
            ViolationCode::WhitespaceValue,
            format!("{field} must not include leading/trailing whitespace"),
        );
        return false;
    }
    if is_placeholder_token(value) {
        push_violation(
            violations,
            scope,
            field,
            ViolationCode::PlaceholderValue,
            format!("{field} must not be a placeholder token"),
        );
        return false;
    }

    true
}

fn contains_forbidden_build_rootfs_token(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(FORBIDDEN_BUILD_ROOTFS_TOKEN)
}

fn first_transform_output<'a>(
    violations: &mut Vec<Violation>,
    field: &'static str,
    outputs: &'a [String],
) -> Option<&'a str> {
    outputs.first().map(String::as_str).or_else(|| {
        push_violation(
            violations,
            None,
            field,
            ViolationCode::MissingValue,
            format!("{field} must contain at least one output name"),
        );
        None
    })
}

fn live_uki_output<'a>(
    violations: &mut Vec<Violation>,
    field: &'static str,
    outputs: &'a [String],
    index: usize,
) -> Option<&'a str> {
    outputs.get(index).map(String::as_str).or_else(|| {
        push_violation(
            violations,
            Some(ContractScope::Build),
            field,
            ViolationCode::MissingValue,
            format!("{field} must mirror transforms.live_uki.output_names[{index}]"),
        );
        None
    })
}

fn expected_build_runtime_required_inputs<'a>(
    violations: &mut Vec<Violation>,
    contract: &'a ConformanceContract,
) -> Vec<&'a str> {
    let mut values = Vec::new();
    if let Some(rootfs) = first_transform_output(
        violations,
        "transforms.rootfs_image.output_names",
        &contract.transforms.rootfs_image.output_names,
    ) {
        values.push(rootfs);
    }
    if let Some(initramfs_live) = first_transform_output(
        violations,
        "transforms.initramfs_live.output_names",
        &contract.transforms.initramfs_live.output_names,
    ) {
        values.push(initramfs_live);
    }
    if let Some(overlay) = first_transform_output(
        violations,
        "transforms.overlay_image.output_names",
        &contract.transforms.overlay_image.output_names,
    ) {
        values.push(overlay);
    }
    values
}

fn validate_artifact_identity_mirrors(
    violations: &mut Vec<Violation>,
    contract: &ConformanceContract,
) {
    if let Some(rootfs_name) = first_transform_output(
        violations,
        "transforms.rootfs_image.output_names",
        &contract.transforms.rootfs_image.output_names,
    ) {
        if contract.artifacts.rootfs_name != rootfs_name {
            push_violation(
                violations,
                None,
                "artifacts.rootfs_name",
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "artifacts.rootfs_name must mirror transforms.rootfs_image.output_names[0] ('{}')",
                    rootfs_name
                ),
            );
        }
    }

    if let Some(initramfs_live_name) = first_transform_output(
        violations,
        "transforms.initramfs_live.output_names",
        &contract.transforms.initramfs_live.output_names,
    ) {
        if contract.artifacts.initramfs_live_output != initramfs_live_name {
            push_violation(
                violations,
                None,
                "artifacts.initramfs_live_output",
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "artifacts.initramfs_live_output must mirror transforms.initramfs_live.output_names[0] ('{}')",
                    initramfs_live_name
                ),
            );
        }
    }

    if let Some(iso_name) = first_transform_output(
        violations,
        "transforms.iso.output_names",
        &contract.transforms.iso.output_names,
    ) {
        if contract.artifacts.iso_filename != iso_name {
            push_violation(
                violations,
                None,
                "artifacts.iso_filename",
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "artifacts.iso_filename must mirror transforms.iso.output_names[0] ('{}')",
                    iso_name
                ),
            );
        }
    }

    let installed_transform_output = contract
        .transforms
        .initramfs_installed
        .as_ref()
        .and_then(|transform| transform.output_names.first())
        .cloned();
    if contract.artifacts.initramfs_installed_output != installed_transform_output {
        let expected = installed_transform_output.as_deref().unwrap_or("<none>");
        push_violation(
            violations,
            None,
            "artifacts.initramfs_installed_output",
            ViolationCode::InvalidPathDeclaration,
            format!(
                "artifacts.initramfs_installed_output must mirror transforms.initramfs_installed.output_names[0] ('{}')",
                expected
            ),
        );
    }

    let installed_uki_outputs = contract
        .transforms
        .installed_uki
        .as_ref()
        .map(|transform| transform.output_names.clone())
        .unwrap_or_default();
    if contract.artifacts.installed_uki_outputs != installed_uki_outputs {
        push_violation(
            violations,
            None,
            "artifacts.installed_uki_outputs",
            ViolationCode::InvalidPathDeclaration,
            format!(
                "artifacts.installed_uki_outputs must mirror transforms.installed_uki.output_names ({:?})",
                installed_uki_outputs
            ),
        );
    }

    let disk_image_output = contract
        .transforms
        .disk_image
        .as_ref()
        .and_then(|transform| transform.output_names.first())
        .cloned();
    if contract.artifacts.disk_image_output != disk_image_output {
        let expected = disk_image_output.as_deref().unwrap_or("<none>");
        push_violation(
            violations,
            None,
            "artifacts.disk_image_output",
            ViolationCode::InvalidPathDeclaration,
            format!(
                "artifacts.disk_image_output must mirror transforms.disk_image.output_names[0] ('{}')",
                expected
            ),
        );
    }
}

fn validate_release_outputs(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let mut expected_primary_outputs = Vec::new();
    if let Some(iso_output) = first_transform_output(
        violations,
        "transforms.iso.output_names",
        &contract.transforms.iso.output_names,
    ) {
        expected_primary_outputs.push(iso_output.to_string());
    }
    if let Some(disk_image) = contract.transforms.disk_image.as_ref() {
        if let Some(disk_output) = first_transform_output(
            violations,
            "transforms.disk_image.output_names",
            &disk_image.output_names,
        ) {
            expected_primary_outputs.push(disk_output.to_string());
        }
    }
    if contract.release.primary_outputs != expected_primary_outputs {
        push_violation(
            violations,
            None,
            "release.primary_outputs",
            ViolationCode::InvalidPathDeclaration,
            format!(
                "release.primary_outputs must mirror Ring 0 final outputs ({:?})",
                expected_primary_outputs
            ),
        );
    }

    let primary: HashSet<&str> = contract
        .release
        .primary_outputs
        .iter()
        .map(String::as_str)
        .collect();
    let supporting: HashSet<&str> = contract
        .release
        .supporting_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(overlap) = primary.intersection(&supporting).next() {
        push_violation(
            violations,
            None,
            "release.supporting_artifacts",
            ViolationCode::DuplicateEntry,
            format!(
                "release.primary_outputs and release.supporting_artifacts must not overlap ('{}')",
                overlap
            ),
        );
    }

    let metadata_outputs: HashSet<&str> = contract
        .release
        .metadata_outputs
        .iter()
        .map(String::as_str)
        .collect();
    let metadata_facts: HashSet<&str> = contract
        .release
        .metadata_facts
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(overlap) = metadata_outputs.intersection(&metadata_facts).next() {
        push_violation(
            violations,
            None,
            "release.metadata_facts",
            ViolationCode::DuplicateEntry,
            format!(
                "release.metadata_outputs and release.metadata_facts must not overlap ('{}')",
                overlap
            ),
        );
    }
}

fn validate_unique_values(
    violations: &mut Vec<Violation>,
    scope: Option<ContractScope>,
    field: &str,
    values: &[String],
) {
    if values.is_empty() {
        push_violation(
            violations,
            scope,
            field,
            ViolationCode::MissingValue,
            format!("{field} must be non-empty"),
        );
        return;
    }

    let mut seen = HashSet::new();
    for value in values {
        validate_non_empty_trimmed(violations, scope, field, value);
        if !seen.insert(value) {
            push_violation(
                violations,
                scope,
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
    scope: Option<ContractScope>,
    field: &str,
    values: &[String],
) {
    validate_unique_values(violations, scope, field, values);

    for value in values {
        if !is_command_token(value) {
            push_violation(
                violations,
                scope,
                field,
                ViolationCode::InvalidToken,
                format!("{field} value '{value}' is not a valid command token"),
            );
        }
    }
}

fn validate_kernel_cmdline_tokens(
    violations: &mut Vec<Violation>,
    scope: ContractScope,
    field: &str,
    values: &[String],
) {
    let mut seen = HashSet::new();
    for value in values {
        if !validate_non_empty_trimmed(violations, Some(scope), field, value) {
            continue;
        }

        if value.contains(char::is_whitespace) {
            push_violation(
                violations,
                Some(scope),
                field,
                ViolationCode::InvalidToken,
                format!("{field} value '{value}' must be a single cmdline token"),
            );
        }
        if !seen.insert(value) {
            push_violation(
                violations,
                Some(scope),
                field,
                ViolationCode::DuplicateEntry,
                format!("{field} contains duplicate value '{value}'"),
            );
        }
    }
}

fn validate_evidence(
    violations: &mut Vec<Violation>,
    scope: ContractScope,
    field_prefix: &str,
    script_path: &str,
    pass_marker: &str,
    expected_script_prefix: &str,
) {
    let script_field = format!("{field_prefix}.script_path");
    let marker_field = format!("{field_prefix}.pass_marker");

    let script_ok = validate_non_empty_trimmed(violations, Some(scope), &script_field, script_path);
    let marker_ok = validate_non_empty_trimmed(violations, Some(scope), &marker_field, pass_marker);
    let mut script_filename = None;

    if script_ok {
        if !is_relative_contract_path(script_path) {
            push_violation(
                violations,
                Some(scope),
                &script_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{script_field} must be a safe relative script path"),
            );
        }
        script_filename = script_path.rsplit('/').next();
        let valid_filename = script_filename
            .filter(|filename| !filename.is_empty())
            .map(|filename| {
                filename.starts_with(expected_script_prefix) && filename.ends_with(".sh")
            })
            .unwrap_or(false);
        if !valid_filename {
            push_violation(
                violations,
                Some(scope),
                &script_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!(
                    "{script_field} basename must start with '{expected_script_prefix}' and end with '.sh'"
                ),
            );
        }
    }

    if marker_ok {
        let lowered = pass_marker.to_ascii_uppercase();
        if !lowered.contains("PASS") {
            push_violation(
                violations,
                Some(scope),
                &marker_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{marker_field} must contain PASS"),
            );
        } else if script_ok {
            let expected_marker =
                canonical_pass_marker_for_script(script_filename.unwrap_or(script_path));
            if pass_marker != expected_marker {
                push_violation(
                    violations,
                    Some(scope),
                    &marker_field,
                    ViolationCode::InvalidEvidenceDeclaration,
                    format!("{marker_field} must equal '{expected_marker}'"),
                );
            }
        }
    }
}

fn canonical_pass_marker_for_script(script_path: &str) -> String {
    let stem = script_path.strip_suffix(".sh").unwrap_or(script_path);
    let tokens: Vec<String> = stem
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_uppercase())
        .collect();
    format!("{} PASSED", tokens.join(" "))
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

fn is_safe_filename(value: &str) -> bool {
    !value.contains('/') && !value.contains('\\')
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

fn validate_relative_paths_allow_empty(
    violations: &mut Vec<Violation>,
    field: &str,
    values: &[String],
) {
    let mut seen = HashSet::new();
    for value in values {
        let ok = validate_non_empty_trimmed(violations, Some(ContractScope::Build), field, value);
        if !ok {
            continue;
        }

        if !seen.insert(value) {
            push_violation(
                violations,
                Some(ContractScope::Build),
                field,
                ViolationCode::DuplicateEntry,
                format!("{field} contains duplicate value '{value}'"),
            );
        }

        if !is_relative_contract_path(value) {
            push_violation(
                violations,
                Some(ContractScope::Build),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} value '{value}' must be a relative normalized path"),
            );
        }
    }
}

fn validate_build_runtime_non_kernel_inputs(
    violations: &mut Vec<Violation>,
    contract: &ConformanceContract,
) {
    let kernel = &contract.build.kernel;
    let required_field = BUILD_RUNTIME_REQUIRED_INPUTS_FIELD;
    let required_build_runtime: Vec<String> =
        expected_build_runtime_required_inputs(violations, contract)
            .into_iter()
            .map(str::to_string)
            .collect();

    if required_build_runtime.len() != 3 {
        push_violation(
            violations,
            Some(ContractScope::Build),
            required_field,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "{required_field} must derive exactly three build-runtime artifacts from Ring 1 transforms (rootfs, initramfs_live, overlay_image)"
            ),
        );
    }

    validate_relative_paths_allow_empty(violations, required_field, &required_build_runtime);

    let kernel_paths = [
        kernel.release_path.as_str(),
        kernel.image_path.as_str(),
        kernel.modules_path.as_str(),
    ];
    for value in &required_build_runtime {
        if kernel_paths.contains(&value.as_str()) {
            push_violation(
                violations,
                Some(ContractScope::Build),
                required_field,
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "'{value}' is a kernel artifact path and must not be declared in build-runtime non-kernel input buckets"
                ),
            );
        }
    }
}

fn validate_build_contract(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let build = &contract.build;
    let kernel = &build.kernel;

    validate_command_entries(
        violations,
        Some(ContractScope::Build),
        BUILD_REQUIRED_TOOLS_FIELD,
        &build.required_build_tools,
    );

    let kconfig_field = BUILD_KERNEL_KCONFIG_FIELD;
    if validate_non_empty_trimmed(
        violations,
        Some(ContractScope::Build),
        kconfig_field,
        &kernel.kconfig_path,
    ) && kernel.kconfig_path != REQUIRED_VARIANT_KCONFIG
    {
        push_violation(
            violations,
            Some(ContractScope::Build),
            kconfig_field,
            ViolationCode::InvalidPathDeclaration,
            format!(
                "{BUILD_KERNEL_KCONFIG_FIELD} must be exactly '{}'",
                REQUIRED_VARIANT_KCONFIG
            ),
        );
    }

    for (field, value) in [
        (
            BUILD_KERNEL_RECIPE_SCRIPT_FIELD,
            kernel.recipe_script.as_str(),
        ),
        (
            BUILD_KERNEL_RECIPE_INVOCATION_FIELD,
            kernel.recipe_invocation.as_str(),
        ),
        (BUILD_KERNEL_RELEASE_FIELD, kernel.release_path.as_str()),
        (BUILD_KERNEL_IMAGE_FIELD, kernel.image_path.as_str()),
        (BUILD_KERNEL_MODULES_FIELD, kernel.modules_path.as_str()),
    ] {
        if validate_non_empty_trimmed(violations, Some(ContractScope::Build), field, value)
            && !is_relative_contract_path(value)
        {
            push_violation(
                violations,
                Some(ContractScope::Build),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} must be a relative normalized path"),
            );
        }
    }

    if kernel.recipe_invocation != REQUIRED_RECIPE_INVOCATION {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_RECIPE_INVOCATION_FIELD,
            ViolationCode::RecipeKernelOrchestrationRequired,
            format!(
                "{BUILD_KERNEL_RECIPE_INVOCATION_FIELD} must be '{}'",
                REQUIRED_RECIPE_INVOCATION
            ),
        );
    }

    if kernel.release_path != REQUIRED_KERNEL_RELEASE_PATH {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_RELEASE_FIELD,
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "{BUILD_KERNEL_RELEASE_FIELD} must be '{}'",
                REQUIRED_KERNEL_RELEASE_PATH
            ),
        );
    }
    if kernel.image_path != REQUIRED_KERNEL_IMAGE_PATH {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_IMAGE_FIELD,
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "{BUILD_KERNEL_IMAGE_FIELD} must be '{}'",
                REQUIRED_KERNEL_IMAGE_PATH
            ),
        );
    }
    if kernel.modules_path != REQUIRED_KERNEL_MODULES_PATH {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_MODULES_FIELD,
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "{BUILD_KERNEL_MODULES_FIELD} must be '{}'",
                REQUIRED_KERNEL_MODULES_PATH
            ),
        );
    }

    if kernel.module_install_path != REQUIRED_MODULE_INSTALL_PATH {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_MODULE_INSTALL_FIELD,
            ViolationCode::UnsupportedModuleInstallPath,
            format!(
                "{BUILD_KERNEL_MODULE_INSTALL_FIELD} must be '{}' to enforce cross-distro consistency",
                REQUIRED_MODULE_INSTALL_PATH
            ),
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(ContractScope::Build),
        BUILD_KERNEL_VERSION_FIELD,
        &kernel.version,
    ) && !is_kernel_version_token(&kernel.version)
    {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_VERSION_FIELD,
            ViolationCode::InvalidKernelProvenance,
            "build.kernel.version must be digits/dot format (for example 6.12.71)",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(ContractScope::Build),
        BUILD_KERNEL_SHA256_FIELD,
        &kernel.sha256,
    ) && !is_sha256_hex(&kernel.sha256)
    {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_SHA256_FIELD,
            ViolationCode::InvalidKernelProvenance,
            "build.kernel.sha256 must be a 64-character hex SHA256",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(ContractScope::Build),
        BUILD_KERNEL_LOCALVERSION_FIELD,
        &kernel.localversion,
    ) && (kernel.localversion.len() < 2
        || !kernel.localversion.starts_with('-')
        || kernel
            .localversion
            .chars()
            .skip(1)
            .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_'))
    {
        push_violation(
            violations,
            Some(ContractScope::Build),
            BUILD_KERNEL_LOCALVERSION_FIELD,
            ViolationCode::InvalidKernelProvenance,
            "build.kernel.localversion must be '-' followed by lowercase alnum/underscore",
        );
    }

    validate_evidence(
        violations,
        ContractScope::Build,
        BUILD_EVIDENCE_FIELD,
        &build.evidence.script_path,
        &build.evidence.pass_marker,
        EVIDENCE_SCRIPT_PREFIX,
    );

    for (index, field) in [
        (0usize, LIVE_UKI_PRIMARY_OUTPUT_FIELD),
        (1usize, LIVE_UKI_EMERGENCY_OUTPUT_FIELD),
        (2usize, LIVE_UKI_DEBUG_OUTPUT_FIELD),
    ] {
        let Some(value) = live_uki_output(
            violations,
            field,
            &contract.transforms.live_uki.output_names,
            index,
        ) else {
            continue;
        };
        if !validate_non_empty_trimmed(violations, Some(ContractScope::Build), field, value) {
            continue;
        }
        if !value.ends_with(".efi") {
            push_violation(
                violations,
                Some(ContractScope::Build),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} must end with '.efi'"),
            );
        }
        if !is_safe_filename(value) {
            push_violation(
                violations,
                Some(ContractScope::Build),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} must be a filename without path separators"),
            );
        }
    }
    let live_cmdline = contract
        .transforms
        .live_uki
        .extra_cmdline
        .as_deref()
        .unwrap_or_default();
    if live_cmdline != live_cmdline.trim() {
        push_violation(
            violations,
            Some(ContractScope::Build),
            LIVE_UKI_EXTRA_CMDLINE_FIELD,
            ViolationCode::WhitespaceValue,
            "transforms.live_uki.extra_cmdline must not include leading/trailing whitespace",
        );
    }

    validate_build_runtime_non_kernel_inputs(violations, contract);
}

fn validate_ring3_sources(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let rootfs_source = &contract.sources.rootfs_source;
    if rootfs_source
        .storage_max_objects
        .is_some_and(|objects| !(1..=1_000_000).contains(&objects))
    {
        push_violation(
            violations,
            None,
            "sources.rootfs_source.storage_max_objects",
            ViolationCode::InvalidToken,
            "recipe storage object limit must be between 1 and 1000000",
        );
    }
    for (field, value) in [
        ("sources.rootfs_source.memory_mib", rootfs_source.memory_mib),
        (
            "sources.rootfs_source.preseed_memory_mib",
            rootfs_source.preseed_memory_mib,
        ),
    ] {
        if value.is_some_and(|mib| !(16..=1_048_576).contains(&mib)) {
            push_violation(
                violations,
                None,
                field,
                ViolationCode::InvalidToken,
                "recipe memory limit must be between 16 and 1048576 MiB",
            );
        }
    }

    if validate_non_empty_trimmed(
        violations,
        None,
        ROOTFS_SOURCE_RECIPE_SCRIPT_FIELD,
        &rootfs_source.recipe_script,
    ) && !is_relative_contract_path(&rootfs_source.recipe_script)
    {
        push_violation(
            violations,
            None,
            ROOTFS_SOURCE_RECIPE_SCRIPT_FIELD,
            ViolationCode::InvalidPathDeclaration,
            format!("{ROOTFS_SOURCE_RECIPE_SCRIPT_FIELD} must be a relative normalized path"),
        );
    }

    if let Some(preseed_recipe_script) = rootfs_source.preseed_recipe_script.as_deref() {
        if validate_non_empty_trimmed(
            violations,
            None,
            ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
            preseed_recipe_script,
        ) && !is_relative_contract_path(preseed_recipe_script)
        {
            push_violation(violations, None, ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
                ViolationCode::InvalidPathDeclaration,
                format!("{ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD} must be a relative normalized path"));
        }
        if rootfs_source.preseed_outputs.is_empty() {
            push_violation(violations, None, "sources.rootfs_source.preseed_outputs",
                ViolationCode::MissingValue,
                "sources.rootfs_source.preseed_outputs must declare required product names and kinds");
        }
    } else {
        if rootfs_source.kind == RootfsSourceKind::RecipeRpmSet {
            push_violation(violations, None, ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
                ViolationCode::MissingValue,
                format!("{ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD} is required for {ROOTFS_SOURCE_KIND_FIELD} = 'recipe_rpm_set'"));
        }
        if !rootfs_source.preseed_outputs.is_empty() {
            push_violation(
                violations,
                None,
                "sources.rootfs_source.preseed_outputs",
                ViolationCode::InvalidToken,
                "preseed_outputs requires an explicit preseed_recipe_script",
            );
        }
    }
    for name in rootfs_source.preseed_outputs.keys() {
        validate_non_empty_trimmed(
            violations,
            None,
            "sources.rootfs_source.preseed_outputs",
            name,
        );
    }
    if rootfs_source.kind == RootfsSourceKind::RecipeRpmSet && !rootfs_source.defines.is_empty() {
        push_violation(violations, None, ROOTFS_SOURCE_DEFINES_FIELD,
            ViolationCode::InvalidToken,
            format!("{ROOTFS_SOURCE_DEFINES_FIELD} must be empty when {ROOTFS_SOURCE_KIND_FIELD} = 'recipe_rpm_set'"));
    }
    match (&rootfs_source.rpm_base, rootfs_source.kind) {
        (None, RootfsSourceKind::RecipeRpmSet) => push_violation(
            violations,
            None,
            "sources.rootfs_source.rpm_base",
            ViolationCode::MissingValue,
            "sources.rootfs_source.rpm_base is required for kind = 'recipe_rpm_set'",
        ),
        (Some(_), RootfsSourceKind::RecipeCustom) => push_violation(
            violations,
            None,
            "sources.rootfs_source.rpm_base",
            ViolationCode::InvalidToken,
            "sources.rootfs_source.rpm_base only applies to kind = 'recipe_rpm_set'",
        ),
        (Some(base), RootfsSourceKind::RecipeRpmSet) => {
            if base.fedora_release == 0 {
                push_violation(violations, None, "sources.rootfs_source.rpm_base.fedora_release",
                    ViolationCode::MissingValue, "rpm_base.fedora_release must name a Fedora release");
            }
            if !is_relative_contract_path(&base.signing_key) {
                push_violation(violations, None, "sources.rootfs_source.rpm_base.signing_key",
                    ViolationCode::InvalidPathDeclaration,
                    "rpm_base.signing_key must be a relative normalized path to the release key");
            }
            if base.packages.is_empty() {
                push_violation(violations, None, "sources.rootfs_source.rpm_base.packages",
                    ViolationCode::MissingValue, "rpm_base.packages must list the packages taken from the base");
            }
            let mut seen = std::collections::BTreeSet::new();
            for name in &base.packages {
                validate_non_empty_trimmed(violations, None, "sources.rootfs_source.rpm_base.packages", name);
                if !seen.insert(name.as_str()) {
                    push_violation(violations, None, "sources.rootfs_source.rpm_base.packages",
                        ViolationCode::InvalidToken, format!("rpm_base.packages lists '{name}' twice"));
                }
            }
        }
        (None, RootfsSourceKind::RecipeCustom) => {}
    }

    for (name, path) in &rootfs_source.inputs {
        let field = format!("sources.rootfs_source.inputs.{name}");
        validate_non_empty_trimmed(violations, None, &field, path);
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            push_violation(
                violations,
                None,
                &field,
                ViolationCode::InvalidToken,
                "recipe input names must contain only ASCII letters, digits, underscore or hyphen",
            );
        }
    }

    for (key, value) in &rootfs_source.defines {
        let key_ok = validate_non_empty_trimmed(violations, None, ROOTFS_SOURCE_DEFINES_FIELD, key);
        let field = format!("{ROOTFS_SOURCE_DEFINES_FIELD}.{key}");
        let value_ok = validate_non_empty_trimmed(violations, None, &field, value);
        if key_ok
            && !key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            push_violation(
                violations,
                None,
                ROOTFS_SOURCE_DEFINES_FIELD,
                ViolationCode::InvalidToken,
                format!(
                    "{ROOTFS_SOURCE_DEFINES_FIELD} key '{key}' must use ASCII uppercase, digits, or underscore"
                ),
            );
        }
        if !value_ok {
            continue;
        }
    }
}

fn validate_build_erofs_boundary(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let rootfs_field = "artifacts.rootfs_name";
    if validate_non_empty_trimmed(
        violations,
        None,
        rootfs_field,
        &contract.artifacts.rootfs_name,
    ) {
        let rootfs_name = contract.artifacts.rootfs_name.as_str();
        if contains_forbidden_build_rootfs_token(rootfs_name) {
            push_violation(
                violations,
                None,
                rootfs_field,
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "{rootfs_field} must declare an EROFS artifact; squashfs naming is forbidden ({rootfs_name})"
                ),
            );
        }
        if !rootfs_name.ends_with(".erofs") {
            push_violation(
                violations,
                None,
                rootfs_field,
                ViolationCode::InvalidPathDeclaration,
                format!("{rootfs_field} must end with '.erofs'"),
            );
        }
    }

    let required_inputs_field = BUILD_RUNTIME_REQUIRED_INPUTS_FIELD;
    for item in expected_build_runtime_required_inputs(violations, contract) {
        if contains_forbidden_build_rootfs_token(item) {
            push_violation(
                violations,
                Some(ContractScope::Build),
                required_inputs_field,
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "{required_inputs_field} contains forbidden squashfs artifact '{item}'; build-runtime payloads must be EROFS"
                ),
            );
        }
    }

    let required_tools_field = BUILD_REQUIRED_TOOLS_FIELD;
    for tool in &contract.build.required_build_tools {
        if contains_forbidden_build_rootfs_token(tool) {
            push_violation(
                violations,
                Some(ContractScope::Build),
                required_tools_field,
                ViolationCode::InvalidToken,
                format!(
                    "{required_tools_field} contains forbidden squashfs tool '{tool}'; build-runtime uses EROFS tooling"
                ),
            );
        }
    }
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

    validate_build_erofs_boundary(&mut violations, contract);
    validate_ring3_sources(&mut violations, contract);
    validate_artifact_identity_mirrors(&mut violations, contract);
    validate_release_outputs(&mut violations, contract);
    validate_build_runtime_non_kernel_inputs(&mut violations, contract);
    validate_build_contract(&mut violations, contract);
    let live_boot = &contract.scenarios.live_boot;
    validate_evidence(
        &mut violations,
        ContractScope::LiveBoot,
        LIVE_BOOT_EVIDENCE_FIELD,
        &live_boot.evidence.script_path,
        &live_boot.evidence.pass_marker,
        "live-",
    );
    validate_kernel_cmdline_tokens(
        &mut violations,
        ContractScope::LiveBoot,
        LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD,
        &live_boot.required_kernel_cmdline,
    );
    validate_command_entries(
        &mut violations,
        Some(ContractScope::LiveBoot),
        LIVE_BOOT_REQUIRED_SERVICES_FIELD,
        &live_boot.required_live_services,
    );
    for token in BOOT_REQUIRED_KERNEL_CMDLINE_BASE {
        if !live_boot
            .required_kernel_cmdline
            .iter()
            .any(|candidate| candidate == token)
        {
            push_violation(
                &mut violations,
                Some(ContractScope::LiveBoot),
                LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD,
                ViolationCode::MissingValue,
                format!(
                    "{LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD} must include '{}'",
                    token
                ),
            );
        }
    }
    validate_command_entries(
        &mut violations,
        Some(ContractScope::LiveBoot),
        LIVE_ENVIRONMENT_REQUIRED_SERVICES_FIELD,
        &contract.scenarios.live_environment.required_services,
    );
    validate_evidence(
        &mut violations,
        ContractScope::LiveTools,
        LIVE_TOOLS_EVIDENCE_FIELD,
        &contract.scenarios.live_tools.evidence.script_path,
        &contract.scenarios.live_tools.evidence.pass_marker,
        "live-",
    );
    validate_evidence(
        &mut violations,
        ContractScope::Install,
        INSTALL_EVIDENCE_FIELD,
        &contract.scenarios.install.evidence.script_path,
        &contract.scenarios.install.evidence.pass_marker,
        "install",
    );
    validate_evidence(
        &mut violations,
        ContractScope::InstalledBoot,
        INSTALLED_BOOT_EVIDENCE_FIELD,
        &contract.scenarios.installed_boot.evidence.script_path,
        &contract.scenarios.installed_boot.evidence.pass_marker,
        "installed-",
    );
    validate_evidence(
        &mut violations,
        ContractScope::AutomatedLogin,
        AUTOMATED_LOGIN_EVIDENCE_FIELD,
        &contract.scenarios.automated_login.evidence.script_path,
        &contract.scenarios.automated_login.evidence.pass_marker,
        "automated-",
    );
    validate_evidence(
        &mut violations,
        ContractScope::Runtime,
        INSTALLED_TOOLS_EVIDENCE_FIELD,
        &contract.scenarios.installed_tools.evidence.script_path,
        &contract.scenarios.installed_tools.evidence.pass_marker,
        "installed-",
    );
    for service in BOOT_REQUIRED_LIVE_SERVICES_BASE {
        if !live_boot
            .required_live_services
            .iter()
            .any(|candidate| candidate == service)
        {
            push_violation(
                &mut violations,
                Some(ContractScope::LiveBoot),
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                ViolationCode::MissingValue,
                format!(
                    "{LIVE_BOOT_REQUIRED_SERVICES_FIELD} must include '{}'",
                    service
                ),
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
