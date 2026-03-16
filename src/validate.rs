//! Contract validation engine.
//!
//! Current phase: Stage 00-only enforcement.
//! Stage 01-Stage 08 declarations may exist in the schema, but this validator only
//! executes Stage 00 build-capability conformance checks.

use std::collections::HashSet;

use crate::build_host_legacy::{
    EVIDENCE_SCRIPT_PREFIX, REQUIRED_BUILD_TOOLS_BASELINE, REQUIRED_KERNEL_IMAGE_PATH,
    REQUIRED_KERNEL_MODULES_PATH, REQUIRED_KERNEL_RELEASE_PATH, REQUIRED_MODULE_INSTALL_PATH,
    REQUIRED_RECIPE_INVOCATION, REQUIRED_VARIANT_KCONFIG,
};
use crate::error::{ConformanceError, ConformanceReport, StageId, Violation, ViolationCode};
use crate::schema::{
    ConformanceContract, RootfsSourceKind, CONTRACT_SCHEMA_VERSION,
    STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE, STAGE_01_REQUIRED_LIVE_SERVICES_BASE,
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
const FORBIDDEN_STAGE00_ROOTFS_TOKEN: &str = "squashfs";
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
const BUILD_RUNTIME_DEFERRED_LIVE_BOOT_FIELD: &str =
    "compatibility.build_runtime.deferred_live_boot_inputs";
const BUILD_RUNTIME_DEFERRED_LIVE_TOOLS_FIELD: &str =
    "compatibility.build_runtime.deferred_live_tools_inputs";
const BUILD_RUNTIME_DEFERRED_INSTALL_PLUS_FIELD: &str =
    "compatibility.build_runtime.deferred_install_plus_inputs";
const LIVE_UKI_PRIMARY_OUTPUT_FIELD: &str = "transforms.live_uki.output_names[0]";
const LIVE_UKI_EMERGENCY_OUTPUT_FIELD: &str = "transforms.live_uki.output_names[1]";
const LIVE_UKI_DEBUG_OUTPUT_FIELD: &str = "transforms.live_uki.output_names[2]";
const LIVE_UKI_EXTRA_CMDLINE_FIELD: &str = "transforms.live_uki.extra_cmdline";
const LIVE_BOOT_EVIDENCE_FIELD: &str = "scenarios.live_boot.evidence";
const LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD: &str = "scenarios.live_boot.required_kernel_cmdline";
const LIVE_BOOT_REQUIRED_SERVICES_FIELD: &str = "scenarios.live_boot.required_live_services";
const LIVE_TOOLS_EVIDENCE_FIELD: &str = "scenarios.live_tools.evidence";
const INSTALL_EVIDENCE_FIELD: &str = "scenarios.install.evidence";
const INSTALLED_BOOT_EVIDENCE_FIELD: &str = "scenarios.installed_boot.evidence";
const AUTOMATED_LOGIN_EVIDENCE_FIELD: &str = "scenarios.automated_login.evidence";
const INSTALLED_TOOLS_EVIDENCE_FIELD: &str = "scenarios.installed_tools.evidence";

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

fn contains_forbidden_stage00_rootfs_token(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(FORBIDDEN_STAGE00_ROOTFS_TOKEN)
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
            Some(StageId::Stage00),
            field,
            ViolationCode::MissingValue,
            format!("{field} must mirror transforms.live_uki.output_names[{index}]"),
        );
        None
    })
}

fn expected_stage_00_required_inputs<'a>(
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

fn validate_release_mirrors_stage_08(
    violations: &mut Vec<Violation>,
    contract: &ConformanceContract,
) {
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

fn validate_kernel_cmdline_tokens(
    violations: &mut Vec<Violation>,
    stage: StageId,
    field: &str,
    values: &[String],
) {
    let mut seen = HashSet::new();
    for value in values {
        if !validate_non_empty_trimmed(violations, Some(stage), field, value) {
            continue;
        }

        if value.contains(char::is_whitespace) {
            push_violation(
                violations,
                Some(stage),
                field,
                ViolationCode::InvalidToken,
                format!("{field} value '{value}' must be a single cmdline token"),
            );
        }
        if !seen.insert(value) {
            push_violation(
                violations,
                Some(stage),
                field,
                ViolationCode::DuplicateEntry,
                format!("{field} contains duplicate value '{value}'"),
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

    let script_ok = validate_non_empty_trimmed(violations, Some(stage), &script_field, script_path);
    let marker_ok = validate_non_empty_trimmed(violations, Some(stage), &marker_field, pass_marker);

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
        let valid_prefix = script_path.starts_with(expected_script_prefix);
        if !valid_prefix || !script_path.ends_with(".sh") {
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
        if !lowered.contains("PASS") {
            push_violation(
                violations,
                Some(stage),
                &marker_field,
                ViolationCode::InvalidEvidenceDeclaration,
                format!("{marker_field} must contain PASS"),
            );
        } else if script_ok {
            let expected_marker = canonical_pass_marker_for_script(script_path);
            if pass_marker != expected_marker {
                push_violation(
                    violations,
                    Some(stage),
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
        let ok = validate_non_empty_trimmed(violations, Some(StageId::Stage00), field, value);
        if !ok {
            continue;
        }

        if !seen.insert(value) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                field,
                ViolationCode::DuplicateEntry,
                format!("{field} contains duplicate value '{value}'"),
            );
        }

        if !is_relative_contract_path(value) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} value '{value}' must be a relative normalized path"),
            );
        }
    }
}

fn validate_stage_00_non_kernel_inputs(
    violations: &mut Vec<Violation>,
    contract: &ConformanceContract,
) {
    let kernel = &contract.build.kernel;
    let required_field = BUILD_RUNTIME_REQUIRED_INPUTS_FIELD;
    let stage01_field = BUILD_RUNTIME_DEFERRED_LIVE_BOOT_FIELD;
    let stage02_field = BUILD_RUNTIME_DEFERRED_LIVE_TOOLS_FIELD;
    let stage03_field = BUILD_RUNTIME_DEFERRED_INSTALL_PLUS_FIELD;
    let required_for_00build: Vec<String> = expected_stage_00_required_inputs(violations, contract)
        .into_iter()
        .map(str::to_string)
        .collect();
    let empty_group: Vec<String> = Vec::new();

    if required_for_00build.len() != 3 {
        push_violation(
            violations,
            Some(StageId::Stage00),
            required_field,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "{required_field} must derive exactly three Stage 00 artifacts from Ring 1 transforms (rootfs, initramfs_live, overlay_image)"
            ),
        );
    }

    validate_relative_paths_allow_empty(violations, required_field, &required_for_00build);
    validate_relative_paths_allow_empty(violations, stage01_field, &empty_group);
    validate_relative_paths_allow_empty(violations, stage02_field, &empty_group);
    validate_relative_paths_allow_empty(violations, stage03_field, &empty_group);

    let kernel_paths = [
        kernel.release_path.as_str(),
        kernel.image_path.as_str(),
        kernel.modules_path.as_str(),
    ];
    for value in &required_for_00build {
        if kernel_paths.contains(&value.as_str()) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                required_field,
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "'{value}' is a kernel artifact path and must not be declared in stage_00 non-kernel input buckets"
                ),
            );
        }
    }
}

fn validate_stage_00_build(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let build = &contract.build;
    let kernel = &build.kernel;

    validate_command_entries(
        violations,
        Some(StageId::Stage00),
        BUILD_REQUIRED_TOOLS_FIELD,
        &build.required_build_tools,
    );
    let stage_00_tools: HashSet<&str> = build
        .required_build_tools
        .iter()
        .map(String::as_str)
        .collect();
    for tool in REQUIRED_BUILD_TOOLS_BASELINE {
        if !stage_00_tools.contains(tool) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                BUILD_REQUIRED_TOOLS_FIELD,
                ViolationCode::MissingRequiredBuildTool,
                format!("{BUILD_REQUIRED_TOOLS_FIELD} must include '{tool}'"),
            );
        }
    }

    let kconfig_field = BUILD_KERNEL_KCONFIG_FIELD;
    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
        kconfig_field,
        &kernel.kconfig_path,
    ) && kernel.kconfig_path != REQUIRED_VARIANT_KCONFIG
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
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

    if kernel.recipe_invocation != REQUIRED_RECIPE_INVOCATION {
        push_violation(
            violations,
            Some(StageId::Stage00),
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
            Some(StageId::Stage00),
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
            Some(StageId::Stage00),
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
            Some(StageId::Stage00),
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
            Some(StageId::Stage00),
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
        Some(StageId::Stage00),
        BUILD_KERNEL_VERSION_FIELD,
        &kernel.version,
    ) && !is_kernel_version_token(&kernel.version)
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
            BUILD_KERNEL_VERSION_FIELD,
            ViolationCode::InvalidKernelProvenance,
            "build.kernel.version must be digits/dot format (for example 6.12.71)",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
        BUILD_KERNEL_SHA256_FIELD,
        &kernel.sha256,
    ) && !is_sha256_hex(&kernel.sha256)
    {
        push_violation(
            violations,
            Some(StageId::Stage00),
            BUILD_KERNEL_SHA256_FIELD,
            ViolationCode::InvalidKernelProvenance,
            "build.kernel.sha256 must be a 64-character hex SHA256",
        );
    }

    if validate_non_empty_trimmed(
        violations,
        Some(StageId::Stage00),
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
            Some(StageId::Stage00),
            BUILD_KERNEL_LOCALVERSION_FIELD,
            ViolationCode::InvalidKernelProvenance,
            "build.kernel.localversion must be '-' followed by lowercase alnum/underscore",
        );
    }

    validate_evidence(
        violations,
        StageId::Stage00,
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
        if !validate_non_empty_trimmed(violations, Some(StageId::Stage00), field, value) {
            continue;
        }
        if !value.ends_with(".efi") {
            push_violation(
                violations,
                Some(StageId::Stage00),
                field,
                ViolationCode::InvalidPathDeclaration,
                format!("{field} must end with '.efi'"),
            );
        }
        if !is_safe_filename(value) {
            push_violation(
                violations,
                Some(StageId::Stage00),
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
            Some(StageId::Stage00),
            LIVE_UKI_EXTRA_CMDLINE_FIELD,
            ViolationCode::WhitespaceValue,
            "transforms.live_uki.extra_cmdline must not include leading/trailing whitespace",
        );
    }

    validate_stage_00_non_kernel_inputs(violations, contract);
}

fn validate_ring3_sources(violations: &mut Vec<Violation>, contract: &ConformanceContract) {
    let rootfs_source = &contract.sources.rootfs_source;

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

    match rootfs_source.kind {
        RootfsSourceKind::RecipeRpmDvd => {
            if let Some(preseed_recipe_script) = rootfs_source.preseed_recipe_script.as_deref() {
                if validate_non_empty_trimmed(
                    violations,
                    None,
                    ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
                    preseed_recipe_script,
                ) && !is_relative_contract_path(preseed_recipe_script)
                {
                    push_violation(
                        violations,
                        None,
                        ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
                        ViolationCode::InvalidPathDeclaration,
                        format!(
                            "{ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD} must be a relative normalized path"
                        ),
                    );
                }
            } else {
                push_violation(
                    violations,
                    None,
                    ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
                    ViolationCode::MissingValue,
                    format!(
                        "{ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD} is required for {} = 'recipe_rpm_dvd'",
                        ROOTFS_SOURCE_KIND_FIELD
                    ),
                );
            }
            if !rootfs_source.defines.is_empty() {
                push_violation(
                    violations,
                    None,
                    ROOTFS_SOURCE_DEFINES_FIELD,
                    ViolationCode::InvalidToken,
                    format!(
                        "{ROOTFS_SOURCE_DEFINES_FIELD} must be empty when {} = 'recipe_rpm_dvd'",
                        ROOTFS_SOURCE_KIND_FIELD
                    ),
                );
            }
        }
        RootfsSourceKind::RecipeCustom => {
            if rootfs_source.preseed_recipe_script.is_some() {
                push_violation(
                    violations,
                    None,
                    ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD,
                    ViolationCode::InvalidToken,
                    format!(
                        "{ROOTFS_SOURCE_PRESEED_RECIPE_SCRIPT_FIELD} must be omitted when {} = 'recipe_custom'",
                        ROOTFS_SOURCE_KIND_FIELD
                    ),
                );
            }
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

fn validate_stage_00_erofs_boundary(
    violations: &mut Vec<Violation>,
    contract: &ConformanceContract,
) {
    let rootfs_field = "artifacts.rootfs_name";
    if validate_non_empty_trimmed(
        violations,
        None,
        rootfs_field,
        &contract.artifacts.rootfs_name,
    ) {
        let rootfs_name = contract.artifacts.rootfs_name.as_str();
        if contains_forbidden_stage00_rootfs_token(rootfs_name) {
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

    let required_inputs_field = "transforms.stage00_required_inputs";
    for item in expected_stage_00_required_inputs(violations, contract) {
        if contains_forbidden_stage00_rootfs_token(item) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                required_inputs_field,
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "{required_inputs_field} contains forbidden squashfs artifact '{item}'; Stage 00 payloads must be EROFS"
                ),
            );
        }
    }

    let required_tools_field = BUILD_REQUIRED_TOOLS_FIELD;
    for tool in &contract.build.required_build_tools {
        if contains_forbidden_stage00_rootfs_token(tool) {
            push_violation(
                violations,
                Some(StageId::Stage00),
                required_tools_field,
                ViolationCode::InvalidToken,
                format!(
                    "{required_tools_field} contains forbidden squashfs tool '{tool}'; Stage 00 uses EROFS tooling"
                ),
            );
        }
    }
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

    validate_stage_00_erofs_boundary(&mut violations, contract);
    validate_ring3_sources(&mut violations, contract);
    validate_artifact_identity_mirrors(&mut violations, contract);
    validate_release_mirrors_stage_08(&mut violations, contract);
    validate_stage_00_build(&mut violations, contract);
    let live_boot = &contract.scenarios.live_boot;
    validate_evidence(
        &mut violations,
        StageId::Stage01,
        LIVE_BOOT_EVIDENCE_FIELD,
        &live_boot.evidence.script_path,
        &live_boot.evidence.pass_marker,
        "live-",
    );
    validate_kernel_cmdline_tokens(
        &mut violations,
        StageId::Stage01,
        LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD,
        &live_boot.required_kernel_cmdline,
    );
    validate_command_entries(
        &mut violations,
        Some(StageId::Stage01),
        LIVE_BOOT_REQUIRED_SERVICES_FIELD,
        &live_boot.required_live_services,
    );
    for token in STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE {
        if !live_boot
            .required_kernel_cmdline
            .iter()
            .any(|candidate| candidate == token)
        {
            push_violation(
                &mut violations,
                Some(StageId::Stage01),
                LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD,
                ViolationCode::MissingValue,
                format!(
                    "{LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD} must include '{}'",
                    token
                ),
            );
        }
    }
    validate_evidence(
        &mut violations,
        StageId::Stage02,
        LIVE_TOOLS_EVIDENCE_FIELD,
        &contract.scenarios.live_tools.evidence.script_path,
        &contract.scenarios.live_tools.evidence.pass_marker,
        "live-",
    );
    validate_evidence(
        &mut violations,
        StageId::Stage03,
        INSTALL_EVIDENCE_FIELD,
        &contract.scenarios.install.evidence.script_path,
        &contract.scenarios.install.evidence.pass_marker,
        "install",
    );
    validate_evidence(
        &mut violations,
        StageId::Stage04,
        INSTALLED_BOOT_EVIDENCE_FIELD,
        &contract.scenarios.installed_boot.evidence.script_path,
        &contract.scenarios.installed_boot.evidence.pass_marker,
        "installed-",
    );
    validate_evidence(
        &mut violations,
        StageId::Stage05,
        AUTOMATED_LOGIN_EVIDENCE_FIELD,
        &contract.scenarios.automated_login.evidence.script_path,
        &contract.scenarios.automated_login.evidence.pass_marker,
        "automated-",
    );
    validate_evidence(
        &mut violations,
        StageId::Stage06,
        INSTALLED_TOOLS_EVIDENCE_FIELD,
        &contract.scenarios.installed_tools.evidence.script_path,
        &contract.scenarios.installed_tools.evidence.pass_marker,
        "installed-",
    );
    for service in STAGE_01_REQUIRED_LIVE_SERVICES_BASE {
        if !live_boot
            .required_live_services
            .iter()
            .any(|candidate| candidate == service)
        {
            push_violation(
                &mut violations,
                Some(StageId::Stage01),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;
    use std::collections::BTreeMap;

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
            build: BuildContract {
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
                kernel: KernelBuildContract {
                    kconfig_path: "kconfig".to_string(),
                    recipe_script: "distro-builder/recipes/linux.rhai".to_string(),
                    recipe_invocation: "recipe install".to_string(),
                    release_path: "kernel-build/include/config/kernel.release".to_string(),
                    image_path: "staging/boot/vmlinuz".to_string(),
                    modules_path: "staging/usr/lib/modules/<kernel.release>".to_string(),
                    version: "6.12.71".to_string(),
                    sha256: "143e8bc76cc41f831b51aa5e75819bed55bed41f299d35922820f1d2d2b02600"
                        .to_string(),
                    localversion: "-exampleos".to_string(),
                    module_install_path: "/usr/lib/modules".to_string(),
                },
                evidence: ScriptEvidence {
                    script_path: "build-capability.sh".to_string(),
                    pass_marker: "BUILD CAPABILITY PASSED".to_string(),
                },
            },
            sources: SourceContract {
                rootfs_source: RootfsSourceContract {
                    kind: RootfsSourceKind::RecipeRpmDvd,
                    recipe_script: "distro-builder/recipes/fedora-dvd-source-rootfs.rhai"
                        .to_string(),
                    preseed_recipe_script: Some(
                        "distro-builder/recipes/fedora-preseed-iso.rhai".to_string(),
                    ),
                    defines: BTreeMap::new(),
                },
            },
            products: ProductContract {
                rootfs_base: ProductDecl {
                    logical_name: "product.rootfs.base".to_string(),
                    description: "Canonical base root filesystem tree".to_string(),
                    extends: None,
                },
                live_overlay: ProductDecl {
                    logical_name: "product.payload.live_overlay".to_string(),
                    description: "Read-only live overlay payload tree".to_string(),
                    extends: None,
                },
                boot_live: ProductDecl {
                    logical_name: "product.payload.boot.live".to_string(),
                    description: "Live boot payload inputs".to_string(),
                    extends: Some("product.rootfs.base".to_string()),
                },
                live_tools: ProductDecl {
                    logical_name: "product.payload.live_tools".to_string(),
                    description: "Live tools payload tree".to_string(),
                    extends: Some("product.payload.boot.live".to_string()),
                },
                boot_installed: Some(ProductDecl {
                    logical_name: "product.payload.boot.installed".to_string(),
                    description: "Installed-system boot payload inputs".to_string(),
                    extends: Some("product.rootfs.base".to_string()),
                }),
                kernel_staging: ProductDecl {
                    logical_name: "product.kernel.staging".to_string(),
                    description: "Kernel image and modules staging product".to_string(),
                    extends: None,
                },
            },
            transforms: TransformContract {
                rootfs_image: ArtifactTransform {
                    logical_name: "artifact.rootfs.erofs".to_string(),
                    dependencies: vec!["product.rootfs.base".to_string()],
                    output_names: vec!["exampleos.erofs".to_string()],
                    format: "erofs".to_string(),
                    extra_cmdline: None,
                },
                overlay_image: ArtifactTransform {
                    logical_name: "artifact.overlay.erofs".to_string(),
                    dependencies: vec!["product.payload.live_overlay".to_string()],
                    output_names: vec!["overlayfs.erofs".to_string()],
                    format: "erofs".to_string(),
                    extra_cmdline: None,
                },
                initramfs_live: ArtifactTransform {
                    logical_name: "artifact.initramfs.live".to_string(),
                    dependencies: vec![
                        "product.payload.boot.live".to_string(),
                        "product.kernel.staging".to_string(),
                    ],
                    output_names: vec!["initramfs-live.cpio.gz".to_string()],
                    format: "cpio.gz".to_string(),
                    extra_cmdline: None,
                },
                initramfs_installed: Some(ArtifactTransform {
                    logical_name: "artifact.initramfs.installed".to_string(),
                    dependencies: vec![
                        "product.payload.boot.installed".to_string(),
                        "product.kernel.staging".to_string(),
                    ],
                    output_names: vec!["initramfs-installed.img".to_string()],
                    format: "img".to_string(),
                    extra_cmdline: None,
                }),
                live_uki: ArtifactTransform {
                    logical_name: "artifact.uki.live".to_string(),
                    dependencies: vec![
                        "product.payload.boot.live".to_string(),
                        "product.kernel.staging".to_string(),
                    ],
                    output_names: vec![
                        "exampleos-live.efi".to_string(),
                        "exampleos-emergency.efi".to_string(),
                        "exampleos-debug.efi".to_string(),
                    ],
                    format: "uki".to_string(),
                    extra_cmdline: Some("video=1920x1080".to_string()),
                },
                installed_uki: Some(ArtifactTransform {
                    logical_name: "artifact.uki.installed".to_string(),
                    dependencies: vec![
                        "product.payload.boot.installed".to_string(),
                        "product.kernel.staging".to_string(),
                    ],
                    output_names: vec![
                        "exampleos.efi".to_string(),
                        "exampleos-recovery.efi".to_string(),
                    ],
                    format: "uki".to_string(),
                    extra_cmdline: None,
                }),
                iso: ArtifactTransform {
                    logical_name: "artifact.iso".to_string(),
                    dependencies: vec![
                        "artifact.rootfs.erofs".to_string(),
                        "artifact.overlay.erofs".to_string(),
                        "artifact.initramfs.live".to_string(),
                        "artifact.uki.live".to_string(),
                    ],
                    output_names: vec!["exampleos.iso".to_string()],
                    format: "iso".to_string(),
                    extra_cmdline: None,
                },
                disk_image: None,
            },
            scenarios: ScenarioContract {
                live_boot: BootStage {
                    success_patterns: vec!["Boot complete".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    required_kernel_cmdline: vec!["audit=1".to_string(), "inst.sshd=0".to_string()],
                    required_live_services: vec!["sshd".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "live-boot.sh".to_string(),
                        pass_marker: "LIVE BOOT PASSED".to_string(),
                    },
                },
                live_tools: ToolsStage {
                    required_tools: vec!["bash".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "live-tools.sh".to_string(),
                        pass_marker: "LIVE TOOLS PASSED".to_string(),
                    },
                },
                install: InstallStage {
                    required_tools: vec!["recstrap".to_string()],
                    required_services: vec!["sshd".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "install.sh".to_string(),
                        pass_marker: "INSTALL PASSED".to_string(),
                    },
                },
                installed_boot: BootStage {
                    success_patterns: vec!["example login:".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    required_kernel_cmdline: vec![],
                    required_live_services: vec![],
                    evidence: ScriptEvidence {
                        script_path: "installed-boot.sh".to_string(),
                        pass_marker: "INSTALLED BOOT PASSED".to_string(),
                    },
                },
                automated_login: AutomatedLoginStage {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("example".to_string()),
                    default_password: Some("example".to_string()),
                    login_prompt_pattern: "example login:".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "automated-login.sh".to_string(),
                        pass_marker: "AUTOMATED LOGIN PASSED".to_string(),
                    },
                },
                installed_tools: ToolsStage {
                    required_tools: vec!["sudo".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "installed-tools.sh".to_string(),
                        pass_marker: "INSTALLED TOOLS PASSED".to_string(),
                    },
                },
                runtime_policy: RuntimePolicyStage {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec![],
                    immutable_required_ro_paths: vec![],
                },
            },
            release: ReleaseContract {
                primary_outputs: vec!["exampleos.iso".to_string()],
                supporting_artifacts: vec![
                    "exampleos.erofs".to_string(),
                    "initramfs-live.cpio.gz".to_string(),
                    "initramfs-installed.img".to_string(),
                ],
                metadata_outputs: vec![],
                metadata_facts: vec![
                    "kernel_source.version".to_string(),
                    "kernel_source.sha256".to_string(),
                    "kernel_source.localversion".to_string(),
                    "artifact.rootfs_name".to_string(),
                    "artifact.iso_filename".to_string(),
                ],
            },
            artifacts: ArtifactIdentity {
                rootfs_name: "exampleos.erofs".to_string(),
                initramfs_live_output: "initramfs-live.cpio.gz".to_string(),
                iso_filename: "exampleos.iso".to_string(),
                initramfs_installed_output: Some("initramfs-installed.img".to_string()),
                installed_uki_outputs: vec![
                    "exampleos.efi".to_string(),
                    "exampleos-recovery.efi".to_string(),
                ],
                disk_image_output: None,
            },
        }
    }

    #[test]
    fn valid_contract_passes() {
        let report = validate_contract(&valid_contract());
        assert!(report.passed(), "violations: {:#?}", report.violations);
    }

    #[test]
    fn build_evidence_accepts_build_capability_pass_marker() {
        let mut contract = valid_contract();
        contract.build.evidence.pass_marker = "BUILD CAPABILITY PASSED".to_string();

        let report = validate_contract(&contract);
        assert!(report.passed(), "violations: {:#?}", report.violations);
    }

    #[test]
    fn release_primary_outputs_must_mirror_ring0_transforms() {
        let mut contract = valid_contract();
        contract.release.primary_outputs = vec!["drifted-exampleos.iso".to_string()];

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "release.primary_outputs"));
    }

    #[test]
    fn ring3_rpm_dvd_requires_preseed_recipe_script() {
        let mut contract = valid_contract();
        contract.sources.rootfs_source.preseed_recipe_script = None;

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "sources.rootfs_source.preseed_recipe_script"));
    }

    #[test]
    fn ring3_custom_source_rejects_preseed_recipe_script() {
        let mut contract = valid_contract();
        contract.sources.rootfs_source.kind = RootfsSourceKind::RecipeCustom;

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "sources.rootfs_source.preseed_recipe_script"));
    }

    #[test]
    fn stage_00_requires_recipe_lifecycle_invocation() {
        let mut contract = valid_contract();
        contract.build.kernel.recipe_invocation = "recipe run".to_string();

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
            .build
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
    fn stage_00_rejects_squashfs_rootfs_name() {
        let mut contract = valid_contract();
        contract.artifacts.rootfs_name = "exampleos.squashfs".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report.violations.iter().any(|v| {
            v.field == "artifacts.rootfs_name" && v.code == ViolationCode::InvalidPathDeclaration
        }));
    }

    #[test]
    fn stage_00_rejects_squashfs_tools() {
        let mut contract = valid_contract();
        contract
            .build
            .required_build_tools
            .push("mksquashfs".to_string());

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report.violations.iter().any(|v| {
            v.field == BUILD_REQUIRED_TOOLS_FIELD && v.code == ViolationCode::InvalidToken
        }));
    }

    #[test]
    fn stage_00_requires_usrmerge_module_install_path() {
        let mut contract = valid_contract();
        contract.build.kernel.module_install_path = "/lib/modules".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UnsupportedModuleInstallPath));
    }

    #[test]
    fn stage_00_requires_minimal_non_kernel_input_baseline() {
        let mut contract = valid_contract();
        contract.transforms.overlay_image.output_names.clear();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == BUILD_RUNTIME_REQUIRED_INPUTS_FIELD));
    }

    #[test]
    fn stage_00_non_kernel_inputs_reject_kernel_paths_in_transform_outputs() {
        let mut contract = valid_contract();
        contract.transforms.overlay_image.output_names[0] = "staging/boot/vmlinuz".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == BUILD_RUNTIME_REQUIRED_INPUTS_FIELD));
    }

    #[test]
    fn stage_00_iso_assembly_rejects_non_filename_paths() {
        let mut contract = valid_contract();
        contract.transforms.live_uki.output_names[0] = "efi/live.efi".to_string();

        let report = validate_contract(&contract);
        assert!(!report.passed());
        assert!(report.violations.iter().any(|v| {
            v.field == LIVE_UKI_PRIMARY_OUTPUT_FIELD
                && v.code == ViolationCode::InvalidPathDeclaration
        }));
    }

    #[test]
    fn stage_00_iso_assembly_allows_empty_live_cmdline() {
        let mut contract = valid_contract();
        contract.transforms.live_uki.extra_cmdline = None;

        let report = validate_contract(&contract);
        assert!(report.passed(), "violations: {:#?}", report.violations);
    }
}
