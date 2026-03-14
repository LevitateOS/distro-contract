//! Runtime Stage 00 provenance checks against real build outputs.
//!
//! Unlike declaration-only validation, this verifies that declared Stage 00
//! invariants match on-disk artifacts (kconfig + kernel build outputs).

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{ConformanceError, ConformanceReport, StageId, Violation, ViolationCode};
use crate::fs_layout::{validate_layout, LayoutRequirement};
use crate::schema::{
    ConformanceContract, STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE,
    STAGE_01_REQUIRED_LIVE_SERVICES_BASE,
};

const LEGACY_ROOTFS_COMPONENT_SEQUENCES: &[&[&str]] = &[
    &["leviso", "downloads", "rootfs"],
    &["ralphos", "downloads", "rootfs"],
    &["acornos", "downloads", "rootfs"],
    &["iuppiteros", "downloads", "rootfs"],
];

#[derive(Debug, Clone)]
pub struct Stage00RuntimeArtifacts {
    pub rootfs_image: PathBuf,
    pub initramfs_live: PathBuf,
    pub overlay_image: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LiveBootRuntimeArtifacts {
    pub rootfs_image: PathBuf,
    pub initramfs_live: PathBuf,
    pub overlay_image: PathBuf,
    pub live_overlay_dir: PathBuf,
    pub rootfs_source_pointer: PathBuf,
}

fn push_stage_violation(
    violations: &mut Vec<Violation>,
    stage: StageId,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    violations.push(Violation {
        stage: Some(stage),
        field: field.into(),
        code,
        message: message.into(),
    });
}

fn push_violation(
    violations: &mut Vec<Violation>,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    push_stage_violation(violations, StageId::Stage00, field, code, message);
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn stage00_runtime_artifacts_from_contract(
    contract: &ConformanceContract,
    stage_artifact_dir: &Path,
) -> Stage00RuntimeArtifacts {
    let rootfs_name = contract
        .transforms
        .rootfs_image
        .output_names
        .first()
        .map(String::as_str)
        .unwrap_or(&contract.artifacts.rootfs_name);
    let initramfs_live = contract
        .transforms
        .initramfs_live
        .output_names
        .first()
        .map(String::as_str)
        .unwrap_or(&contract.artifacts.initramfs_live_output);
    let overlay_name = contract
        .transforms
        .overlay_image
        .output_names
        .first()
        .map(String::as_str)
        .unwrap_or("overlayfs.erofs");

    Stage00RuntimeArtifacts {
        rootfs_image: stage_artifact_dir.join(rootfs_name),
        initramfs_live: stage_artifact_dir.join(initramfs_live),
        overlay_image: stage_artifact_dir.join(overlay_name),
    }
}

fn live_boot_scenario<'a>(contract: &'a ConformanceContract) -> &'a crate::schema::BootStage {
    contract
        .scenarios
        .live_boot
        .as_ref()
        .unwrap_or(&contract.stages.stage_01_live_boot)
}

fn parse_kconfig_localversion(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let line = line.trim();
        if !line.starts_with("CONFIG_LOCALVERSION=") {
            continue;
        }

        let value = line
            .trim_start_matches("CONFIG_LOCALVERSION=")
            .trim()
            .to_string();

        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            return Some(value[1..value.len() - 1].to_string());
        }

        return Some(value);
    }

    None
}

fn is_real_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir() && !m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Validate Stage 00 runtime/provenance invariants against on-disk files.
pub fn validate_stage_00_runtime(
    contract: &ConformanceContract,
    variant_dir: &Path,
    artifact_dir: &Path,
) -> ConformanceReport {
    let runtime_artifacts = stage00_runtime_artifacts_from_contract(contract, artifact_dir);
    validate_stage_00_runtime_with_artifacts(
        contract,
        variant_dir,
        artifact_dir,
        &runtime_artifacts,
    )
}

/// Validate Stage 00 runtime/provenance with split kernel + stage artifact roots.
///
/// Use `kernel_artifact_dir` for kernel provenance outputs and
/// `stage_artifact_dir` for stage-scoped non-kernel artifacts.
pub fn validate_stage_00_runtime_with_stage_dirs(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    stage_artifact_dir: &Path,
) -> ConformanceReport {
    let runtime_artifacts = stage00_runtime_artifacts_from_contract(contract, stage_artifact_dir);
    validate_stage_00_runtime_with_artifacts(
        contract,
        variant_dir,
        kernel_artifact_dir,
        &runtime_artifacts,
    )
}

/// Validate Stage 00 runtime/provenance using explicit artifact paths.
pub fn validate_stage_00_runtime_with_artifacts(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifacts: &Stage00RuntimeArtifacts,
) -> ConformanceReport {
    let stage_00 = &contract.stages.stage_00_build;
    let mut violations = Vec::new();

    let variant_layout = validate_layout(
        Some(StageId::Stage00),
        variant_dir,
        &[LayoutRequirement::file(
            "stage_00_build.kernel_kconfig_path",
            &stage_00.kernel_kconfig_path,
            ViolationCode::MissingRequiredKernelOutput,
            "declared kernel kconfig path",
        )],
    );
    let kconfig_missing = variant_layout.has_field_violation("stage_00_build.kernel_kconfig_path");
    violations.extend(variant_layout.violations);

    let artifact_layout = validate_layout(
        Some(StageId::Stage00),
        kernel_artifact_dir,
        &[
            LayoutRequirement::file(
                "stage_00_build.kernel_release_path",
                &stage_00.kernel_release_path,
                ViolationCode::MissingRequiredKernelOutput,
                "kernel.release output",
            ),
            LayoutRequirement::file(
                "stage_00_build.kernel_image_path",
                &stage_00.kernel_image_path,
                ViolationCode::MissingRequiredKernelOutput,
                "kernel image output",
            ),
        ],
    );
    let release_missing = artifact_layout.has_field_violation("stage_00_build.kernel_release_path");
    violations.extend(artifact_layout.violations);

    for (field, expectation, path) in [
        (
            "transforms.rootfs_image.output_names",
            "required Stage 00 rootfs image",
            &artifacts.rootfs_image,
        ),
        (
            "transforms.initramfs_live.output_names",
            "required Stage 00 live initramfs",
            &artifacts.initramfs_live,
        ),
        (
            "transforms.overlay_image.output_names",
            "required Stage 00 overlay image",
            &artifacts.overlay_image,
        ),
    ] {
        if !has_file(path) {
            push_violation(
                &mut violations,
                field,
                ViolationCode::MissingBaselineArtifact,
                format!("missing {} at '{}'", expectation, path.display()),
            );
        }
    }

    let kconfig_path = variant_dir.join(&stage_00.kernel_kconfig_path);
    if !kconfig_missing {
        match fs::read_to_string(&kconfig_path) {
            Ok(raw) => match parse_kconfig_localversion(&raw) {
                Some(localversion) => {
                    if localversion != stage_00.kernel_localversion {
                        push_violation(
                            &mut violations,
                            "stage_00_build.kernel_localversion",
                            ViolationCode::InvalidKernelProvenance,
                            format!(
                                "kconfig CONFIG_LOCALVERSION='{}' does not match declared '{}'",
                                localversion, stage_00.kernel_localversion
                            ),
                        );
                    }
                }
                None => {
                    push_violation(
                        &mut violations,
                        "stage_00_build.kernel_localversion",
                        ViolationCode::InvalidKernelProvenance,
                        format!(
                            "kconfig '{}' is missing CONFIG_LOCALVERSION",
                            kconfig_path.display()
                        ),
                    );
                }
            },
            Err(err) => {
                push_violation(
                    &mut violations,
                    "stage_00_build.kernel_kconfig_path",
                    ViolationCode::MissingRequiredKernelOutput,
                    format!(
                        "failed reading kconfig '{}': {}",
                        kconfig_path.display(),
                        err
                    ),
                );
            }
        }
    }

    let release_path = kernel_artifact_dir.join(&stage_00.kernel_release_path);
    let kernel_release = match if release_missing {
        None
    } else {
        read_trimmed(&release_path)
    } {
        Some(value) => {
            if !value.starts_with(&stage_00.kernel_version) {
                push_violation(
                    &mut violations,
                    "stage_00_build.kernel_release_path",
                    ViolationCode::InvalidKernelProvenance,
                    format!(
                        "kernel.release '{}' does not start with declared kernel_version '{}'",
                        value, stage_00.kernel_version
                    ),
                );
            }
            if !value.ends_with(&stage_00.kernel_localversion) {
                push_violation(
                    &mut violations,
                    "stage_00_build.kernel_release_path",
                    ViolationCode::InvalidKernelProvenance,
                    format!(
                        "kernel.release '{}' does not end with declared kernel_localversion '{}'",
                        value, stage_00.kernel_localversion
                    ),
                );
            }
            Some(value)
        }
        None => {
            if !release_missing {
                push_violation(
                    &mut violations,
                    "stage_00_build.kernel_release_path",
                    ViolationCode::MissingRequiredKernelOutput,
                    format!(
                        "missing or empty kernel.release output at '{}'",
                        release_path.display()
                    ),
                );
            }
            None
        }
    };

    if let Some(kernel_release) = kernel_release {
        let expanded_modules_rel = stage_00
            .kernel_modules_path
            .replace("<kernel.release>", &kernel_release);
        let modules_layout = validate_layout(
            Some(StageId::Stage00),
            kernel_artifact_dir,
            &[LayoutRequirement::directory(
                "stage_00_build.kernel_modules_path",
                expanded_modules_rel,
                ViolationCode::MissingRequiredKernelOutput,
                "kernel modules output",
            )],
        );
        violations.extend(modules_layout.violations);
    }

    let usrmerge_root = kernel_artifact_dir.join(PathBuf::from("staging/usr/lib/modules"));
    let legacy_root = kernel_artifact_dir.join(PathBuf::from("staging/lib/modules"));
    if is_real_directory(&legacy_root) && !usrmerge_root.is_dir() {
        push_violation(
            &mut violations,
            "stage_00_build.module_install_path",
            ViolationCode::UnsupportedModuleInstallPath,
            format!(
                "detected real modules directory at '{}' without usrmerge root '{}'",
                legacy_root.display(),
                usrmerge_root.display()
            ),
        );
    }

    ConformanceReport {
        distro_id: contract.identity.os_id.clone(),
        schema_version: contract.schema_version,
        violations,
    }
}

/// Require Stage 00 runtime checks to pass.
pub fn require_valid_stage_00_runtime(
    contract: &ConformanceContract,
    variant_dir: &Path,
    artifact_dir: &Path,
) -> Result<(), ConformanceError> {
    let report = validate_stage_00_runtime(contract, variant_dir, artifact_dir);
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

pub fn require_valid_stage_00_runtime_with_artifacts(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifacts: &Stage00RuntimeArtifacts,
) -> Result<(), ConformanceError> {
    let report = validate_stage_00_runtime_with_artifacts(
        contract,
        variant_dir,
        kernel_artifact_dir,
        artifacts,
    );
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

/// Require Stage 00 runtime checks to pass with split kernel + stage roots.
pub fn require_valid_stage_00_runtime_with_stage_dirs(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    stage_artifact_dir: &Path,
) -> Result<(), ConformanceError> {
    let report = validate_stage_00_runtime_with_stage_dirs(
        contract,
        variant_dir,
        kernel_artifact_dir,
        stage_artifact_dir,
    );
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

fn stage01_artifact_name(tag: &str, suffix: &str) -> String {
    format!("{tag}-{suffix}")
}

fn stage01_overlay_dir_name(stage_artifact_tag: &str) -> String {
    stage01_artifact_name(stage_artifact_tag, "live-overlay")
}

fn stage_rootfs_source_pointer_name(stage_artifact_tag: &str) -> String {
    format!(".{stage_artifact_tag}-live-rootfs-source.path")
}

fn has_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

fn has_directory(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

fn has_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn symlink_target_equals(path: &Path, expected: &str) -> bool {
    fs::read_link(path)
        .map(|target| target == PathBuf::from(expected))
        .unwrap_or(false)
}

fn resolve_live_boot_rootfs_source_dir(
    rootfs_source_pointer: &Path,
    violations: &mut Vec<Violation>,
) -> Option<PathBuf> {
    let Some(raw) = read_trimmed(rootfs_source_pointer) else {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.rootfs_source_path",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing Stage 01 rootfs source pointer '{}'",
                rootfs_source_pointer.display()
            ),
        );
        return None;
    };

    let candidate = PathBuf::from(raw);
    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        rootfs_source_pointer
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    };

    if is_legacy_rootfs_source(&resolved) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.rootfs_source_path",
            ViolationCode::InvalidPathDeclaration,
            format!(
                "policy violation: legacy rootfs source '{}' is forbidden for Stage 01 runtime",
                resolved.display()
            ),
        );
        return None;
    }

    if !has_directory(&resolved) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.rootfs_source_path",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "Stage 01 rootfs source directory does not exist: '{}'",
                resolved.display()
            ),
        );
        return None;
    }

    Some(resolved)
}

fn is_legacy_rootfs_source(path: &Path) -> bool {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();

    LEGACY_ROOTFS_COMPONENT_SEQUENCES
        .iter()
        .any(|needle| contains_component_sequence(&components, needle))
}

fn contains_component_sequence(haystack: &[String], needle: &[&str]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window.iter().map(String::as_str).eq(needle.iter().copied()))
}

fn validate_stage01_shared_contract_requirements(
    live_boot: &crate::schema::BootStage,
    violations: &mut Vec<Violation>,
) {
    for token in STAGE_01_REQUIRED_KERNEL_CMDLINE_BASE {
        if live_boot
            .required_kernel_cmdline
            .iter()
            .any(|candidate| candidate == token)
        {
            continue;
        }
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.required_kernel_cmdline",
            ViolationCode::MissingValue,
            format!(
                "Stage 01 required kernel cmdline token '{}' is missing from contract",
                token
            ),
        );
    }

    for service in STAGE_01_REQUIRED_LIVE_SERVICES_BASE {
        if live_boot
            .required_live_services
            .iter()
            .any(|candidate| candidate == service)
        {
            continue;
        }
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.required_live_services",
            ViolationCode::MissingValue,
            format!(
                "Stage 01 required live service '{}' is missing from contract",
                service
            ),
        );
    }
}

fn validate_stage01_systemd_ssh(
    live_boot: &crate::schema::BootStage,
    rootfs_dir: &Path,
    live_overlay_dir: &Path,
    violations: &mut Vec<Violation>,
) {
    validate_stage01_usrmerge_symlinks(rootfs_dir, violations);
    validate_stage01_locale_completeness(rootfs_dir, violations);
    validate_stage01_required_ssh_artifacts(rootfs_dir, violations);

    let rootfs_layout = validate_layout(
        Some(StageId::Stage01),
        rootfs_dir,
        &[
            LayoutRequirement::file(
                "stage_01_live_boot.required_live_services",
                "usr/sbin/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenSSH daemon binary",
            ),
            LayoutRequirement::file(
                "stage_01_live_boot.required_live_services",
                "usr/lib/systemd/system/sshd.service",
                ViolationCode::MissingBaselineArtifact,
                "systemd sshd service unit",
            ),
            LayoutRequirement::file(
                "stage_01_live_boot.required_live_services",
                "usr/lib/systemd/system/sshd-keygen@.service",
                ViolationCode::MissingBaselineArtifact,
                "systemd sshd keygen unit",
            ),
            LayoutRequirement::directory(
                "stage_01_live_boot.required_live_services",
                "var/empty/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenSSH privilege-separation directory",
            ),
        ],
    );
    violations.extend(rootfs_layout.violations);

    let wants_link =
        live_overlay_dir.join("etc/systemd/system/multi-user.target.wants/sshd.service");
    if !has_symlink(&wants_link) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.required_live_services",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing systemd Stage 01 sshd enablement symlink '{}'",
                wants_link.display()
            ),
        );
    }

    let rootfs_tmpfiles = rootfs_dir.join("usr/lib/tmpfiles.d/sshd.conf");
    let overlay_tmpfiles = live_overlay_dir.join("etc/tmpfiles.d/sshd-local.conf");
    if !has_file(&rootfs_tmpfiles) && !has_file(&overlay_tmpfiles) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.required_live_services",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing /run/sshd tmpfiles policy (checked '{}' and '{}')",
                rootfs_tmpfiles.display(),
                overlay_tmpfiles.display()
            ),
        );
    }

    let anaconda_sshd = rootfs_dir.join("usr/lib/systemd/system/anaconda-sshd.service");
    if has_file(&anaconda_sshd)
        && !live_boot
            .required_kernel_cmdline
            .iter()
            .any(|token| token == "inst.sshd=0")
    {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.required_kernel_cmdline",
            ViolationCode::MissingValue,
            format!(
                "found '{}' but required kernel cmdline is missing 'inst.sshd=0'; \
                 this can race/conflict with primary sshd.service on port 22",
                anaconda_sshd.display()
            ),
        );
    }

    validate_stage01_forbidden_tool_leaks(rootfs_dir, violations);
}

fn validate_stage01_usrmerge_symlinks(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    for (rel, expected_target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/sbin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib64"),
    ] {
        let path = rootfs_dir.join(rel);
        if !has_symlink(&path) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.envelope",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing required Stage 01 merged-usr symlink '{}'; expected '{}' -> '{}'",
                    path.display(),
                    rel,
                    expected_target
                ),
            );
            continue;
        }
        if !symlink_target_equals(&path, expected_target) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.envelope",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "invalid Stage 01 merged-usr symlink '{}'; expected target '{}'",
                    path.display(),
                    expected_target
                ),
            );
        }
    }
}

fn validate_stage01_openrc_ssh(
    live_boot: &crate::schema::BootStage,
    rootfs_dir: &Path,
    live_overlay_dir: &Path,
    violations: &mut Vec<Violation>,
) {
    validate_stage01_openrc_locale_completeness(rootfs_dir, violations);
    validate_stage01_required_ssh_artifacts(rootfs_dir, violations);

    let rootfs_layout = validate_layout(
        Some(StageId::Stage01),
        rootfs_dir,
        &[
            LayoutRequirement::file(
                "stage_01_live_boot.required_live_services",
                "usr/sbin/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenSSH daemon binary",
            ),
            LayoutRequirement::file(
                "stage_01_live_boot.required_live_services",
                "etc/init.d/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenRC sshd service script",
            ),
        ],
    );
    violations.extend(rootfs_layout.violations);

    let runlevel_link = live_overlay_dir.join("etc/runlevels/default/sshd");
    if !has_symlink(&runlevel_link) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.required_live_services",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing OpenRC Stage 01 sshd runlevel symlink '{}'",
                runlevel_link.display()
            ),
        );
    }

    if live_boot
        .required_live_services
        .iter()
        .any(|service| service == "networking")
    {
        let networking_script = rootfs_dir.join("etc/init.d/networking");
        if !has_file(&networking_script) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.required_live_services",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC networking service script '{}'",
                    networking_script.display()
                ),
            );
        }

        let interfaces_path = rootfs_dir.join("etc/network/interfaces");
        if !has_file(&interfaces_path) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.required_live_services",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC network interfaces config '{}'",
                    interfaces_path.display()
                ),
            );
        }

        let networking_boot_link = live_overlay_dir.join("etc/runlevels/boot/networking");
        if !has_symlink(&networking_boot_link) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.required_live_services",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC Stage 01 networking runlevel symlink '{}'",
                    networking_boot_link.display()
                ),
            );
        }
    }

    if live_boot
        .required_live_services
        .iter()
        .any(|service| service == "dhcpcd")
    {
        let dhcpcd_script = rootfs_dir.join("etc/init.d/dhcpcd");
        if !has_file(&dhcpcd_script) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.required_live_services",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC dhcpcd service script '{}'",
                    dhcpcd_script.display()
                ),
            );
        }

        let dhcpcd_link = live_overlay_dir.join("etc/runlevels/default/dhcpcd");
        if !has_symlink(&dhcpcd_link) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.required_live_services",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC Stage 01 dhcpcd runlevel symlink '{}'",
                    dhcpcd_link.display()
                ),
            );
        }
    }

    validate_stage01_forbidden_tool_leaks(rootfs_dir, violations);
}

fn validate_stage01_openrc_locale_completeness(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    let locale_conf = rootfs_dir.join("etc/locale.conf");
    if !has_file(&locale_conf) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.locale",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing Stage 01 locale config '{}'; expected canonical LANG=C.UTF-8",
                locale_conf.display()
            ),
        );
    } else {
        match fs::read_to_string(&locale_conf) {
            Ok(content) => {
                let has_c_utf8 = content
                    .lines()
                    .map(str::trim)
                    .any(|line| line == "LANG=C.UTF-8");
                if !has_c_utf8 {
                    push_stage_violation(
                        violations,
                        StageId::Stage01,
                        "stage_01_live_boot.locale",
                        ViolationCode::MissingValue,
                        format!(
                            "invalid Stage 01 locale config '{}': expected line 'LANG=C.UTF-8'",
                            locale_conf.display()
                        ),
                    );
                }
            }
            Err(err) => {
                push_stage_violation(
                    violations,
                    StageId::Stage01,
                    "stage_01_live_boot.locale",
                    ViolationCode::MissingBaselineArtifact,
                    format!(
                        "failed reading Stage 01 locale config '{}': {}",
                        locale_conf.display(),
                        err
                    ),
                );
            }
        }
    }

    let glibc_locale_payload_candidates = [
        "lib/locale/C.utf8/LC_CTYPE",
        "usr/lib/locale/C.utf8/LC_CTYPE",
        "lib64/locale/C.utf8/LC_CTYPE",
        "usr/lib64/locale/C.utf8/LC_CTYPE",
    ];
    let has_glibc_payload = glibc_locale_payload_candidates
        .iter()
        .any(|rel| has_file(&rootfs_dir.join(rel)));
    let has_musl_payload = has_file(&rootfs_dir.join("usr/share/i18n/locales/musl/en_US.UTF-8"));
    if !has_glibc_payload && !has_musl_payload {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.locale",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing Stage 01 locale payload under '{}'; expected one of glibc paths [{}] or musl path 'usr/share/i18n/locales/musl/en_US.UTF-8'",
                rootfs_dir.display(),
                glibc_locale_payload_candidates.join(", ")
            ),
        );
    }
}

fn validate_stage01_forbidden_tool_leaks(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    for rel in ["usr/bin/recstrap", "usr/bin/recfstab", "usr/bin/recchroot"] {
        let path = rootfs_dir.join(rel);
        if has_file(&path) {
            push_stage_violation(
                violations,
                StageId::Stage01,
                "stage_01_live_boot.envelope",
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "forbidden Stage 02 payload leaked into Stage 01 rootfs: '{}'",
                    path.display()
                ),
            );
        }
    }
}

fn validate_stage01_required_ssh_artifacts(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    let ssh_layout = validate_layout(
        Some(StageId::Stage01),
        rootfs_dir,
        &[
            LayoutRequirement::file(
                "stage_01_live_boot.required_live_services",
                "etc/ssh/sshd_config",
                ViolationCode::MissingBaselineArtifact,
                "canonical Stage 01 sshd config",
            ),
            LayoutRequirement::directory(
                "stage_01_live_boot.required_live_services",
                "usr/share/empty.sshd",
                ViolationCode::MissingBaselineArtifact,
                "Stage 01 empty sshd directory",
            ),
        ],
    );
    violations.extend(ssh_layout.violations);
}

fn validate_stage01_locale_completeness(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    let locale_conf = rootfs_dir.join("etc/locale.conf");
    if !has_file(&locale_conf) {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.locale",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing Stage 01 locale config '{}'; expected canonical LANG=C.UTF-8",
                locale_conf.display()
            ),
        );
    } else {
        match fs::read_to_string(&locale_conf) {
            Ok(content) => {
                let has_c_utf8 = content
                    .lines()
                    .map(str::trim)
                    .any(|line| line == "LANG=C.UTF-8");
                if !has_c_utf8 {
                    push_stage_violation(
                        violations,
                        StageId::Stage01,
                        "stage_01_live_boot.locale",
                        ViolationCode::MissingValue,
                        format!(
                            "invalid Stage 01 locale config '{}': expected line 'LANG=C.UTF-8'",
                            locale_conf.display()
                        ),
                    );
                }
            }
            Err(err) => {
                push_stage_violation(
                    violations,
                    StageId::Stage01,
                    "stage_01_live_boot.locale",
                    ViolationCode::MissingBaselineArtifact,
                    format!(
                        "failed reading Stage 01 locale config '{}': {}",
                        locale_conf.display(),
                        err
                    ),
                );
            }
        }
    }

    let locale_payload_candidates = [
        "lib/locale/C.utf8/LC_CTYPE",
        "usr/lib/locale/C.utf8/LC_CTYPE",
        "lib64/locale/C.utf8/LC_CTYPE",
        "usr/lib64/locale/C.utf8/LC_CTYPE",
    ];
    let has_payload = locale_payload_candidates
        .iter()
        .any(|rel| has_file(&rootfs_dir.join(rel)));
    if !has_payload {
        push_stage_violation(
            violations,
            StageId::Stage01,
            "stage_01_live_boot.locale",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing Stage 01 UTF-8 locale payload under '{}'; expected one of: {}",
                rootfs_dir.display(),
                locale_payload_candidates.join(", ")
            ),
        );
    }
}

/// Validate live-boot runtime SSH/service wiring against explicit artifact paths.
pub fn validate_live_boot_runtime(
    contract: &ConformanceContract,
    artifacts: &LiveBootRuntimeArtifacts,
) -> ConformanceReport {
    let mut violations = Vec::new();
    let live_boot = live_boot_scenario(contract);
    validate_stage01_shared_contract_requirements(live_boot, &mut violations);

    for (field, expectation, path, is_dir) in [
        (
            "stage_01_live_boot.artifacts",
            "Stage 01 rootfs image",
            artifacts.rootfs_image.as_path(),
            false,
        ),
        (
            "stage_01_live_boot.artifacts",
            "Stage 01 live initramfs",
            artifacts.initramfs_live.as_path(),
            false,
        ),
        (
            "stage_01_live_boot.artifacts",
            "Stage 01 live overlay image",
            artifacts.overlay_image.as_path(),
            false,
        ),
        (
            "stage_01_live_boot.artifacts",
            "Stage 01 live overlay source directory",
            artifacts.live_overlay_dir.as_path(),
            true,
        ),
    ] {
        let exists = if is_dir {
            has_directory(path)
        } else {
            has_file(path)
        };
        if !exists {
            push_stage_violation(
                &mut violations,
                StageId::Stage01,
                field,
                ViolationCode::MissingBaselineArtifact,
                format!("missing {} at '{}'", expectation, path.display()),
            );
        }
    }

    let Some(rootfs_source_dir) =
        resolve_live_boot_rootfs_source_dir(&artifacts.rootfs_source_pointer, &mut violations)
    else {
        return ConformanceReport {
            distro_id: contract.identity.os_id.clone(),
            schema_version: contract.schema_version,
            violations,
        };
    };
    let live_overlay_dir = &artifacts.live_overlay_dir;

    let has_systemd_unit = has_file(&rootfs_source_dir.join("usr/lib/systemd/system/sshd.service"));
    let has_openrc_script = has_file(&rootfs_source_dir.join("etc/init.d/sshd"));
    if has_systemd_unit {
        validate_stage01_systemd_ssh(
            live_boot,
            &rootfs_source_dir,
            live_overlay_dir,
            &mut violations,
        );
    } else if has_openrc_script {
        validate_stage01_openrc_ssh(
            live_boot,
            &rootfs_source_dir,
            live_overlay_dir,
            &mut violations,
        );
    } else {
        push_stage_violation(
            &mut violations,
            StageId::Stage01,
            "stage_01_live_boot.required_live_services",
            ViolationCode::MissingBaselineArtifact,
            format!(
                "unable to locate Stage 01 ssh service wiring under '{}': \
                 expected systemd unit 'usr/lib/systemd/system/sshd.service' or OpenRC script 'etc/init.d/sshd'",
                rootfs_source_dir.display()
            ),
        );
    }

    ConformanceReport {
        distro_id: contract.identity.os_id.clone(),
        schema_version: contract.schema_version,
        violations,
    }
}

/// Validate Stage 01 runtime SSH/service wiring against stage-scoped compatibility artifacts.
pub fn validate_stage_01_runtime(
    contract: &ConformanceContract,
    stage_artifact_dir: &Path,
    stage_artifact_tag: &str,
) -> ConformanceReport {
    let artifacts = LiveBootRuntimeArtifacts {
        rootfs_image: stage_artifact_dir.join(stage01_artifact_name(
            stage_artifact_tag,
            "filesystem.erofs",
        )),
        initramfs_live: stage_artifact_dir.join(stage01_artifact_name(
            stage_artifact_tag,
            "initramfs-live.cpio.gz",
        )),
        overlay_image: stage_artifact_dir
            .join(stage01_artifact_name(stage_artifact_tag, "overlayfs.erofs")),
        live_overlay_dir: stage_artifact_dir.join(stage01_overlay_dir_name(stage_artifact_tag)),
        rootfs_source_pointer: stage_artifact_dir
            .join(stage_rootfs_source_pointer_name(stage_artifact_tag)),
    };
    validate_live_boot_runtime(contract, &artifacts)
}

/// Require Stage 01 runtime checks to pass for stage-scoped artifacts.
pub fn require_valid_stage_01_runtime(
    contract: &ConformanceContract,
    stage_artifact_dir: &Path,
    stage_artifact_tag: &str,
) -> Result<(), ConformanceError> {
    let report = validate_stage_01_runtime(contract, stage_artifact_dir, stage_artifact_tag);
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

pub fn require_valid_live_boot_runtime(
    contract: &ConformanceContract,
    artifacts: &LiveBootRuntimeArtifacts,
) -> Result<(), ConformanceError> {
    let report = validate_live_boot_runtime(contract, artifacts);
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
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn valid_contract() -> ConformanceContract {
        ConformanceContract {
            schema_version: CONTRACT_SCHEMA_VERSION,
            identity: DistroIdentity {
                os_name: "LevitateOS".to_string(),
                os_id: "levitateos".to_string(),
                iso_label: "LEVITATEOS".to_string(),
                os_version: "1.0".to_string(),
                default_hostname: "levitateos".to_string(),
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
                    localversion: "-levitate".to_string(),
                    module_install_path: "/usr/lib/modules".to_string(),
                },
                evidence: ScriptEvidence {
                    script_path: "00Build-build-capability.sh".to_string(),
                    pass_marker: "STAGE 00 PASSED".to_string(),
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
                    extends: None,
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
                    output_names: vec!["s00-filesystem.erofs".to_string()],
                    format: "erofs".to_string(),
                    extra_cmdline: None,
                },
                overlay_image: ArtifactTransform {
                    logical_name: "artifact.overlay.erofs".to_string(),
                    dependencies: vec!["product.payload.live_overlay".to_string()],
                    output_names: vec!["s00-overlayfs.erofs".to_string()],
                    format: "erofs".to_string(),
                    extra_cmdline: None,
                },
                initramfs_live: ArtifactTransform {
                    logical_name: "artifact.initramfs.live".to_string(),
                    dependencies: vec![
                        "product.payload.boot.live".to_string(),
                        "product.kernel.staging".to_string(),
                    ],
                    output_names: vec!["s00-initramfs-live.cpio.gz".to_string()],
                    format: "cpio.gz".to_string(),
                    extra_cmdline: None,
                },
                initramfs_installed: Some(ArtifactTransform {
                    logical_name: "artifact.initramfs.installed".to_string(),
                    dependencies: vec![
                        "product.payload.boot.installed".to_string(),
                        "product.kernel.staging".to_string(),
                    ],
                    output_names: vec!["s00-initramfs-installed.img".to_string()],
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
                        "levitateos-live.efi".to_string(),
                        "levitateos-emergency.efi".to_string(),
                        "levitateos-debug.efi".to_string(),
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
                        "levitateos.efi".to_string(),
                        "levitateos-recovery.efi".to_string(),
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
                    output_names: vec!["levitateos-x86_64.iso".to_string()],
                    format: "iso".to_string(),
                    extra_cmdline: None,
                },
                disk_image: None,
            },
            scenarios: ScenarioContract {
                live_boot: Some(BootStage {
                    success_patterns: vec!["LevitateOS".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    required_kernel_cmdline: vec!["audit=1".to_string(), "inst.sshd=0".to_string()],
                    required_live_services: vec!["sshd".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-01-live-boot.sh".to_string(),
                        pass_marker: "STAGE 01 PASSED".to_string(),
                    },
                }),
                live_tools: Some(ToolsStage {
                    required_tools: vec!["bash".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-02-live-tools.sh".to_string(),
                        pass_marker: "STAGE 02 PASSED".to_string(),
                    },
                }),
                install: Some(InstallStage {
                    required_tools: vec!["recstrap".to_string()],
                    required_services: vec!["sshd".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-03-installation.sh".to_string(),
                        pass_marker: "STAGE 03 PASSED".to_string(),
                    },
                }),
                installed_boot: Some(BootStage {
                    success_patterns: vec!["levitateos login:".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    required_kernel_cmdline: vec![],
                    required_live_services: vec![],
                    evidence: ScriptEvidence {
                        script_path: "stage-04-installed-boot.sh".to_string(),
                        pass_marker: "STAGE 04 PASSED".to_string(),
                    },
                }),
                automated_login: Some(AutomatedLoginStage {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("levitate".to_string()),
                    default_password: Some("levitate".to_string()),
                    login_prompt_pattern: "levitateos login:".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "stage-05-automated-login.sh".to_string(),
                        pass_marker: "STAGE 05 PASSED".to_string(),
                    },
                }),
                installed_tools: Some(ToolsStage {
                    required_tools: vec!["sudo".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-06-daily-driver.sh".to_string(),
                        pass_marker: "STAGE 06 PASSED".to_string(),
                    },
                }),
                runtime_policy: Some(RuntimePolicyStage {
                    rootfs_mutability: RootfsMutability::Mutable,
                    mutable_required_rw_paths: vec![],
                    immutable_required_ro_paths: vec![],
                }),
            },
            release: ReleaseContract {
                primary_outputs: vec!["levitateos-x86_64.iso".to_string()],
                supporting_artifacts: vec![
                    "s00-filesystem.erofs".to_string(),
                    "s00-initramfs-live.cpio.gz".to_string(),
                    "s00-initramfs-installed.img".to_string(),
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
                rootfs_name: "s00-filesystem.erofs".to_string(),
                initramfs_live_output: "s00-initramfs-live.cpio.gz".to_string(),
                iso_filename: "levitateos-x86_64.iso".to_string(),
                initramfs_installed_output: Some("s00-initramfs-installed.img".to_string()),
                installed_uki_outputs: vec![
                    "levitateos.efi".to_string(),
                    "levitateos-recovery.efi".to_string(),
                ],
                disk_image_output: None,
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
                    kernel_localversion: "-levitate".to_string(),
                    module_install_path: "/usr/lib/modules".to_string(),
                    non_kernel_inputs: Stage00NonKernelInputs {
                        required_for_00build: vec![
                            "s00-filesystem.erofs".to_string(),
                            "s00-initramfs-live.cpio.gz".to_string(),
                            "s00-overlayfs.erofs".to_string(),
                        ],
                        deferred_to_01boot: vec![],
                        deferred_to_02livetools: vec![],
                        deferred_to_03install_plus: vec![],
                    },
                    iso_assembly: Stage00IsoAssembly {
                        live_uki_filename: "levitateos-live.efi".to_string(),
                        emergency_uki_filename: "levitateos-emergency.efi".to_string(),
                        debug_uki_filename: "levitateos-debug.efi".to_string(),
                        live_cmdline: "video=1920x1080".to_string(),
                    },
                    evidence: ScriptEvidence {
                        script_path: "00Build-build-capability.sh".to_string(),
                        pass_marker: "STAGE 00 PASSED".to_string(),
                    },
                },
                stage_01_live_boot: BootStage {
                    success_patterns: vec!["LevitateOS".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    required_kernel_cmdline: vec!["audit=1".to_string(), "inst.sshd=0".to_string()],
                    required_live_services: vec!["sshd".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-01-live-boot.sh".to_string(),
                        pass_marker: "STAGE 01 PASSED".to_string(),
                    },
                },
                stage_02_live_tools: ToolsStage {
                    required_tools: vec!["bash".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-02-live-tools.sh".to_string(),
                        pass_marker: "STAGE 02 PASSED".to_string(),
                    },
                },
                stage_03_install: InstallStage {
                    required_tools: vec!["recstrap".to_string()],
                    required_services: vec!["sshd".to_string()],
                    evidence: ScriptEvidence {
                        script_path: "stage-03-installation.sh".to_string(),
                        pass_marker: "STAGE 03 PASSED".to_string(),
                    },
                },
                stage_04_installed_boot: BootStage {
                    success_patterns: vec!["levitateos login:".to_string()],
                    fatal_patterns: vec!["Kernel panic".to_string()],
                    required_kernel_cmdline: vec![],
                    required_live_services: vec![],
                    evidence: ScriptEvidence {
                        script_path: "stage-04-installed-boot.sh".to_string(),
                        pass_marker: "STAGE 04 PASSED".to_string(),
                    },
                },
                stage_05_automated_login: AutomatedLoginStage {
                    auth_mode: AuthMode::DefaultPasswordLogin,
                    default_username: Some("levitate".to_string()),
                    default_password: Some("levitate".to_string()),
                    login_prompt_pattern: "levitateos login:".to_string(),
                    evidence: ScriptEvidence {
                        script_path: "stage-05-automated-login.sh".to_string(),
                        pass_marker: "STAGE 05 PASSED".to_string(),
                    },
                },
                stage_06_installed_tools: ToolsStage {
                    required_tools: vec!["sudo".to_string()],
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
                    required_artifacts: vec![
                        "levitateos-x86_64.iso".to_string(),
                        "s00-filesystem.erofs".to_string(),
                        "s00-initramfs-live.cpio.gz".to_string(),
                        "s00-initramfs-installed.img".to_string(),
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

    fn temp_dir(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "distro-contract-runtime-{test_name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, content).expect("write file");
    }

    fn write_stage01_systemd_artifacts(stage_dir: &Path, include_anaconda_sshd: bool) {
        write_file(&stage_dir.join("s01-filesystem.erofs"), "rootfs");
        write_file(&stage_dir.join("s01-initramfs-live.cpio.gz"), "initramfs");
        write_file(&stage_dir.join("s01-overlayfs.erofs"), "overlay");

        let rootfs_source = stage_dir.join("s01-rootfs-source-test");
        fs::create_dir_all(&rootfs_source).expect("create rootfs source");
        write_file(
            &stage_dir.join(".s01-live-rootfs-source.path"),
            &format!("{}\n", rootfs_source.display()),
        );
        symlink("usr/bin", rootfs_source.join("bin")).expect("create bin symlink");
        symlink("usr/sbin", rootfs_source.join("sbin")).expect("create sbin symlink");
        symlink("usr/lib", rootfs_source.join("lib")).expect("create lib symlink");
        symlink("usr/lib64", rootfs_source.join("lib64")).expect("create lib64 symlink");

        write_file(&rootfs_source.join("usr/sbin/sshd"), "binary");
        write_file(
            &rootfs_source.join("usr/lib/systemd/system/sshd.service"),
            "[Service]\nExecStart=/usr/sbin/sshd -D\n",
        );
        write_file(
            &rootfs_source.join("usr/lib/systemd/system/sshd-keygen@.service"),
            "[Service]\nExecStart=/usr/libexec/openssh/sshd-keygen %i\n",
        );
        write_file(
            &rootfs_source.join("usr/lib/tmpfiles.d/sshd.conf"),
            "d /run/sshd 0755 root root -\n",
        );
        fs::create_dir_all(rootfs_source.join("etc/ssh")).expect("create etc/ssh");
        write_file(
            &rootfs_source.join("etc/ssh/sshd_config"),
            "PermitRootLogin yes\n",
        );
        fs::create_dir_all(rootfs_source.join("usr/share/empty.sshd"))
            .expect("create empty.sshd dir");
        write_file(&rootfs_source.join("etc/locale.conf"), "LANG=C.UTF-8\n");
        write_file(
            &rootfs_source.join("usr/lib/locale/C.utf8/LC_CTYPE"),
            "locale",
        );
        fs::create_dir_all(rootfs_source.join("var/empty/sshd")).expect("create privsep dir");

        if include_anaconda_sshd {
            write_file(
                &rootfs_source.join("usr/lib/systemd/system/anaconda-sshd.service"),
                "[Unit]\nDescription=anaconda sshd\n",
            );
        }

        let wants_dir =
            stage_dir.join("s01-live-overlay/etc/systemd/system/multi-user.target.wants");
        fs::create_dir_all(&wants_dir).expect("create wants dir");
        symlink(
            "/usr/lib/systemd/system/sshd.service",
            wants_dir.join("sshd.service"),
        )
        .expect("create sshd wants symlink");
        write_file(
            &stage_dir.join("s01-live-overlay/etc/tmpfiles.d/sshd-local.conf"),
            "d /run/sshd 0755 root root -\n",
        );
    }

    #[test]
    fn stage_00_runtime_passes_when_kconfig_and_outputs_match() {
        let variant_dir = temp_dir("runtime-ok-variant");
        let artifact_dir = temp_dir("runtime-ok-artifacts");
        let contract = valid_contract();

        write_file(
            &variant_dir.join("kconfig"),
            "CONFIG_LOCALVERSION=\"-levitate\"\n",
        );
        write_file(
            &artifact_dir.join("kernel-build/include/config/kernel.release"),
            "6.12.71-levitate\n",
        );
        write_file(&artifact_dir.join("staging/boot/vmlinuz"), "kernel");
        write_file(&artifact_dir.join("s00-filesystem.erofs"), "rootfs");
        write_file(
            &artifact_dir.join("s00-initramfs-live.cpio.gz"),
            "initramfs-live",
        );
        write_file(&artifact_dir.join("s00-overlayfs.erofs"), "overlay");
        fs::create_dir_all(&artifact_dir.join("staging/usr/lib/modules/6.12.71-levitate"))
            .expect("create modules dir");

        let report = validate_stage_00_runtime(&contract, &variant_dir, &artifact_dir);
        assert!(report.passed(), "{:#?}", report.violations);

        fs::remove_dir_all(variant_dir).expect("cleanup variant");
        fs::remove_dir_all(artifact_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_00_runtime_fails_on_localversion_mismatch() {
        let variant_dir = temp_dir("runtime-mismatch-variant");
        let artifact_dir = temp_dir("runtime-mismatch-artifacts");
        let contract = valid_contract();

        write_file(
            &variant_dir.join("kconfig"),
            "CONFIG_LOCALVERSION=\"-other\"\n",
        );
        write_file(
            &artifact_dir.join("kernel-build/include/config/kernel.release"),
            "6.12.71-other\n",
        );
        write_file(&artifact_dir.join("staging/boot/vmlinuz"), "kernel");
        write_file(&artifact_dir.join("s00-filesystem.erofs"), "rootfs");
        write_file(
            &artifact_dir.join("s00-initramfs-live.cpio.gz"),
            "initramfs-live",
        );
        write_file(&artifact_dir.join("s00-overlayfs.erofs"), "overlay");
        fs::create_dir_all(&artifact_dir.join("staging/usr/lib/modules/6.12.71-other"))
            .expect("create modules dir");

        let report = validate_stage_00_runtime(&contract, &variant_dir, &artifact_dir);
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::InvalidKernelProvenance));

        fs::remove_dir_all(variant_dir).expect("cleanup variant");
        fs::remove_dir_all(artifact_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_passes_for_systemd_ssh_wiring() {
        let stage_dir = temp_dir("stage01-runtime-ok");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, true);

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(report.passed(), "{:#?}", report.violations);

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_anaconda_sshd_present_without_inst_sshd_zero() {
        let stage_dir = temp_dir("stage01-runtime-anaconda-missing-cmdline");
        let mut contract = valid_contract();
        contract.stages.stage_01_live_boot.required_kernel_cmdline = vec!["audit=1".to_string()];
        if let Some(live_boot) = contract.scenarios.live_boot.as_mut() {
            live_boot.required_kernel_cmdline = vec!["audit=1".to_string()];
        }
        write_stage01_systemd_artifacts(&stage_dir, true);

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "stage_01_live_boot.required_kernel_cmdline"));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_rootfs_source_points_to_legacy_path() {
        let stage_dir = temp_dir("stage01-runtime-legacy-rootfs");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, false);

        let mut legacy_rootfs = stage_dir.clone();
        for component in ["leviso", "downloads", "rootfs"] {
            legacy_rootfs.push(component);
        }
        fs::create_dir_all(legacy_rootfs.join("usr/lib/systemd/system"))
            .expect("create legacy rootfs systemd dir");
        fs::create_dir_all(legacy_rootfs.join("usr/lib/tmpfiles.d"))
            .expect("create legacy tmpfiles dir");
        fs::create_dir_all(legacy_rootfs.join("var/empty/sshd")).expect("create legacy privsep");
        write_file(&legacy_rootfs.join("usr/sbin/sshd"), "binary");
        write_file(
            &legacy_rootfs.join("usr/lib/systemd/system/sshd.service"),
            "[Service]\nExecStart=/usr/sbin/sshd -D\n",
        );
        write_file(
            &legacy_rootfs.join("usr/lib/systemd/system/sshd-keygen@.service"),
            "[Service]\nExecStart=/usr/libexec/openssh/sshd-keygen %i\n",
        );
        write_file(
            &legacy_rootfs.join("usr/lib/tmpfiles.d/sshd.conf"),
            "d /run/sshd 0755 root root -\n",
        );
        write_file(
            &stage_dir.join(".s01-live-rootfs-source.path"),
            &format!("{}\n", legacy_rootfs.display()),
        );

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report.violations.iter().any(|v| {
            v.field == "stage_01_live_boot.rootfs_source_path"
                && v.code == ViolationCode::InvalidPathDeclaration
        }));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_locale_config_missing() {
        let stage_dir = temp_dir("stage01-runtime-missing-locale-conf");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, false);

        let rootfs_source = read_trimmed(&stage_dir.join(".s01-live-rootfs-source.path"))
            .map(PathBuf::from)
            .expect("rootfs source path");
        fs::remove_file(rootfs_source.join("etc/locale.conf")).expect("remove locale.conf");

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "stage_01_live_boot.locale"));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_locale_payload_missing() {
        let stage_dir = temp_dir("stage01-runtime-missing-locale-payload");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, false);

        let rootfs_source = read_trimmed(&stage_dir.join(".s01-live-rootfs-source.path"))
            .map(PathBuf::from)
            .expect("rootfs source path");
        fs::remove_file(rootfs_source.join("usr/lib/locale/C.utf8/LC_CTYPE"))
            .expect("remove locale payload");

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "stage_01_live_boot.locale"));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_sshd_config_missing() {
        let stage_dir = temp_dir("stage01-runtime-missing-sshd-config");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, false);

        let rootfs_source = read_trimmed(&stage_dir.join(".s01-live-rootfs-source.path"))
            .map(PathBuf::from)
            .expect("rootfs source path");
        fs::remove_file(rootfs_source.join("etc/ssh/sshd_config")).expect("remove sshd_config");

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "stage_01_live_boot.required_live_services"));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_empty_sshd_missing() {
        let stage_dir = temp_dir("stage01-runtime-missing-empty-sshd");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, false);

        let rootfs_source = read_trimmed(&stage_dir.join(".s01-live-rootfs-source.path"))
            .map(PathBuf::from)
            .expect("rootfs source path");
        fs::remove_dir_all(rootfs_source.join("usr/share/empty.sshd")).expect("remove empty.sshd");

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "stage_01_live_boot.required_live_services"));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }

    #[test]
    fn stage_01_runtime_fails_when_usrmerge_symlink_missing() {
        let stage_dir = temp_dir("stage01-runtime-missing-usrmerge-symlink");
        let contract = valid_contract();
        write_stage01_systemd_artifacts(&stage_dir, false);

        let rootfs_source = read_trimmed(&stage_dir.join(".s01-live-rootfs-source.path"))
            .map(PathBuf::from)
            .expect("rootfs source path");
        fs::remove_file(rootfs_source.join("lib64")).expect("remove lib64 symlink");
        fs::create_dir_all(rootfs_source.join("lib64")).expect("create wrong lib64 directory");

        let report = validate_stage_01_runtime(&contract, &stage_dir, "s01");
        assert!(!report.passed());
        assert!(report
            .violations
            .iter()
            .any(|v| v.field == "stage_01_live_boot.envelope"));

        fs::remove_dir_all(stage_dir).expect("cleanup artifacts");
    }
}
