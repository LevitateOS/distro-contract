//! Runtime provenance and live-boot conformance checks against real outputs.
//!
//! Unlike declaration-only validation, this verifies that canonical build and
//! live-boot invariants match on-disk artifacts.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{CheckpointId, ConformanceError, ConformanceReport, Violation, ViolationCode};
use crate::fs_layout::{validate_layout, LayoutRequirement};
use crate::schema::{
    ConformanceContract, BOOT_REQUIRED_KERNEL_CMDLINE_BASE, BOOT_REQUIRED_LIVE_SERVICES_BASE,
};
use crate::variant::{resolve_variant_owner_paths, VariantContractLoadError};

const LEGACY_ROOTFS_COMPONENT_SEQUENCES: &[&[&str]] = &[
    &["leviso", "downloads", "rootfs"],
    &["ralphos", "downloads", "rootfs"],
    &["acornos", "downloads", "rootfs"],
    &["iuppiteros", "downloads", "rootfs"],
];

const BUILD_KERNEL_KCONFIG_FIELD: &str = "build.kernel.kconfig_path";
const BUILD_KERNEL_RELEASE_FIELD: &str = "build.kernel.release_path";
const BUILD_KERNEL_IMAGE_FIELD: &str = "build.kernel.image_path";
const BUILD_KERNEL_MODULES_FIELD: &str = "build.kernel.modules_path";
const BUILD_KERNEL_LOCALVERSION_FIELD: &str = "build.kernel.localversion";
const BUILD_KERNEL_MODULE_INSTALL_FIELD: &str = "build.kernel.module_install_path";
const LIVE_BOOT_ROOTFS_SOURCE_FIELD: &str = "scenarios.live_boot.rootfs_source_path";
const LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD: &str = "scenarios.live_boot.required_kernel_cmdline";
const LIVE_BOOT_REQUIRED_SERVICES_FIELD: &str = "scenarios.live_boot.required_live_services";
const LIVE_BOOT_ENVELOPE_FIELD: &str = "scenarios.live_boot.envelope";
const LIVE_BOOT_LOCALE_FIELD: &str = "scenarios.live_boot.locale";
const LIVE_BOOT_ARTIFACTS_FIELD: &str = "scenarios.live_boot.artifacts";

#[derive(Debug, Clone)]
pub struct BuildRuntimeArtifacts {
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

fn push_checkpoint_violation(
    violations: &mut Vec<Violation>,
    checkpoint: CheckpointId,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    violations.push(Violation {
        checkpoint: Some(checkpoint),
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
    push_checkpoint_violation(violations, CheckpointId::Build, field, code, message);
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolved_build_host_support_root(
    variant_dir: &Path,
) -> Result<PathBuf, VariantContractLoadError> {
    match resolve_variant_owner_paths(variant_dir) {
        Ok(paths) => Ok(paths.build_host_support_root),
        Err(VariantContractLoadError::PartialRingManifestSet { present, .. })
            if present.is_empty() =>
        {
            Ok(variant_dir.to_path_buf())
        }
        Err(err) => Err(err),
    }
}

fn build_runtime_artifacts_from_contract(
    contract: &ConformanceContract,
    artifact_dir: &Path,
) -> BuildRuntimeArtifacts {
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

    BuildRuntimeArtifacts {
        rootfs_image: artifact_dir.join(rootfs_name),
        initramfs_live: artifact_dir.join(initramfs_live),
        overlay_image: artifact_dir.join(overlay_name),
    }
}

fn live_boot_scenario<'a>(contract: &'a ConformanceContract) -> &'a crate::schema::BootCheckpoint {
    &contract.scenarios.live_boot
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

/// Validate build-runtime provenance invariants against on-disk files.
pub fn validate_build_runtime(
    contract: &ConformanceContract,
    variant_dir: &Path,
    artifact_dir: &Path,
) -> ConformanceReport {
    let runtime_artifacts = build_runtime_artifacts_from_contract(contract, artifact_dir);
    validate_build_runtime_with_artifacts(contract, variant_dir, artifact_dir, &runtime_artifacts)
}

/// Validate build-runtime provenance with split kernel + non-kernel artifact roots.
///
/// Use `kernel_artifact_dir` for kernel provenance outputs and
/// `artifact_dir` for non-kernel build artifacts.
pub fn validate_build_runtime_with_split_artifact_roots(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifact_dir: &Path,
) -> ConformanceReport {
    let runtime_artifacts = build_runtime_artifacts_from_contract(contract, artifact_dir);
    validate_build_runtime_with_artifacts(
        contract,
        variant_dir,
        kernel_artifact_dir,
        &runtime_artifacts,
    )
}

/// Validate build-runtime provenance using explicit artifact paths.
pub fn validate_build_runtime_with_artifacts(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifacts: &BuildRuntimeArtifacts,
) -> ConformanceReport {
    let build = &contract.build;
    let kernel = &build.kernel;
    let mut violations = Vec::new();
    let build_host_support_root = match resolved_build_host_support_root(variant_dir) {
        Ok(path) => path,
        Err(err) => {
            push_violation(
                &mut violations,
                BUILD_KERNEL_KCONFIG_FIELD,
                ViolationCode::InvalidPathDeclaration,
                format!(
                    "invalid build-host ownership scaffold under '{}': {}",
                    variant_dir.display(),
                    err
                ),
            );
            variant_dir.to_path_buf()
        }
    };

    let variant_layout = validate_layout(
        Some(CheckpointId::Build),
        &build_host_support_root,
        &[LayoutRequirement::file(
            BUILD_KERNEL_KCONFIG_FIELD,
            &kernel.kconfig_path,
            ViolationCode::MissingRequiredKernelOutput,
            "declared kernel kconfig path",
        )],
    );
    let kconfig_missing = variant_layout.has_field_violation(BUILD_KERNEL_KCONFIG_FIELD);
    violations.extend(variant_layout.violations);

    let artifact_layout = validate_layout(
        Some(CheckpointId::Build),
        kernel_artifact_dir,
        &[
            LayoutRequirement::file(
                BUILD_KERNEL_RELEASE_FIELD,
                &kernel.release_path,
                ViolationCode::MissingRequiredKernelOutput,
                "kernel.release output",
            ),
            LayoutRequirement::file(
                BUILD_KERNEL_IMAGE_FIELD,
                &kernel.image_path,
                ViolationCode::MissingRequiredKernelOutput,
                "kernel image output",
            ),
        ],
    );
    let release_missing = artifact_layout.has_field_violation(BUILD_KERNEL_RELEASE_FIELD);
    violations.extend(artifact_layout.violations);

    for (field, expectation, path) in [
        (
            "transforms.rootfs_image.output_names",
            "required build-runtime rootfs image",
            &artifacts.rootfs_image,
        ),
        (
            "transforms.initramfs_live.output_names",
            "required build-runtime initramfs",
            &artifacts.initramfs_live,
        ),
        (
            "transforms.overlay_image.output_names",
            "required build-runtime overlay image",
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

    let kconfig_path = build_host_support_root.join(&kernel.kconfig_path);
    if !kconfig_missing {
        match fs::read_to_string(&kconfig_path) {
            Ok(raw) => match parse_kconfig_localversion(&raw) {
                Some(localversion) => {
                    if localversion != kernel.localversion {
                        push_violation(
                            &mut violations,
                            BUILD_KERNEL_LOCALVERSION_FIELD,
                            ViolationCode::InvalidKernelProvenance,
                            format!(
                                "kconfig CONFIG_LOCALVERSION='{}' does not match declared '{}'",
                                localversion, kernel.localversion
                            ),
                        );
                    }
                }
                None => {
                    push_violation(
                        &mut violations,
                        BUILD_KERNEL_LOCALVERSION_FIELD,
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
                    BUILD_KERNEL_KCONFIG_FIELD,
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

    let release_path = kernel_artifact_dir.join(&kernel.release_path);
    let kernel_release = match if release_missing {
        None
    } else {
        read_trimmed(&release_path)
    } {
        Some(value) => {
            if !value.starts_with(&kernel.version) {
                push_violation(
                    &mut violations,
                    BUILD_KERNEL_RELEASE_FIELD,
                    ViolationCode::InvalidKernelProvenance,
                    format!(
                        "kernel.release '{}' does not start with declared kernel_version '{}'",
                        value, kernel.version
                    ),
                );
            }
            if !value.ends_with(&kernel.localversion) {
                push_violation(
                    &mut violations,
                    BUILD_KERNEL_RELEASE_FIELD,
                    ViolationCode::InvalidKernelProvenance,
                    format!(
                        "kernel.release '{}' does not end with declared kernel_localversion '{}'",
                        value, kernel.localversion
                    ),
                );
            }
            Some(value)
        }
        None => {
            if !release_missing {
                push_violation(
                    &mut violations,
                    BUILD_KERNEL_RELEASE_FIELD,
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
        let expanded_modules_rel = kernel
            .modules_path
            .replace("<kernel.release>", &kernel_release);
        let modules_layout = validate_layout(
            Some(CheckpointId::Build),
            kernel_artifact_dir,
            &[LayoutRequirement::directory(
                BUILD_KERNEL_MODULES_FIELD,
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
            BUILD_KERNEL_MODULE_INSTALL_FIELD,
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

/// Require build-runtime checks to pass.
pub fn require_valid_build_runtime(
    contract: &ConformanceContract,
    variant_dir: &Path,
    artifact_dir: &Path,
) -> Result<(), ConformanceError> {
    let report = validate_build_runtime(contract, variant_dir, artifact_dir);
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

pub fn require_valid_build_runtime_with_artifacts(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifacts: &BuildRuntimeArtifacts,
) -> Result<(), ConformanceError> {
    let report = validate_build_runtime_with_artifacts(
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

/// Require build-runtime checks to pass with split kernel + non-kernel artifact roots.
pub fn require_valid_build_runtime_with_split_artifact_roots(
    contract: &ConformanceContract,
    variant_dir: &Path,
    kernel_artifact_dir: &Path,
    artifact_dir: &Path,
) -> Result<(), ConformanceError> {
    let report = validate_build_runtime_with_split_artifact_roots(
        contract,
        variant_dir,
        kernel_artifact_dir,
        artifact_dir,
    );
    if report.passed() {
        Ok(())
    } else {
        Err(ConformanceError { report })
    }
}

fn tagged_live_boot_artifact_name(tag: &str, suffix: &str) -> String {
    format!("{tag}-{suffix}")
}

fn tagged_live_boot_overlay_dir_name(artifact_tag: &str) -> String {
    tagged_live_boot_artifact_name(artifact_tag, "live-overlay")
}

fn tagged_live_boot_rootfs_source_pointer_name(artifact_tag: &str) -> String {
    format!(".{artifact_tag}-live-rootfs-source.path")
}

fn live_boot_runtime_artifacts_from_tagged_artifact_dir(
    artifact_dir: &Path,
    artifact_tag: &str,
) -> LiveBootRuntimeArtifacts {
    LiveBootRuntimeArtifacts {
        rootfs_image: artifact_dir.join(tagged_live_boot_artifact_name(
            artifact_tag,
            "filesystem.erofs",
        )),
        initramfs_live: artifact_dir.join(tagged_live_boot_artifact_name(
            artifact_tag,
            "initramfs-live.cpio.gz",
        )),
        overlay_image: artifact_dir.join(tagged_live_boot_artifact_name(
            artifact_tag,
            "overlayfs.erofs",
        )),
        live_overlay_dir: artifact_dir.join(tagged_live_boot_overlay_dir_name(artifact_tag)),
        rootfs_source_pointer: artifact_dir
            .join(tagged_live_boot_rootfs_source_pointer_name(artifact_tag)),
    }
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
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_ROOTFS_SOURCE_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing live-boot rootfs source pointer '{}'",
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
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_ROOTFS_SOURCE_FIELD,
            ViolationCode::InvalidPathDeclaration,
            format!(
                "policy violation: legacy rootfs source '{}' is forbidden for live-boot runtime",
                resolved.display()
            ),
        );
        return None;
    }

    if !has_directory(&resolved) {
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_ROOTFS_SOURCE_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "live-boot rootfs source directory does not exist: '{}'",
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

fn validate_live_boot_contract_requirements(
    live_boot: &crate::schema::BootCheckpoint,
    violations: &mut Vec<Violation>,
) {
    for token in BOOT_REQUIRED_KERNEL_CMDLINE_BASE {
        if live_boot
            .required_kernel_cmdline
            .iter()
            .any(|candidate| candidate == token)
        {
            continue;
        }
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD,
            ViolationCode::MissingValue,
            format!(
                "live-boot required kernel cmdline token '{}' is missing from contract",
                token
            ),
        );
    }

    for service in BOOT_REQUIRED_LIVE_SERVICES_BASE {
        if live_boot
            .required_live_services
            .iter()
            .any(|candidate| candidate == service)
        {
            continue;
        }
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_SERVICES_FIELD,
            ViolationCode::MissingValue,
            format!(
                "live-boot required live service '{}' is missing from contract",
                service
            ),
        );
    }
}

fn validate_systemd_live_boot_ssh(
    live_boot: &crate::schema::BootCheckpoint,
    rootfs_dir: &Path,
    live_overlay_dir: &Path,
    violations: &mut Vec<Violation>,
) {
    validate_live_boot_usrmerge_symlinks(rootfs_dir, violations);
    validate_systemd_live_boot_locale_completeness(rootfs_dir, violations);
    validate_live_boot_required_ssh_artifacts(rootfs_dir, violations);

    let rootfs_layout = validate_layout(
        Some(CheckpointId::Boot),
        rootfs_dir,
        &[
            LayoutRequirement::file(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "usr/sbin/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenSSH daemon binary",
            ),
            LayoutRequirement::file(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "usr/lib/systemd/system/sshd.service",
                ViolationCode::MissingBaselineArtifact,
                "systemd sshd service unit",
            ),
            LayoutRequirement::file(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "usr/lib/systemd/system/sshd-keygen@.service",
                ViolationCode::MissingBaselineArtifact,
                "systemd sshd keygen unit",
            ),
            LayoutRequirement::directory(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
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
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_SERVICES_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing systemd live-boot sshd enablement symlink '{}'",
                wants_link.display()
            ),
        );
    }

    let rootfs_tmpfiles = rootfs_dir.join("usr/lib/tmpfiles.d/sshd.conf");
    let overlay_tmpfiles = live_overlay_dir.join("etc/tmpfiles.d/sshd-local.conf");
    if !has_file(&rootfs_tmpfiles) && !has_file(&overlay_tmpfiles) {
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_SERVICES_FIELD,
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
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_KERNEL_CMDLINE_FIELD,
            ViolationCode::MissingValue,
            format!(
                "found '{}' but required kernel cmdline is missing 'inst.sshd=0'; \
                 this can race/conflict with primary sshd.service on port 22",
                anaconda_sshd.display()
            ),
        );
    }

    validate_forbidden_installed_tool_leaks(rootfs_dir, violations);
}

fn validate_live_boot_usrmerge_symlinks(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    for (rel, expected_target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/sbin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib64"),
    ] {
        let path = rootfs_dir.join(rel);
        if !has_symlink(&path) {
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_ENVELOPE_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing required live-boot merged-usr symlink '{}'; expected '{}' -> '{}'",
                    path.display(),
                    rel,
                    expected_target
                ),
            );
            continue;
        }
        if !symlink_target_equals(&path, expected_target) {
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_ENVELOPE_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "invalid live-boot merged-usr symlink '{}'; expected target '{}'",
                    path.display(),
                    expected_target
                ),
            );
        }
    }
}

fn validate_openrc_live_boot_ssh(
    live_boot: &crate::schema::BootCheckpoint,
    rootfs_dir: &Path,
    live_overlay_dir: &Path,
    violations: &mut Vec<Violation>,
) {
    validate_openrc_live_boot_locale_completeness(rootfs_dir, violations);
    validate_live_boot_required_ssh_artifacts(rootfs_dir, violations);

    let rootfs_layout = validate_layout(
        Some(CheckpointId::Boot),
        rootfs_dir,
        &[
            LayoutRequirement::file(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "usr/sbin/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenSSH daemon binary",
            ),
            LayoutRequirement::file(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "etc/init.d/sshd",
                ViolationCode::MissingBaselineArtifact,
                "OpenRC sshd service script",
            ),
        ],
    );
    violations.extend(rootfs_layout.violations);

    let runlevel_link = live_overlay_dir.join("etc/runlevels/default/sshd");
    if !has_symlink(&runlevel_link) {
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_SERVICES_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing OpenRC live-boot sshd runlevel symlink '{}'",
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
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC networking service script '{}'",
                    networking_script.display()
                ),
            );
        }

        let interfaces_path = rootfs_dir.join("etc/network/interfaces");
        if !has_file(&interfaces_path) {
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC network interfaces config '{}'",
                    interfaces_path.display()
                ),
            );
        }

        let networking_boot_link = live_overlay_dir.join("etc/runlevels/boot/networking");
        if !has_symlink(&networking_boot_link) {
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC live-boot networking runlevel symlink '{}'",
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
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC dhcpcd service script '{}'",
                    dhcpcd_script.display()
                ),
            );
        }

        let dhcpcd_link = live_overlay_dir.join("etc/runlevels/default/dhcpcd");
        if !has_symlink(&dhcpcd_link) {
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "missing OpenRC live-boot dhcpcd runlevel symlink '{}'",
                    dhcpcd_link.display()
                ),
            );
        }
    }

    validate_forbidden_installed_tool_leaks(rootfs_dir, violations);
}

fn validate_openrc_live_boot_locale_completeness(
    rootfs_dir: &Path,
    violations: &mut Vec<Violation>,
) {
    let locale_conf = rootfs_dir.join("etc/locale.conf");
    if !has_file(&locale_conf) {
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_LOCALE_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing live-boot locale config '{}'; expected canonical LANG=C.UTF-8",
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
                    push_checkpoint_violation(
                        violations,
                        CheckpointId::Boot,
                        LIVE_BOOT_LOCALE_FIELD,
                        ViolationCode::MissingValue,
                        format!(
                            "invalid live-boot locale config '{}': expected line 'LANG=C.UTF-8'",
                            locale_conf.display()
                        ),
                    );
                }
            }
            Err(err) => {
                push_checkpoint_violation(
                    violations,
                    CheckpointId::Boot,
                    LIVE_BOOT_LOCALE_FIELD,
                    ViolationCode::MissingBaselineArtifact,
                    format!(
                        "failed reading live-boot locale config '{}': {}",
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
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_LOCALE_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing live-boot locale payload under '{}'; expected one of glibc paths [{}] or musl path 'usr/share/i18n/locales/musl/en_US.UTF-8'",
                rootfs_dir.display(),
                glibc_locale_payload_candidates.join(", ")
            ),
        );
    }
}

fn validate_forbidden_installed_tool_leaks(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    for rel in ["usr/bin/recstrap", "usr/bin/recfstab", "usr/bin/recchroot"] {
        let path = rootfs_dir.join(rel);
        if has_file(&path) {
            push_checkpoint_violation(
                violations,
                CheckpointId::Boot,
                LIVE_BOOT_ENVELOPE_FIELD,
                ViolationCode::MissingBaselineArtifact,
                format!(
                    "forbidden installed-tools payload leaked into live-boot rootfs: '{}'",
                    path.display()
                ),
            );
        }
    }
}

fn validate_live_boot_required_ssh_artifacts(rootfs_dir: &Path, violations: &mut Vec<Violation>) {
    let ssh_layout = validate_layout(
        Some(CheckpointId::Boot),
        rootfs_dir,
        &[
            LayoutRequirement::file(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "etc/ssh/sshd_config",
                ViolationCode::MissingBaselineArtifact,
                "canonical live-boot sshd config",
            ),
            LayoutRequirement::directory(
                LIVE_BOOT_REQUIRED_SERVICES_FIELD,
                "usr/share/empty.sshd",
                ViolationCode::MissingBaselineArtifact,
                "live-boot empty sshd directory",
            ),
        ],
    );
    violations.extend(ssh_layout.violations);
}

fn validate_systemd_live_boot_locale_completeness(
    rootfs_dir: &Path,
    violations: &mut Vec<Violation>,
) {
    let locale_conf = rootfs_dir.join("etc/locale.conf");
    if !has_file(&locale_conf) {
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_LOCALE_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing live-boot locale config '{}'; expected canonical LANG=C.UTF-8",
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
                    push_checkpoint_violation(
                        violations,
                        CheckpointId::Boot,
                        LIVE_BOOT_LOCALE_FIELD,
                        ViolationCode::MissingValue,
                        format!(
                            "invalid live-boot locale config '{}': expected line 'LANG=C.UTF-8'",
                            locale_conf.display()
                        ),
                    );
                }
            }
            Err(err) => {
                push_checkpoint_violation(
                    violations,
                    CheckpointId::Boot,
                    LIVE_BOOT_LOCALE_FIELD,
                    ViolationCode::MissingBaselineArtifact,
                    format!(
                        "failed reading live-boot locale config '{}': {}",
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
        push_checkpoint_violation(
            violations,
            CheckpointId::Boot,
            LIVE_BOOT_LOCALE_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "missing live-boot UTF-8 locale payload under '{}'; expected one of: {}",
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
    validate_live_boot_contract_requirements(live_boot, &mut violations);

    for (field, expectation, path, is_dir) in [
        (
            LIVE_BOOT_ARTIFACTS_FIELD,
            "live-boot rootfs image",
            artifacts.rootfs_image.as_path(),
            false,
        ),
        (
            LIVE_BOOT_ARTIFACTS_FIELD,
            "live-boot initramfs",
            artifacts.initramfs_live.as_path(),
            false,
        ),
        (
            LIVE_BOOT_ARTIFACTS_FIELD,
            "live-boot overlay image",
            artifacts.overlay_image.as_path(),
            false,
        ),
        (
            LIVE_BOOT_ARTIFACTS_FIELD,
            "live-boot overlay source directory",
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
            push_checkpoint_violation(
                &mut violations,
                CheckpointId::Boot,
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
        validate_systemd_live_boot_ssh(
            live_boot,
            &rootfs_source_dir,
            live_overlay_dir,
            &mut violations,
        );
    } else if has_openrc_script {
        validate_openrc_live_boot_ssh(
            live_boot,
            &rootfs_source_dir,
            live_overlay_dir,
            &mut violations,
        );
    } else {
        push_checkpoint_violation(
            &mut violations,
            CheckpointId::Boot,
            LIVE_BOOT_REQUIRED_SERVICES_FIELD,
            ViolationCode::MissingBaselineArtifact,
            format!(
                "unable to locate live-boot ssh service wiring under '{}': \
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

/// Validate live-boot runtime using a compatibility artifact root plus tag.
pub fn validate_live_boot_runtime_with_compatibility_artifact_dir(
    contract: &ConformanceContract,
    artifact_dir: &Path,
    artifact_tag: &str,
) -> ConformanceReport {
    let artifacts =
        live_boot_runtime_artifacts_from_tagged_artifact_dir(artifact_dir, artifact_tag);
    validate_live_boot_runtime(contract, &artifacts)
}

pub fn require_valid_live_boot_runtime_with_compatibility_artifact_dir(
    contract: &ConformanceContract,
    artifact_dir: &Path,
    artifact_tag: &str,
) -> Result<(), ConformanceError> {
    let report = validate_live_boot_runtime_with_compatibility_artifact_dir(
        contract,
        artifact_dir,
        artifact_tag,
    );
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
