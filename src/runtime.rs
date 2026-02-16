//! Runtime Stage 00 provenance checks against real build outputs.
//!
//! Unlike declaration-only validation, this verifies that declared Stage 00
//! invariants match on-disk artifacts (kconfig + kernel build outputs).

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{StageId, ConformanceError, ConformanceReport, Violation, ViolationCode};
use crate::schema::ConformanceContract;

fn push_violation(
    violations: &mut Vec<Violation>,
    field: impl Into<String>,
    code: ViolationCode,
    message: impl Into<String>,
) {
    violations.push(Violation {
        stage: Some(StageId::Stage00),
        field: field.into(),
        code,
        message: message.into(),
    });
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
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
    let stage_00 = &contract.stages.stage_00_build;
    let mut violations = Vec::new();

    let kconfig_path = variant_dir.join(&stage_00.kernel_kconfig_path);
    if !kconfig_path.is_file() {
        push_violation(
            &mut violations,
            "stage_00_build.kernel_kconfig_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "declared kernel kconfig path does not exist: '{}'",
                kconfig_path.display()
            ),
        );
    } else {
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

    let release_path = artifact_dir.join(&stage_00.kernel_release_path);
    let kernel_release = match read_trimmed(&release_path) {
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
            push_violation(
                &mut violations,
                "stage_00_build.kernel_release_path",
                ViolationCode::MissingRequiredKernelOutput,
                format!(
                    "missing or empty kernel.release output at '{}'",
                    release_path.display()
                ),
            );
            None
        }
    };

    let kernel_image_path = artifact_dir.join(&stage_00.kernel_image_path);
    if !kernel_image_path.is_file() {
        push_violation(
            &mut violations,
            "stage_00_build.kernel_image_path",
            ViolationCode::MissingRequiredKernelOutput,
            format!(
                "missing kernel image output at '{}'",
                kernel_image_path.display()
            ),
        );
    }

    if let Some(kernel_release) = kernel_release {
        let expanded_modules_rel = stage_00
            .kernel_modules_path
            .replace("<kernel.release>", &kernel_release);
        let modules_path = artifact_dir.join(expanded_modules_rel);
        if !modules_path.is_dir() {
            push_violation(
                &mut violations,
                "stage_00_build.kernel_modules_path",
                ViolationCode::MissingRequiredKernelOutput,
                format!(
                    "missing kernel modules output for release '{}' at '{}'",
                    kernel_release,
                    modules_path.display()
                ),
            );
        }
    }

    let usrmerge_root = artifact_dir.join(PathBuf::from("staging/usr/lib/modules"));
    let legacy_root = artifact_dir.join(PathBuf::from("staging/lib/modules"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;
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
            artifacts: ArtifactIdentity {
                rootfs_name: "filesystem.erofs".to_string(),
                initramfs_live_output: "initramfs-live.cpio.gz".to_string(),
                iso_filename: "levitateos-x86_64.iso".to_string(),
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
                    kernel_localversion: "-levitate".to_string(),
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
}
