//! Checks of built artifacts against the contract: kernel provenance and the
//! live boot's SSH, locale and merged-/usr wiring.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Violation;
use crate::schema::{ConformanceContract, LiveService};
use crate::variant::Variant;
use distro_profile::{InitSystem, Libc};

/// The build outputs `validate_build_runtime` checks.
#[derive(Debug, Clone)]
pub struct BuildRuntimeArtifacts {
    pub rootfs_image: PathBuf,
    pub initramfs_live: PathBuf,
    pub overlay_image: PathBuf,
    /// The kernel build's `kernel.release` file.
    pub kernel_release: PathBuf,
    pub kernel_image: PathBuf,
    /// The directory holding `<kernel.release>/` with the modules.
    pub kernel_modules: PathBuf,
}

/// The live-boot outputs `validate_live_boot_runtime` checks.
#[derive(Debug, Clone)]
pub struct LiveBootRuntimeArtifacts {
    pub rootfs_image: PathBuf,
    pub initramfs_live: PathBuf,
    pub overlay_image: PathBuf,
    pub live_overlay_dir: PathBuf,
    /// A file holding the path of the rootfs source tree.
    pub rootfs_source_pointer: PathBuf,
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

fn is_dir(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_dir())
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

fn read_trimmed(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Collects one violation per missing artifact, under the artifact's path.
struct Missing(Vec<Violation>);

impl Missing {
    fn push(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.0.push(Violation::new(field, message));
    }

    fn file(&mut self, path: &Path, what: &str) -> bool {
        let ok = is_file(path);
        if !ok {
            self.push(path.display().to_string(), format!("missing {what}"));
        }
        ok
    }

    fn dir(&mut self, path: &Path, what: &str) -> bool {
        let ok = is_dir(path);
        if !ok {
            self.push(path.display().to_string(), format!("missing {what}"));
        }
        ok
    }

    fn symlink(&mut self, path: &Path, what: &str) {
        if !is_symlink(path) {
            self.push(path.display().to_string(), format!("missing {what}"));
        }
    }
}

fn kconfig_localversion(kconfig: &str) -> Option<String> {
    let value = kconfig
        .lines()
        .find_map(|line| line.trim().strip_prefix("CONFIG_LOCALVERSION="))?
        .trim();
    Some(
        value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value)
            .to_string(),
    )
}

/// Check the kernel build and the boot images against the variant's kernel pin.
pub fn validate_build_runtime(
    variant: &Variant,
    artifacts: &BuildRuntimeArtifacts,
) -> Vec<Violation> {
    let kernel = &variant.contract.build.kernel;
    let mut out = Missing(Vec::new());

    let kconfig = variant.path("kconfig");
    match fs::read_to_string(&kconfig).ok().as_deref().map(kconfig_localversion) {
        None => out.push("kconfig", format!("cannot read {}", kconfig.display())),
        Some(None) => out.push("kconfig", "sets no CONFIG_LOCALVERSION"),
        Some(Some(found)) if found != kernel.localversion => out.push(
            "build.kernel.localversion",
            format!("kconfig sets CONFIG_LOCALVERSION='{found}', not '{}'", kernel.localversion),
        ),
        Some(Some(_)) => {}
    }

    out.file(&artifacts.kernel_image, "kernel image");
    out.file(&artifacts.rootfs_image, "rootfs image");
    out.file(&artifacts.initramfs_live, "live initramfs");
    out.file(&artifacts.overlay_image, "overlay image");

    let release_path = &artifacts.kernel_release;
    match read_trimmed(release_path) {
        None => out.push(
            release_path.display().to_string(),
            "missing or empty kernel.release",
        ),
        Some(release) => {
            if !release.starts_with(&kernel.version) {
                out.push(
                    "build.kernel.version",
                    format!("the built kernel is '{release}', not version {}", kernel.version),
                );
            } else if !release.ends_with(&kernel.localversion) {
                out.push(
                    "build.kernel.localversion",
                    format!("the built kernel '{release}' does not end with {}", kernel.localversion),
                );
            }
            out.dir(&artifacts.kernel_modules.join(&release), "kernel modules");
        }
    }
    out.0
}

/// Check the live boot's rootfs and overlay for working SSH, the live
/// services, a UTF-8 locale and (systemd) merged /usr, as the variant's
/// profile (init, libc) has them.
pub fn validate_live_boot_runtime(
    contract: &ConformanceContract,
    artifacts: &LiveBootRuntimeArtifacts,
) -> Vec<Violation> {
    let profile = &contract.profile;
    let mut out = Missing(Vec::new());
    out.file(&artifacts.rootfs_image, "live-boot rootfs image");
    out.file(&artifacts.initramfs_live, "live-boot initramfs");
    out.file(&artifacts.overlay_image, "live-boot overlay image");
    out.dir(&artifacts.live_overlay_dir, "live-boot overlay source directory");

    let pointer = &artifacts.rootfs_source_pointer;
    let Some(source) = read_trimmed(pointer) else {
        out.push(pointer.display().to_string(), "missing live-boot rootfs source pointer");
        return out.0;
    };
    let source = PathBuf::from(source);
    let rootfs = if source.is_absolute() {
        source
    } else {
        pointer.parent().unwrap_or(Path::new(".")).join(source)
    };
    if !out.dir(&rootfs, "live-boot rootfs source directory") {
        return out.0;
    }
    let overlay = &artifacts.live_overlay_dir;
    let services = "live.services";

    let sshd_service = match profile.init {
        InitSystem::Systemd => "usr/lib/systemd/system/sshd.service",
        InitSystem::Openrc => "etc/init.d/sshd",
    };
    if !is_file(&rootfs.join(sshd_service)) {
        out.push(
            services,
            format!("{} has no {sshd_service} ({} sshd service)", rootfs.display(), profile.init),
        );
        return out.0;
    }

    out.file(&rootfs.join("usr/sbin/sshd"), "OpenSSH daemon");
    out.file(&rootfs.join("etc/ssh/sshd_config"), "sshd config");
    out.dir(&rootfs.join("usr/share/empty.sshd"), "empty sshd directory");
    check_locale(&mut out, &rootfs, profile.libc == Libc::Musl);

    if profile.init == InitSystem::Systemd {
        for (link, target) in [
            ("bin", "usr/bin"),
            ("sbin", "usr/sbin"),
            ("lib", "usr/lib"),
            ("lib64", "usr/lib64"),
        ] {
            let path = rootfs.join(link);
            if fs::read_link(&path).ok().as_deref() != Some(Path::new(target)) {
                out.push(
                    path.display().to_string(),
                    format!("must be a merged-/usr symlink to '{target}'"),
                );
            }
        }
        out.file(
            &rootfs.join("usr/lib/systemd/system/sshd-keygen@.service"),
            "systemd sshd keygen unit",
        );
        out.dir(&rootfs.join("var/empty/sshd"), "OpenSSH privilege-separation directory");
        out.symlink(
            &overlay.join("etc/systemd/system/multi-user.target.wants/sshd.service"),
            "sshd enablement symlink",
        );
        let tmpfiles = rootfs.join("usr/lib/tmpfiles.d/sshd.conf");
        let local_tmpfiles = overlay.join("etc/tmpfiles.d/sshd-local.conf");
        if !is_file(&tmpfiles) && !is_file(&local_tmpfiles) {
            out.push(
                tmpfiles.display().to_string(),
                format!("missing /run/sshd tmpfiles policy (or {})", local_tmpfiles.display()),
            );
        }
    } else {
        out.symlink(&overlay.join("etc/runlevels/default/sshd"), "OpenRC sshd runlevel symlink");
        if contract.live_services().contains(&LiveService::Network) {
            out.file(&rootfs.join("etc/init.d/networking"), "OpenRC networking service");
            out.file(&rootfs.join("etc/network/interfaces"), "network interfaces config");
            out.symlink(
                &overlay.join("etc/runlevels/boot/networking"),
                "OpenRC networking runlevel symlink",
            );
            out.file(&rootfs.join("etc/init.d/dhcpcd"), "OpenRC dhcpcd service");
            out.symlink(
                &overlay.join("etc/runlevels/default/dhcpcd"),
                "OpenRC dhcpcd runlevel symlink",
            );
        }
    }
    out.0
}

/// `etc/locale.conf` sets `LANG=C.UTF-8`, and the C.UTF-8 locale is there
/// (glibc's compiled one, or with musl also musl's).
fn check_locale(out: &mut Missing, rootfs: &Path, musl_allowed: bool) {
    let locale_conf = rootfs.join("etc/locale.conf");
    if out.file(&locale_conf, "locale config (LANG=C.UTF-8)") {
        let sets_c_utf8 = fs::read_to_string(&locale_conf)
            .is_ok_and(|text| text.lines().any(|line| line.trim() == "LANG=C.UTF-8"));
        if !sets_c_utf8 {
            out.push(locale_conf.display().to_string(), "must set LANG=C.UTF-8");
        }
    }
    let glibc = [
        "lib/locale/C.utf8/LC_CTYPE",
        "usr/lib/locale/C.utf8/LC_CTYPE",
        "lib64/locale/C.utf8/LC_CTYPE",
        "usr/lib64/locale/C.utf8/LC_CTYPE",
    ];
    let musl = "usr/share/i18n/locales/musl/en_US.UTF-8";
    let found = glibc.iter().any(|rel| is_file(&rootfs.join(rel)))
        || (musl_allowed && is_file(&rootfs.join(musl)));
    if !found {
        let expected = if musl_allowed {
            format!("{} or {musl}", glibc.join(", "))
        } else {
            glibc.join(", ")
        };
        out.push(
            rootfs.display().to_string(),
            format!("missing the UTF-8 locale (one of {expected})"),
        );
    }
}
