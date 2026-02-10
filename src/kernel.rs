//! Kernel build and installation contracts.

/// Configuration for kernel installation.
///
/// Implemented by distro-specific configs to customize
/// where and how the kernel is installed.
pub trait KernelInstallConfig {
    /// Path where modules are installed (e.g., "/usr/lib/modules" or "/lib/modules").
    fn module_install_path(&self) -> &str;

    /// Kernel filename in /boot (e.g., "vmlinuz").
    fn kernel_filename(&self) -> &str;
}

/// Trait for CLI commands that can trigger kernel builds.
///
/// Enforces the two-step confirmation pattern (`--kernel` + `--dangerously-waste-the-users-time`)
/// across all distro builders. Each crate's Build command implements this.
pub trait KernelBuildGuard {
    /// Whether the user passed `--kernel` or the `kernel` subcommand.
    fn kernel_requested(&self) -> bool;

    /// Whether the user also passed `--dangerously-waste-the-users-time`.
    fn kernel_confirmed(&self) -> bool;

    /// Example command shown in the warning box (e.g., "cargo run -- build --kernel --dangerously-waste-the-users-time").
    fn kernel_example_cmd(&self) -> &str;

    /// Gate kernel builds behind the two-step confirmation.
    /// Prints a warning and exits if `kernel_requested()` but not `kernel_confirmed()`.
    fn require_kernel_confirmation(&self) {
        if !self.kernel_requested() {
            return;
        }
        if self.kernel_confirmed() {
            return;
        }
        let example_cmd = self.kernel_example_cmd();
        eprintln!();
        eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
        eprintln!("  ║  KERNEL BUILD TAKES ~1 HOUR                                  ║");
        eprintln!("  ║                                                              ║");
        eprintln!("  ║  To confirm, add: --dangerously-waste-the-users-time         ║");
        eprintln!("  ║                                                              ║");
        eprintln!("  ║  Example:                                                    ║");
        eprintln!("  ║    {:<57}║", example_cmd);
        eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(1);
    }
}

/// Simple implementation of [`KernelBuildGuard`] for use in match arms.
///
/// Constructed from the destructured clap fields:
/// ```rust,ignore
/// let guard = KernelGuard::new(true, confirmed, "cargo run -- build kernel --dangerously-waste-the-users-time");
/// guard.require_kernel_confirmation();
/// ```
pub struct KernelGuard<'a> {
    pub requested: bool,
    pub confirmed: bool,
    pub example_cmd: &'a str,
}

impl<'a> KernelGuard<'a> {
    pub fn new(requested: bool, confirmed: bool, example_cmd: &'a str) -> Self {
        Self { requested, confirmed, example_cmd }
    }
}

impl KernelBuildGuard for KernelGuard<'_> {
    fn kernel_requested(&self) -> bool { self.requested }
    fn kernel_confirmed(&self) -> bool { self.confirmed }
    fn kernel_example_cmd(&self) -> &str { self.example_cmd }
}
