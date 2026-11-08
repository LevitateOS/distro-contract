//! The live ISO's install screen, the same on every variant: its parts, and the
//! names the builder that puts it together, the split pane and the tests that
//! drive it share.
//!
//! On each of [`CONSOLES`], getty starts [`LAUNCHER`] in place of login. The
//! launcher runs the split pane [`SPLIT`] with [`HUB`] on the left and [`DOCS`]
//! at [`DOCS_PAGE`] on the right, and becomes a [`SHELL`] login shell when the
//! screen ends. A serial console (`ttyS*`) runs the screen only when the
//! boot-injection payload sets [`SERIAL_KEY`]`=1`. Both apps are told the
//! distro's name (and the hub its shell) through the flags their manifests
//! declare; [`APPS`] are commands for the shell beside the docs. Paths are
//! relative to a layer's root.

/// Consoles whose getty starts the install screen.
pub const CONSOLES: &[&str] = &["tty1", "ttyS0"];
/// The shell the hub opens and the login shell that takes over when the screen ends.
pub const SHELL: &str = "/bin/bash";
/// The left pane: the install steps in order, with the shell one key away (a TUI
/// app under `tui/apps`, by its `bin` name).
pub const HUB: &str = "install-hub";
/// The right pane: the install guide.
pub const DOCS: &str = "install-docs";
/// The page the docs open at, the same slug on every distro.
pub const DOCS_PAGE: &str = "installation";
/// TUI apps the live ISO carries besides the hub and the docs.
pub const APPS: &[&str] = &["disk-plan", "base-system"];

macro_rules! bin_dir {
    () => {
        "usr/local/bin"
    };
}
/// Where each TUI app's command goes: `BIN_DIR/<app name>`.
pub const BIN_DIR: &str = bin_dir!();
/// What getty starts on an install-screen console; `--probe` prints
/// `PROBE_PREFIX<split pane path>`.
pub const LAUNCHER: &str = concat!(bin_dir!(), "/install-ux");
pub const PROBE_PREFIX: &str = "install-entrypoint-helper=";
/// The split pane, `install-split-pane`'s `install-split`, where the builder's
/// live tools install it (`usr/bin/<binary>`).
pub const SPLIT: &str = "usr/bin/install-split";
/// The `TERM` the split pane gives its panes (it is their terminal, a vt100
/// emulator); headless captures of the apps use the same.
pub const PANE_TERM: &str = "xterm-256color";
/// The boot-injection key that turns the install screen on for a serial console.
pub const SERIAL_KEY: &str = "INSTALL_UX_SERIAL";
/// Set to 1, the launcher runs the split pane's `--smoke` with its real panes instead.
pub const SMOKE_ENV: &str = "INSTALL_UX_SMOKE";
/// The line `install-split --smoke` starts its report with when both panes drew.
pub const SMOKE_OK: &str = "split-smoke:ok";
