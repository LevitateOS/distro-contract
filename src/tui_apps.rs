//! The terminal apps under `tui/apps/`, as their own `package.json` files describe them.
//!
//! Each app is a member of the root JavaScript workspace and declares itself once:
//! its `bin` entry gives its one name (also the directory name and the package name
//! `@levitate/<name>`) and its entry file, and an optional `levitate` block lists the
//! Rust tools it runs from PATH and how `cargo xtask inspect` renders it. xtask and
//! the builder read apps from here instead of spelling out paths.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Workspace members under this prefix are apps; others (the kit, docs) are libraries.
const APPS_PREFIX: &str = "tui/apps/";

#[derive(Debug, Clone)]
pub struct TuiApp {
    /// The app's one name: `bin` key, directory name, `@levitate/<name>`.
    pub name: String,
    /// Absolute app directory.
    pub dir: PathBuf,
    /// Entry file, relative to `dir`.
    pub entry: PathBuf,
    /// Cargo packages whose binaries the app runs from PATH.
    pub tools: Vec<String>,
    /// How `cargo xtask inspect` renders the app headlessly.
    pub inspect: Inspect,
}

#[derive(Debug)]
pub struct TuiAppError(String);

impl fmt::Display for TuiAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TuiAppError {}

fn err(message: impl Into<String>) -> TuiAppError {
    TuiAppError(message.into())
}

#[derive(Deserialize)]
struct RootManifest {
    workspaces: Vec<String>,
}

#[derive(Deserialize)]
struct AppManifest {
    name: String,
    #[serde(default)]
    bin: BTreeMap<String, String>,
    #[serde(default)]
    levitate: Levitate,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Levitate {
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    inspect: Inspect,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Inspect {
    /// Arguments passed before any the caller gives.
    #[serde(default)]
    pub args: Vec<String>,
    /// How to render every page: run the app with `list` to print one page per line,
    /// then render each with `arg <page>`.
    #[serde(default)]
    pub pages: Option<Pages>,
    /// Tool invocations a headless run must never make, as `tool token…`: a call to
    /// `tool` whose arguments contain every token is refused (e.g. `recpart apply --confirm`).
    #[serde(default)]
    pub refuse: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pages {
    pub list: Vec<String>,
    pub arg: String,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, TuiAppError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| err(format!("reading '{}': {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| err(format!("parsing '{}': {e}", path.display())))
}

/// The root workspace members that are TUI packages (apps and the kit).
pub fn tui_packages(repo_root: &Path) -> Result<Vec<PathBuf>, TuiAppError> {
    let root: RootManifest = read_json(&repo_root.join("package.json"))?;
    Ok(root
        .workspaces
        .iter()
        .filter(|member| member.starts_with("tui/"))
        .map(|member| repo_root.join(member))
        .collect())
}

/// Every app in the root workspace, in workspace order.
pub fn discover(repo_root: &Path) -> Result<Vec<TuiApp>, TuiAppError> {
    let root: RootManifest = read_json(&repo_root.join("package.json"))?;
    root.workspaces
        .iter()
        .filter(|member| member.starts_with(APPS_PREFIX))
        .map(|member| load(&repo_root.join(member)))
        .collect()
}

/// The app called `name`.
pub fn find(repo_root: &Path, name: &str) -> Result<TuiApp, TuiAppError> {
    let apps = discover(repo_root)?;
    let names: Vec<String> = apps.iter().map(|app| app.name.clone()).collect();
    apps.into_iter().find(|app| app.name == name).ok_or_else(|| {
        err(format!(
            "no TUI app named '{name}' (apps in the root workspace: {})",
            names.join(", ")
        ))
    })
}

fn load(dir: &Path) -> Result<TuiApp, TuiAppError> {
    let path = dir.join("package.json");
    let manifest: AppManifest = read_json(&path)?;
    let mut bins = manifest.bin.into_iter();
    let (name, entry) = match (bins.next(), bins.next()) {
        (Some(bin), None) => bin,
        _ => return Err(err(format!("'{}' must declare exactly one bin", path.display()))),
    };
    let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    if dir_name != name || manifest.name != format!("@levitate/{name}") {
        return Err(err(format!(
            "'{}': the bin name, the directory name and the package name '@levitate/<name>' must agree (bin '{name}', directory '{dir_name}', package '{}')",
            path.display(),
            manifest.name
        )));
    }
    Ok(TuiApp {
        name,
        dir: dir.to_path_buf(),
        entry: PathBuf::from(entry),
        tools: manifest.levitate.tools,
        inspect: manifest.levitate.inspect,
    })
}
