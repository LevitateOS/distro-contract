//! Where a checkout's builds and scenario runs put their outputs (the
//! `.artifacts` layout), and the record every run leaves: one manifest
//! schema for release builds and scenario runs, written atomically, with an
//! atomic run-directory allocator and a prune that keeps what is still used.
//!
//! Every `.artifacts` path is a function here; the builder, xtask and
//! install-tests read them instead of spelling paths.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::registry::{ProductId, ScenarioId};

/// How many runs of one release product a build keeps.
pub const RELEASE_RETENTION: usize = 5;
/// How many runs of one scenario a scenario run keeps.
pub const SCENARIO_RETENTION: usize = 5;

const MANIFEST: &str = "run-manifest.json";

fn artifacts(repo_root: &Path) -> PathBuf {
    repo_root.join(".artifacts")
}

/// `.artifacts/out/<variant>`: every release and scenario run of a variant.
pub fn distro_output_dir(repo_root: &Path, distro_id: &str) -> PathBuf {
    artifacts(repo_root).join("out").join(distro_id)
}

/// The runs of one release product: `out/<variant>/releases/<product>`.
pub fn release_dir(repo_root: &Path, distro_id: &str, product: ProductId) -> PathBuf {
    distro_output_dir(repo_root, distro_id)
        .join("releases")
        .join(product.name())
}

/// The runs of one scenario: `out/<variant>/scenarios/<scenario>`.
pub fn scenario_dir(repo_root: &Path, distro_id: &str, scenario: ScenarioId) -> PathBuf {
    distro_output_dir(repo_root, distro_id)
        .join("scenarios")
        .join(scenario.key())
}

/// The variant's current kernel build (a link to the selected bundle).
pub fn kernel_dir(repo_root: &Path, distro_id: &str) -> PathBuf {
    artifacts(repo_root)
        .join("kernel")
        .join(distro_id)
        .join("current")
}

/// The Recipe build and state directory of a variant's recipes.
pub fn recipe_work_dir(repo_root: &Path, distro_id: &str) -> PathBuf {
    artifacts(repo_root)
        .join("work")
        .join(distro_id)
        .join("downloads")
}

/// The work directory of the variant's rootfs source recipes.
pub fn rootfs_source_work_dir(repo_root: &Path, distro_id: &str) -> PathBuf {
    artifacts(repo_root)
        .join("work")
        .join(distro_id)
        .join("rootfs-source-provider")
}

/// Where `cargo xtask build erofs` prepares a product outside a release run.
pub fn prepared_dir(repo_root: &Path, distro_id: &str, product: ProductId) -> PathBuf {
    artifacts(repo_root)
        .join("prepared")
        .join(distro_id)
        .join(product.name())
}

/// The SSH key scenario guests trust (its public half beside it, `.pub`).
pub fn ssh_key(repo_root: &Path) -> PathBuf {
    artifacts(repo_root).join("ssh").join("id_ed25519")
}

/// What a run is a run of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunKind {
    ReleaseProduct,
    Scenario,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Building,
    Success,
    Failed,
}

/// A run another run used; prune keeps it while the user is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRef {
    pub target_kind: RunKind,
    pub target_name: String,
    pub run_id: String,
}

/// The record a run leaves in its directory, `run-manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    /// The run directory's name, by construction.
    pub run_id: String,
    pub distro_id: String,
    pub target_kind: RunKind,
    /// The product name or the scenario key.
    pub target_name: String,
    pub status: RunStatus,
    /// RFC 3339, UTC.
    pub created_at_utc: String,
    pub finished_at_utc: Option<String>,
    /// Release runs: the ISO built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_path: Option<PathBuf>,
    /// Scenario runs: the runs whose outputs this run used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<RunRef>,
    /// Scenario runs: what the inputs were, so a later run can tell whether
    /// this result still holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Scenario runs: what the run proved, or why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Install runs: the layout installed (`ab` or `mutable`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_mode: Option<String>,
}

impl RunManifest {
    /// The release product a release run built.
    pub fn product(&self) -> Option<ProductId> {
        (self.target_kind == RunKind::ReleaseProduct)
            .then(|| ProductId::from_name(&self.target_name))
            .flatten()
    }

    /// A reference to this run, for a run that uses it.
    pub fn reference(&self) -> RunRef {
        RunRef {
            target_kind: self.target_kind,
            target_name: self.target_name.clone(),
            run_id: self.run_id.clone(),
        }
    }
}

/// A run in progress: its directory and the manifest it keeps there.
#[derive(Debug)]
pub struct Run {
    pub dir: PathBuf,
    pub manifest: RunManifest,
}

impl Run {
    /// Allocate a new run directory under `parent` and record the run as
    /// `building`.
    pub fn start(parent: &Path, distro_id: &str, kind: RunKind, target: &str) -> io::Result<Self> {
        let (run_id, dir) = allocate(parent)?;
        let run = Self {
            dir,
            manifest: RunManifest {
                run_id,
                distro_id: distro_id.to_string(),
                target_kind: kind,
                target_name: target.to_string(),
                status: RunStatus::Building,
                created_at_utc: now_rfc3339(),
                finished_at_utc: None,
                iso_path: None,
                inputs: Vec::new(),
                fingerprint: None,
                evidence: None,
                install_mode: None,
            },
        };
        run.save()?;
        Ok(run)
    }

    /// A release build of `product`.
    pub fn start_release(repo_root: &Path, distro_id: &str, product: ProductId) -> io::Result<Self> {
        Self::start(
            &release_dir(repo_root, distro_id, product),
            distro_id,
            RunKind::ReleaseProduct,
            product.name(),
        )
    }

    /// A run of `scenario`.
    pub fn start_scenario(repo_root: &Path, distro_id: &str, scenario: ScenarioId) -> io::Result<Self> {
        Self::start(
            &scenario_dir(repo_root, distro_id, scenario),
            distro_id,
            RunKind::Scenario,
            scenario.key(),
        )
    }

    /// Write the manifest as it stands.
    pub fn save(&self) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(&self.manifest).map_err(io::Error::other)?;
        write_atomic(&self.dir.join(MANIFEST), &json)
    }

    /// Record the run's end: `success` or `failed`, now.
    pub fn finish(mut self, success: bool) -> io::Result<RunManifest> {
        self.manifest.status = if success {
            RunStatus::Success
        } else {
            RunStatus::Failed
        };
        self.manifest.finished_at_utc = Some(now_rfc3339());
        self.save()?;
        Ok(self.manifest)
    }
}

/// A run directory found under a run parent, newest first in [`list`].
#[derive(Debug)]
pub struct RunEntry {
    pub dir: PathBuf,
    pub run_id: String,
    /// The manifest, or why the run cannot be used (none written, or unreadable).
    pub manifest: Result<RunManifest, String>,
}

/// The manifest in `run_dir`; an error when there is none or it cannot be read.
pub fn read(run_dir: &Path) -> Result<RunManifest, String> {
    let path = run_dir.join(MANIFEST);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(format!("'{}' has no run manifest", run_dir.display()))
        }
        Err(err) => return Err(format!("reading '{}': {err}", path.display())),
    };
    let manifest: RunManifest =
        serde_json::from_slice(&bytes).map_err(|err| format!("parsing '{}': {err}", path.display()))?;
    if Some(manifest.run_id.as_str()) != run_dir.file_name().and_then(|name| name.to_str()) {
        return Err(format!(
            "'{}' records run id '{}', not its directory name",
            path.display(),
            manifest.run_id
        ));
    }
    Ok(manifest)
}

/// The runs under `parent`, newest first (run ids sort by allocation time).
pub fn list(parent: &Path) -> io::Result<Vec<RunEntry>> {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(context(err, format!("reading run directory '{}'", parent.display()))),
    };
    let mut runs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| context(err, format!("reading '{}'", parent.display())))?;
        let dir = entry.path();
        let Some(run_id) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if run_id.starts_with('.') || !dir.is_dir() {
            continue;
        }
        let manifest = read(&dir);
        runs.push(RunEntry { dir, run_id, manifest });
    }
    runs.sort_by(|a, b| id_order(&b.run_id).cmp(&id_order(&a.run_id)));
    Ok(runs)
}

/// The newest run under `parent` that succeeded.
pub fn latest_success(parent: &Path) -> io::Result<Option<(PathBuf, RunManifest)>> {
    Ok(list(parent)?.into_iter().find_map(|run| match run.manifest {
        Ok(manifest) if manifest.status == RunStatus::Success => Some((run.dir, manifest)),
        _ => None,
    }))
}

/// The ISO of the newest successful release of `product`; `None` when there
/// is none. A successful run without its ISO is an error.
pub fn latest_release_iso(repo_root: &Path, distro_id: &str, product: ProductId) -> io::Result<Option<PathBuf>> {
    let Some((dir, manifest)) = latest_success(&release_dir(repo_root, distro_id, product))? else {
        return Ok(None);
    };
    match manifest.iso_path {
        Some(iso) if iso.is_file() => Ok(Some(iso)),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("the latest successful {product} release '{}' has no ISO", dir.display()),
        )),
    }
}

/// Remove old runs under `parent`, keeping the newest `keep`, the newest
/// successful one, and every run another run of the variant (anywhere under
/// its output directory) names as an input. Directories without a usable
/// manifest are removed like any other old run.
pub fn prune(repo_root: &Path, distro_id: &str, parent: &Path, keep: usize) -> io::Result<()> {
    let runs = list(parent)?;
    let newest_success = runs
        .iter()
        .position(|run| run.manifest.as_ref().is_ok_and(|m| m.status == RunStatus::Success));
    let referenced = referenced_runs(repo_root, distro_id)?;
    for (index, run) in runs.iter().enumerate() {
        let used = run.manifest.as_ref().is_ok_and(|m| referenced.contains(&m.reference()));
        if index < keep || Some(index) == newest_success || used {
            continue;
        }
        fs::remove_dir_all(&run.dir)
            .map_err(|err| context(err, format!("removing old run '{}'", run.dir.display())))?;
    }
    Ok(())
}

/// Every run that a run of the variant names as an input.
fn referenced_runs(repo_root: &Path, distro_id: &str) -> io::Result<Vec<RunRef>> {
    let out = distro_output_dir(repo_root, distro_id);
    let mut refs = Vec::new();
    for group in ["releases", "scenarios"] {
        let Ok(targets) = fs::read_dir(out.join(group)) else {
            continue;
        };
        for target in targets.flatten() {
            for run in list(&target.path())? {
                if let Ok(manifest) = run.manifest {
                    refs.extend(manifest.inputs);
                }
            }
        }
    }
    Ok(refs)
}

/// Make a new, unique run directory under `parent`. The id is the time of
/// allocation in nanoseconds above the process id (base62, so ids sort by
/// time); `create_dir` fails on an existing name, so two processes never get
/// the same directory.
fn allocate(parent: &Path) -> io::Result<(String, PathBuf)> {
    fs::create_dir_all(parent)
        .map_err(|err| context(err, format!("creating run directory '{}'", parent.display())))?;
    loop {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let run_id = base62((nanos << 32) | u128::from(std::process::id()));
        let dir = parent.join(&run_id);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok((run_id, dir)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(context(err, format!("creating run directory '{}'", dir.display()))),
        }
    }
}

/// Run ids of one alphabet compare by length, then by text.
fn id_order(id: &str) -> (usize, &str) {
    (id.len(), id)
}

fn base62(mut value: u128) -> String {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut digits = Vec::new();
    loop {
        digits.push(ALPHABET[(value % 62) as usize]);
        value /= 62;
        if value == 0 {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).expect("base62 digits are ASCII")
}

/// Now as RFC 3339 in UTC, to the second.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// Replace `path` with `bytes` atomically: a temporary file beside it,
/// synced, renamed over it, and the directory synced.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other(format!("'{}' has no parent directory", path.display())))?;
    fs::create_dir_all(parent).map_err(|err| context(err, format!("creating '{}'", parent.display())))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let written = (|| {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.map_err(|err| context(err, format!("writing '{}'", path.display())))
}

fn context(err: io::Error, what: String) -> io::Error {
    io::Error::new(err.kind(), format!("{what}: {err}"))
}
