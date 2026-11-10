//! The contract's rules, applied once when a variant loads. Each value is
//! checked by one rule of its kind and a bad value yields one violation, under
//! its `distro.toml` field path.

use std::collections::HashSet;
use std::path::{Component, Path};

use crate::error::Violation;
use crate::schema::{ConformanceContract, CONTRACT_SCHEMA_VERSION};

/// `at!(c.a.b)` is the field path `"a.b"` and a reference to the value, so the
/// path in a report is spelt by the field access itself.
macro_rules! at {
    ($root:ident . $first:ident $(. $rest:ident)*) => {
        (
            concat!(stringify!($first) $(, ".", stringify!($rest))*),
            &$root.$first $(.$rest)*,
        )
    };
}

/// A rule for one kind of value: `Err` says what the value should be.
type Rule = fn(&str) -> Result<(), String>;

struct Check<'a> {
    repo_root: &'a Path,
    variant_dir: &'a Path,
    violations: Vec<Violation>,
}

impl Check<'_> {
    fn fail(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.violations.push(Violation::new(field, message));
    }

    /// A non-empty value without surrounding whitespace that passes `rule`.
    fn value(&mut self, field: &str, value: &str, rule: Option<Rule>) -> bool {
        let problem = if value.trim().is_empty() {
            Err("must not be empty".to_string())
        } else if value != value.trim() {
            Err(format!("'{value}' has surrounding whitespace"))
        } else {
            rule.map_or(Ok(()), |rule| rule(value))
        };
        match problem {
            Ok(()) => true,
            Err(message) => {
                self.fail(field, message);
                false
            }
        }
    }

    fn name(&mut self, field: &str, value: &str) -> bool {
        self.value(field, value, None)
    }

    /// A list of distinct values, each passing `rule`.
    fn list(&mut self, field: &str, values: &[String], required: bool, rule: Option<Rule>) {
        if required && values.is_empty() {
            self.fail(field, "must list at least one value");
        }
        let mut seen = HashSet::new();
        for (index, value) in values.iter().enumerate() {
            let field = format!("{field}[{index}]");
            if self.value(&field, value, rule) && !seen.insert(value) {
                self.fail(field, format!("'{value}' is listed twice"));
            }
        }
    }

    fn relative_path(&mut self, field: &str, value: &str) -> bool {
        self.value(field, value, Some(relative_path))
    }

    /// A relative path naming a file under `base`.
    fn file_under(&mut self, field: &str, base: &Path, value: &str) {
        if self.relative_path(field, value) && !base.join(value).is_file() {
            self.fail(field, format!("no file {}", base.join(value).display()));
        }
    }

    fn repo_file(&mut self, field: &str, value: &str) {
        self.file_under(field, self.repo_root, value);
    }

    fn variant_file(&mut self, field: &str, value: &str) {
        self.file_under(field, self.variant_dir, value);
    }
}

fn only(value: &str, allowed: fn(char) -> bool, what: &str) -> Result<(), String> {
    if value.chars().all(allowed) {
        Ok(())
    } else {
        Err(format!("'{value}' is not {what}"))
    }
}

/// A relative path that stays below its base: no root, no `..`.
fn relative_path(value: &str) -> Result<(), String> {
    let below = Path::new(value)
        .components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir));
    if below {
        Ok(())
    } else {
        Err(format!("'{value}' must be a relative path without '..'"))
    }
}

fn os_id(value: &str) -> Result<(), String> {
    only(
        value,
        |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
        "lowercase letters, digits and '_'",
    )
}

/// The variant's branding, beside `distro.toml`, which the desktop system
/// shows: the wallpapers (3840x2160 JPEGs) for a light and for a dark look,
/// and the mark (24px, and the 16px micro mark) in ink for a light surface
/// and in paper for a dark one. Each is (the rootfs recipe's input, the file).
pub const BRANDING: [(&str, &str); 6] = [
    ("wallpaper_light", "branding/wallpaper-light.jpg"),
    ("wallpaper_dark", "branding/wallpaper-dark.jpg"),
    ("logo_ink", "branding/logo-ink.svg"),
    ("logo_paper", "branding/logo-paper.svg"),
    ("logo_micro_ink", "branding/logo-micro-ink.svg"),
    ("logo_micro_paper", "branding/logo-micro-paper.svg"),
];

/// Every rule, over the whole contract.
pub(crate) fn validate(
    c: &ConformanceContract,
    repo_root: &Path,
    variant_dir: &Path,
) -> Vec<Violation> {
    let mut ck = Check {
        repo_root,
        variant_dir,
        violations: Vec::new(),
    };

    if c.schema_version != CONTRACT_SCHEMA_VERSION {
        ck.fail(
            "schema_version",
            format!("must be {CONTRACT_SCHEMA_VERSION}, got {}", c.schema_version),
        );
    }

    for (field, value) in [at!(c.identity.os_name), at!(c.identity.os_version)] {
        ck.name(field, value);
    }
    let (field, value) = at!(c.identity.os_id);
    ck.value(field, value, Some(os_id));
    if let Some(url) = &c.identity.home_url {
        if !url.starts_with("https://") || url.contains(char::is_whitespace) || url.contains('"') {
            ck.fail("identity.home_url", format!("must be an https:// URL, got {url:?}"));
        }
    }

    ck.variant_file("kconfig", "kconfig");
    for (_, file) in BRANDING {
        ck.variant_file(file, file);
    }
    if let Err(error) = c.release.validate() { ck.fail("release", format!("{error:#}")); }
    if let Some(source) = &c.release.source { ck.repo_file("release.source.recipe", &source.recipe); }
    check_sources(&mut ck, c);
    ck.violations
}


fn check_sources(ck: &mut Check, c: &ConformanceContract) {
    let (field, script) = at!(c.sources.rootfs_source.recipe_script);
    ck.repo_file(field, script);

    let (field, preseed) = at!(c.sources.rootfs_source.preseed_recipe_script);
    ck.repo_file(field, preseed);
    let (field, preseed) = at!(c.desktop.preseed_recipe_script);
    ck.repo_file(field, preseed);
    let (field, preseed) = at!(c.desktop.apps_build_preseed_recipe_script);
    ck.repo_file(field, preseed);
    let (field, root) = at!(c.desktop.apps_build_root_recipe_script);
    ck.repo_file(field, root);

    let (field, base) = at!(c.sources.rootfs_source.base);
    let release = format!("{field}.release");
    if ck.name(&release, &base.release)
        && c.profile.packages == distro_profile::PackageBackend::Rpm
        && !base.release.parse::<u32>().is_ok_and(|n| n > 0)
    {
        ck.fail(release, "must be a Fedora release number");
    }
    ck.variant_file(&format!("{field}.signing_key"), &base.signing_key);
    ck.list(&format!("{field}.packages"), &base.packages, true, None);
}
