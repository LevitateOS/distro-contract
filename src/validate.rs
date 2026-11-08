//! The contract's rules, applied once when a variant loads. Each value is
//! checked by one rule of its kind and a bad value yields one violation, under
//! its `distro.toml` field path.

use std::collections::HashSet;
use std::path::{Component, Path};

use crate::error::Violation;
use crate::schema::{ConformanceContract, LiveService, RootfsSourceKind, CONTRACT_SCHEMA_VERSION};

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

fn input_name(value: &str) -> Result<(), String> {
    only(
        value,
        |c| c.is_ascii_alphanumeric() || c == '_' || c == '-',
        "letters, digits, '_' or '-'",
    )
}

fn define_name(value: &str) -> Result<(), String> {
    only(
        value,
        |c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_',
        "uppercase letters, digits and '_'",
    )
}

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

    check_kernel(&mut ck, c);
    check_sources(&mut ck, c);
    check_layers(&mut ck, c);
    ck.violations
}

/// The kernel's pin is the kernel recipe's (`kernel/metadata.rhai`); the
/// variant has its kernel line (`profile.kernel_line`) and `kconfig`.
fn check_kernel(ck: &mut Check, _c: &ConformanceContract) {
    ck.variant_file("kconfig", "kconfig");
}

fn check_sources(ck: &mut Check, c: &ConformanceContract) {
    let source = &c.sources.rootfs_source;
    let (field, objects) = at!(c.sources.rootfs_source.storage_max_objects);
    if objects.is_some_and(|n| !(1..=1_000_000).contains(&n)) {
        ck.fail(field, "must be between 1 and 1000000");
    }
    for (field, mib) in [
        at!(c.sources.rootfs_source.memory_mib),
        at!(c.sources.rootfs_source.preseed_memory_mib),
    ] {
        if mib.is_some_and(|n| !(16..=1_048_576).contains(&n)) {
            ck.fail(field, "must be between 16 and 1048576 MiB");
        }
    }

    let (field, script) = at!(c.sources.rootfs_source.recipe_script);
    ck.repo_file(field, script);

    let (field, preseed) = at!(c.sources.rootfs_source.preseed_recipe_script);
    let (outputs_field, outputs) = at!(c.sources.rootfs_source.preseed_outputs);
    match preseed {
        Some(script) => {
            ck.repo_file(field, script);
            if outputs.is_empty() {
                ck.fail(outputs_field, "must name the preseed recipe's outputs and their kinds");
            }
        }
        None => {
            ck.fail(field, "is required: it downloads the base's locked packages");
        }
    }
    for name in outputs.keys() {
        ck.name(&format!("{outputs_field}.{name}"), name);
    }

    let (field, inputs) = at!(c.sources.rootfs_source.inputs);
    for (name, path) in inputs {
        let field = format!("{field}.{name}");
        if ck.value(&field, name, Some(input_name)) {
            ck.repo_file(&field, path);
        }
    }

    let (field, defines) = at!(c.sources.rootfs_source.defines);
    if source.kind == RootfsSourceKind::RecipeRpmSet && !defines.is_empty() {
        ck.fail(field, "must be empty for kind = 'recipe_rpm_set'");
    }
    for (key, value) in defines {
        let field = format!("{field}.{key}");
        if ck.value(&field, key, Some(define_name)) {
            ck.name(&field, value);
        }
    }

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

/// `[live]` and `[installed]` hold only what the variant adds to the shared
/// lists, so a value already given to every variant is a mistake.
fn check_layers(ck: &mut Check, c: &ConformanceContract) {
    let (field, services) = at!(c.live.services);
    let mut seen = HashSet::new();
    for (index, service) in services.iter().enumerate() {
        let field = format!("{field}[{index}]");
        if *service == LiveService::Ssh {
            ck.fail(field, "every live system runs sshd; list only the other services");
        } else if !seen.insert(service) {
            ck.fail(field, format!("{service:?} is listed twice"));
        }
    }
}
