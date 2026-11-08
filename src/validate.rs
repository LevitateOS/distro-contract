//! The contract's rules, applied once when a variant loads. Each value is
//! checked by one rule of its kind and a bad value yields one violation, under
//! its `distro.toml` field path.

use std::collections::HashSet;
use std::path::{Component, Path};

use crate::error::Violation;
use crate::schema::{
    ArtifactTransform, BootPayloadContract, ConformanceContract, PayloadProducerContract,
    RootfsSourceKind, RuntimeActionContract, ScriptEvidence, CONTRACT_SCHEMA_VERSION,
};

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

    fn optional_name(&mut self, field: &str, value: &Option<String>) {
        if let Some(value) = value {
            self.name(field, value);
        }
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

fn absolute_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if path.is_absolute() && !path.components().any(|part| part == Component::ParentDir) {
        Ok(())
    } else {
        Err(format!("'{value}' must be an absolute path without '..'"))
    }
}

fn file_name(value: &str) -> Result<(), String> {
    only(value, |c| c != '/' && c != '\\', "a file name")
}

fn console(value: &str) -> Result<(), String> {
    let digits = value
        .strip_prefix("ttyS")
        .or_else(|| value.strip_prefix("tty"))
        .unwrap_or("");
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(format!("'{value}' is not ttyN or ttySN"))
    }
}

fn service(value: &str) -> Result<(), String> {
    only(
        value,
        |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'),
        "a service name",
    )
}

fn cmdline_token(value: &str) -> Result<(), String> {
    only(value, |c| !c.is_whitespace(), "a single cmdline token")
}

fn os_id(value: &str) -> Result<(), String> {
    only(
        value,
        |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
        "lowercase letters, digits and '_'",
    )
}

fn kernel_version(value: &str) -> Result<(), String> {
    only(value, |c| c.is_ascii_digit() || c == '.', "a version of digits and dots")?;
    if value.contains('.') {
        Ok(())
    } else {
        Err(format!("'{value}' is not a version like 6.12.71"))
    }
}

fn sha256(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("'{value}' is not 64 hex digits"))
    }
}

fn localversion(value: &str) -> Result<(), String> {
    match value.strip_prefix('-') {
        Some(rest) if !rest.is_empty() => only(
            rest,
            |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
            "'-' and lowercase letters, digits or '_'",
        )
        .map_err(|_| format!("'{value}' is not '-' and lowercase letters, digits or '_'")),
        _ => Err(format!("'{value}' is not '-' and lowercase letters, digits or '_'")),
    }
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
    check_products(&mut ck, c);
    check_transforms(&mut ck, c);
    check_release(&mut ck, c);
    check_scenarios(&mut ck, c);
    ck.violations
}

fn check_kernel(ck: &mut Check, c: &ConformanceContract) {
    ck.variant_file("kconfig", "kconfig");
    let (field, value) = at!(c.build.kernel.version);
    ck.value(field, value, Some(kernel_version));
    let (field, value) = at!(c.build.kernel.sha256);
    ck.value(field, value, Some(sha256));
    // Derived from the variant id, which therefore has to make a valid one.
    ck.value(
        "build.kernel.localversion (from the variant id)",
        &c.build.kernel.localversion,
        Some(localversion),
    );
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
        None if source.kind == RootfsSourceKind::RecipeRpmSet => {
            ck.fail(field, "is required for kind = 'recipe_rpm_set'");
        }
        None if !outputs.is_empty() => {
            ck.fail(outputs_field, "needs a preseed_recipe_script");
        }
        None => {}
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

    let (field, rpm_base) = at!(c.sources.rootfs_source.rpm_base);
    match (rpm_base, source.kind) {
        (None, RootfsSourceKind::RecipeRpmSet) => {
            ck.fail(field, "is required for kind = 'recipe_rpm_set'")
        }
        (Some(_), RootfsSourceKind::RecipeCustom) => {
            ck.fail(field, "only applies to kind = 'recipe_rpm_set'")
        }
        (Some(base), RootfsSourceKind::RecipeRpmSet) => {
            if base.fedora_release == 0 {
                ck.fail(format!("{field}.fedora_release"), "must name a Fedora release");
            }
            ck.variant_file(&format!("{field}.signing_key"), &base.signing_key);
            ck.list(&format!("{field}.packages"), &base.packages, true, None);
        }
        (None, RootfsSourceKind::RecipeCustom) => {}
    }
}

fn check_products(ck: &mut Check, c: &ConformanceContract) {
    let products = &c.products;
    for (field, product) in [
        ("products.rootfs_base", &products.rootfs_base),
        ("products.live_overlay", &products.live_overlay),
        ("products.boot_live", &products.boot_live),
        ("products.live_tools", &products.live_tools),
        ("products.kernel_staging", &products.kernel_staging),
    ]
    .into_iter()
    .chain(products.boot_installed.iter().map(|p| ("products.boot_installed", p)))
    {
        ck.name(&format!("{field}.logical_name"), &product.logical_name);
        ck.optional_name(&format!("{field}.extends"), &product.extends);
    }

    let (field, boot_installed) = at!(c.product_config.boot_installed);
    if boot_installed.is_some() != products.boot_installed.is_some() {
        ck.fail(field, "must be present exactly when products.boot_installed is");
    }
    let (field, boot_live) = at!(c.product_config.boot_live);
    check_payload(ck, field, boot_live);
    if let Some(payload) = boot_installed {
        check_payload(ck, "product_config.boot_installed", payload);
    }

    let (field, actions) = at!(c.product_config.live_tools_actions);
    for (index, action) in actions.iter().enumerate() {
        let field = format!("{field}[{index}]");
        let (package, binary) = match action {
            RuntimeActionContract::ToolPayloadWorkspaceBinary { package, binary } => {
                (package, binary)
            }
            RuntimeActionContract::RootfsWorkspaceBinary {
                package,
                binary,
                destination,
            } => {
                ck.relative_path(&format!("{field}.destination"), destination);
                (package, binary)
            }
        };
        ck.name(&format!("{field}.package"), package);
        ck.optional_name(&format!("{field}.binary"), binary);
    }

    let (field, consoles) = at!(c.product_config.install_ux.consoles);
    ck.list(field, consoles, true, Some(console));
    let (field, shell) = at!(c.product_config.install_ux.shell);
    ck.value(field, shell, Some(absolute_path));
    let (field, app) = at!(c.product_config.install_ux.docs.app);
    ck.name(field, app);
    let (field, page) = at!(c.product_config.install_ux.docs.page);
    ck.optional_name(field, page);
    let (field, args) = at!(c.product_config.install_ux.docs.args);
    for (index, arg) in args.iter().enumerate() {
        ck.name(&format!("{field}[{index}]"), arg);
    }
    let (field, apps) = at!(c.product_config.install_ux.apps);
    ck.list(field, apps, false, None);
    let (field, hub) = at!(c.product_config.install_ux.hub);
    ck.optional_name(field, hub);
}

fn check_payload(ck: &mut Check, field: &str, payload: &BootPayloadContract) {
    let field = format!("{field}.producers");
    if payload.producers.is_empty() {
        ck.fail(&field, "must list at least one producer");
    }
    for (index, producer) in payload.producers.iter().enumerate() {
        let field = format!("{field}[{index}]");
        match producer {
            PayloadProducerContract::CopyTree {
                source,
                destination,
            }
            | PayloadProducerContract::CopySymlink {
                source,
                destination,
            }
            | PayloadProducerContract::CopyFile {
                source,
                destination,
                ..
            } => {
                ck.relative_path(&format!("{field}.source"), source);
                ck.relative_path(&format!("{field}.destination"), destination);
            }
            PayloadProducerContract::WriteText { path, .. } => {
                ck.relative_path(&format!("{field}.path"), path);
            }
        }
    }
}

fn check_transforms(ck: &mut Check, c: &ConformanceContract) {
    let t = &c.transforms;
    let mut transforms: Vec<(&str, &ArtifactTransform, usize)> = vec![
        ("transforms.rootfs_image", &t.rootfs_image, 1),
        ("transforms.overlay_image", &t.overlay_image, 1),
        ("transforms.initramfs_live", &t.initramfs_live, 1),
        ("transforms.live_uki", &t.live_uki, 3),
        ("transforms.iso", &t.iso, 1),
    ];
    if let Some(transform) = &t.initramfs_installed {
        transforms.push(("transforms.initramfs_installed", transform, 1));
    }
    if let Some(transform) = &t.installed_uki {
        transforms.push(("transforms.installed_uki", transform, 0));
    }
    if let Some(transform) = &t.disk_image {
        transforms.push(("transforms.disk_image", transform, 1));
    }

    let mut seen = HashSet::new();
    for (field, transform, count) in transforms {
        ck.name(&format!("{field}.logical_name"), &transform.logical_name);
        let outputs_field = format!("{field}.output_names");
        let outputs = &transform.output_names;
        if count > 0 && outputs.len() != count {
            ck.fail(
                &outputs_field,
                format!("must list exactly {count} output name(s), found {}", outputs.len()),
            );
        } else if outputs.is_empty() {
            ck.fail(&outputs_field, "must list at least one output name");
        }
        for (index, output) in outputs.iter().enumerate() {
            let field = format!("{outputs_field}[{index}]");
            if !ck.value(&field, output, Some(file_name)) {
                continue;
            }
            if !seen.insert(output) {
                ck.fail(field, format!("'{output}' is already another output's name"));
            } else if transform.format == "uki" && !output.ends_with(".efi") {
                ck.fail(field, format!("'{output}' must end with '.efi'"));
            } else if transform.format == "erofs" && !output.ends_with(".erofs") {
                ck.fail(field, format!("'{output}' must end with '.erofs'"));
            }
        }
    }

    let (field, cmdline) = at!(c.transforms.live_uki.extra_cmdline);
    if cmdline.as_deref().is_some_and(|v| v != v.trim()) {
        ck.fail(field, "has surrounding whitespace");
    }
}

fn check_release(ck: &mut Check, c: &ConformanceContract) {
    let expected: Vec<String> = c
        .transforms
        .iso
        .output_names
        .first()
        .into_iter()
        .chain(c.transforms.disk_image.iter().filter_map(|t| t.output_names.first()))
        .cloned()
        .collect();
    let (field, primary) = at!(c.release.primary_outputs);
    if *primary != expected {
        ck.fail(field, format!("must be the ISO and disk image outputs {expected:?}"));
    }
    let (field, supporting) = at!(c.release.supporting_artifacts);
    if let Some(both) = supporting.iter().find(|name| primary.contains(name)) {
        ck.fail(field, format!("'{both}' is already a primary output"));
    }
    let (field, facts) = at!(c.release.metadata_facts);
    if let Some(both) = facts.iter().find(|name| c.release.metadata_outputs.contains(name)) {
        ck.fail(field, format!("'{both}' is already a metadata output"));
    }
}

fn check_scenarios(ck: &mut Check, c: &ConformanceContract) {
    let s = &c.scenarios;
    for (field, evidence) in [
        ("scenarios.live_boot.evidence", &s.live_boot.evidence),
        ("scenarios.live_tools.evidence", &s.live_tools.evidence),
        ("scenarios.install.evidence", &s.install.evidence),
        ("scenarios.installed_boot.evidence", &s.installed_boot.evidence),
        ("scenarios.automated_login.evidence", &s.automated_login.evidence),
        ("scenarios.installed_tools.evidence", &s.installed_tools.evidence),
    ] {
        check_evidence(ck, field, evidence);
    }

    let (field, cmdline) = at!(c.scenarios.live_boot.required_kernel_cmdline);
    ck.list(field, cmdline, false, Some(cmdline_token));
    for (field, services) in [
        at!(c.scenarios.live_boot.required_live_services),
        at!(c.scenarios.live_environment.required_services),
    ] {
        ck.list(field, services, true, Some(service));
    }
}

fn check_evidence(ck: &mut Check, field: &str, evidence: &ScriptEvidence) {
    let script_field = format!("{field}.script_path");
    if ck.relative_path(&script_field, &evidence.script_path) {
        let script = &evidence.script_path;
        if !script.ends_with(".sh") {
            ck.fail(&script_field, format!("'{script}' must be a '.sh' script"));
        } else {
            let marker = pass_marker_for(script);
            if evidence.pass_marker != marker {
                ck.fail(format!("{field}.pass_marker"), format!("must be '{marker}'"));
            }
        }
    }
}

/// `live-boot.sh` prints `LIVE BOOT PASSED`.
fn pass_marker_for(script_path: &str) -> String {
    let name = script_path.rsplit('/').next().unwrap_or(script_path);
    let stem = name.strip_suffix(".sh").unwrap_or(name);
    let words: Vec<String> = stem
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();
    format!("{} PASSED", words.join(" "))
}
