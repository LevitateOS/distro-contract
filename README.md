# distro-contract

The variant contract of LevitateOS and AcornOS: the schema of
`distro/variants/<id>/distro.toml`, its loader and rules, and checks of built
artifacts against it.

A variant directory holds `distro.toml`, the kernel configuration `kconfig`,
signing keys under `keys/` and release hooks under `hooks/`. The Rust types in
`schema.rs` are the TOML shape (`deny_unknown_fields`): adding a field means
adding it to the type and the file.

## Public API

- `load(repo_root, distro_id) -> Result<Variant, LoadError>`: reads
  `distro.toml` once, validates every rule in one pass (each bad value is one
  `Violation` under its field path, such as
  `product_config.install_ux.consoles[1]`), and derives `contract.artifacts`
  from the transforms. It also derives the names that follow from the id
  (`identity.iso_label` = `os_id` in capitals, `identity.default_hostname` =
  `os_id`, `build.kernel.localversion` = `-<id>`,
  `scenarios.automated_login.login_prompt_pattern` = `<os_id> login:`), so no
  file spells them. There is no unvalidated load.
- `contract.profile`: the variant's `[profile]` (`distro_profile::Profile`,
  re-exported as `profile`): package backend, init system, libc, privilege
  tool, desktop and kernel line. Every live tool is built for the libc. The
  builder writes the profile into the image's `/etc/os-release` as `REC_*`
  fields for the tools on the target.
- `Variant { id, repo_root, dir, manifest, contract }`, with
  `Variant::path(rel)` for files beside `distro.toml`.
- `distro_ids(repo_root)`: the directories under `distro/variants` that hold a
  `distro.toml`.
- `validate_build_runtime(&Variant, &BuildRuntimeArtifacts)` and
  `validate_live_boot_runtime(&Profile, &BootScenario, &LiveBootRuntimeArtifacts)`:
  checks of built artifacts (kernel provenance against `kconfig` and the pin;
  live-boot SSH, locale and merged-/usr wiring), returning `Vec<Violation>`.
- `schema::*`: `ConformanceContract` and its parts; `CONTRACT_SCHEMA_VERSION`
  (`7`).
- `tui_apps`: discovery of the TUI apps under `tui/apps`.
