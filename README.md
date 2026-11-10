# distro-contract

The variant contract of LevitateOS and AcornOS: the schema of
`distro/variants/<id>/distro.toml`, its loader and rules, and checks of built
artifacts against it.

A variant directory holds `distro.toml`, the options of its kernel line
`kconfig` (applied after `_shared/kconfig`),
and signing keys under `keys/`. The Rust types in
`schema.rs` are the TOML shape (`deny_unknown_fields`): adding a field means
adding it to the type and the file.

## Public API

- `load(repo_root, distro_id) -> Result<Variant, LoadError>`: reads
  `distro.toml` once, validates every rule in one pass (each bad value is one
  `Violation` under its field path, such as `live.services[1]`). It
  derives the names that follow from the ids (`identity.iso_label` = `os_id`
  in capitals, `identity.default_hostname` = `os_id`, `identity.login_prompt`
  = `<os_id> login:`, and
  `contract.artifacts`: `<os_id>-x86_64-<product>.iso`, the live UKIs by role,
  `filesystem.erofs`, ...), so no file spells them. There is no unvalidated
  load.
- `registry`: `ProductId` and `ScenarioId`, the products and scenarios every
  variant has, each named once with its title, parent, release flag, inputs
  and order. The builder, xtask and install-tests name none of their own.
- `contract.live`, `contract.installed`: what the variant adds to the shared
  lists; `live_services()`/`live_service_units()`,
  `live_tools()` and `installed_tools()` give the whole lists.
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
  `validate_live_boot_runtime(&ConformanceContract, &LiveBootRuntimeArtifacts)`:
  checks of built artifacts (the kernel bundle's files, whose pin the kernel
  recipe checks;
  live-boot SSH, live services, locale and merged-/usr wiring), returning `Vec<Violation>`.
- `schema::*`: `ConformanceContract` and its parts; `CONTRACT_SCHEMA_VERSION`
  (`9`).
- `install_ux`: the live install screen, the same on every variant: its
  consoles, apps and docs page, and the paths and names the builder, the
  split pane and the install tests share.

`release` owns the versioned installed-system manifest, intended inventory,
compatibility checks and distribution release trust shared by builder and recab.
See [the release format](docs/releases.md).
