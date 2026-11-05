# distro-contract

Conformance schema + validation engine for LevitateOS variant contracts.

## Purpose

This crate enforces canonical declaration integrity plus build-runtime provenance:

- Define the canonical conformance contract schema
- Load canonical contracts from the ring/owner manifest family in `distro-variants/*`
- Validate anti-gaming and consistency rules
- Validate build-runtime provenance against real outputs (`build-host/kernel/kconfig`, `kernel.release`, `vmlinuz`, modules path)
- Return deterministic violation reports

Runtime checks validate required artifact payload, filesystem layout, kernel provenance and live-environment correctness against explicit product artifacts. Diagnostics identify the build owner or named scenario; there is no numbered checkpoint ladder or later-stage payload prohibition.

It does **not** own runtime testing (QEMU/scenarios) and does **not** own
builder/component/disk interfaces.

## Public API

- `ConformanceContract`: full declaration schema
  - canonical owners: `identity`, `build`, `sources`, `products`, `transforms`, `scenarios`, `release`, `artifacts`
- `load_variant_contract_bundle_for_distro_from(&Path, &str) -> Result<LoadedVariantContract, VariantContractLoadError>`
- `validate_contract(&ConformanceContract) -> ConformanceReport`
- `require_valid_contract(&ConformanceContract) -> Result<(), ConformanceError>`
- `validate_build_runtime(&ConformanceContract, &Path, &Path) -> ConformanceReport`
- `require_valid_build_runtime(&ConformanceContract, &Path, &Path) -> Result<(), ConformanceError>`
- `validate_build_runtime_with_split_artifact_roots(&ConformanceContract, &Path, &Path, &Path) -> ConformanceReport`
- `validate_live_boot_runtime(&ConformanceContract, &LiveBootRuntimeArtifacts) -> ConformanceReport`

## Schema Version

Current contract schema version: `6` (`CONTRACT_SCHEMA_VERSION`).
