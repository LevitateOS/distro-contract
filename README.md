# distro-contract

Conformance schema + validation engine for LevitateOS distro stage contracts.

## Purpose

This crate enforces Stage 00 declaration + Stage 00 runtime provenance:

- Define Stage 00..Stage 08 contract schema
- Load Stage 00 contracts from `distro-variants/*/stage-00.toml`
- Validate anti-gaming and consistency rules
- Validate Stage 00 runtime provenance against real outputs (`kconfig`, `kernel.release`, `vmlinuz`, modules path)
- Return deterministic violation reports

It does **not** own runtime testing (QEMU/stages) and does **not** own
builder/component/disk interfaces.

## Public API

- `ConformanceContract`: full declaration schema
- `load_stage_00_contract_bundle_for_distro_from(&Path, &str) -> Result<LoadedVariantContract, VariantContractLoadError>`
- `validate_contract(&ConformanceContract) -> ConformanceReport`
- `require_valid_contract(&ConformanceContract) -> Result<(), ConformanceError>`
- `validate_stage_00_runtime(&ConformanceContract, &Path, &Path) -> ConformanceReport`
- `require_valid_stage_00_runtime(&ConformanceContract, &Path, &Path) -> Result<(), ConformanceError>`

## Schema Version

Current contract schema version: `3` (`CONTRACT_SCHEMA_VERSION`).
