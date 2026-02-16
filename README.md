# distro-contract

Conformance schema + validation engine for LevitateOS distro checkpoint contracts.

## Purpose

This crate enforces CP0 declaration + CP0 runtime provenance:

- Define CP0..CP8 contract schema
- Load CP0 contracts from `distro-variants/*/cp0.toml`
- Validate anti-gaming and consistency rules
- Validate CP0 runtime provenance against real outputs (`kconfig`, `kernel.release`, `vmlinuz`, modules path)
- Return deterministic violation reports

It does **not** own runtime testing (QEMU/checkpoints) and does **not** own
builder/component/disk interfaces.

## Public API

- `ConformanceContract`: full declaration schema
- `load_cp0_contract_bundle_for_distro_from(&Path, &str) -> Result<LoadedVariantContract, VariantContractLoadError>`
- `validate_contract(&ConformanceContract) -> ConformanceReport`
- `require_valid_contract(&ConformanceContract) -> Result<(), ConformanceError>`
- `run_preflight(&ConformanceContract) -> Result<ConformanceReport, ConformanceError>`
- `validate_cp0_runtime(&ConformanceContract, &Path, &Path) -> ConformanceReport`
- `require_valid_cp0_runtime(&ConformanceContract, &Path, &Path) -> Result<(), ConformanceError>`

## Schema Version

Current contract schema version: `3` (`CONTRACT_SCHEMA_VERSION`).
