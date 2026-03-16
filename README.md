# distro-contract

Conformance schema + validation engine for LevitateOS variant contracts.

## Purpose

This crate enforces canonical declaration integrity plus Stage 00 runtime provenance:

- Define Stage 00..Stage 08 contract schema
- Load canonical contracts from the ring/owner manifest family in `distro-variants/*`
- Validate anti-gaming and consistency rules
- Validate Stage 00 runtime provenance against real outputs (`kconfig`, `kernel.release`, `vmlinuz`, modules path)
- Return deterministic violation reports

This crate is also the policy authority for stage-envelope conformance:

- Stage artifacts must satisfy "nothing more, nothing less" for their stage boundary.
- Missing required payload is a failure.
- Extra payload that belongs to later stages is a failure.
- Filesystem layout checks (required/forbidden paths per stage) are first-class conformance rules.

It does **not** own runtime testing (QEMU/stages) and does **not** own
builder/component/disk interfaces.

## Public API

- `ConformanceContract`: full declaration schema
- `distro_contract::compatibility`: legacy stage-shaped compatibility types and helpers
- `load_variant_contract_bundle_for_distro_from(&Path, &str) -> Result<LoadedVariantContract, VariantContractLoadError>`
- `validate_contract(&ConformanceContract) -> ConformanceReport`
- `require_valid_contract(&ConformanceContract) -> Result<(), ConformanceError>`
- `validate_build_runtime(&ConformanceContract, &Path, &Path) -> ConformanceReport`
- `require_valid_build_runtime(&ConformanceContract, &Path, &Path) -> Result<(), ConformanceError>`
- `validate_live_boot_runtime(&ConformanceContract, &LiveBootRuntimeArtifacts) -> ConformanceReport`
- `validate_live_boot_runtime_with_stage_dir(&ConformanceContract, &Path, &str) -> ConformanceReport`

## Schema Version

Current contract schema version: `6` (`CONTRACT_SCHEMA_VERSION`).
