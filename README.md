# distro-contract

Conformance schema + validation engine for LevitateOS distro checkpoint contracts.

## Purpose

This crate is intentionally limited to declaration conformance:

- Define CP1..CP8 contract schema
- Validate anti-gaming and consistency rules
- Return deterministic violation reports

It does **not** own runtime testing (QEMU/checkpoints) and does **not** own
builder/component/disk interfaces.

## Public API

- `ConformanceContract`: full declaration schema
- `validate_contract(&ConformanceContract) -> ConformanceReport`
- `require_valid_contract(&ConformanceContract) -> Result<(), ConformanceError>`
- `run_preflight(&ConformanceContract) -> Result<ConformanceReport, ConformanceError>`

## Schema Version

Current contract schema version: `2` (`CONTRACT_SCHEMA_VERSION`).
