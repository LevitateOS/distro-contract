# distro-contract

Trait contracts for the LevitateOS distro family.

This crate defines the **interfaces** that distro builders implement. It has
near-zero dependencies (just `anyhow`) so that any crate can depend on it
without pulling in build infrastructure.

## Traits

| Trait | Module | Purpose |
|-------|--------|---------|
| `KernelInstallConfig` | `kernel` | Where/how to install kernel and modules |
| `KernelBuildGuard` | `kernel` | Two-step kernel build confirmation |
| `DistroConfig` | `context` | OS identity, boot modules, init system |
| `BuildContext` | `context` | Source/staging/output paths |
| `Installable` | `component` | Declarative component installation |
| `DiskImageConfig` | `disk` | Disk image building |

## Usage

Implemented by:
- **leviso** (LevitateOS)
- **AcornOS**
- **IuppiterOS**

Re-exported by **distro-builder** so existing code doesn't need to change imports.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
