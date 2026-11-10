# Installed-system releases

`release::ReleaseManifest` in this crate is the shared version 1 format for
media and online payloads. The builder publishes `release.json`; recab imports
and stages that same document. It is distinct from a build run record and a
personalized slot's generation/boot seal.

The manifest binds distro, architecture, init, libc, flavour, channel, positive
monotonic sequence and display version; the existing system-source digest;
minimum recab version and state/boot protocols; kernel release and module-tree
digest; and the relative path, SHA256 and byte length of each payload:

- `live/filesystem.erofs`
- `system-inventory.json`
- `boot/vmlinuz`
- `boot/initramfs-installed.img`

Member names cannot escape the release directory. The same layout can be served
under an online release base URL. A channel's sequence is publisher-controlled;
advancing an OS version string or a build clock never silently advances it.
Imports accept the installed sequence or newer and refuse implicit downgrades.
Recab discovery pins a newer release; successful merge advances the prepared release baseline.

`SystemInventory` records canonical paths, kinds, content fingerprints, numeric
UID/GID, modes, raw xattrs and link identity using Recipe's existing target
metadata entry type. It excludes shared/runtime contents, the embedded target
manifest and personalized slot/generation records. Existing shared mount-root
symlinks remain system entries. No file bodies or personalized account secrets
are stored in this inventory. Target timestamps follow the existing image
writer's epoch-zero policy.

The image writer derives the inventory from the exact tar stream given to
`mkfs.erofs`, and records it with the output image digest in a local
`<image>.release.json` provenance record. Release emission checks that binding
and the prepared tree, then verifies boot artifacts from a frozen input set.
This permits producing a target's zstd image on a host kernel lacking EROFS zstd.
The provenance record is not another release manifest or a trust authority and
is not required on media. Recab consumers mount the actual verified EROFS image
read-only and compare its complete system inventory and boot bindings before
any candidate mutation; they do not trust an embedded metadata file as proof of
actual on-image ownership or capabilities.

The distro contract's optional `[release]` table declares `channel`, `sequence`,
optional `source = { index, recipe }` and optional
`trust = { ed25519 = "<64 lowercase hex characters>" }`. An enabled source must
use HTTPS (or loopback HTTP for a local fixture) without credentials or a
fragment, name an existing repository recipe,
and declare distribution release trust. The builder packages that recipe at
`/usr/share/recab/update-acquire.rhai`, fills its single configured-endpoint
marker and rewrites the installed recipe path. Recab gives Recipe only a small
request file, the configured endpoint and a bounded byte budget. Package-signing keys and `HOME_URL` are not release keys
or update endpoints. The checked-in variants declare development sequence 1,
without a production source or key; publishing a newer release must deliberately
advance the sequence and configure the actual service/key.

The installed root carries this policy at
`/usr/lib/recab/update-source.json`. A detached `release.sig` contains a 64-byte
Ed25519 signature of the exact `release.json` bytes. Verification uses the
installed distribution key, never a key asserted by incoming metadata.
Production signing takes a PKCS#8 DER Ed25519 key through an explicit producer
argument/environment path; secret bytes are not recorded in provenance or
manifests. A configured key requires a signature even with `--trusted-local`.
With no configured key, unsigned local/media use requires explicit
`--trusted-local`; it is reported as local trust, not cryptographic verification.

Recab verifies compatibility and identity before payload import. It hashes every
artifact while copying to a private set, freezes that set with a read-only bind,
and uses only those paths through filesystem/boot validation and staging.
Changing an original source name after verification cannot change the consumed
bytes. Import moves the verified payloads into a private content-addressed cache,
without a second full payload copy. Reused cache objects are rehashed, and future
consumers verify them again. Import leaves the running/prepared roots, ledger
and boot selection unchanged. Disk space and all artifact staging still cost
I/O; these are not zero-write or SMART guarantees.

Release policy is a regular slot-owned root file. Recab refuses symlinked or
group/world-writable policy so shared mutable state cannot replace the
distribution trust authority.


## Online index and recovery

The local publisher writes version 1 `index.json`: a positive monotonic index
sequence, channel and at most 256 current release entries, one per
(distro, architecture, init, libc, flavour). Each entry binds the complete release
identity and the manifest/signature's relative paths, SHA256 and byte lengths.
The detached signature covers exact index bytes with the installed distribution
key. Its authoritative path is `index-signatures/<SHA256(index.json)>.sig`;
`index.sig` is a convenience copy. Content-addressed signatures let a reader
finish verifying an older index while publication advances atomically.

Recab fetches metadata only through Recipe. It verifies the index before
selecting a manifest, and that manifest before pinning payload URLs and hashes.
Index and release high-water marks refuse rollback and same-sequence changes.
They are scoped to the installed policy/profile/acquisition recipe, never to an
untrusted key or source in the incoming release. HTTPS is required except for
loopback HTTP fixtures. Index/manifest bodies are limited to 1 MiB; signatures
are exactly 64 bytes. Payload requests use signed lengths and hashes.

Check/download hold the recab operation lock without changing slot contents,
preparation revisions, ledger or boot selection. Pins, status and completed
transfers live under the private state directory. Retry uses a selected manifest
ID, rehashes completed artifacts, and restarts the incomplete artifact. A
successful download performs complete P07 validation before cache publication.
Cached inputs are reverified offline; they are retained rather than collected
behind a preparation or running operation. Actual producer, export and private
verification copies still cost disk writes; logical verified byte counts are
not device-write or SMART counters.

`update apply` merges the pinned release against the retained release baseline
and captured prepared system. Its structured `merge` reports redacted conflicts,
revision, progress and recovery state. The candidate stays unavailable until
conflicts/dependency work are resolved and the complete tree validates. Account
baselines contain field/member fingerprints; raw account bodies remain only in
protected system files. Local Recipe selection survives and required native
reproduction runs through Recipe with the verified manifest as its bounded target
input. Baseline advancement and boot-input selection happen only after success.

The initial baseline is captured before installer personalization. An installation
without it must explicitly adopt a verified original release; current personalized
contents cannot stand in for O. Verified baselines retain the content-addressed
release ID. Manifest/media staging uses this same merge and never formats the
inactive filesystem. Raw artifact paths require their corresponding manifest.
