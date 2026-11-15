# The release set

`release::ReleaseManifest` is the record of what a system part built. The
builder writes it as `release-set.json` in the part's directory; the combiner links
it into the release run directory, verifies it and puts it on the ISO beside
the members it names. Preflight checks a release run against it again.

It names the distro, architecture, init, libc and version (every system part
is the base system, so it names no flavour); the digest
of the system sources the part was built from; the kernel release and the
digest of its module tree in the rootfs; and the relative path, SHA-256 and
byte length of each member:

- `live/filesystem.erofs`
- `boot/vmlinuz`
- `boot/initramfs-installed.img`

Member names cannot leave the release directory.

`release-set.json` is only a record of what an ISO build produced. It is not
the update manifest: that is `release.json`, which the release build writes
next to the ISO (with `base.tar.zst`, `boot.tar.zst` and `recipes.tar.zst`)
for `cargo xtask release publish` to sign and publish
(docs/release-engineering.md at the repository root, sections 2, 3 and 10).
