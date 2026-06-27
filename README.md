# io-vaj-apt

Repository infrastructure for the io.vaj.tl package archive.

Artifacts are stored in Cloudflare R2 and served at `https://repo.pathayam.xyz`.

## Public Key

The archive signing key is at `keys/io-vaj-archive.gpg`.

Fingerprint: `98C1 464F EE61 FCBA 4E7F  54AE 86B6 50B2 12C8 DB81`

## Quick Start

```bash
# 1. Generate repository metadata from pool/
./scripts/generate-repo.sh

# 2. Sign the Release file
./scripts/sign-release.sh

# 3. Publish to R2
source ~/.config/vaj-apt/r2.env
./scripts/publish-r2.py --all
```

## Foundation Catalog

The foundation catalog at `manifests/foundation.tsv` contains 157 packages
recovered from the certified Phase 0A bootstrap (SHA-256:
`be890809bd455df736ba3a71fe656534be102433535fcf115f64271a4800c9c3`).

Each entry records: package name, version, architecture, SHA-256, and
repository object path. The manifest is the authoritative allowlist for
`publish-r2.py`.

To reproduce the catalog from the manifest, place each `.deb` at its
object path under `pool/`, then run `generate-repo.sh`.

## Source Configuration

Add the VAJ repository to your APT sources:

```
deb [signed-by=/data/data/io.vaj.tl/files/usr/etc/apt/keyrings/io-vaj-archive.gpg]
    https://repo.pathayam.xyz stable main
```
