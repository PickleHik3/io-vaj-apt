# io-vaj-apt

Repository infrastructure for the io.vaj.tl package archive.

Artifacts are stored in Cloudflare R2 and served at `https://repo.pathayam.xyz`.

## Layout

```
keys/                  Public GPG keys for APT trust
scripts/               Repository generation and publishing tooling
pool/                  Binary package pool (not committed)
dists/                 Generated repository metadata (not committed)
```

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

## Public Key

The archive signing key is at `keys/io-vaj-archive.gpg`.

Fingerprint: `98C1 464F EE61 FCBA 4E7F  54AE 86B6 50B2 12C8 DB81`

Install into APT:

```bash
cp keys/io-vaj-archive.gpg /data/data/io.vaj.tl/files/usr/etc/apt/keyrings/
```

## Source Configuration

```
deb [signed-by=/data/data/io.vaj.tl/files/usr/etc/apt/keyrings/io-vaj-archive.gpg]
    https://repo.pathayam.xyz stable main
```
