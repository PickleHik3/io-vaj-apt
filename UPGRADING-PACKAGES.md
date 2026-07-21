# Upgrading already-published packages

How to publish a **new version of a package that is already in the catalog**.
This is different from adding a *new* package, and the normal CI staging flow
(`remote-build.sh` → `publish.yml` → `stage-debs.py`) **does not do it**.

Read `AGENTS.md` (project policy) and `REMOTE-BUILD.md` (the additions/CI flow)
first. This file covers only the upgrade case.

## Why the CI staging flow can't upgrade

`scripts/stage-debs.py` stages a deb **only if its package name is not already
in `manifests/foundation.tsv`** (`discover_new_debs` → `load_published_names`).
For an upgrade the name is already present, so:

- `stage-debs.py` skips the deb → it never reaches the pool.
- `publish.yml` gates `generate_repo` / sign / publish on `staged != 0`, so an
  all-upgrade staging release is a **clean no-op**: CI runs, stages nothing,
  deletes the staging release, publishes nothing.

`stage-debs.py` was written for additions only, and predates no upgrade. Do not
"fix" it under time pressure to publish an upgrade — use the process below.

## The actual mechanism: manifest-row replacement + local publish

`scripts/generate_repo.py` is **manifest-authoritative and fail-closed**: it
emits `Packages`/`Release` from exactly the rows in `foundation.tsv`, never
scans the full pool, and aborts if any listed deb is missing locally. So the
upgrade *is* the manifest edit — replacing a row retires the old version and
selects the new one. The pool is immutable: the new-version deb has a new
filename, so it is a new pool object; the old object stays on disk unreferenced.

Precedent: `openexr 3.4.4 → 3.4.4-1`, commit `c8bb93c`
("Phase 5: publish Wave H OpenEXR OpenJPH runtime repair") — a single
one-row edit of `foundation.tsv` (version + sha256 + object_path all replaced).

### Where publishing runs

The **primary host** holds the production secrets locally under
`~/.config/vaj-apt/` (GPG home `gnupg-production`, `archive-signing.passphrase`,
R2 creds `r2.env` / `cloudflare-write.env`). Local publish is the upgrade path
and runs entirely on the primary host. Remote build machines have no secrets —
they only *build* and hand debs to CI; they cannot publish upgrades.

## Procedure

Prereq: the new-version `.deb` is built (recipe bumped in `termux-packages`
@ `io-vaj-package`; see that repo's build docs). Run from the io-vaj-apt repo
root on the primary host.

1. **Copy each new deb into the pool** (path pattern
   `pool/main/<first-char>/<name>/<file>`):

   ```bash
   cp git_2.55.0_aarch64.deb pool/main/g/git/
   # ...one per upgraded package
   ```

2. **Replace the manifest row** for each upgraded package in
   `manifests/foundation.tsv`. Columns are tab-separated:

   ```
   name<TAB>version<TAB>arch<TAB>sha256<TAB>object_path<TAB>size_bytes
   ```

   Update version, sha256, object_path, and size_bytes together. sha256 and
   size must match the new pool object exactly (generate_repo re-hashes and will
   fail closed on a mismatch):

   ```bash
   sha256sum pool/main/g/git/git_2.55.0_aarch64.deb
   stat -c %s  pool/main/g/git/git_2.55.0_aarch64.deb
   ```

   Edit the row in place — do **not** append a second row for the same name
   (duplicate names are invalid; the catalog would be ambiguous).

3. **Regenerate, sign, publish** (order is mandatory — pool objects, then
   `Packages` → `Packages.gz` → `Release` → `Release.gpg` → `InRelease` last):

   ```bash
   source ~/.config/vaj-apt/r2.env          # R2 write creds
   python3 scripts/generate_repo.py         # default manifest = manifests/foundation.tsv
   ./scripts/sign-release.sh                # auto-uses ~/.config/vaj-apt gnupg + passphrase
   python3 scripts/publish-r2.py --all      # upload manifest allowlist to R2
   python3 scripts/publish-r2.py --verify   # confirm mutable-metadata cache policy
   ```

4. **Commit the manifest** to `io-vaj-apt` (branch `io-vaj-package`):

   ```bash
   git add manifests/foundation.tsv && git commit -m "Publish upgrade wave: <pkgs>"
   ```

## Cautions

- **Dependency closure**: if the upgraded package needs a *newer* version of a
  dependency, that dependency must be upgraded in the same wave (its row + pool
  object too), or generate_repo/apt resolution will be inconsistent. Example:
  `vulkan-loader-generic` pins `find_package(VulkanHeaders <version>)`, so
  `vulkan-headers` must be bumped alongside it.
- **Never collapse** published / publicly-verified / device-accepted (AGENTS.md).
  This process only *publishes*; device acceptance is a separate step.
- **No force flags, no purge/recursive-sync** (AGENTS.md). Publish only the
  audited object set + the five mutable metadata keys.
- The old pool object is retained (immutable pool). Do not delete it as part of
  an upgrade.
- Local pool must be complete for every manifest-listed deb or generate_repo
  fails closed. If the primary host's pool is thinned, sync from R2 first
  (`cloudflare-read.env` + the R2 read path) before generating.
