# Remote build → central publish

How VAJ APT packages get built on **any machine** and published to
`https://repo.pathayam.xyz` **without** that machine ever holding a secret.

Read this before touching `remote-build.sh`, `.github/workflows/publish.yml`,
or `scripts/stage-debs.py`. Project policy still lives in `AGENTS.md`
(no force flags, gated waves, immutable pool, never collapse
published/verified/device-accepted).

## Topology

```
build machine(s)              GitHub                     CI: publish.yml (secret vault)
──────────────                ──────                     ──────────────────────────────
frozen builder image
recipes @ io-vaj-package
  │ remote-build.sh
  ▼
output/*.deb
  │ gh release create          staging-<ts>
  │   (GitHub PAT only,         (.deb assets) ──trigger──▶ import GPG key      (secret)
  │    NO GPG, NO R2)                                       aws s3 sync pool ← R2 (read)
                                                            stage-debs.py  (pool+manifest)
                                                            generate_repo.py
                                                            sign-release.sh    (secret)
                                                            publish-r2.py --all (R2 write)
                                                            publish-r2.py --verify
                                                            commit manifest → io-vaj-package
                                                            gh release delete staging-<ts>
```

**Secret boundary:** every secret (GPG private key, passphrase, R2 keys) lives
**only** in GitHub Actions secrets on `PickleHik3/io-vaj-apt`. Build machines
authenticate to GitHub with a plain PAT and hand debs off as release assets.
Add a build machine = load an image + `gh auth login`. Nothing else.

> **Additions only.** This flow publishes *new* package names. `stage-debs.py`
> skips any name already in the manifest, so it cannot publish a new version of
> an already-published package. To **upgrade** an existing package, see
> `UPGRADING-PACKAGES.md` (manual manifest-row replacement + local publish).

## The three moving parts

| File | Repo / location | Role |
|---|---|---|
| `remote-build.sh` | `termux-packages` @ `io-vaj-package` | Build machine: run the builder container, then `gh release create staging-<ts>` — in queue mode every `--handoff-every` minutes (default 60) plus a final pass, waiting for the previous staging release to be consumed first |
| `build-all-queue.sh` | `termux-packages` @ `io-vaj-package` | Decides *what* to build from the live repo index: a package is skipped only when its published version equals the recipe's. `UPDATES_ONLY=1` restricts to already-published packages; `DRY_RUN=1` prints decisions |
| `.github/workflows/publish.yml` | `io-vaj-apt` (default branch) | The only holder of secrets. Stages, signs, publishes, cleans up |
| `scripts/stage-debs.py` | `io-vaj-apt` | Shared staging: copy debs → pool; **new** names are appended to `foundation.tsv`, **newer versions replace their row in place** (dpkg version order, never a downgrade, old pool object retained). Used by CI **and** local `publish-wave-*.py` |

## Why the CI job syncs the whole pool

`generate_repo.py` is **manifest-authoritative and fail-closed**: it reads
*every* `.deb` selected by `manifests/foundation.tsv` (runs `dpkg-deb
--ctrl-tarfile` + re-hashes each) to regenerate `Packages`/`Release`. The pool
(~4.7 GB) is **not** in git — its source of truth is R2. So `publish.yml` must
`aws s3 sync s3://$R2_BUCKET/pool pool` before generating metadata, then add the
new wave on top. R2 has no egress fees, so the sync is free bandwidth (~2–3 min).
If a manifest-listed deb is missing after sync, metadata generation fails
closed — that is intended.

## Operating the build machine

One-time image load (transfer `vaj-builder.tar.zst` from the primary host):

```bash
zstd -dc vaj-builder.tar.zst | docker load     # io-vaj-phase0a-builder:c9cc6b28
```

Recipes + auth:

```bash
git clone https://github.com/PickleHik3/termux-packages
cd termux-packages && git checkout io-vaj-package
gh auth login          # PAT, repo scope — the only credential this box needs
```

The container's `builder` user is UID 1001. If the host user is not 1001 (Azure's
`azureuser` is 1000), the mounted checkout must be group-writable by gid 1001 or
the build dies on `mkdir output: Permission denied`:

```bash
sudo groupadd -g 1001 builder; sudo usermod -aG builder "$USER"
sudo chgrp -R 1001 . && sudo chmod -R g+w . && sudo find . -type d -exec chmod g+s {} +
```

The repo must be reachable from the build machine **without a Cloudflare
challenge**: Bot Fight Mode on the `pathayam.xyz` zone answered Azure's IP with a
managed challenge (`cf-mitigated: challenge`, HTTP 403) and every `-I` dependency
download spun in 60 s retry loops. It is off; keep it off — apt clients cannot
pass challenges either.

Build + hand off:

```bash
UPDATES_ONLY=1 ./remote-build.sh        # rebuild every published package whose recipe moved
./remote-build.sh                       # …plus every queued package never published yet
./remote-build.sh build-tier1-libs.txt  # one tier (no index check — builds everything listed)
./remote-build.sh --pkgs zsh jq bc      # named packages (start here for a first test)
./remote-build.sh --pkgs zsh --no-publish   # build only, no staging release
./remote-build.sh --pkgs tree --publish-all # hand off every deb already in output/
```

Queue mode records `PASS`/`FAIL` per package in `output/remote-build.results`,
still hands off the debs that did build, and exits non-zero if anything failed.
Dependencies come from the repo with `-I`; a dependency version the repo lacks is
built on the spot and handed off like any other deb, so a wave for one package
routinely carries its stale dependencies (zsh 5.9.2 brought 33 of them).

`remote-build.sh` refuses to start if the frozen image is absent or `gh` is
unauthenticated. It creates a fresh `vaj-remote-builder` container each run
(distinct name — will not collide with the primary host's
`termux-package-builder`).

## What CI does per staging release

`publish.yml` fires on `release: published` for `staging-*` tags (or manual
`workflow_dispatch` with `release_tag`). It must be `published`, not
`prereleased`: `gh release create` with assets creates a draft and publishes it
once the uploads finish, and GitHub does not fire `prereleased` for a draft that
becomes a pre-release. Steps, in order:

1. checkout `io-vaj-package`; fail fast if any of the six secrets is unset
2. import GPG key from `VAJ_GPG_PRIVATE_KEY_B64` into an ephemeral `GNUPGHOME`;
   write passphrase to a temp file
3. `gh release download` the `*.deb` assets → `incoming/`
4. `aws s3 sync` pool ← R2 (≈5 GB, ~10 min; retried up to 4× — one object
   failing with "Max Retries Exceeded" is normal)
5. `stage-debs.py incoming` → copies to pool, appends new rows / replaces
   upgraded rows, prints `STAGED=<n>` (new + upgraded). Name/version/arch come
   from each deb's control file, never the filename: GitHub release assets
   cannot contain `:`, so `foo_1:2.0_all.deb` arrives as `foo_1.2.0_all.deb`
6. if `STAGED=0`, skip the rest
7. `generate_repo.py` → `sign-release.sh` → `publish-r2.py --all` → `publish-r2.py --verify`
8. commit updated `foundation.tsv` to `io-vaj-package`
9. delete the `staging-*` release — **only on success**. A failed run leaves it
   in place; fix the cause and re-run with `gh workflow run publish.yml -f
   release_tag=staging-<ts>`.

`concurrency: vaj-apt-publish` serializes runs, but GitHub keeps at most **one
pending** run per group: a third staging release created while one publishes
and one waits gets its run cancelled and sits unconsumed. `remote-build.sh`
therefore waits for `gh release list` to show no `staging-*` release before
creating the next one. A publish run takes ~20 min end to end.

`publish-r2.py` compares the clearsigned `InRelease` payload with `Release`
ignoring the trailing newline: gpg 2.4.4 (ubuntu-latest) drops it, gpg 2.4.9
(primary host) keeps it.

## Required GitHub Actions secrets (repo: PickleHik3/io-vaj-apt)

| Secret | Source on the primary host |
|---|---|
| `VAJ_GPG_PRIVATE_KEY_B64` | `gpg --armor --export-secret-keys 98C1464F… \| base64 -w0` (from `~/.config/vaj-apt/gnupg-production`) |
| `VAJ_SIGNING_PASSPHRASE` | `~/.config/vaj-apt/archive-signing.passphrase` |
| `AWS_ACCESS_KEY_ID` | `~/.config/vaj-apt/r2.env` |
| `AWS_SECRET_ACCESS_KEY` | `~/.config/vaj-apt/r2.env` |
| `R2_S3_ENDPOINT` | `~/.config/vaj-apt/r2.env` |
| `R2_BUCKET` | `~/.config/vaj-apt/r2.env` |

## Payload integrity: no foreign files

Builds must be **serial** (`build-all-queue.sh` uses `MAX_JOBS=1`). The build
system collects a package's payload as "everything in the prefix newer than the
timestamp", so two builds sharing one prefix leak into each other. The old
primary-host queue ran concurrently and produced 279 contaminated debs out of
1,656 (`audits/2026-08-28-contaminated-debs.tsv`; e.g. arpack-ng shipping all of
ruby, 145 debs shipping dash's `bin/sh` and therefore uninstallable). Check any
deb or the whole pool against upstream Termux's `Contents-aarch64` with:

```bash
python3 scripts/audit-deb-contents.py incoming/          # or pool/
```

Remediation was a VAJ revision bump on the affected recipes so the index-driven
queue rebuilds them. Wiring this script into `publish.yml` as a gate on
`incoming/` is the obvious next hardening step.

## Local publish still works

`stage-debs.py` is the extracted staging step; local `publish-wave-*.py` and the
manual sequence (`generate_repo.py → sign-release.sh → publish-r2.py --all`) are
unchanged. CI and local share one staging code path.

## First-run checklist

1. `gh repo edit PickleHik3/io-vaj-apt --default-branch io-vaj-package` (done once)
2. Set the six secrets above (done 2026-08-27)
3. Load the image on one build machine, `gh auth login`
4. `./remote-build.sh --pkgs tree --no-publish` — confirm a deb builds (pick a
   package the container has not built; `zsh` pulls ~30 stale deps)
5. `./remote-build.sh --pkgs zsh` — confirm the staging release appears and
   `publish.yml` runs green
6. Verify `zsh` on `https://repo.pathayam.xyz` and the manifest commit landed
7. Only then run larger waves

## The Azure build machine (2026-08-27)

Resource group `vaj-build` (eastus), VM `vaj-builder`, `Standard_E4as_v7`
(4 vCPU / 32 GB — the trial subscription caps every family at 4 vCPU and offers
only v7 SKUs in eastus), Ubuntu 24.04, 256 GB StandardSSD, user `azureuser`,
SSH key from the primary host. Image, `gh` auth and the recipes are in place.
Public IP: `az vm show -d -g vaj-build -n vaj-builder --query publicIps -o tsv`.

- `~/run-queue.sh [args]` — detached wrapper: `UPDATES_ONLY=1 ./remote-build.sh`,
  log in `~/queue-latest.log`, then `~/self-deallocate.sh` (managed identity +
  ARM REST; a guest `shutdown` would keep billing). Launch with
  `nohup ~/run-queue.sh > /dev/null 2>&1 &`.
- Between runs: `az vm deallocate -g vaj-build -n vaj-builder` (~$0.23/h running,
  only the disk when deallocated). Start again with `az vm start`.
- It builds with **`io-vaj-builder:<recipes-sha>`** (`:latest` alias): upstream's
  current `scripts/Dockerfile` (`FROM ubuntu:26.04`) built at the merged recipes
  tree, builder UID 1001, no VAJ patches (the VAJ identity lives in the mounted
  recipes' `scripts/properties.sh`). The frozen 24.04 image
  `io-vaj-phase0a-builder:c9cc6b28` is kept but no longer usable for current
  recipes: python 3.14 needs autoconf ≥ 2.72 and every meson/GIR package fails
  with `Unhandled introspection XML tag 'pointer'` on its host
  gobject-introspection. (`c9cc6b28-ac272`, frozen + autoconf 2.72, was an
  interim step; superseded.) Rebuild after a recipes merge that touches
  `scripts/setup-ubuntu.sh` or `scripts/Dockerfile`:
  `docker build -t io-vaj-builder:$(git rev-parse --short HEAD) -t io-vaj-builder:latest -f scripts/Dockerfile scripts/`
- Every package build is bounded by `PKG_TIMEOUT` (default 8 h); `dotnet9.0` is
  in `build-exclusions.txt` (its source build hangs on a zombie MSBuild server).
- Stopping a run: kill `remote-build.sh` **by PID**, then `docker rm -f
  vaj-remote-builder`. Killing only the `run-queue.sh` wrapper leaves the build
  running and loses the auto-deallocate; a `pkill -f` pattern that also appears
  in your own ssh command line kills your session.
