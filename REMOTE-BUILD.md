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
| `remote-build.sh` | `termux-packages` @ `io-vaj-package` | Build machine: run the builder container, then `gh release create staging-<ts>` |
| `.github/workflows/publish.yml` | `io-vaj-apt` (default branch) | The only holder of secrets. Stages, signs, publishes, cleans up |
| `scripts/stage-debs.py` | `io-vaj-apt` | Shared staging: copy debs → pool, append `foundation.tsv`. Used by CI **and** local `publish-wave-*.py` |

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

Build + hand off:

```bash
./remote-build.sh                       # full queue (~1,660 pkgs)
./remote-build.sh build-tier1-libs.txt  # one tier
./remote-build.sh --pkgs zsh jq bc      # named packages (start here for a first test)
./remote-build.sh --pkgs zsh --no-publish   # build only, no staging release
```

`remote-build.sh` refuses to start if the frozen image is absent or `gh` is
unauthenticated. It creates a fresh `vaj-remote-builder` container each run
(distinct name — will not collide with the primary host's
`termux-package-builder`).

## What CI does per staging release

`publish.yml` fires on `release: prereleased` for `staging-*` tags (or manual
`workflow_dispatch` with `release_tag`). Steps, in order:

1. checkout `io-vaj-package`
2. import GPG key from `VAJ_GPG_PRIVATE_KEY_B64` into an ephemeral `GNUPGHOME`;
   write passphrase to a temp file
3. `gh release download` the `*.deb` assets → `incoming/`
4. `aws s3 sync` pool ← R2
5. `stage-debs.py incoming` → copies to pool, appends manifest, prints `STAGED=<n>`
6. if `STAGED=0`, skip the rest
7. `generate_repo.py` → `sign-release.sh` → `publish-r2.py --all` → `publish-r2.py --verify`
8. commit updated `foundation.tsv` to `io-vaj-package`
9. delete the `staging-*` release (always, even on failure)

`concurrency: vaj-apt-publish` serializes runs — two build machines produce two
staging releases that publish one after another; the pool/manifest never race.

## Required GitHub Actions secrets (repo: PickleHik3/io-vaj-apt)

| Secret | Source on the primary host |
|---|---|
| `VAJ_GPG_PRIVATE_KEY_B64` | `gpg --armor --export-secret-keys 98C1464F… \| base64 -w0` (from `~/.config/vaj-apt/gnupg-production`) |
| `VAJ_SIGNING_PASSPHRASE` | `~/.config/vaj-apt/archive-signing.passphrase` |
| `AWS_ACCESS_KEY_ID` | `~/.config/vaj-apt/r2.env` |
| `AWS_SECRET_ACCESS_KEY` | `~/.config/vaj-apt/r2.env` |
| `R2_S3_ENDPOINT` | `~/.config/vaj-apt/r2.env` |
| `R2_BUCKET` | `~/.config/vaj-apt/r2.env` |

## Local publish still works

`stage-debs.py` is the extracted staging step; local `publish-wave-*.py` and the
manual sequence (`generate_repo.py → sign-release.sh → publish-r2.py --all`) are
unchanged. CI and local share one staging code path.

## First-run checklist

1. `gh repo edit PickleHik3/io-vaj-apt --default-branch io-vaj-package` (done once)
2. Set the six secrets above
3. Load the image on one build machine, `gh auth login`
4. `./remote-build.sh --pkgs zsh --no-publish` — confirm a deb builds
5. `./remote-build.sh --pkgs zsh` — confirm the staging release appears and
   `publish.yml` runs green
6. Verify `zsh` on `https://repo.pathayam.xyz` and the manifest commit landed
7. Only then run larger waves
