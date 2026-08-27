#!/usr/bin/env python3
"""stage-debs.py — Stage .deb objects into the pool and update the manifest.

Shared staging step for both local publication (publish-wave-*.py) and the CI
publish workflow. Does ONLY steps 1-3 of the canonical sequence:

  1. Discover .deb files in <deb-dir>. For each package name:
       - not in the manifest            -> NEW: append a row
       - in the manifest, older version -> UPGRADE: replace the row in place
                                           (the old pool object is retained;
                                           the pool is immutable)
       - same or newer version already  -> skip (never downgrade, never
                                           replace an object of equal version)
  2. Compute sha256/size and copy each staged deb to
     pool/main/{first_char}/{pkg_name}/
  3. Rewrite foundation.tsv (rows stay in place, no duplicate names) and
     update the "# Package count:" header

It intentionally does NOT generate metadata, sign, or publish — the caller
chains generate_repo.py -> sign-release.sh -> publish-r2.py after this succeeds.

Usage:
    python3 scripts/stage-debs.py <deb-dir> [--repo-root DIR] [--manifest FILE]
                                            [--evidence TSV] [--dry-run]

Exit codes: 0 = staged (or nothing to do), 1 = error (e.g. unparseable filename).
Prints the number of staged packages (new + upgraded) on the last line as
"STAGED=<n>".
"""

from __future__ import annotations
import argparse
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT_DEFAULT = Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- Debian version comparison (dpkg algorithm, Debian Policy 5.6.12) -------

def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_fragment(a: str, b: str) -> int:
    while a or b:
        # non-digit prefix
        ma = re.match(r"[^0-9]*", a).group(0)
        mb = re.match(r"[^0-9]*", b).group(0)
        for i in range(max(len(ma), len(mb))):
            oa = _order(ma[i]) if i < len(ma) else 0
            ob = _order(mb[i]) if i < len(mb) else 0
            if oa != ob:
                return -1 if oa < ob else 1
        a, b = a[len(ma):], b[len(mb):]
        # digit run
        da = re.match(r"[0-9]*", a).group(0)
        db = re.match(r"[0-9]*", b).group(0)
        na, nb = int(da or "0"), int(db or "0")
        if na != nb:
            return -1 if na < nb else 1
        a, b = a[len(da):], b[len(db):]
    return 0


def _split_version(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """Return -1 if a < b, 0 if equal, 1 if a > b, as dpkg --compare-versions."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _cmp_fragment(ua, ub)
    if c:
        return c
    return _cmp_fragment(ra, rb)


def pkg_name_from_filename(fname: str) -> str:
    return fname.split("_")[0]


def pool_path(pkg_name: str, fname: str) -> str:
    return f"pool/main/{pkg_name[0]}/{pkg_name}/{fname}"


def load_manifest_rows(manifest: Path) -> dict[str, list[str]]:
    """Return name -> [name, version, arch, sha256, object_path, size] for every
    data row in foundation.tsv."""
    rows: dict[str, list[str]] = {}
    with open(manifest, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if parts and parts[0]:
                rows[parts[0]] = parts
    return rows


def read_control(deb: Path) -> tuple[str, str, str] | None:
    """(Package, Version, Architecture) from the deb's control file.

    Authoritative over the filename: GitHub release assets cannot contain ':',
    so an epoch version like 1:2026.07.16 reaches CI as 1.2026.07.16 in the
    name, which would compare as OLDER than the published 1:2026.05.14."""
    try:
        out = subprocess.run(
            ["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture"],
            check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    fields = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
    if not all(k in fields for k in ("Package", "Version", "Architecture")):
        return None
    return fields["Package"], fields["Version"], fields["Architecture"]


def canonical_deb_name(name: str, ver: str, arch: str) -> str:
    """Pool objects are named name_version_arch.deb with the epoch colon kept
    (68 such objects already in the pool)."""
    return f"{name}_{ver}_{arch}.deb"


def classify_debs(deb_dir: Path, rows: dict[str, list[str]]):
    """Sort incoming debs into (new, upgrades, skipped, errors).
    new/upgrades: list of (Path, name, version, arch); skipped: list of str."""
    new, upgrades, skipped, errors = [], [], [], []
    seen: dict[str, tuple] = {}
    for deb in sorted(deb_dir.glob("*.deb")):
        parsed = read_control(deb)
        if not parsed:
            errors.append(f"Cannot read Package/Version/Architecture from control file: {deb.name}")
            continue
        name, ver, arch = parsed
        # two debs of the same name in one wave: keep the newest
        if name in seen and compare_versions(ver, seen[name][2]) <= 0:
            skipped.append(f"{deb.name}: superseded by {seen[name][0].name} in the same wave")
            continue
        seen[name] = (deb, name, ver, arch)
    for deb, name, ver, arch in seen.values():
        if name not in rows:
            new.append((deb, name, ver, arch))
            continue
        published = rows[name][1]
        c = compare_versions(ver, published)
        if c > 0:
            upgrades.append((deb, name, ver, arch))
        elif c == 0:
            skipped.append(f"{deb.name}: {published} already published")
        else:
            skipped.append(f"{deb.name}: OLDER than published {published}; not downgrading")
    return new, upgrades, skipped, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("deb_dir", help="directory containing built .deb files")
    ap.add_argument("--repo-root", default=str(REPO_ROOT_DEFAULT))
    ap.add_argument("--manifest", default=None,
                    help="path to foundation.tsv (default: <repo-root>/manifests/foundation.tsv)")
    ap.add_argument("--evidence", default=None,
                    help="optional path to write an artifact-integrity .tsv")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be staged; do not copy or write the manifest")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    deb_dir = Path(args.deb_dir).resolve()
    manifest = Path(args.manifest).resolve() if args.manifest else repo_root / "manifests" / "foundation.tsv"

    if not deb_dir.is_dir():
        print(f"ERROR: deb dir not found: {deb_dir}", file=sys.stderr)
        return 1
    if not manifest.is_file():
        print(f"ERROR: manifest not found: {manifest}", file=sys.stderr)
        return 1

    print("=== stage-debs ===")
    print(f"Repo root:  {repo_root}")
    print(f"Source dir: {deb_dir}")
    print(f"Manifest:   {manifest}")

    rows = load_manifest_rows(manifest)
    new_debs, upgrade_debs, skipped, errors = classify_debs(deb_dir, rows)
    print(f"Already published: {len(rows)}")
    print(f"New to stage:      {len(new_debs)}")
    print(f"Upgrades to stage: {len(upgrade_debs)}")
    for msg in skipped:
        print(f"  skip: {msg}")
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    staged = [(d, "new") for d in new_debs] + [(d, "upgrade") for d in upgrade_debs]
    if not staged:
        print("Nothing to stage.")
        print("STAGED=0")
        return 0

    # --- Step 1+2: integrity + copy to pool ---
    entries: list[tuple] = []   # (kind, pkg, ver, arch, sha, ppath, size)
    integrity_rows: list[str] = []

    for (src, pkg, ver, arch), kind in staged:
        fname = canonical_deb_name(pkg, ver, arch)   # not src.name: see read_control
        ppath = pool_path(pkg, fname)
        dest = repo_root / ppath

        if not args.dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                shutil.copy2(src, dest)
                print(f"  staged ({kind}): {ppath}")
            else:
                print(f"  exists ({kind}): {ppath}")
            sha = sha256_file(dest)
            size = dest.stat().st_size
        else:
            print(f"  would stage ({kind}): {ppath}")
            sha = sha256_file(src)
            size = src.stat().st_size

        if kind == "upgrade":
            print(f"    {pkg}: {rows[pkg][1]} -> {ver}")
        entries.append((kind, pkg, ver, arch, sha, ppath, size))
        integrity_rows.append(f"{pkg}\t{ver}\t{arch}\t{size}\t{sha}\t{ppath}")

    # --- Step 3: rewrite manifest (replace upgraded rows in place, append new) ---
    if not args.dry_run:
        replacements = {pkg: (pkg, ver, arch, sha, ppath, str(size))
                        for kind, pkg, ver, arch, sha, ppath, size in entries if kind == "upgrade"}
        appended = [(pkg, ver, arch, sha, ppath, str(size))
                    for kind, pkg, ver, arch, sha, ppath, size in entries if kind == "new"]
        lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
        existing_count = sum(1 for l in lines if l.strip() and not l.startswith("#"))
        new_total = existing_count + len(appended)

        updated = []
        saw_count = False
        for line in lines:
            if line.startswith("# Package count:"):
                updated.append(f"# Package count: {new_total}\n")
                saw_count = True
                continue
            if line.strip() and not line.startswith("#"):
                name = line.split("\t", 1)[0]
                if name in replacements:
                    updated.append("\t".join(replacements[name]) + "\n")
                    continue
            updated.append(line)
        if not saw_count:
            print("WARNING: no '# Package count:' header found; count not written", file=sys.stderr)

        content = "".join(updated)
        if not content.endswith("\n"):
            content += "\n"
        for row in appended:
            # column order: name version arch sha256 object-path size
            content += "\t".join(row) + "\n"
        manifest.write_text(content, encoding="utf-8")
        print(f"\nManifest updated: {existing_count} -> {new_total} packages "
              f"({len(appended)} new, {len(replacements)} upgraded)")

    if args.evidence:
        ev = Path(args.evidence)
        ev.parent.mkdir(parents=True, exist_ok=True)
        with open(ev, "w", encoding="utf-8") as f:
            f.write("package\tversion\tarch\tsize_bytes\tsha256\tobject_path\n")
            f.write("\n".join(integrity_rows) + "\n")
        print(f"Integrity TSV: {ev}")

    print(f"STAGED={len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
