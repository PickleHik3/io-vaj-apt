#!/usr/bin/env python3
"""stage-debs.py — Stage new .deb objects into the pool and append the manifest.

Shared staging step for both local publication (publish-wave-*.py) and the CI
publish workflow. Does ONLY steps 1-3 of the canonical sequence:

  1. Discover .deb files in <deb-dir> whose package name is not yet in the manifest
  2. Compute sha256/size and copy each to pool/main/{first_char}/{pkg_name}/
  3. Append entries to foundation.tsv and update the "# Package count:" header

It intentionally does NOT generate metadata, sign, or publish — the caller
chains generate_repo.py -> sign-release.sh -> publish-r2.py after this succeeds.

Usage:
    python3 scripts/stage-debs.py <deb-dir> [--repo-root DIR] [--manifest FILE]
                                            [--evidence TSV] [--dry-run]

Exit codes: 0 = staged (or nothing new), 1 = error (e.g. unparseable filename).
Prints the number of newly staged packages on the last line as "STAGED=<n>".
"""

from __future__ import annotations
import argparse
import hashlib
import shutil
import sys
from pathlib import Path

REPO_ROOT_DEFAULT = Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pkg_name_from_filename(fname: str) -> str:
    return fname.split("_")[0]


def pool_path(pkg_name: str, fname: str) -> str:
    return f"pool/main/{pkg_name[0]}/{pkg_name}/{fname}"


def load_published_names(manifest: Path) -> set[str]:
    """Return set of package names already in foundation.tsv."""
    published: set[str] = set()
    with open(manifest, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if parts:
                published.add(parts[0])
    return published


def discover_new_debs(deb_dir: Path, published_names: set[str]) -> list[Path]:
    """Sorted .deb paths in deb_dir whose package name is not yet published."""
    new = []
    for deb in sorted(deb_dir.glob("*.deb")):
        if pkg_name_from_filename(deb.name) not in published_names:
            new.append(deb)
    return new


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

    published = load_published_names(manifest)
    new_debs = discover_new_debs(deb_dir, published)
    print(f"Already published: {len(published)}")
    print(f"New to stage:      {len(new_debs)}")

    if not new_debs:
        print("Nothing new to stage.")
        print("STAGED=0")
        return 0

    # --- Step 1+2: integrity + copy to pool ---
    new_entries: list[tuple] = []
    integrity_rows: list[str] = []
    errors: list[str] = []

    for src in new_debs:
        fname = src.name
        pkg = pkg_name_from_filename(fname)
        ppath = pool_path(pkg, fname)
        dest = repo_root / ppath

        parts = fname.removesuffix(".deb").split("_")
        if len(parts) < 3:
            errors.append(f"Cannot parse filename (expect name_version_arch.deb): {fname}")
            continue
        ver, arch = parts[1], parts[2]

        if not args.dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                shutil.copy2(src, dest)
                print(f"  staged: {ppath}")
            else:
                print(f"  exists: {ppath}")
            sha = sha256_file(dest)
            size = dest.stat().st_size
        else:
            print(f"  would stage: {ppath}")
            sha = sha256_file(src)
            size = src.stat().st_size

        new_entries.append((pkg, ver, arch, sha, ppath, size))
        integrity_rows.append(f"{pkg}\t{ver}\t{arch}\t{size}\t{sha}\t{ppath}")

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # --- Step 3: append manifest + bump count ---
    if not args.dry_run:
        lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
        existing_count = sum(1 for l in lines if l.strip() and not l.startswith("#"))
        new_total = existing_count + len(new_entries)

        updated = []
        saw_count = False
        for line in lines:
            if line.startswith("# Package count:"):
                updated.append(f"# Package count: {new_total}\n")
                saw_count = True
            else:
                updated.append(line)
        if not saw_count:
            print("WARNING: no '# Package count:' header found; count not written", file=sys.stderr)

        content = "".join(updated)
        if not content.endswith("\n"):
            content += "\n"
        for pkg, ver, arch, sha, ppath, size in new_entries:
            # column order: name version arch sha256 object-path size
            content += f"{pkg}\t{ver}\t{arch}\t{sha}\t{ppath}\t{size}\n"
        manifest.write_text(content, encoding="utf-8")
        print(f"\nManifest updated: {existing_count} -> {new_total} packages")

    if args.evidence:
        ev = Path(args.evidence)
        ev.parent.mkdir(parents=True, exist_ok=True)
        with open(ev, "w", encoding="utf-8") as f:
            f.write("package\tversion\tarch\tsize_bytes\tsha256\tobject_path\n")
            f.write("\n".join(integrity_rows) + "\n")
        print(f"Integrity TSV: {ev}")

    print(f"STAGED={len(new_entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
