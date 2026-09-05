#!/usr/bin/env python3
"""audit-deb-contents.py — find debs that carry another package's files.

The old primary-host queue built packages concurrently into one shared prefix
and collected payloads by timestamp, so a deb could pick up whatever another
build installed meanwhile (2026-08-28 audit: 279 of 1,656 published debs, e.g.
arpack-ng shipping all of ruby, 145 debs shipping dash's bin/sh -> dpkg refuses
to install them). Ground truth for "who owns this path" is upstream Termux's
Contents-aarch64 indexes -- main, x11 and root (same recipes, same subpackage
splits, com.termux prefix).

Usage:
    scripts/audit-deb-contents.py <deb-or-dir>...  [--prefix io.vaj.tl]
                                  [--contents CACHE.gz] [--min-foreign 1] [--tsv OUT]
Exit 0 = every deb clean, 1 = at least one contaminated deb (listed), 2 = error.
A path with no upstream owner (VAJ-only package, version drift) is not counted.
"""
from __future__ import annotations
import argparse, gzip, os, subprocess, sys, tempfile, urllib.request
from collections import Counter, defaultdict
from pathlib import Path

# One index per upstream repository. termux-main alone was ground truth until
# 2026-09-05, which is fine while we only publish main-repo recipes; the moment
# an x11 or root package is audited, every one of its files has no upstream
# owner and the audit silently says nothing about it. Note the suite names
# differ: main is "stable", the other two are named after the repository.
UPSTREAM = {
    "termux-main": "https://packages.termux.dev/apt/termux-main/dists/stable/Contents-aarch64.gz",
    "termux-x11": "https://packages.termux.dev/apt/termux-x11/dists/x11/Contents-aarch64.gz",
    "termux-root": "https://packages.termux.dev/apt/termux-root/dists/root/Contents-aarch64.gz",
}


def load_owners(cache: Path) -> dict[str, set[str]]:
    """path -> every upstream package that ships it.

    A set, not a single name: the same path can be claimed by more than one
    repository's index, and taking only the first claimant made a deb look
    contaminated whenever the other claimant was the deb itself.
    """
    owners: dict[str, set[str]] = {}
    for repo, url in UPSTREAM.items():
        # Keep the caller's --contents as the base name so one flag still
        # controls where the caches live.
        part = cache.parent / f"{cache.name.removesuffix('.gz')}.{repo}.gz"
        if not part.is_file():
            req = urllib.request.Request(url, headers={"User-Agent": "Debian APT-HTTP/1.3"})
            with urllib.request.urlopen(req, timeout=120) as r, open(part, "wb") as f:
                f.write(r.read())
        with gzip.open(part, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").rsplit(None, 1)
                if len(parts) != 2:
                    continue
                path, pkgs = parts
                # "section/name,section/name" -> each owner's bare name
                owners.setdefault(path, set()).update(
                    entry.rsplit("/", 1)[-1] for entry in pkgs.split(",")
                )
    return owners


def deb_paths(deb: Path) -> list[str]:
    tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], check=True, capture_output=True).stdout
    lst = subprocess.run(["tar", "-t"], input=tar, check=True, capture_output=True).stdout
    out = []
    for raw in lst.splitlines():
        p = raw.decode("utf-8", errors="replace")
        if p.endswith("/"):
            continue
        out.append(p[2:] if p.startswith("./") else p)
    return out


def deb_name(deb: Path) -> str:
    out = subprocess.run(["dpkg-deb", "-f", str(deb), "Package"], check=True, capture_output=True, text=True).stdout
    return out.strip()


def related(owner: str, pkg: str) -> bool:
    """Same source: foo / foo-static / foo-dev / python-foo style splits."""
    return owner == pkg or owner.startswith(pkg) or pkg.startswith(owner)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="+", help=".deb files or directories (searched recursively)")
    ap.add_argument("--prefix", default="io.vaj.tl", help="app id in the debs' paths (default io.vaj.tl)")
    ap.add_argument("--contents", default=os.path.join(tempfile.gettempdir(), "termux-Contents-aarch64.gz"),
                    help="cached upstream Contents-aarch64.gz (downloaded if missing)")
    ap.add_argument("--min-foreign", type=int, default=1, help="flag a deb at this many foreign files (default 1)")
    ap.add_argument("--tsv", help="write name<TAB>foreign<TAB>total<TAB>top-owners per contaminated deb")
    a = ap.parse_args()

    debs: list[Path] = []
    for t in a.targets:
        p = Path(t)
        debs += sorted(p.rglob("*.deb")) if p.is_dir() else [p]
    if not debs:
        print("no debs given", file=sys.stderr); return 2
    owners = load_owners(Path(a.contents))
    ours, theirs = f"data/data/{a.prefix}/", "data/data/com.termux/"

    bad = []
    for deb in debs:
        if not deb.is_file():
            print(f"SKIP {deb}: not found (pool not synced?)", file=sys.stderr)
            continue
        name = deb_name(deb)
        total = foreign = 0
        who: Counter = Counter()
        for path in deb_paths(deb):
            if "/share/doc/" in path or "/CONTROL/" in path:
                continue
            total += 1
            claimants = owners.get(path.replace(ours, theirs, 1))
            if claimants and not any(related(o, name) for o in claimants):
                foreign += 1; who[sorted(claimants)[0]] += 1
        if foreign >= a.min_foreign:
            bad.append((name, foreign, total, who))
            print(f"CONTAMINATED {deb.name}: {foreign}/{total} files belong to "
                  f"{', '.join(f'{o}({n})' for o, n in who.most_common(3))}")
    print(f"audited {len(debs)} deb(s): {len(bad)} contaminated")
    if a.tsv:
        with open(a.tsv, "w", encoding="utf-8") as f:
            for name, foreign, total, who in sorted(bad, key=lambda x: -x[1]):
                f.write(f"{name}\t{foreign}\t{total}\t{','.join(o for o, _ in who.most_common(3))}\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
