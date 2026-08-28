#!/usr/bin/env python3
"""audit-deb-contents.py — find debs that carry another package's files.

The old primary-host queue built packages concurrently into one shared prefix
and collected payloads by timestamp, so a deb could pick up whatever another
build installed meanwhile (2026-08-28 audit: 279 of 1,656 published debs, e.g.
arpack-ng shipping all of ruby, 145 debs shipping dash's bin/sh -> dpkg refuses
to install them). Ground truth for "who owns this path" is upstream Termux's
Contents-aarch64 index (same recipes, same subpackage splits, com.termux prefix).

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

UPSTREAM = "https://packages.termux.dev/apt/termux-main/dists/stable/Contents-aarch64.gz"


def load_owners(cache: Path) -> dict[str, str]:
    if not cache.is_file():
        req = urllib.request.Request(UPSTREAM, headers={"User-Agent": "Debian APT-HTTP/1.3"})
        with urllib.request.urlopen(req, timeout=120) as r, open(cache, "wb") as f:
            f.write(r.read())
    owners: dict[str, str] = {}
    with gzip.open(cache, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").rsplit(None, 1)
            if len(parts) != 2:
                continue
            path, pkgs = parts
            # "section/name,section/name" -> first owner's bare name
            owners[path] = pkgs.split(",")[0].rsplit("/", 1)[-1]
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
            owner = owners.get(path.replace(ours, theirs, 1))
            if owner and not related(owner, name):
                foreign += 1; who[owner] += 1
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
