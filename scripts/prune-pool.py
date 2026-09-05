#!/usr/bin/env python3
"""prune-pool.py — delete pool objects the published index no longer references.

The publisher only ever adds. Every rebuild uploads a new deb and leaves its
predecessor in the bucket, where nothing references it: not the Packages index,
not the manifests, not apt. By 2026-09-05 that was 955 objects and 4.51 GB
against R2's 10 GB free tier, which the bucket had already exceeded (11.28 GB).

Ground truth is the *published* index, fetched live. A key is deletable only
when it is a .deb under the pool prefix, absent from that index, and older than
--min-age hours -- a deb uploaded by a wave that has not yet regenerated the
index is referenced by nothing yet and must not be mistaken for garbage.

Usage:
    scripts/prune-pool.py                    # dry run, prints what it would do
    scripts/prune-pool.py --apply            # delete
Credentials come from the environment (r2.env): R2_BUCKET, R2_S3_ENDPOINT,
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
"""
from __future__ import annotations
import argparse, datetime, gzip, io, os, sys, urllib.request

DEFAULT_INDEX = "https://repo.pathayam.xyz/dists/stable/main/binary-aarch64/Packages.gz"


def published_filenames(url: str) -> set[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Debian APT-HTTP/1.3"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = gzip.decompress(r.read()).decode("utf-8", errors="replace")
    names = {line.split(None, 1)[1].strip()
             for line in raw.splitlines() if line.startswith("Filename:")}
    if not names:
        raise SystemExit("published index carries no Filename: fields; refusing to guess")
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="actually delete (default: dry run)")
    ap.add_argument("--index", default=DEFAULT_INDEX, help="published Packages.gz")
    ap.add_argument("--prefix", default="pool/", help="only touch keys under this prefix")
    ap.add_argument("--min-age", type=float, default=24.0,
                    help="keep unreferenced objects younger than this many hours (default 24)")
    ap.add_argument("--max-fraction", type=float, default=0.6,
                    help="abort if this fraction of the pool looks unreferenced (default 0.6)")
    ap.add_argument("--list", help="write the deletable keys to this file")
    a = ap.parse_args()

    import boto3  # imported late so --help works without it
    missing = [v for v in ("R2_BUCKET", "R2_S3_ENDPOINT") if not os.environ.get(v)]
    if missing:
        raise SystemExit(f"missing environment: {', '.join(missing)} (source r2.env)")

    keep = published_filenames(a.index)
    s3 = boto3.client("s3", endpoint_url=os.environ["R2_S3_ENDPOINT"], region_name="auto")
    bucket = os.environ["R2_BUCKET"]

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=a.min_age)
    total = total_bytes = 0
    stale: list[tuple[str, int]] = []
    young = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=a.prefix):
        for o in page.get("Contents", []):
            key, size = o["Key"], o["Size"]
            total += 1
            total_bytes += size
            if key in keep or not key.endswith(".deb"):
                continue
            if o["LastModified"] > cutoff:
                young += 1
                continue
            stale.append((key, size))

    stale_bytes = sum(s for _, s in stale)
    print(f"pool:        {total} objects, {total_bytes / 1e9:.2f} GB")
    print(f"referenced:  {len(keep)} debs in the published index")
    print(f"unreferenced and older than {a.min_age}h: {len(stale)} objects, {stale_bytes / 1e9:.2f} GB")
    if young:
        print(f"unreferenced but younger, kept: {young} (a wave may still be publishing them)")
    print(f"after pruning: {(total_bytes - stale_bytes) / 1e9:.2f} GB")

    if a.list:
        with open(a.list, "w", encoding="utf-8") as f:
            f.write("\n".join(k for k, _ in sorted(stale)) + "\n")
        print(f"keys written to {a.list}")

    if not stale:
        return 0
    if total and len(stale) / total > a.max_fraction:
        raise SystemExit(f"{len(stale)}/{total} of the pool looks unreferenced -- that is more "
                         "than --max-fraction; the index is probably wrong, refusing to delete")
    if not a.apply:
        print("\ndry run: pass --apply to delete")
        return 0

    # R2 answers a 1000-key DeleteObjects with InternalError often enough that
    # the SDK exhausts its retries. Small batches, and a per-object fallback for
    # a batch that still will not go through.
    def delete_one(key: str) -> bool:
        for attempt in range(4):
            try:
                s3.delete_object(Bucket=bucket, Key=key)
                return True
            except Exception as exc:  # noqa: BLE001 - report and move on
                if attempt == 3:
                    print(f"ERROR {key}: {exc}", file=sys.stderr)
        return False

    deleted = freed = 0
    for i in range(0, len(stale), 100):
        chunk = stale[i:i + 100]
        try:
            resp = s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": k} for k, _ in chunk], "Quiet": True},
            )
            failed = {e.get("Key") for e in resp.get("Errors", [])}
            for e in resp.get("Errors", []):
                print(f"ERROR {e.get('Key')}: {e.get('Message')}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - fall back to one at a time
            print(f"batch of {len(chunk)} failed ({exc}); retrying individually", file=sys.stderr)
            failed = {k for k, _ in chunk if not delete_one(k)}
        for key, size in chunk:
            if key not in failed:
                deleted += 1
                freed += size
        print(f"  {deleted}/{len(stale)} deleted", end="\r", file=sys.stderr)
    print(f"deleted {deleted} objects, freed {freed / 1e9:.2f} GB")
    return 0 if deleted == len(stale) else 1


if __name__ == "__main__":
    sys.exit(main())
