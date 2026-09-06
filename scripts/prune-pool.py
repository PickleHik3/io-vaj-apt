#!/usr/bin/env python3
"""prune-pool.py — delete pool objects the published index no longer references.

The publisher only ever adds. Every rebuild uploads a new deb and leaves its
predecessor in the bucket, referenced by nothing: not the Packages index, not
the manifests, not apt. By 2026-09-05 that was 955 objects and 4.51 GB against
R2's 10 GB free tier, which the bucket had already exceeded (11.28 GB).

Ground truth is the *published* index, fetched live, so this cannot be run
against a stale local copy. Three guards, because this deletes:

  - only keys ending in .deb under --prefix are ever considered;
  - nothing younger than --min-age, since a wave that has uploaded debs but not
    yet regenerated the index has files no index references yet;
  - an abort if more than --max-fraction of the pool looks unreferenced, which
    means the index is wrong rather than the pool dirty.

Usage:
    scripts/prune-pool.py                    # dry run, prints what it would do
    scripts/prune-pool.py --apply            # delete

Environment (r2.env, or the workflow's repository secrets):
    R2_BUCKET  R2_S3_ENDPOINT  AWS_ACCESS_KEY_ID  AWS_SECRET_ACCESS_KEY
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import hmac
import importlib.util
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_INDEX = "https://repo.pathayam.xyz/dists/stable/main/binary-aarch64/Packages.gz"
_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

# Reuse the publisher's SigV4 helpers rather than keeping a second copy, and
# rather than boto3: nothing else in this repository's CI installs a package.
_PUBLISHER = Path(__file__).resolve().parent / "publish-r2.py"
_spec = importlib.util.spec_from_file_location("vaj_publish_r2", _PUBLISHER)
_pub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pub)


def s3_request(method, endpoint, bucket, key, query, access_key, secret_key, region):
    """Signed S3 request against R2. Returns (status, body_bytes)."""
    service = "s3"
    encoded_bucket = urllib.parse.quote(bucket, safe="")
    encoded_key = urllib.parse.quote(key, safe="/~")
    canonical_uri = f"/{encoded_bucket}/{encoded_key}" if key else f"/{encoded_bucket}"
    # The canonical query string is sorted by key and percent-encoded; getting
    # this wrong is a SignatureDoesNotMatch, not a helpful error.
    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted((query or {}).items())
    )
    t = datetime.datetime.now(datetime.UTC)
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    payload_hash = _pub.sha256(b"")
    headers = {
        "Host": endpoint.replace("https://", ""),
        "X-Amz-Date": amzdate,
        "X-Amz-Content-SHA256": payload_hash,
    }
    signed_headers = ";".join(sorted(k.lower() for k in headers))
    canonical_headers = "".join(
        f"{k.lower()}:{v}\n" for k, v in sorted(headers.items(), key=lambda x: x[0].lower())
    )
    canonical_request = (
        f"{method}\n{canonical_uri}\n{canonical_query}\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amzdate}\n{credential_scope}\n"
        + _pub.sha256(canonical_request.encode("utf-8"))
    )
    signing_key = _pub.get_signature_key(secret_key, datestamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    url = f"{endpoint}{canonical_uri}"
    if canonical_query:
        url += f"?{canonical_query}"
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:  # noqa: BLE001 - the status is what matters
            return e.code, b""


def _parse_last_modified(raw: str) -> datetime.datetime:
    """S3 reports fractional seconds; R2 has been seen to omit them."""
    raw = (raw or "").replace("Z", "+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.datetime.strptime(raw, fmt)
        except ValueError:
            continue
    raise SystemExit(f"could not parse LastModified {raw!r}")


def list_pool(endpoint, bucket, prefix, access_key, secret_key, region):
    """Yield (key, size, last_modified) for every object under prefix."""
    token = None
    while True:
        query = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
        if token:
            query["continuation-token"] = token
        status, body = s3_request("GET", endpoint, bucket, "", query,
                                  access_key, secret_key, region)
        if status != 200:
            raise SystemExit(f"list failed with HTTP {status}: "
                             f"{body[:400].decode(errors='replace')}")
        root = ET.fromstring(body)
        for c in root.findall(f"{_NS}Contents"):
            yield (c.findtext(f"{_NS}Key") or "",
                   int(c.findtext(f"{_NS}Size") or 0),
                   _parse_last_modified(c.findtext(f"{_NS}LastModified")))
        if (root.findtext(f"{_NS}IsTruncated") or "false").lower() != "true":
            return
        token = root.findtext(f"{_NS}NextContinuationToken")
        if not token:
            return


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

    missing = [v for v in ("R2_BUCKET", "R2_S3_ENDPOINT",
                           "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
               if not os.environ.get(v)]
    if missing:
        raise SystemExit(f"missing environment: {', '.join(missing)} (source r2.env)")
    bucket = os.environ["R2_BUCKET"]
    endpoint = os.environ["R2_S3_ENDPOINT"].rstrip("/")
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    region = os.environ.get("AWS_REGION", "auto")

    keep = published_filenames(a.index)
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=a.min_age)

    total = total_bytes = young = 0
    stale: list[tuple[str, int]] = []
    for key, size, when in list_pool(endpoint, bucket, a.prefix, access_key, secret_key, region):
        total += 1
        total_bytes += size
        if key in keep or not key.endswith(".deb"):
            continue
        if when > cutoff:
            young += 1
            continue
        stale.append((key, size))

    stale_bytes = sum(s for _, s in stale)
    print(f"pool:        {total} objects, {total_bytes / 1e9:.2f} GB")
    print(f"referenced:  {len(keep)} debs in the published index")
    print(f"unreferenced and older than {a.min_age}h: {len(stale)} objects, "
          f"{stale_bytes / 1e9:.2f} GB")
    if young:
        print(f"unreferenced but younger, kept: {young} (a wave may still be publishing them)")
    print(f"after pruning: {(total_bytes - stale_bytes) / 1e9:.2f} GB")

    if a.list:
        Path(a.list).write_text("\n".join(k for k, _ in sorted(stale)) + "\n", encoding="utf-8")
        print(f"keys written to {a.list}")

    if not stale:
        return 0
    if total and len(stale) / total > a.max_fraction:
        raise SystemExit(f"{len(stale)}/{total} of the pool looks unreferenced -- that is more "
                         "than --max-fraction; the index is probably wrong, refusing to delete")
    if not a.apply:
        print("\ndry run: pass --apply to delete")
        return 0

    # R2 answers a bulk DeleteObjects with InternalError until the caller gives
    # up, so delete one key at a time. 955 objects took about two minutes.
    deleted = freed = 0
    for key, size in stale:
        for attempt in range(4):
            status, body = s3_request("DELETE", endpoint, bucket, key, None,
                                      access_key, secret_key, region)
            if status in (200, 204):
                deleted += 1
                freed += size
                break
            if attempt == 3:
                print(f"ERROR {key}: HTTP {status} {body[:200].decode(errors='replace')}",
                      file=sys.stderr)
        if deleted and deleted % 100 == 0:
            print(f"  {deleted}/{len(stale)} deleted", file=sys.stderr)
    print(f"deleted {deleted} objects, freed {freed / 1e9:.2f} GB")
    return 0 if deleted == len(stale) else 1


if __name__ == "__main__":
    sys.exit(main())
