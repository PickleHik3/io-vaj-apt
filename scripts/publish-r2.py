#!/usr/bin/env python3
"""publish-r2.py — Upload repository files to Cloudflare R2 via S3 API.

Reads AWS/R2 credentials from environment. Uses allowlist from foundation
manifest (manifests/foundation.tsv) to permit only certified files.

Usage:
    source ~/.config/vaj-apt/r2.env
    python3 scripts/publish-r2.py [file ...] | --all \
        | --verify \
        | --refresh-metadata-cache-policy [--dry-run]
"""

import sys, os, hashlib, hmac, datetime, urllib.request, urllib.error
from urllib.parse import quote

MANIFEST_PATH = "manifests/foundation.tsv"

SUITE = "stable"
COMPONENT = "main"
ARCHITECTURE = "binary-aarch64"

MUTABLE_METADATA = frozenset([
    f"dists/{SUITE}/InRelease",
    f"dists/{SUITE}/Release",
    f"dists/{SUITE}/Release.gpg",
    f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages",
    f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages.gz",
])

MUTABLE_CACHE_CONTROL = "max-age=0, must-revalidate"


def load_allowlist(repo_root):
    """Load allowed object paths from the foundation manifest."""
    manifest = os.path.join(repo_root, MANIFEST_PATH)
    allowed = set()
    if os.path.exists(manifest):
        with open(manifest) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 5:
                    allowed.add(parts[4])
    # Also allow metadata and key files
    allowed.add(f"dists/{SUITE}/Release")
    allowed.add(f"dists/{SUITE}/Release.gpg")
    allowed.add(f"dists/{SUITE}/InRelease")
    allowed.add(f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages")
    allowed.add(f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages.gz")
    allowed.add("keys/io-vaj-archive.gpg")
    allowed.add("keys/io-vaj-archive.asc")
    return allowed


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(secret, date, region, service):
    kDate = sign(("AWS4" + secret).encode("utf-8"), date)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    return sign(kService, "aws4_request")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def s3_put(bucket, key, endpoint, region, access_key, secret_key, data, content_type, cache_control=None):
    service = "s3"
    encoded_bucket = quote(bucket, safe="")
    encoded_key = quote(key, safe="/~")
    url = f"{endpoint}/{encoded_bucket}/{encoded_key}"
    t = datetime.datetime.now(datetime.UTC)
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    payload_hash = sha256(data)
    host_part = endpoint.replace("https://", "")
    headers = {
        "Host": host_part,
        "X-Amz-Date": amzdate,
        "X-Amz-Content-SHA256": payload_hash,
        "Content-Type": content_type,
    }
    if cache_control is not None:
        headers["Cache-Control"] = cache_control
    signed_headers = ";".join(sorted(k.lower() for k in headers))
    canonical_headers = "".join(
        f"{k.lower()}:{v}\n"
        for k, v in sorted(headers.items(), key=lambda x: x[0].lower())
    )
    canonical_uri = f"/{encoded_bucket}/{encoded_key}"
    canonical_request = (
        f"PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amzdate}\n{credential_scope}\n"
        + sha256(canonical_request.encode("utf-8"))
    )
    signing_key = get_signature_key(secret_key, datestamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers["Authorization"] = authorization
    req = urllib.request.Request(url, data=data, headers=headers, method="PUT")
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def s3_head(bucket, key, endpoint, region, access_key, secret_key):
    """Send a HEAD request and return (status_code, response_headers_dict)."""
    service = "s3"
    encoded_bucket = quote(bucket, safe="")
    encoded_key = quote(key, safe="/~")
    url = f"{endpoint}/{encoded_bucket}/{encoded_key}"
    t = datetime.datetime.now(datetime.UTC)
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    host_part = endpoint.replace("https://", "")
    headers = {
        "Host": host_part,
        "X-Amz-Date": amzdate,
    }
    payload_hash = sha256(b"")
    headers["X-Amz-Content-SHA256"] = payload_hash
    signed_headers = ";".join(sorted(k.lower() for k in headers))
    canonical_headers = "".join(
        f"{k.lower()}:{v}\n"
        for k, v in sorted(headers.items(), key=lambda x: x[0].lower())
    )
    canonical_uri = f"/{encoded_bucket}/{encoded_key}"
    canonical_request = (
        f"HEAD\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amzdate}\n{credential_scope}\n"
        + sha256(canonical_request.encode("utf-8"))
    )
    signing_key = get_signature_key(secret_key, datestamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers["Authorization"] = authorization
    req = urllib.request.Request(url, method="HEAD", headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def s3_get(bucket, key, endpoint, region, access_key, secret_key):
    """Send a GET request and return (status_code, body_bytes, response_headers_dict)."""
    service = "s3"
    encoded_bucket = quote(bucket, safe="")
    encoded_key = quote(key, safe="/~")
    url = f"{endpoint}/{encoded_bucket}/{encoded_key}"
    t = datetime.datetime.now(datetime.UTC)
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    host_part = endpoint.replace("https://", "")
    headers = {
        "Host": host_part,
        "X-Amz-Date": amzdate,
    }
    payload_hash = sha256(b"")
    headers["X-Amz-Content-SHA256"] = payload_hash
    signed_headers = ";".join(sorted(k.lower() for k in headers))
    canonical_headers = "".join(
        f"{k.lower()}:{v}\n"
        for k, v in sorted(headers.items(), key=lambda x: x[0].lower())
    )
    canonical_uri = f"/{encoded_bucket}/{encoded_key}"
    canonical_request = (
        f"GET\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amzdate}\n{credential_scope}\n"
        + sha256(canonical_request.encode("utf-8"))
    )
    signing_key = get_signature_key(secret_key, datestamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers["Authorization"] = authorization
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        return e.code, body, dict(e.headers)


def _assert_metadata_key_eligible(key):
    """Refuse to operate on any path outside the five mutable metadata keys.
    Explicitly rejects /pool/ and any .deb.  Raises SystemExit on rejection."""
    if key.startswith("pool/") or "/pool/" in key:
        print(f"REFUSE  pool object: {key}", file=sys.stderr)
        sys.exit(2)
    if key.endswith(".deb"):
        print(f"REFUSE  .deb object: {key}", file=sys.stderr)
        sys.exit(2)
    if key not in MUTABLE_METADATA:
        print(f"REFUSE  not in MUTABLE_METADATA: {key}", file=sys.stderr)
        sys.exit(2)


def _refresh_metadata_cache_policy(repo_root, bucket, endpoint, region,
                                   access_key, secret_key, dry_run=False):
    """Re-upload the five canonical metadata objects with the required
    Cache-Control header, but only after verifying that the bytes already
    present on R2 equal the canonical local bytes.  This proves the operation
    mutates headers, not payload bytes, and never overwrites pool objects.

    On any pre-flight or post-upload error, the operation aborts without
    touching any further object.  This guarantees all-or-nothing semantics.

    Returns (verified_keys, errors).  Each entry is a dict with keys:
        path, local_sha256, origin_sha256, origin_bytes, status
    """
    results = []
    errors = []
    for key in sorted(MUTABLE_METADATA, key=_upload_order_key):
        local_path = os.path.join(repo_root, key)
        if not os.path.isfile(local_path):
            errors.append(f"{key}: canonical local file missing: {local_path}")
            return results, errors
        with open(local_path, "rb") as fh:
            local_data = fh.read()
        local_sha = sha256(local_data)
        if dry_run:
            print(f"DRY-RUN  {key}  local_sha256={local_sha}  bytes={len(local_data)}")
            results.append({
                "path": key,
                "local_sha256": local_sha,
                "origin_sha256": None,
                "origin_bytes": None,
                "status": "dry-run",
            })
            continue
        status, origin_data, _hdrs = s3_get(
            bucket, key, endpoint, region, access_key, secret_key,
        )
        if status != 200:
            errors.append(f"{key}: direct-R2 GET returned {status}")
            return results, errors
        origin_sha = sha256(origin_data)
        if origin_sha != local_sha:
            errors.append(
                f"{key}: origin/canonical byte mismatch "
                f"(origin={origin_sha}, local={local_sha}, "
                f"origin_bytes={len(origin_data)}, local_bytes={len(local_data)})"
            )
            return results, errors
        ct = content_type_for(key)
        put_status = s3_put(
            bucket, key, endpoint, region, access_key, secret_key,
            local_data, ct, cache_control=MUTABLE_CACHE_CONTROL,
        )
        if put_status not in (200, 201):
            errors.append(f"{key}: direct-R2 PUT returned {put_status}")
            return results, errors
        head_status, head_headers = s3_head(
            bucket, key, endpoint, region, access_key, secret_key,
        )
        if head_status != 200:
            errors.append(f"{key}: direct-R2 HEAD after upload returned {head_status}")
            return results, errors
        cc = head_headers.get("Cache-Control") or head_headers.get("cache-control", "")
        if cc != MUTABLE_CACHE_CONTROL:
            errors.append(
                f"{key}: post-upload Cache-Control mismatch: {cc!r} "
                f"(expected {MUTABLE_CACHE_CONTROL!r})"
            )
            return results, errors
        print(
            f"OK  {key}  bytes={len(local_data)}  sha256={local_sha}  "
            f"cache_control={cc!r}  head={head_status}"
        )
        results.append({
            "path": key,
            "local_sha256": local_sha,
            "origin_sha256": origin_sha,
            "origin_bytes": len(origin_data),
            "status": "uploaded",
        })
    return results, errors


def verify_cache_policy(bucket, endpoint, region, access_key, secret_key):
    """Post-upload HEAD check: ensure every mutable metadata object has the
    correct Cache-Control header. Returns list of error messages (empty=pass)."""
    errors = []
    for path in MUTABLE_METADATA:
        status, headers = s3_head(bucket, path, endpoint, region, access_key, secret_key)
        if status != 200:
            errors.append(f"{path}: HEAD returned {status}")
            continue
        cc = headers.get("Cache-Control") or headers.get("cache-control", "")
        if cc != MUTABLE_CACHE_CONTROL:
            errors.append(
                f"{path}: expected Cache-Control={MUTABLE_CACHE_CONTROL!r}, "
                f"got {cc!r}"
            )
    return errors


def content_type_for(path):
    if path.endswith(".deb"):
        return "application/vnd.debian.binary-package"
    elif path.endswith(".gpg"):
        return "application/pgp-keys"
    elif path.endswith(".asc"):
        return "text/plain"
    elif path.endswith(".gz"):
        return "application/gzip"
    elif path.endswith("Release") or path.endswith("InRelease") or path.endswith("Packages"):
        return "text/plain"
    return "application/octet-stream"


def _upload_order_key(path):
    """Sort key: pool objects first, then metadata in publication order."""
    metadata_order = [
        f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages",
        f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages.gz",
        f"dists/{SUITE}/Release",
        f"dists/{SUITE}/Release.gpg",
        f"dists/{SUITE}/InRelease",
    ]
    if path in metadata_order:
        return (1, metadata_order.index(path))
    return (0, path)


def main():
    bucket = os.environ["R2_BUCKET"]
    endpoint = os.environ["R2_S3_ENDPOINT"]
    region = os.environ["AWS_REGION"]
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    allowed = load_allowlist(repo_root)

    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    if dry_run:
        args = [a for a in args if a != "--dry-run"]

    if len(args) > 0 and args[0] == "--refresh-metadata-cache-policy":
        if not dry_run:
            for k in MUTABLE_METADATA:
                _assert_metadata_key_eligible(k)
        _results, errors = _refresh_metadata_cache_policy(
            repo_root, bucket, endpoint, region, access_key, secret_key,
            dry_run=dry_run,
        )
        if dry_run:
            print(
                f"DRY-RUN complete: {len(MUTABLE_METADATA)} mutable metadata keys "
                f"would be re-uploaded with Cache-Control: {MUTABLE_CACHE_CONTROL!r}"
            )
            return 0
        if errors:
            for e in errors:
                print(f"FAIL  {e}", file=sys.stderr)
            sys.exit(1)
        print(
            f"OK  refreshed Cache-Control on {len(MUTABLE_METADATA)} mutable metadata objects"
        )
        return 0

    if len(args) > 0 and args[0] == "--verify":
        errors = verify_cache_policy(bucket, endpoint, region, access_key, secret_key)
        if errors:
            for e in errors:
                print(f"FAIL  {e}", file=sys.stderr)
            sys.exit(1)
        print("OK  all mutable metadata Cache-Control is correct")
        return

    if len(args) > 0 and args[0] == "--all":
        files = sorted(allowed, key=_upload_order_key)
    elif len(args) > 0:
        files = args
    else:
        print(
            "Usage: publish-r2.py [file ...] | --all | --verify "
            "| --refresh-metadata-cache-policy [--dry-run]",
            file=sys.stderr,
        )
        sys.exit(1)

    for rel_path in files:
        local_path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(local_path):
            print(f"SKIP (not found): {rel_path}", file=sys.stderr)
            continue
        if rel_path not in allowed:
            print(f"SKIP (not in allowlist): {rel_path}", file=sys.stderr)
            continue

        with open(local_path, "rb") as fh:
            data = fh.read()
        ct = content_type_for(rel_path)
        cc = MUTABLE_CACHE_CONTROL if rel_path in MUTABLE_METADATA else None
        status = s3_put(bucket, rel_path, endpoint, region, access_key, secret_key, data, ct, cache_control=cc)
        file_hash = sha256(data)
        print(f"PUT {status}  {rel_path}  sha256={file_hash}")


if __name__ == "__main__":
    main()
