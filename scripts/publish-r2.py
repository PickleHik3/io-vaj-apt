#!/usr/bin/env python3
"""publish-r2.py — Upload repository files to Cloudflare R2 via S3 API.

Reads AWS/R2 credentials from environment. Uses allowlist from foundation
manifest (manifests/foundation.tsv) to permit only certified files.

Usage:
    source ~/.config/vaj-apt/r2.env
    python3 scripts/publish-r2.py [file ...] | --all | --delta
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

    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        errors = verify_cache_policy(bucket, endpoint, region, access_key, secret_key)
        if errors:
            for e in errors:
                print(f"FAIL  {e}", file=sys.stderr)
            sys.exit(1)
        print("OK  all mutable metadata Cache-Control is correct")
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        files = sorted(allowed, key=_upload_order_key)
    elif len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        print("Usage: publish-r2.py [file ...] | --all | --verify", file=sys.stderr)
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
