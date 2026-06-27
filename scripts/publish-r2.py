#!/usr/bin/env python3
"""publish-r2.py -- Upload explicit file allowlist to Cloudflare R2 via S3 API.

Reads AWS/R2 credentials from environment (source r2.env first).
Uses AWS Signature V4 with Python stdlib only. No boto3/awscli needed.
Never uses sync, recursive delete, or bucket-wide operations.

Usage:
    source /path/to/r2.env
    python3 scripts/publish-r2.py [file1] [file2] ...
    python3 scripts/publish-r2.py --all
"""

import sys, os, hashlib, hmac, datetime, urllib.request, urllib.error

ALLOWLIST = [
    "pool/main/t/termux-api/termux-api_0.59.1-2_aarch64.deb",
    "dists/stable/main/binary-aarch64/Packages",
    "dists/stable/main/binary-aarch64/Packages.gz",
    "dists/stable/Release",
    "dists/stable/Release.gpg",
    "dists/stable/InRelease",
    "keys/io-vaj-archive.gpg",
    "keys/io-vaj-archive.asc",
]


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(secret, date, region, service):
    kDate = sign(("AWS4" + secret).encode("utf-8"), date)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    return sign(kService, "aws4_request")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def s3_put(bucket, key, endpoint, region, access_key, secret_key, data, content_type):
    service = "s3"
    url = f"{endpoint}/{bucket}/{key}"
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
    signed_headers = ";".join(sorted(k.lower() for k in headers))
    canonical_headers = "".join(
        f"{k.lower()}:{v}\n"
        for k, v in sorted(headers.items(), key=lambda x: x[0].lower())
    )
    canonical_uri = f"/{bucket}/{key}"
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
        resp = urllib.request.urlopen(req, timeout=30)
        return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    bucket = os.environ["R2_BUCKET"]
    endpoint = os.environ["R2_S3_ENDPOINT"]
    region = os.environ["AWS_REGION"]
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]

    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        files = ALLOWLIST
    elif len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        print("Usage: publish-r2.py [file ...] | --all", file=sys.stderr)
        sys.exit(1)

    # Determine repo root from script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    for rel_path in files:
        local_path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(local_path):
            print(f"SKIP (not found): {rel_path}", file=sys.stderr)
            continue

        # Restrict to allowlist
        if files is ALLOWLIST or rel_path in ALLOWLIST:
            pass
        else:
            print(f"SKIP (not in allowlist): {rel_path}", file=sys.stderr)
            continue

        with open(local_path, "rb") as fh:
            data = fh.read()

        # Content-Type heuristic
        if rel_path.endswith(".deb"):
            ct = "application/vnd.debian.binary-package"
        elif rel_path.endswith(".gpg"):
            ct = "application/pgp-keys"
        elif rel_path.endswith(".asc"):
            ct = "text/plain"
        elif rel_path.endswith(".gz"):
            ct = "application/gzip"
        elif rel_path.endswith("Release"):
            ct = "text/plain"
        elif rel_path.endswith("InRelease"):
            ct = "text/plain"
        elif rel_path.endswith("Packages"):
            ct = "text/plain"
        else:
            ct = "application/octet-stream"

        status = s3_put(
            bucket, rel_path, endpoint, region, access_key, secret_key, data, ct
        )
        file_hash = sha256(data)
        print(f"PUT {status}  {rel_path}  sha256={file_hash}")


if __name__ == "__main__":
    main()
