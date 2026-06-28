"""Tests for the --refresh-metadata-cache-policy subcommand in publish-r2.py.

These tests use mocked S3 responses and an isolated tempdir repo root.  No
network, no credentials, no filesystem pollution.  They prove the new
subcommand:

* only acts on the exact five MUTABLE_METADATA keys,
* refuses to touch /pool/ or any .deb,
* verifies direct-R2 GET bytes equal canonical local bytes before PUT,
* uses the required Cache-Control on every upload,
* performs no upload during --dry-run,
* transforms neither payload bytes nor object keys.
"""

import importlib.util, os, sys, tempfile, unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_PUB_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "publish-r2.py")
_spec = importlib.util.spec_from_file_location("publish_r2", _PUB_PATH)
pub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pub)

SUITE = pub.SUITE
COMPONENT = pub.COMPONENT
ARCHITECTURE = pub.ARCHITECTURE
MUTABLE_METADATA = pub.MUTABLE_METADATA
MUTABLE_CACHE_CONTROL = pub.MUTABLE_CACHE_CONTROL


FAKE_BUCKET = "test-bucket"
FAKE_ENDPOINT = "https://fake.example.com"
FAKE_REGION = "us-east-1"
FAKE_ACCESS_KEY = "AKIDEXAMPLE"
FAKE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def _req_headers(req):
    return {k.lower(): v for k, v in req.header_items()}


class _HeadersDict(dict):
    def get(self, k, default=None):
        return super().get(k.lower(), default)


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body

    def read(self, *a, **kw):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    @property
    def headers(self):
        return _HeadersDict(self._headers)

    def getheader(self, name, default=None):
        return self._headers.get(name.lower(), default)


def _make_fake_urlopen(remote_bytes_map, remote_cache_control_map, captures):
    """Returns a fake urlopen.

    * GET <key>     -> 200 + body from remote_bytes_map
    * PUT <key>     -> 200, no body, captures request
    * HEAD <key>    -> 200 + cache_control from remote_cache_control_map
    """
    def fake(req, *a, **kw):
        method = req.method
        url = req.full_url
        for k in MUTABLE_METADATA:
            if url.endswith("/" + quote(k, safe="/~")):
                if method == "GET":
                    return FakeResponse(200, body=remote_bytes_map[k])
                if method == "PUT":
                    captures.append(req)
                    return FakeResponse(200, body=b"")
                if method == "HEAD":
                    cc = remote_cache_control_map.get(
                        k, MUTABLE_CACHE_CONTROL,
                    )
                    return FakeResponse(200, headers={"cache-control": cc})
        return FakeResponse(404, body=b"")
    return fake


def _write_tree(root, contents):
    for rel, body in contents.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(body)


class TestAssertMetadataKeyEligible(unittest.TestCase):
    def test_each_mutable_key_passes(self):
        for k in MUTABLE_METADATA:
            pub._assert_metadata_key_eligible(k)

    def test_pool_root_rejected(self):
        for k in ["pool/main/a/apt/apt_2.8.1-3_aarch64.deb",
                  "pool/main/z/zsh/zsh_5.9.1-1_aarch64.deb"]:
            with self.assertRaises(SystemExit):
                pub._assert_metadata_key_eligible(k)

    def test_deb_extension_rejected(self):
        with self.assertRaises(SystemExit):
            pub._assert_metadata_key_eligible("dists/stable/main/foo.deb")

    def test_unrelated_dists_key_rejected(self):
        with self.assertRaises(SystemExit):
            pub._assert_metadata_key_eligible("dists/stable/Release.bak")


class TestRefreshMetadataDryRun(unittest.TestCase):
    def setUp(self):
        self.captures = []
        self.local_bytes = {
            k: b"contents-of-" + k.encode() for k in MUTABLE_METADATA
        }
        self.remote_bytes = dict(self.local_bytes)
        self.remote_cc = {k: MUTABLE_CACHE_CONTROL for k in MUTABLE_METADATA}
        self.tmp = tempfile.mkdtemp()
        _write_tree(self.tmp, self.local_bytes)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_prints_exactly_five_keys(self):
        buf_out = []
        from io import StringIO
        fake = _make_fake_urlopen(
            self.remote_bytes, self.remote_cc, self.captures,
        )
        with patch("urllib.request.urlopen", fake):
            with redirect_stdout(StringIO()) as buf:
                results, errors = pub._refresh_metadata_cache_policy(
                    self.tmp, FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY, dry_run=True,
                )
            buf_out.append(buf.getvalue())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 5)
        for r in results:
            self.assertEqual(r["status"], "dry-run")
            self.assertIn(r["path"], MUTABLE_METADATA)
        out = "".join(buf_out)
        for k in MUTABLE_METADATA:
            self.assertIn(k, out, f"dry-run output missing key {k}")
        self.assertIn("DRY-RUN", out)
        self.assertEqual(self.captures, [])
        self.assertEqual(len(MUTABLE_METADATA), 5)


class TestRefreshMetadataRealRun(unittest.TestCase):
    def setUp(self):
        self.captures = []
        self.local_bytes = {
            k: b"contents-of-" + k.encode() for k in MUTABLE_METADATA
        }
        self.remote_bytes = dict(self.local_bytes)
        self.remote_cc = {k: MUTABLE_CACHE_CONTROL for k in MUTABLE_METADATA}
        self.tmp = tempfile.mkdtemp()
        _write_tree(self.tmp, self.local_bytes)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_real_run_verifies_origin_bytes_then_uploads_with_cc(self):
        from io import StringIO
        fake = _make_fake_urlopen(
            self.remote_bytes, self.remote_cc, self.captures,
        )
        with patch("urllib.request.urlopen", fake):
            with redirect_stdout(StringIO()):
                results, errors = pub._refresh_metadata_cache_policy(
                    self.tmp, FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY, dry_run=False,
                )
        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        self.assertEqual(len(results), 5)
        self.assertEqual(len(self.captures), 5)
        for r in results:
            self.assertEqual(r["status"], "uploaded")
            self.assertEqual(r["origin_sha256"], r["local_sha256"])
        for req in self.captures:
            hdrs = _req_headers(req)
            self.assertEqual(
                hdrs.get("cache-control"), MUTABLE_CACHE_CONTROL,
            )
            matched = None
            for k in MUTABLE_METADATA:
                if req.full_url.endswith("/" + quote(k, safe="/~")):
                    matched = k
                    break
            self.assertIsNotNone(matched)
            self.assertEqual(req.data, self.local_bytes[matched])

    def test_object_key_and_bytes_unchanged(self):
        from io import StringIO
        fake = _make_fake_urlopen(
            self.remote_bytes, self.remote_cc, self.captures,
        )
        with patch("urllib.request.urlopen", fake):
            with redirect_stdout(StringIO()):
                pub._refresh_metadata_cache_policy(
                    self.tmp, FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY, dry_run=False,
                )
        for req in self.captures:
            matched = None
            for k in MUTABLE_METADATA:
                if req.full_url.endswith("/" + quote(k, safe="/~")):
                    matched = k
                    break
            self.assertIsNotNone(matched)
            self.assertIn(matched, MUTABLE_METADATA)
            self.assertEqual(req.data, self.local_bytes[matched])
            self.assertNotIn("/pool/", req.full_url)
            self.assertFalse(req.full_url.endswith(".deb"))

    def test_origin_byte_mismatch_blocks_upload(self):
        from io import StringIO
        first_processed = sorted(MUTABLE_METADATA, key=pub._upload_order_key)[0]
        self.remote_bytes[first_processed] = b"DRIFTED-ORIGIN-BYTES"
        fake = _make_fake_urlopen(
            self.remote_bytes, self.remote_cc, self.captures,
        )
        with patch("urllib.request.urlopen", fake):
            with redirect_stdout(StringIO()):
                results, errors = pub._refresh_metadata_cache_policy(
                    self.tmp, FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY, dry_run=False,
                )
        self.assertTrue(
            len(errors) >= 1,
            f"expected at least one error, got {errors}",
        )
        self.assertTrue(
            any("byte mismatch" in e for e in errors),
            f"expected byte-mismatch error, got {errors}",
        )
        self.assertEqual(
            len(self.captures), 0,
            "no upload should occur when origin bytes differ from canonical",
        )

    def test_post_upload_head_must_show_required_cache_control(self):
        from io import StringIO
        self.remote_cc = {
            k: "public, max-age=3600" for k in MUTABLE_METADATA
        }
        self.remote_bytes = dict(self.local_bytes)
        fake = _make_fake_urlopen(
            self.remote_bytes, self.remote_cc, self.captures,
        )
        with patch("urllib.request.urlopen", fake):
            with redirect_stdout(StringIO()):
                results, errors = pub._refresh_metadata_cache_policy(
                    self.tmp, FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY, dry_run=False,
                )
        self.assertTrue(len(errors) >= 1)
        self.assertTrue(
            any("Cache-Control mismatch" in e for e in errors),
            f"expected cache-control error, got {errors}",
        )

    def test_only_mutation_path_is_metadata_keys(self):
        from io import StringIO
        fake = _make_fake_urlopen(
            self.remote_bytes, self.remote_cc, self.captures,
        )
        with patch("urllib.request.urlopen", fake):
            with redirect_stdout(StringIO()):
                results, errors = pub._refresh_metadata_cache_policy(
                    self.tmp, FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY, dry_run=True,
                )
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 5)
        for r in results:
            self.assertIn(r["path"], MUTABLE_METADATA)
            self.assertFalse(r["path"].startswith("pool/"))
            self.assertFalse(r["path"].endswith(".deb"))


class TestPoolNeverEligible(unittest.TestCase):
    def test_pool_paths_not_in_mutable_metadata(self):
        pool_samples = [
            "pool/main/a/apt/apt_2.8.1-3_aarch64.deb",
            "pool/main/z/zsh/zsh_5.9.1-1_aarch64.deb",
            "pool/main/m/m4/m4_1.4.19-4_aarch64.deb",
        ]
        for p in pool_samples:
            self.assertNotIn(p, MUTABLE_METADATA)


class TestMainDispatch(unittest.TestCase):
    """Tests for the main() dispatch when --refresh-metadata-cache-policy
    is invoked via the script's CLI surface.  The real-run path is exercised
    directly in TestRefreshMetadataRealRun; this class only asserts that the
    CLI dispatches into the helper."""

    def test_dry_run_does_not_invoke_urlopen(self):
        local_bytes = {
            k: b"contents-of-" + k.encode() for k in MUTABLE_METADATA
        }
        tmp = tempfile.mkdtemp()
        try:
            _write_tree(tmp, local_bytes)
            env_keys = [
                "R2_BUCKET", "R2_S3_ENDPOINT", "AWS_REGION",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            ]
            env_vals = [
                FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
            ]
            saved = {k: os.environ.get(k) for k in env_keys}
            for k, v in zip(env_keys, env_vals):
                os.environ[k] = v

            old_argv = sys.argv
            sys.argv = [
                "publish-r2.py",
                "--refresh-metadata-cache-policy",
                "--dry-run",
            ]
            try:
                def deny(req, *a, **kw):
                    raise AssertionError(
                        "no network call expected in --dry-run"
                    )
                from io import StringIO
                with patch("urllib.request.urlopen", deny):
                    with redirect_stdout(StringIO()) as buf:
                        rc = pub.main()
                self.assertEqual(rc, 0)
                out = buf.getvalue()
                for k in MUTABLE_METADATA:
                    self.assertIn(k, out)
                self.assertIn("DRY-RUN", out)
            finally:
                sys.argv = old_argv
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
