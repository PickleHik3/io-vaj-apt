"""Tests for APT metadata cache-control policy in publish-r2.py.

These tests use mocked S3 clients.  No network, no credentials.
"""

import importlib.util, io, os, sys, unittest
from unittest.mock import patch, MagicMock
from urllib.request import Request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import publish-r2.py via importlib (it has a hyphen, so standard import
# won't work).
_PUB_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "publish-r2.py")
_spec = importlib.util.spec_from_file_location("publish_r2", _PUB_PATH)
pub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pub)

SUITE = pub.SUITE
COMPONENT = pub.COMPONENT
ARCHITECTURE = pub.ARCHITECTURE
MUTABLE_METADATA = pub.MUTABLE_METADATA
MUTABLE_CACHE_CONTROL = pub.MUTABLE_CACHE_CONTROL
_upload_order_key = pub._upload_order_key
verify_cache_policy = pub.verify_cache_policy
s3_put = pub.s3_put


FAKE_BUCKET = "test-bucket"
FAKE_ENDPOINT = "https://fake.example.com"
FAKE_REGION = "us-east-1"
FAKE_ACCESS_KEY = "AKIDEXAMPLE"
FAKE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def _req_headers(req):
    """Extract headers from a urllib.request.Request as a case-insensitive dict."""
    return {k.lower(): v for k, v in req.header_items()}


class FakeResponse:
    """Simulate an http.client.HTTPResponse / urllib response."""

    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        # Store headers with lowercase keys, mimicking email.message.Message
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


class _HeadersDict(dict):
    """A dict subclass that supports case-insensitive .get() like email headers."""
    def get(self, k, default=None):
        return super().get(k.lower(), default)


class TestCachePolicyIsolation(unittest.TestCase):
    """Verify that s3_put adds Cache-Control only for mutable metadata."""

    def setUp(self):
        self.captured_requests = []

    def _fake_urlopen(self, req, *a, **kw):
        self.captured_requests.append(req)
        body = req.data or b""
        return FakeResponse(200, body=body)

    def test_mutable_objects_get_cache_control(self):
        """Every mutable metadata object receives the exact Cache-Control header."""
        for path in sorted(MUTABLE_METADATA):
            with patch("urllib.request.urlopen", self._fake_urlopen):
                self.captured_requests.clear()
                s3_put(
                    FAKE_BUCKET, path, FAKE_ENDPOINT, FAKE_REGION,
                    FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
                    b"payload", "text/plain",
                    cache_control=MUTABLE_CACHE_CONTROL,
                )
                self.assertEqual(len(self.captured_requests), 1)
                req = self.captured_requests[0]
                hdrs = _req_headers(req)
                cc = hdrs.get("cache-control")
                self.assertEqual(
                    cc, MUTABLE_CACHE_CONTROL,
                    f"{path}: expected Cache-Control={MUTABLE_CACHE_CONTROL!r}, got {cc!r}",
                )

    def test_pool_deb_object_no_cache_control(self):
        """A pool/.deb object does NOT receive the mutable-metadata cache policy."""
        pool_path = "pool/main/h/hello/hello_2.12-1_aarch64.deb"
        with patch("urllib.request.urlopen", self._fake_urlopen):
            self.captured_requests.clear()
            s3_put(
                FAKE_BUCKET, pool_path, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
                b"deb-content", "application/vnd.debian.binary-package",
                cache_control=None,
            )
            self.assertEqual(len(self.captured_requests), 1)
            req = self.captured_requests[0]
            hdrs = _req_headers(req)
            self.assertNotIn("cache-control", hdrs,
                             f"pool path {pool_path} should NOT have Cache-Control")

    def test_pool_deb_object_explicit_cc_allowed(self):
        """When explicit cache_control is passed for pool objects, it's forwarded."""
        pool_path = "pool/main/h/hello/hello_2.12-1_aarch64.deb"
        my_cc = "public, max-age=31536000"
        with patch("urllib.request.urlopen", self._fake_urlopen):
            self.captured_requests.clear()
            s3_put(
                FAKE_BUCKET, pool_path, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
                b"deb-content", "application/vnd.debian.binary-package",
                cache_control=my_cc,
            )
            self.assertEqual(len(self.captured_requests), 1)
            req = self.captured_requests[0]
            hdrs = _req_headers(req)
            self.assertEqual(hdrs.get("cache-control"), my_cc)

    def test_no_key_or_payload_alteration(self):
        """Object key (URL path) and data are unchanged by cache-control logic."""
        path = "dists/stable/Release"
        payload = b"some-release-content"
        with patch("urllib.request.urlopen", self._fake_urlopen):
            self.captured_requests.clear()
            status = s3_put(
                FAKE_BUCKET, path, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
                payload, "text/plain",
                cache_control=MUTABLE_CACHE_CONTROL,
            )
            req = self.captured_requests[0]
            from urllib.parse import quote
            self.assertIn(quote(path, safe="/~"), req.full_url)
            self.assertEqual(req.data, payload)
            self.assertEqual(status, 200)


class TestUploadOrder(unittest.TestCase):
    """Verify the _upload_order_key produces the required order."""

    def test_upload_order_key(self):
        items = list(MUTABLE_METADATA) + [
            "pool/main/a/apt/apt_2.8.1-3_aarch64.deb",
            "pool/main/z/zstd/zstd_1.5.7-1_aarch64.deb",
            "keys/io-vaj-archive.gpg",
        ]
        expected = [
            "keys/io-vaj-archive.gpg",
            "pool/main/a/apt/apt_2.8.1-3_aarch64.deb",
            "pool/main/z/zstd/zstd_1.5.7-1_aarch64.deb",
            f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages",
            f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages.gz",
            f"dists/{SUITE}/Release",
            f"dists/{SUITE}/Release.gpg",
            f"dists/{SUITE}/InRelease",
        ]
        sorted_items = sorted(items, key=_upload_order_key)
        self.assertEqual(sorted_items, expected)

    def test_main_all_ordering(self):
        """Simulate --all and capture upload order for spot-check."""
        captured = []

        def tracking_s3_put(bucket, key, endpoint, region, ak, sk, data, ct, cache_control=None):
            captured.append(key)
            return 200

        orig_s3_put = pub.s3_put
        orig_validate = pub.validate_metadata_provenance
        pub.s3_put = tracking_s3_put
        pub.validate_metadata_provenance = lambda *args, **kwargs: {
            "manifest_sha256": "0" * 64,
            "package_count": 0,
            "provenance_path": "unused",
            "packages_path": "unused",
        }

        env_keys = ["R2_BUCKET", "R2_S3_ENDPOINT", "AWS_REGION",
                     "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
        env_vals = [FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                     FAKE_ACCESS_KEY, FAKE_SECRET_KEY]

        saved = {}
        for k, v in zip(env_keys, env_vals):
            saved[k] = os.environ.get(k)
            os.environ[k] = v

        test_args = ["publish-r2.py", "--all"]

        try:
            old_argv = sys.argv
            sys.argv = test_args
            try:
                pub.main()
            except SystemExit:
                pass
            finally:
                sys.argv = old_argv

            metadata_indexes = [
                (i, name) for i, name in enumerate(captured)
                if name in MUTABLE_METADATA
            ]
            pool_indexes = [
                (i, name) for i, name in enumerate(captured)
                if not name.startswith("dists/")
            ]
            for pi, pn in pool_indexes:
                for mi, mn in metadata_indexes:
                    self.assertLess(
                        pi, mi,
                        f"pool object {pn} at index {pi} should precede metadata "
                        f"{mn} at {mi}",
                    )
            meta_order = [
                f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages",
                f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages.gz",
                f"dists/{SUITE}/Release",
                f"dists/{SUITE}/Release.gpg",
                f"dists/{SUITE}/InRelease",
            ]
            present = [p for p in meta_order if p in captured]
            for i in range(len(present) - 1):
                self.assertLess(
                    captured.index(present[i]),
                    captured.index(present[i + 1]),
                    f"{present[i]} should precede {present[i + 1]}",
                )
        finally:
            pub.s3_put = orig_s3_put
            pub.validate_metadata_provenance = orig_validate
            for k in env_keys:
                v = saved.get(k)
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class TestVerifyCachePolicy(unittest.TestCase):
    """Test the --verify HEAD verification path."""

    def test_rejects_absent_cache_control(self):
        """When Cache-Control is absent, verify_cache_policy returns an error."""
        def fake_urlopen(req, *a, **kw):
            return FakeResponse(200, headers={})

        with patch("urllib.request.urlopen", fake_urlopen):
            errors = verify_cache_policy(
                FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
            )
            self.assertTrue(len(errors) >= 1)
            first = errors[0]
            self.assertIn("expected Cache-Control", first)
            self.assertIn("max-age=0, must-revalidate", first)

    def test_rejects_wrong_cache_control(self):
        """When Cache-Control has a wrong value, verify returns an error."""
        def fake_urlopen(req, *a, **kw):
            return FakeResponse(200, headers={
                "cache-control": "public, max-age=3600",
            })

        with patch("urllib.request.urlopen", fake_urlopen):
            errors = verify_cache_policy(
                FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
            )
            self.assertTrue(len(errors) >= 1)
            for e in errors:
                self.assertIn("max-age=0, must-revalidate", e)

    def test_passes_with_correct_cache_control(self):
        """When Cache-Control is correct on all objects, verify returns empty."""
        def fake_urlopen(req, *a, **kw):
            return FakeResponse(200, headers={
                "cache-control": MUTABLE_CACHE_CONTROL,
            })

        with patch("urllib.request.urlopen", fake_urlopen):
            errors = verify_cache_policy(
                FAKE_BUCKET, FAKE_ENDPOINT, FAKE_REGION,
                FAKE_ACCESS_KEY, FAKE_SECRET_KEY,
            )
            self.assertEqual(errors, [])


class TestMutableMetadataSet(unittest.TestCase):
    """Consistency checks on the MUTABLE_METADATA constant."""

    def test_exactly_five_objects(self):
        self.assertEqual(len(MUTABLE_METADATA), 5)

    def test_all_are_dists_paths(self):
        for p in MUTABLE_METADATA:
            self.assertTrue(p.startswith("dists/"), p)

    def test_no_pool_objects(self):
        for p in MUTABLE_METADATA:
            self.assertFalse(p.startswith("pool/"), p)

    def test_derived_from_config(self):
        expected = {
            f"dists/{SUITE}/InRelease",
            f"dists/{SUITE}/Release",
            f"dists/{SUITE}/Release.gpg",
            f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages",
            f"dists/{SUITE}/{COMPONENT}/{ARCHITECTURE}/Packages.gz",
        }
        self.assertEqual(MUTABLE_METADATA, frozenset(expected))


if __name__ == "__main__":
    unittest.main()
