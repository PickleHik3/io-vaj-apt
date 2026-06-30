"""Tests for publisher-side shared-generator provenance enforcement."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


_GEN_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "generate_repo.py")
_GEN_SPEC = importlib.util.spec_from_file_location("generate_repo", _GEN_PATH)
gen = importlib.util.module_from_spec(_GEN_SPEC)
sys.modules[_GEN_SPEC.name] = gen
_GEN_SPEC.loader.exec_module(gen)

_PUB_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "publish-r2.py")
_PUB_SPEC = importlib.util.spec_from_file_location("publish_r2", _PUB_PATH)
pub = importlib.util.module_from_spec(_PUB_SPEC)
sys.modules[_PUB_SPEC.name] = pub
_PUB_SPEC.loader.exec_module(pub)

from tests.test_generate_repo_manifest_authority import _build_authority, _build_deb, _write_manifest


class PublisherProvenanceSyntheticTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                "R2_BUCKET": "test-bucket",
                "R2_S3_ENDPOINT": "https://example.invalid",
                "AWS_REGION": "us-east-1",
                "AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "EXAMPLESECRETKEY",
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def _make_valid_repo(self):
        repo_dir = tempfile.TemporaryDirectory()
        metadata_dir = tempfile.TemporaryDirectory()
        repo_root = Path(repo_dir.name)
        metadata_root = Path(metadata_dir.name)
        rel_path, sha256, size = _build_deb(repo_root, "validpkg", "1.0")
        manifest = repo_root / "manifests" / "foundation.tsv"
        _write_manifest(
            manifest,
            [("validpkg", "1.0", "aarch64", sha256, rel_path, str(size))],
        )
        # Build authority before calling generate_repository (which requires it)
        _build_authority(repo_root, manifest)
        gen.generate_repository(manifest, repo_root, metadata_root)
        return repo_dir, metadata_dir, repo_root, metadata_root, manifest

    def test_publish_request_without_shared_generator_provenance_is_rejected(self):
        repo_dir, metadata_dir, repo_root, metadata_root, manifest = self._make_valid_repo()
        try:
            os.remove(metadata_root / pub.PROVENANCE_REL_PATH)
            with patch.object(pub, "s3_put", side_effect=AssertionError("upload should not occur")):
                old_argv = sys.argv
                sys.argv = [
                    "publish-r2.py",
                    "--all",
                    "--repo-root",
                    str(repo_root),
                    "--metadata-root",
                    str(metadata_root),
                    "--manifest",
                    str(manifest),
                ]
                try:
                    with self.assertRaisesRegex(RuntimeError, "shared-generator provenance missing"):
                        pub.main()
                finally:
                    sys.argv = old_argv
        finally:
            repo_dir.cleanup()
            metadata_dir.cleanup()

    def test_stale_provenance_from_prior_manifest_is_rejected(self):
        repo_dir, metadata_dir, repo_root, metadata_root, manifest = self._make_valid_repo()
        try:
            rel_path, sha256, size = _build_deb(repo_root, "validpkg", "1.1")
            _write_manifest(
                manifest,
                [("validpkg", "1.1", "aarch64", sha256, rel_path, str(size))],
            )
            with self.assertRaisesRegex(RuntimeError, "provenance manifest digest mismatch"):
                pub.validate_metadata_provenance(str(repo_root), str(manifest), str(metadata_root))
        finally:
            repo_dir.cleanup()
            metadata_dir.cleanup()

    def test_provenance_rejects_packages_digest_mismatch(self):
        repo_dir, metadata_dir, repo_root, metadata_root, manifest = self._make_valid_repo()
        try:
            for rel_path in (
                Path("dists/stable/main/binary-aarch64/Packages"),
                Path("dists/stable/main/binary-aarch64/Packages.gz"),
            ):
                with self.subTest(rel_path=rel_path.as_posix()):
                    target = metadata_root / rel_path
                    original = target.read_bytes()
                    target.write_bytes(original + b"\n# drift\n")
                    try:
                        with self.assertRaisesRegex(RuntimeError, "provenance (size|digest) mismatch"):
                            pub.validate_metadata_provenance(str(repo_root), str(manifest), str(metadata_root))
                    finally:
                        target.write_bytes(original)
        finally:
            repo_dir.cleanup()
            metadata_dir.cleanup()


class PublisherProvenanceActiveManifestTests(unittest.TestCase):
    def test_valid_disposable_289_package_generation_passes_publisher_validation(self):
        repo_root = Path(__file__).resolve().parents[1]
        manifest = repo_root / "manifests" / "foundation.tsv"
        current_packages = repo_root / "dists" / "stable" / "main" / "binary-aarch64" / "Packages"
        with tempfile.TemporaryDirectory() as output_str:
            output_root = Path(output_str)
            generated = gen.generate_repository(manifest, repo_root, output_root)
            result = pub.validate_metadata_provenance(str(repo_root), str(manifest), str(output_root))
            generated_bytes = generated["packages_path"].read_bytes()
        self.assertEqual(result["package_count"], 289)
        self.assertEqual(generated_bytes, current_packages.read_bytes())
