"""Regression tests for manifest-authoritative APT metadata generation."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


_GEN_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "generate_repo.py")
_SPEC = importlib.util.spec_from_file_location("generate_repo", _GEN_PATH)
gen = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gen
_SPEC.loader.exec_module(gen)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_packages(packages_path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for stanza in packages_path.read_text(encoding="utf-8").strip().split("\n\n"):
        if not stanza.strip():
            continue
        record: dict[str, str] = {}
        for line in stanza.splitlines():
            if ": " not in line:
                continue
            field, value = line.split(": ", 1)
            record[field] = value
        records.append(record)
    return records


def _write_manifest(manifest_path: Path, rows: list[tuple[str, ...]]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as handle:
        handle.write("# test manifest\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")


def _build_deb(repo_root: Path, name: str, version: str, arch: str = "aarch64") -> tuple[str, str, int]:
    pool_rel = Path("pool/main") / name[0] / name / f"{name}_{version}_{arch}.deb"
    deb_path = repo_root / pool_rel
    deb_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as pkg_dir_str:
        pkg_dir = Path(pkg_dir_str)
        debian_dir = pkg_dir / "DEBIAN"
        debian_dir.mkdir(parents=True)
        control = "\n".join(
            [
                f"Package: {name}",
                f"Version: {version}",
                "Section: base",
                "Priority: optional",
                f"Architecture: {arch}",
                "Maintainer: VAJ Test <test@example.invalid>",
                f"Description: synthetic package {name}",
                "",
            ]
        )
        (debian_dir / "control").write_text(control, encoding="utf-8")
        data_file = pkg_dir / "usr" / "share" / name / "payload.txt"
        data_file.parent.mkdir(parents=True, exist_ok=True)
        data_file.write_text(f"{name} {version}\n", encoding="utf-8")
        subprocess.run(
            ["dpkg-deb", "--build", str(pkg_dir), str(deb_path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    return pool_rel.as_posix(), _sha256(deb_path), deb_path.stat().st_size


def _rename_deb(repo_root: Path, old_rel: str, new_rel: str) -> tuple[str, str, int]:
    old_path = repo_root / old_rel
    new_path = repo_root / new_rel
    new_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.rename(new_path)
    return new_rel, _sha256(new_path), new_path.stat().st_size


class ManifestAuthoritySyntheticPoolTests(unittest.TestCase):
    def test_superseded_openexr_is_excluded(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            old_rel, old_sha, _ = _build_deb(repo_root, "openexr", "3.4.4")
            new_rel, new_sha, _ = _build_deb(repo_root, "openexr", "3.4.4-1")
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("openexr", "3.4.4-1", "aarch64", new_sha, new_rel, str((repo_root / new_rel).stat().st_size))],
            )

            result = gen.generate_repository(manifest, repo_root, output_root)
            records = _parse_packages(result["packages_path"])

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["Package"], "openexr")
            self.assertEqual(records[0]["Version"], "3.4.4-1")
            self.assertEqual(records[0]["Filename"], new_rel)
            self.assertNotIn(old_rel, result["packages_path"].read_text(encoding="utf-8"))

    def test_unreferenced_historical_object_is_excluded(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            kept_rel, kept_sha, _ = _build_deb(repo_root, "hello", "2.0")
            stale_rel, _stale_sha, _ = _build_deb(repo_root, "stalepkg", "0.1")
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("hello", "2.0", "aarch64", kept_sha, kept_rel, str((repo_root / kept_rel).stat().st_size))],
            )

            result = gen.generate_repository(manifest, repo_root, output_root)
            payload = result["packages_path"].read_text(encoding="utf-8")

            self.assertIn(kept_rel, payload)
            self.assertNotIn(stale_rel, payload)

    def test_missing_selected_object_fails_before_metadata_generation(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [(
                    "missingpkg",
                    "1.0",
                    "aarch64",
                    "0" * 64,
                    "pool/main/m/missingpkg/missingpkg_1.0_aarch64.deb",
                    "1234",
                )],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "selected object missing"):
                gen.generate_repository(manifest, repo_root, output_root)
            self.assertFalse((output_root / "dists").exists())

    def test_sha256_mismatch_fails_before_metadata_generation(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            rel_path, sha256, _ = _build_deb(repo_root, "mismatchpkg", "1.0")
            manifest = repo_root / "manifests" / "foundation.tsv"
            wrong_sha = ("0" if sha256[0] != "0" else "1") + sha256[1:]
            _write_manifest(
                manifest,
                [("mismatchpkg", "1.0", "aarch64", wrong_sha, rel_path, str((repo_root / rel_path).stat().st_size))],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "SHA-256 mismatch"):
                gen.generate_repository(manifest, repo_root, output_root)
            self.assertFalse((output_root / "dists").exists())

    def test_control_identity_mismatch_fails_before_metadata_generation(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            actual_rel, _, _ = _build_deb(repo_root, "actualpkg", "1.0")
            rel_path, sha256, _ = _rename_deb(
                repo_root,
                actual_rel,
                "pool/main/w/wrongpkg/wrongpkg_1.0_aarch64.deb",
            )
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("wrongpkg", "1.0", "aarch64", sha256, rel_path, str((repo_root / rel_path).stat().st_size))],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "control Package mismatch"):
                gen.generate_repository(manifest, repo_root, output_root)
            self.assertFalse((output_root / "dists").exists())

    def test_architecture_mismatch_fails_before_metadata_generation(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            actual_rel, _, _ = _build_deb(repo_root, "archpkg", "1.0", arch="all")
            rel_path, sha256, _ = _rename_deb(
                repo_root,
                actual_rel,
                "pool/main/a/archpkg/archpkg_1.0_aarch64.deb",
            )
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("archpkg", "1.0", "aarch64", sha256, rel_path, str((repo_root / rel_path).stat().st_size))],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "control Architecture mismatch"):
                gen.generate_repository(manifest, repo_root, output_root)
            self.assertFalse((output_root / "dists").exists())

    def test_duplicate_package_selection_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            rel_a, sha_a, _ = _build_deb(repo_root, "duppkg", "1.0")
            rel_b, sha_b, _ = _build_deb(repo_root, "duppkg", "1.1")
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [
                    ("duppkg", "1.0", "aarch64", sha_a, rel_a, str((repo_root / rel_a).stat().st_size)),
                    ("duppkg", "1.1", "aarch64", sha_b, rel_b, str((repo_root / rel_b).stat().st_size)),
                ],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "duplicate package selection"):
                gen.generate_repository(manifest, repo_root, output_root)
            self.assertFalse((output_root / "dists").exists())

    def test_size_mismatch_fails_before_metadata_generation(self):
        with tempfile.TemporaryDirectory() as repo_str, tempfile.TemporaryDirectory() as output_str:
            repo_root = Path(repo_str)
            output_root = Path(output_str)
            rel_path, sha256, size = _build_deb(repo_root, "sizepkg", "1.0")
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("sizepkg", "1.0", "aarch64", sha256, rel_path, str(size + 1))],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "size mismatch"):
                gen.generate_repository(manifest, repo_root, output_root)
            self.assertFalse((output_root / "dists").exists())

    def test_missing_size_authority_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo_str:
            repo_root = Path(repo_str)
            rel_path, sha256, _size = _build_deb(repo_root, "nosizepkg", "1.0")
            manifest = repo_root / "manifests" / "foundation.tsv"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(
                "# test manifest\n"
                f"nosizepkg\t1.0\taarch64\t{sha256}\t{rel_path}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "expected 6 tab-separated columns"):
                gen.load_manifest(manifest)

    def test_malformed_size_authority_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo_str:
            repo_root = Path(repo_str)
            rel_path, sha256, _size = _build_deb(repo_root, "badsizepkg", "1.0")
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("badsizepkg", "1.0", "aarch64", sha256, rel_path, "NaN")],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "size must be a positive integer byte count"):
                gen.load_manifest(manifest)

    def test_zero_size_authority_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo_str:
            repo_root = Path(repo_str)
            rel_path, sha256, _size = _build_deb(repo_root, "zeropkg", "1.0")
            manifest = repo_root / "manifests" / "foundation.tsv"
            _write_manifest(
                manifest,
                [("zeropkg", "1.0", "aarch64", sha256, rel_path, "0")],
            )

            with self.assertRaisesRegex(gen.ManifestAuthorityError, "size must be greater than zero"):
                gen.load_manifest(manifest)


class ManifestAuthorityActiveManifestTests(unittest.TestCase):
    def test_active_manifest_matches_generated_package_set(self):
        repo_root = Path(__file__).resolve().parents[1]
        manifest = repo_root / "manifests" / "foundation.tsv"
        entries = gen.load_manifest(manifest)
        expected_by_name = {entry.name: entry for entry in entries}

        with tempfile.TemporaryDirectory() as output_str:
            output_root = Path(output_str)
            result = gen.generate_repository(manifest, repo_root, output_root)
            records = _parse_packages(result["packages_path"])
            payload = result["packages_path"].read_text(encoding="utf-8")

        self.assertEqual(len(entries), 289)
        self.assertEqual(len(records), 289)

        actual_by_name = {record["Package"]: record for record in records}
        self.assertEqual(set(actual_by_name), set(expected_by_name))

        for name, entry in expected_by_name.items():
            record = actual_by_name[name]
            self.assertEqual(record["Version"], entry.version)
            self.assertEqual(record["Architecture"], entry.arch)
            self.assertEqual(record["Filename"], entry.object_path)
            self.assertEqual(int(record["Size"]), entry.size)

        versions = [record["Version"] for record in records if record["Package"] == "openexr"]
        self.assertEqual(versions, ["3.4.4-1"])
        self.assertNotIn("openexr_3.4.4_aarch64.deb", payload)


if __name__ == "__main__":
    unittest.main()
