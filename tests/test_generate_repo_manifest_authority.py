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


def _raw_stanzas_by_package(packages_path: Path) -> dict[str, str]:
    stanzas: dict[str, str] = {}
    text = packages_path.read_text(encoding="utf-8")
    for stanza in text.strip().split("\n\n"):
        if not stanza.strip():
            continue
        stanza_text = stanza + "\n\n"
        name = next(
            line.split(": ", 1)[1]
            for line in stanza.splitlines()
            if line.startswith("Package: ")
        )
        stanzas[name] = stanza_text
    return stanzas


def _field_order(stanza_text: str) -> list[str]:
    order: list[str] = []
    for line in stanza_text.splitlines():
        if not line or line.startswith((" ", "\t")) or ": " not in line:
            continue
        field, _value = line.split(": ", 1)
        order.append(field)
    return order


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

    def test_control_parser_preserves_continuation_lines(self):
        control_text = (
            "Package: continuationpkg\n"
            "Version: 1.0\n"
            "Description: summary line\n"
            " continuation one\n"
            " continuation two\n"
            "Architecture: aarch64\n"
        )

        selected_blocks, identity = gen._parse_selected_control_blocks(control_text)

        self.assertEqual(identity["Package"], "continuationpkg")
        self.assertEqual(identity["Version"], "1.0")
        self.assertEqual(identity["Architecture"], "aarch64")
        self.assertEqual(
            dict(selected_blocks)["Description"],
            "Description: summary line\n continuation one\n continuation two",
        )

    def test_historical_ordering_is_package_generic(self):
        selected_blocks_a = [
            ("Package", "Package: alpha"),
            ("Architecture", "Architecture: aarch64"),
            ("Installed-Size", "Installed-Size: 1"),
            ("Maintainer", "Maintainer: example"),
            ("Version", "Version: 1.0"),
            ("Homepage", "Homepage: https://example.invalid/a"),
            ("Breaks", "Breaks: old-alpha"),
            ("Depends", "Depends: libc++"),
            ("Replaces", "Replaces: old-alpha"),
            ("Description", "Description: alpha package"),
        ]
        selected_blocks_b = [
            ("Package", "Package: beta"),
            ("Architecture", "Architecture: aarch64"),
            ("Installed-Size", "Installed-Size: 2"),
            ("Maintainer", "Maintainer: example"),
            ("Version", "Version: 2.0"),
            ("Homepage", "Homepage: https://example.invalid/b"),
            ("Breaks", "Breaks: old-beta"),
            ("Depends", "Depends: libc++, zlib"),
            ("Replaces", "Replaces: old-beta"),
            ("Description", "Description: beta package"),
        ]
        order = (
            "Package",
            "Version",
            "Architecture",
            "Maintainer",
            "Installed-Size",
            "Depends",
            "Homepage",
            "Description",
            "Breaks",
            "Replaces",
        )

        rendered_a = gen._render_selected_control_blocks(selected_blocks_a, field_order=order)
        rendered_b = gen._render_selected_control_blocks(selected_blocks_b, field_order=order)

        self.assertEqual(_field_order("\n".join(rendered_a) + "\n"), list(order))
        self.assertEqual(_field_order("\n".join(rendered_b) + "\n"), list(order))

    def test_historical_compatibility_rejects_altered_field_order(self):
        profile = gen.HISTORICAL_SERIALIZATION_PROFILES_BY_TRIPLET[("binutils", "2.46.0-3", "aarch64")]
        entry = gen.ManifestEntry(
            name=profile.name,
            version=profile.version,
            arch=profile.arch,
            sha256=profile.sha256,
            object_path="pool/main/b/binutils/binutils_2.46.0-3_aarch64.deb",
            size=2438504,
        )
        altered_stanza = (
            "Package: binutils\n"
            "Architecture: aarch64\n"
            "Installed-Size: 19736\n"
            "Maintainer: @termux\n"
            "Version: 2.46.0-3\n"
            "Homepage: https://www.gnu.org/software/binutils/\n"
            "Breaks: binutils (<< 2.46), binutils-bin, binutils-libs, binutils-dev\n"
            "Depends: libc++, zlib, zstd\n"
            "Replaces: binutils (<< 2.46), binutils-bin, binutils-libs, binutils-dev\n"
            "Description: A GNU collection of binary utilities\n"
            "Filename: pool/main/b/binutils/binutils_2.46.0-3_aarch64.deb\n"
            "Size: 2438504\n"
            "SHA256: 679bd221c7f6e63d0c7e1e926a897b6087982a44f8d4c662b69f4613b3d4d29e\n"
            "MD5sum: dcb99d9c68a37af276f11d31d40add12\n\n"
        )

        with self.assertRaisesRegex(gen.ManifestAuthorityError, "historical serialization compatibility mismatch"):
            gen._enforce_historical_stanza_compatibility(entry, profile, altered_stanza)


class ManifestAuthorityActiveManifestTests(unittest.TestCase):
    def test_active_manifest_regeneration_matches_current_public_packages_bytes(self):
        repo_root = Path(__file__).resolve().parents[1]
        manifest = repo_root / "manifests" / "foundation.tsv"
        current_packages_path = repo_root / "dists" / "stable" / "main" / "binary-aarch64" / "Packages"

        with tempfile.TemporaryDirectory() as output_str:
            output_root = Path(output_str)
            result = gen.generate_repository(manifest, repo_root, output_root)
            regenerated_packages_path = result["packages_path"]

            current_bytes = current_packages_path.read_bytes()
            regenerated_bytes = regenerated_packages_path.read_bytes()
            current_stanzas = _raw_stanzas_by_package(current_packages_path)
            regenerated_stanzas = _raw_stanzas_by_package(regenerated_packages_path)
            regenerated_records = _parse_packages(regenerated_packages_path)

        self.assertEqual(len(regenerated_stanzas), 289)
        self.assertEqual(regenerated_bytes, current_bytes)
        self.assertEqual(set(regenerated_stanzas), set(current_stanzas))
        versions = [record["Version"] for record in regenerated_records if record["Package"] == "openexr"]
        self.assertEqual(versions, ["3.4.4-1"])
        self.assertNotIn("openexr_3.4.4_aarch64.deb", regenerated_bytes.decode("utf-8"))

    def test_six_historical_wave_g_stanzas_regenerate_byte_identical(self):
        repo_root = Path(__file__).resolve().parents[1]
        manifest = repo_root / "manifests" / "foundation.tsv"
        current_packages_path = repo_root / "dists" / "stable" / "main" / "binary-aarch64" / "Packages"
        expected_stanzas = _raw_stanzas_by_package(current_packages_path)
        historical_names = {"binutils", "groff", "dbus", "glib", "libgraphite", "libpixman"}
        expected_profiles = {
            profile.name: profile
            for profile in gen.HISTORICAL_SERIALIZATION_PROFILES
        }

        with tempfile.TemporaryDirectory() as output_str:
            output_root = Path(output_str)
            result = gen.generate_repository(manifest, repo_root, output_root)
            regenerated_stanzas = _raw_stanzas_by_package(result["packages_path"])

        for name in historical_names:
            with self.subTest(name=name):
                self.assertEqual(regenerated_stanzas[name], expected_stanzas[name])
                self.assertEqual(
                    hashlib.sha256(regenerated_stanzas[name].encode("utf-8")).hexdigest(),
                    expected_profiles[name].expected_stanza_sha256,
                )

    def test_existing_non_wave_g_stanzas_retain_byte_identity(self):
        repo_root = Path(__file__).resolve().parents[1]
        manifest = repo_root / "manifests" / "foundation.tsv"
        current_packages_path = repo_root / "dists" / "stable" / "main" / "binary-aarch64" / "Packages"
        expected_stanzas = _raw_stanzas_by_package(current_packages_path)
        sampled_names = {"apt", "io-vaj-keyring", "openexr", "openssh-sftp-server"}

        with tempfile.TemporaryDirectory() as output_str:
            output_root = Path(output_str)
            result = gen.generate_repository(manifest, repo_root, output_root)
            regenerated_stanzas = _raw_stanzas_by_package(result["packages_path"])

        for name in sampled_names:
            with self.subTest(name=name):
                self.assertEqual(regenerated_stanzas[name], expected_stanzas[name])

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
