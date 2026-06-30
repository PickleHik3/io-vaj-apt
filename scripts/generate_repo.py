#!/usr/bin/env python3
"""Generate APT metadata from the manifest-selected package set only.

This generator is intentionally fail-closed:

* it reads package selections only from the active manifest;
* it validates each selected object before writing metadata;
* it never scans the full pool, so retained historical artifacts cannot
  reappear in Packages/Release unless the manifest explicitly selects them.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
import subprocess
import tarfile
from typing import Iterable


SUITE = "stable"
COMPONENT = "main"
ARCHITECTURE = "binary-aarch64"
PROVENANCE_FILENAME = "vaj-metadata-provenance.json"
PROVENANCE_SCHEMA_VERSION = 1
GENERATOR_IDENTITY = "vaj.manifest-authoritative-generator.v2"
ALLOWED_CONTROL_FIELDS = {
    "Package",
    "Version",
    "Architecture",
    "Maintainer",
    "Installed-Size",
    "Depends",
    "Homepage",
    "Description",
    "Breaks",
    "Conflicts",
    "Provides",
    "Replaces",
    "Recommends",
    "Suggests",
}
DEFAULT_AUTHORITY_PATH = Path("manifests") / "historical-serialization-authority.json"


class ManifestAuthorityError(RuntimeError):
    """Raised when manifest-authoritative generation cannot proceed safely."""


@dataclass(frozen=True)
class ManifestEntry:
    name: str
    version: str
    arch: str
    sha256: str
    object_path: str
    size: int

    @property
    def expected_filename(self) -> str:
        return f"{self.name}_{self.version}_{self.arch}.deb"

    def authority_key(self) -> tuple[str, str, str, str, str, int]:
        """Full immutable identity tuple used to look up authority entries."""
        return (self.name, self.version, self.arch, self.sha256, self.object_path, self.size)


def _normalized_manifest_path(path: str) -> str:
    normalized = os.path.normpath(path)
    if normalized.startswith("../") or normalized == ".." or os.path.isabs(path):
        raise ManifestAuthorityError(f"manifest object path must stay inside repo: {path}")
    return normalized


def load_manifest(manifest_path: Path) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    seen_names: dict[str, ManifestEntry] = {}
    seen_paths: dict[str, ManifestEntry] = {}

    with manifest_path.open("r", encoding="utf-8") as handle:
        for lineno, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 6:
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: expected 6 tab-separated columns, got {len(parts)}"
                )
            name, version, arch, sha256, object_path, size_text = parts
            if not size_text.isdigit():
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: size must be a positive integer byte count: {size_text!r}"
                )
            size = int(size_text)
            if size <= 0:
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: size must be greater than zero: {size}"
                )

            entry = ManifestEntry(name, version, arch, sha256, object_path, size)
            object_path = _normalized_manifest_path(entry.object_path)
            if object_path != entry.object_path:
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: manifest object path must be normalized: {entry.object_path}"
                )
            if not object_path.startswith("pool/"):
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: manifest object path must stay under pool/: {entry.object_path}"
                )
            if Path(object_path).name != entry.expected_filename:
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: manifest object filename mismatch: "
                    f"expected {entry.expected_filename}, got {Path(object_path).name}"
                )
            if entry.name in seen_names:
                prior = seen_names[entry.name]
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: duplicate package selection for {entry.name}: "
                    f"{prior.version} at {prior.object_path} and {entry.version} at {entry.object_path}"
                )
            if object_path in seen_paths:
                prior = seen_paths[object_path]
                raise ManifestAuthorityError(
                    f"{manifest_path}:{lineno}: duplicate object path selection for {object_path}: "
                    f"{prior.name} and {entry.name}"
                )
            seen_names[entry.name] = entry
            seen_paths[object_path] = entry
            entries.append(entry)

    return entries


def _hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_digest(manifest_path: Path) -> str:
    return _hash_file(manifest_path, "sha256")


def _extract_control_text(deb_path: Path) -> str:
    result = subprocess.run(
        ["dpkg-deb", "--ctrl-tarfile", str(deb_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:*") as archive:
        for candidate in ("./control", "control"):
            try:
                member = archive.getmember(candidate)
            except KeyError:
                continue
            control_file = archive.extractfile(member)
            if control_file is None:
                break
            return control_file.read().decode("utf-8")
    raise ManifestAuthorityError(f"{deb_path}: control file not found in package metadata")


def _parse_selected_control_blocks(control_text: str) -> tuple[list[tuple[str, str]], dict[str, str]]:
    selected_blocks: list[tuple[str, str]] = []
    identity: dict[str, str] = {}

    current_field: str | None = None
    current_lines: list[str] = []

    def flush_current() -> None:
        nonlocal current_field, current_lines
        if current_field is None:
            current_lines = []
            return
        block = "\n".join(current_lines)
        if current_field in ALLOWED_CONTROL_FIELDS:
            selected_blocks.append((current_field, block))
        if current_field in {"Package", "Version", "Architecture"}:
            identity[current_field] = current_lines[0].split(": ", 1)[1]
        current_field = None
        current_lines = []

    for raw_line in control_text.splitlines():
        if raw_line.startswith((" ", "\t")) and current_field is not None:
            current_lines.append(raw_line)
            continue
        flush_current()
        if ": " not in raw_line:
            continue
        current_field, _value = raw_line.split(": ", 1)
        current_lines = [raw_line]
    flush_current()
    return selected_blocks, identity


def load_authority(authority_path: Path) -> dict[tuple[str, str, str, str, str, int], dict]:
    """Load historical serialization authority from JSON.

    Returns a dict keyed by full identity tuple (name, version, arch, sha256,
    object_path, size) mapping to authority records containing sequence,
    selected_control_field_order, and expected_stanza_sha256.

    Fail-closed: missing/corrupt/duplicate identity/malformed records raise
    ManifestAuthorityError.
    """
    if not authority_path.is_file():
        raise ManifestAuthorityError(
            f"historical serialization authority not found: {authority_path}"
        )

    try:
        raw = json.loads(authority_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ManifestAuthorityError(
            f"failed to parse authority file {authority_path}: {exc}"
        ) from exc

    if not isinstance(raw, dict) or "entries" not in raw:
        raise ManifestAuthorityError(
            f"authority file {authority_path}: missing top-level 'entries' list"
        )

    source = raw.get("source_packages", {})
    if not isinstance(source, dict) or not all(
        k in source for k in ("path", "sha256", "size", "stanza_count", "schema_version")
    ):
        raise ManifestAuthorityError(
            f"authority file {authority_path}: malformed source_packages metadata"
        )

    authority: dict[tuple[str, str, str, str, str, int], dict] = {}
    for i, entry in enumerate(raw["entries"]):
        if not isinstance(entry, dict):
            raise ManifestAuthorityError(
                f"authority file {authority_path}: entry {i} is not a dict"
            )
        ident = entry.get("identity")
        if not isinstance(ident, dict):
            raise ManifestAuthorityError(
                f"authority file {authority_path}: entry {i} missing or invalid 'identity'"
            )
        for key in ("name", "version", "arch", "sha256", "object_path", "size"):
            if key not in ident:
                raise ManifestAuthorityError(
                    f"authority file {authority_path}: entry {i} identity missing '{key}'"
                )
        size = ident["size"]
        if not isinstance(size, int) or size <= 0:
            raise ManifestAuthorityError(
                f"authority file {authority_path}: entry {i} identity 'size' must be positive int, got {size!r}"
            )
        key = (
            str(ident["name"]),
            str(ident["version"]),
            str(ident["arch"]),
            str(ident["sha256"]),
            str(ident["object_path"]),
            size,
        )
        if key in authority:
            raise ManifestAuthorityError(
                f"authority file {authority_path}: duplicate identity at entry {i}: "
                f"{ident['name']} {ident['version']} {ident['arch']}"
            )

        field_order = entry.get("selected_control_field_order")
        if not isinstance(field_order, list) or not field_order:
            raise ManifestAuthorityError(
                f"authority file {authority_path}: entry {i} missing or empty selected_control_field_order"
            )
        for field in field_order:
            if field not in ALLOWED_CONTROL_FIELDS:
                raise ManifestAuthorityError(
                    f"authority file {authority_path}: entry {i} field {field!r} not in ALLOWED_CONTROL_FIELDS"
                )

        expected_sha = entry.get("expected_stanza_sha256")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            raise ManifestAuthorityError(
                f"authority file {authority_path}: entry {i} invalid expected_stanza_sha256"
            )

        seq = entry.get("sequence")
        if not isinstance(seq, int) or seq < 0:
            raise ManifestAuthorityError(
                f"authority file {authority_path}: entry {i} invalid sequence"
            )

        authority[key] = {
            "sequence": seq,
            "field_order": tuple(field_order),
            "expected_stanza_sha256": expected_sha,
        }

    return authority


def _authority_for_entry(
    authority: dict[tuple[str, str, str, str, str, int], dict],
    entry: ManifestEntry,
) -> dict | None:
    """Look up an authority record for the given manifest entry by full identity."""
    return authority.get(entry.authority_key())


def _render_selected_control_blocks(
    selected_blocks: list[tuple[str, str]],
    *,
    field_order: Iterable[str] | None = None,
) -> list[str]:
    if field_order is None:
        return [block for _field, block in selected_blocks]

    ordered_by_field = {field: block for field, block in selected_blocks}
    ordered_lines: list[str] = []
    for field in field_order:
        ordered_lines.append(ordered_by_field[field])
    return ordered_lines


def _validate_authority_fields(
    entry: ManifestEntry,
    authority_rec: dict,
    selected_blocks: list[tuple[str, str]],
) -> None:
    """Validate that selected_blocks match authority expectations (missing/unexpected/duplicates)."""
    seen_fields = [field for field, _block in selected_blocks]
    if len(seen_fields) != len(set(seen_fields)):
        raise ManifestAuthorityError(
            f"{entry.object_path}: historical serialization authority requires unique selected control fields"
        )
    actual_fields = set(seen_fields)
    expected_fields = set(authority_rec["field_order"])
    missing_fields = [field for field in authority_rec["field_order"] if field not in actual_fields]
    unexpected_fields = [field for field in seen_fields if field not in expected_fields]
    if missing_fields:
        raise ManifestAuthorityError(
            f"{entry.object_path}: historical serialization authority missing selected control fields: "
            + ", ".join(missing_fields)
        )
    if unexpected_fields:
        raise ManifestAuthorityError(
            f"{entry.object_path}: historical serialization authority encountered unexpected selected control fields: "
            + ", ".join(unexpected_fields)
        )


def _verify_stanza_sha256(
    entry: ManifestEntry,
    authority_rec: dict,
    stanza_text: str,
) -> None:
    """Verify the full rendered stanza SHA-256 matches the authority record."""
    stanza_sha256 = hashlib.sha256(stanza_text.encode("utf-8")).hexdigest()
    if stanza_sha256 != authority_rec["expected_stanza_sha256"]:
        raise ManifestAuthorityError(
            f"{entry.object_path}: historical serialization authority stanza SHA-256 mismatch: "
            f"expected {authority_rec['expected_stanza_sha256']}, got {stanza_sha256}"
        )


def build_package_stanza(
    repo_root: Path,
    entry: ManifestEntry,
    *,
    authority: dict[tuple[str, str, str, str, str, int], dict] | None = None,
) -> str:
    deb_path = repo_root / entry.object_path
    if not deb_path.is_file():
        raise ManifestAuthorityError(f"selected object missing: {entry.object_path}")

    actual_size = deb_path.stat().st_size
    if actual_size != entry.size:
        raise ManifestAuthorityError(
            f"{entry.object_path}: size mismatch: manifest={entry.size}, actual={actual_size}"
        )

    sha256 = _hash_file(deb_path, "sha256")
    if sha256 != entry.sha256:
        raise ManifestAuthorityError(
            f"{entry.object_path}: SHA-256 mismatch: manifest={entry.sha256}, actual={sha256}"
        )

    control_text = _extract_control_text(deb_path)
    selected_blocks, identity = _parse_selected_control_blocks(control_text)

    for field, expected in (
        ("Package", entry.name),
        ("Version", entry.version),
        ("Architecture", entry.arch),
    ):
        actual = identity.get(field)
        if actual != expected:
            raise ManifestAuthorityError(
                f"{entry.object_path}: control {field} mismatch: expected={expected}, actual={actual}"
            )

    md5sum = _hash_file(deb_path, "md5")
    authority_rec = _authority_for_entry(authority, entry) if authority else None
    if authority_rec is None:
        selected_lines = _render_selected_control_blocks(selected_blocks)
    else:
        _validate_authority_fields(entry, authority_rec, selected_blocks)
        selected_lines = _render_selected_control_blocks(
            selected_blocks,
            field_order=authority_rec["field_order"],
        )
    stanza_lines = [
        *selected_lines,
        f"Filename: {entry.object_path}",
        f"Size: {entry.size}",
        f"SHA256: {sha256}",
        f"MD5sum: {md5sum}",
        "",
    ]
    stanza_text = "\n".join(stanza_lines) + "\n"
    if authority_rec is not None:
        _verify_stanza_sha256(entry, authority_rec, stanza_text)
    return stanza_text


def _release_text(packages_path: Path, packages_gz_path: Path, release_time: datetime) -> str:
    lines = [
        "Origin: VAJ",
        "Label: VAJ Terminal",
        "Suite: stable",
        "Codename: stable",
        f"Date: {release_time.strftime('%a, %d %b %Y %H:%M:%S UTC')}",
        "Architectures: aarch64",
        "Components: main",
        "Description: VAJ Terminal Package Repository",
        "MD5Sum:",
    ]
    for path in (packages_path, packages_gz_path):
        release_path = path.relative_to(path.parents[2])
        lines.append(
            f" {_hash_file(path, 'md5')} {path.stat().st_size:16d} {release_path.as_posix()}"
        )
    lines.append("SHA256:")
    for path in (packages_path, packages_gz_path):
        release_path = path.relative_to(path.parents[2])
        lines.append(
            f" {_hash_file(path, 'sha256')} {path.stat().st_size:16d} {release_path.as_posix()}"
        )
    return "\n".join(lines) + "\n"


def _canonical_gzip_bytes(payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0, filename="") as handle:
        handle.write(payload)
    return buffer.getvalue()


def generator_identity(repo_root: Path) -> dict[str, str | int]:
    script_path = Path(__file__).resolve()
    try:
        script_rel_path = script_path.relative_to(repo_root).as_posix()
    except ValueError:
        script_rel_path = script_path.as_posix()
    return {
        "identity": GENERATOR_IDENTITY,
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "script_path": script_rel_path,
        "script_sha256": _hash_file(script_path, "sha256"),
    }


def _packages_artifact_record(root: Path, path: Path) -> dict[str, str | int]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _hash_file(path, "sha256"),
        "size": path.stat().st_size,
    }


def build_provenance_record(
    manifest_path: Path,
    repo_root: Path,
    output_root: Path,
    entries: list[ManifestEntry],
    packages_path: Path,
    packages_gz_path: Path,
    release_path: Path,
    release_time: datetime,
) -> dict[str, object]:
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "generator": generator_identity(repo_root),
        "manifest": {
            "path": manifest_path.relative_to(repo_root).as_posix(),
            "sha256": manifest_digest(manifest_path),
            "selected_package_count": len(entries),
        },
        "selected_packages": [
            {
                "name": entry.name,
                "version": entry.version,
                "arch": entry.arch,
                "sha256": entry.sha256,
                "object_path": entry.object_path,
                "size": entry.size,
            }
            for entry in entries
        ],
        "artifacts": {
            "Packages": _packages_artifact_record(output_root, packages_path),
            "Packages.gz": _packages_artifact_record(output_root, packages_gz_path),
            "Release": _packages_artifact_record(output_root, release_path),
        },
        "release_generation": {
            "release_time_utc": release_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "release_generated_by_shared_generator": True,
            "inrelease_generated": False,
            "release_gpg_generated": False,
        },
    }


def write_provenance_record(output_root: Path, provenance: dict[str, object]) -> Path:
    provenance_path = output_root / "dists" / SUITE / PROVENANCE_FILENAME
    provenance_path.write_text(
        json.dumps(provenance, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return provenance_path


def _parse_release_time(text: str) -> datetime:
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ManifestAuthorityError(f"invalid release timestamp: {text!r}") from exc
    return parsed.replace(tzinfo=UTC)


def _ordered_manifest_entries(
    entries: list[ManifestEntry],
    authority: dict[tuple[str, str, str, str, str, int], dict],
) -> list[ManifestEntry]:
    """Order entries: authority-matched in authority sequence order, unmatched appended in manifest order."""
    matched: list[tuple[int, ManifestEntry]] = []
    unmatched: list[ManifestEntry] = []
    seen_keys: set[tuple[str, str, str, str, str, int]] = set()
    for entry in entries:
        key = entry.authority_key()
        if key in seen_keys:
            continue
        seen_keys.add(key)
        rec = authority.get(key)
        if rec is not None:
            matched.append((rec["sequence"], entry))
        else:
            unmatched.append(entry)

    matched.sort(key=lambda pair: pair[0])
    return [entry for _seq, entry in matched] + unmatched


def generate_repository(
    manifest_path: Path,
    repo_root: Path,
    output_root: Path,
    *,
    release_time: datetime | None = None,
    authority_path: Path | None = None,
) -> dict[str, object]:
    if authority_path is None:
        authority_path = repo_root / DEFAULT_AUTHORITY_PATH
    authority = load_authority(authority_path)
    manifest_entries = load_manifest(manifest_path)
    entries = _ordered_manifest_entries(manifest_entries, authority)
    stanzas = [build_package_stanza(repo_root, entry, authority=authority) for entry in entries]
    release_time = release_time or datetime.now(UTC)

    dists_root = output_root / "dists" / SUITE
    packages_dir = dists_root / COMPONENT / ARCHITECTURE
    packages_dir.mkdir(parents=True, exist_ok=True)

    packages_path = packages_dir / "Packages"
    packages_gz_path = packages_dir / "Packages.gz"
    release_path = dists_root / "Release"

    packages_content = "".join(stanzas)
    packages_path.write_text(packages_content, encoding="utf-8")
    packages_bytes = packages_content.encode("utf-8")
    packages_gz_path.write_bytes(_canonical_gzip_bytes(packages_bytes))
    release_path.write_text(
        _release_text(packages_path, packages_gz_path, release_time),
        encoding="utf-8",
    )
    provenance = build_provenance_record(
        manifest_path,
        repo_root,
        output_root,
        manifest_entries,
        packages_path,
        packages_gz_path,
        release_path,
        release_time,
    )
    provenance_path = write_provenance_record(output_root, provenance)

    return {
        "package_count": len(entries),
        "packages_path": packages_path,
        "packages_gz_path": packages_gz_path,
        "release_path": release_path,
        "provenance_path": provenance_path,
        "manifest_sha256": provenance["manifest"]["sha256"],
    }


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    parser = argparse.ArgumentParser(
        description="Generate VAJ APT metadata from the manifest-selected package set."
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        default=str(repo_root / "manifests" / "foundation.tsv"),
        help="path to the active manifest TSV",
    )
    parser.add_argument(
        "--repo-root",
        default=str(repo_root),
        help="repository root containing the selected pool/ objects",
    )
    parser.add_argument(
        "--output-root",
        default=str(repo_root),
        help="output workspace root that receives dists/",
    )
    parser.add_argument(
        "--release-timestamp",
        help="UTC timestamp for deterministic Release generation (YYYY-MM-DDTHH:MM:SSZ)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    repo_root = Path(args.repo_root).resolve()
    output_root = Path(args.output_root).resolve()

    release_time = _parse_release_time(args.release_timestamp) if args.release_timestamp else None
    result = generate_repository(
        manifest_path,
        repo_root,
        output_root,
        release_time=release_time,
    )
    print(
        f"[generate-repo] Generated {result['package_count']} package stanzas "
        f"from manifest {manifest_path}"
    )
    print(f"[generate-repo] Wrote {result['packages_path']}")
    print(f"[generate-repo] Wrote {result['packages_gz_path']}")
    print(f"[generate-repo] Wrote {result['release_path']}")
    print(f"[generate-repo] Wrote {result['provenance_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
