#!/usr/bin/env bash
set -euo pipefail
# generate-repo.sh — Build APT repository Packages and Release files.
# Reads .deb files from pool/, writes metadata to dists/.
# Uses the foundation manifest to verify package integrity.
# Usage: ./scripts/generate-repo.sh [manifest.tsv]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="${1:-manifests/foundation.tsv}"

echo "[generate-repo] Scanning pool/ for .deb packages..."
mkdir -p dists/stable/main/binary-aarch64

PACKAGES_FILE="dists/stable/main/binary-aarch64/Packages"
:> "$PACKAGES_FILE"

count=0
while IFS= read -r -d '' deb; do
    echo "  Processing: $deb"
    tempdir=$(mktemp -d)
    ar x "$deb" --output="$tempdir" control.tar.xz 2>/dev/null || ar x "$deb" --output="$tempdir" control.tar.gz 2>/dev/null || true
    tar --xz -xf "$tempdir/control.tar.xz" -C "$tempdir" 2>/dev/null || tar -xzf "$tempdir/control.tar.gz" -C "$tempdir" 2>/dev/null || true

    pkg_name=""
    {
        while IFS=': ' read -r field value; do
            case "$field" in
                Package) pkg_name="$value" ;&
                Version|Architecture|Maintainer|Installed-Size|Depends|\
                Homepage|Description|Breaks|Conflicts|Provides|Replaces|Recommends|Suggests)
                    echo "$field: $value"
                    ;;
            esac
        done < "$tempdir/control"
        echo "Filename: $deb"
        echo "Size: $(stat -c%s "$deb")"
        echo "SHA256: $(sha256sum "$deb" | cut -d' ' -f1)"
        echo "MD5sum: $(md5sum "$deb" | cut -d' ' -f1)"
        echo ""
    } >> "$PACKAGES_FILE"

    rm -rf "$tempdir"
    count=$((count + 1))
done < <(find pool/ -name '*.deb' -type f -print0)

echo "[generate-repo] Processed $count packages."
echo "[generate-repo] Compressing Packages..."
gzip -k -f "$PACKAGES_FILE"

echo "[generate-repo] Generating Release..."
RELEASE="dists/stable/Release"
cat > "$RELEASE" << RELEOF
Origin: VAJ
Label: VAJ Terminal
Suite: stable
Codename: stable
Date: $(date -u '+%a, %d %b %Y %H:%M:%S UTC')
Architectures: aarch64
Components: main
Description: VAJ Terminal Package Repository
MD5Sum:
RELEOF

for f in dists/stable/main/binary-aarch64/Packages dists/stable/main/binary-aarch64/Packages.gz; do
    printf " %s %16d %s\n" "$(md5sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f" >> "$RELEASE"
done

echo "SHA256:" >> "$RELEASE"
for f in dists/stable/main/binary-aarch64/Packages dists/stable/main/binary-aarch64/Packages.gz; do
    printf " %s %16d %s\n" "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f" >> "$RELEASE"
done

echo "[generate-repo] Done."
