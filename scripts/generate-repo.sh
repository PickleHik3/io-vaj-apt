#!/usr/bin/env bash
set -euo pipefail
# generate-repo.sh — Build APT repository Packages and Release files.
# Metadata generation is manifest-authoritative: only manifest-selected .deb
# objects are read, and unselected historical pool artifacts stay invisible.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

exec python3 "$SCRIPT_DIR/generate_repo.py" "$@"
