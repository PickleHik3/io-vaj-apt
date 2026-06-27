#!/usr/bin/env bash
set -euo pipefail
# sign-release.sh — Sign dists/stable/Release with the production GPG key.
# Requires: GNUPGHOME and VAJ_SIGNING_PASSPHRASE_FILE in environment,
#           or set them below.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

GNUPGHOME="${GNUPGHOME:-${HOME}/.config/vaj-apt/gnupg-production}"
PASSPHRASE_FILE="${VAJ_SIGNING_PASSPHRASE_FILE:-${HOME}/.config/vaj-apt/archive-signing.passphrase}"

export GNUPGHOME
PASSPHRASE=$(cat "$PASSPHRASE_FILE")

RELEASE="dists/stable/Release"
INRELEASE="dists/stable/InRelease"
RELEASE_GPG="dists/stable/Release.gpg"

if [ ! -f "$RELEASE" ]; then
    echo "[sign-release] ERROR: $RELEASE not found. Run generate-repo.sh first."
    exit 1
fi

echo "[sign-release] Signing Release -> InRelease (clearsigned)..."
gpg --batch --pinentry-mode loopback --passphrase "$PASSPHRASE" \
    --clearsign -o "$INRELEASE" "$RELEASE"

echo "[sign-release] Signing Release -> Release.gpg (detached)..."
gpg --batch --pinentry-mode loopback --passphrase "$PASSPHRASE" \
    --detach-sign -o "$RELEASE_GPG" "$RELEASE"

echo "[sign-release] Verifying signatures..."
KEYRING="${REPO_ROOT}/keys/io-vaj-archive.gpg"
gpgv --keyring "$KEYRING" "$INRELEASE" 2>&1
gpgv --keyring "$KEYRING" "$RELEASE_GPG" "$RELEASE" 2>&1

echo "[sign-release] Done."
