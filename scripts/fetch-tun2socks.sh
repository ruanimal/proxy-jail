#!/usr/bin/env bash
# scripts/fetch-tun2socks.sh
#
# Downloads xjasonlyu/tun2socks for the given architecture into the specified
# output directory.  Called by `cargo deb` via the "before-build" hook.
#
# Usage:
#   scripts/fetch-tun2socks.sh [ARCH] [OUTPUT_DIR]
#
# Defaults:
#   ARCH       = current system arch (amd64 / arm64)
#   OUTPUT_DIR = target/fetch-tun2socks
#
# The binary is placed at <OUTPUT_DIR>/tun2socks.
# If it already exists, the download is skipped.

set -euo pipefail

VERSION="2.7.0"
RELEASE_URL="https://github.com/xjasonlyu/tun2socks/releases/download/v${VERSION}"

ARCH="${1:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"
OUTPUT_DIR="${2:-target/fetch-tun2socks}"

mkdir -p "$OUTPUT_DIR"
TARGET="$OUTPUT_DIR/tun2socks"

if [ -f "$TARGET" ]; then
    echo "tun2socks already exists at $TARGET, skipping download."
    exit 0
fi

case "$ARCH" in
    amd64|x86_64)
        ZIPFILE="tun2socks-linux-amd64.zip"
        INNER="tun2socks-linux-amd64"       # binary name inside the zip
        ;;
    arm64|aarch64)
        ZIPFILE="tun2socks-linux-arm64.zip"
        INNER="tun2socks-linux-arm64"
        ;;
    *)
        echo "Error: unsupported architecture '$ARCH'. Supported: amd64, arm64." >&2
        exit 1
        ;;
esac

URL="${RELEASE_URL}/${ZIPFILE}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Fetching tun2socks v${VERSION} (${ARCH}) from $URL ..."
curl -fsSL "$URL" -o "$TMP_DIR/$ZIPFILE"
unzip -o "$TMP_DIR/$ZIPFILE" -d "$TMP_DIR"
mv "$TMP_DIR/$INNER" "$TARGET"
chmod +x "$TARGET"

echo "Installed tun2socks -> $TARGET"
