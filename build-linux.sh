#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-dnsx"

echo "================================================"
echo "  lancer-dnsx Build"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD/$BIN"
echo ""

echo "[1/2] Building release binary..."
cargo build --release

echo "[2/2] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "================================================"
