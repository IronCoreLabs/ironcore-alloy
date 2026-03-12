#!/usr/bin/env bash
# Removes generated Java bindings and build artifacts to allow clean
# regeneration when switching between JNA and FFM branches.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GENERATED_DIR="$REPO_ROOT/java/src/main/java/com/ironcorelabs/ironcore_alloy_java"

echo "Cleaning generated bindings from $GENERATED_DIR"
rm -rf "$GENERATED_DIR"
mkdir -p "$GENERATED_DIR"

echo "Cleaning Gradle build artifacts"
rm -rf "$REPO_ROOT/java/build" "$REPO_ROOT/java/.gradle"

echo "Done"
