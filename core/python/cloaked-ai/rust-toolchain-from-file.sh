#! /usr/bin/env bash
# Used by readthedocs to get the right version of rust installed. Based on our github action that does the same.
pip install yq tomlq
for F in rust-toolchain.toml rust-toolchain ; do
  if [ -f "$F" ] ; then
    TOML_FILE="$F"
    break
  fi
done
if [ -z "$TOML_FILE" ]; then
  echo "rust-toolchain{.toml} not found, expecting explicit inputs"
  exit 0
fi
TOML_TOOLCHAIN=$(tomlq -r '.toolchain.channel | select(. != null)' "$TOML_FILE")
if [ -n "$TOML_TOOLCHAIN" ]; then
  echo "toml-toolchain=$TOML_TOOLCHAIN" >> "$GITHUB_OUTPUT"
fi
TOML_TARGETS=$(tomlq -r '.toolchain.targets | select(. != null) | @csv' "$TOML_FILE")
if [ -n "$TOML_TARGETS" ]; then
  echo "toml-targets=$TOML_TARGETS" >> "$GITHUB_OUTPUT"
fi
TOML_COMPONENTS=$(tomlq -r '.toolchain.components | select(. != null) | @csv' "$TOML_FILE")
if [ -n "$TOML_COMPONENTS" ]; then
  echo "toml-components=$TOML_COMPONENTS" >> "$GITHUB_OUTPUT"
fi

