#! /usr/bin/env bash
# Used by readthedocs to get the right version of rust installed. Based on our github action that does the same.
source "$HOME/.cargo/env"
pip install yq tomlq jq
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
TOML_TARGETS=$(tomlq -r '.toolchain.targets | select(. != null) | @csv' "$TOML_FILE")
TOML_COMPONENTS=$(tomlq -r '.toolchain.components | select(. != null) | @csv' "$TOML_FILE")
rustup toolchain install "$TOML_TOOLCHAIN""$TOML_TARGETS""$TOML_COMPONENTS" --profile minimal --no-self-update
rustup default "$TOML_TOOLCHAIN"
rustup override set "$TOML_TOOLCHAIN"
