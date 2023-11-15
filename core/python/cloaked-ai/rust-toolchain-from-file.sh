#! /usr/bin/env bash
# Used by readthedocs to get the right version of rust installed. Based on our github action that does the same.
# install and source rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
source "$HOME/.cargo/env"
# download a jq binary and add it to the path, install other dependencies
echo "$PATH"
curl -o ./jq https://github.com/jqlang/jq/releases/download/jq-1.7/jq-linux-amd64 && chmod +x ./jq && cp ./jq /usr/local/bin/jq 
pip install yq tomlq
# pull the rust-toolchain.toml info
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
# install what we found
rustup toolchain install "$TOML_TOOLCHAIN""$TOML_TARGETS""$TOML_COMPONENTS" --profile minimal --no-self-update
rustup default "$TOML_TOOLCHAIN"
rustup override set "$TOML_TOOLCHAIN"
