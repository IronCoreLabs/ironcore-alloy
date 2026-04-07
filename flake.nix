{
  description = "Vector search POC";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rusttoolchain =
          pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        # nix develop
        devShell = pkgs.mkShell {
          buildInputs = with pkgs;
            [
              rusttoolchain
              pkg-config
              openssl
              # used when generating kotlin bindings in core
              ktlint
              # used when running kotlin tests
              kotlin
              # used when generating python bindings in core
              yapf
              curl
              # used when building python distributions and running tests
              hatch
              # used when building java distributions
              openjdk25
              (gradle-packages.gradle_8.override {
                java = openjdk25;
              })
              (pkgs.google-cloud-sdk.withExtraComponents [ pkgs.google-cloud-sdk.components.gke-gcloud-auth-plugin ])
            ];
          # none of this is needed outside the nix environment, where hatch will be allowed to manage its own python
          # versions. Nix specifically locks that down, so if this isn't done tests will only find versions that happen
          # to be installed by the above `buildInputs` as dependencies.
          shellHook = ''
                        # install pythons we need for our pyproject matrix
                        versions=$(python3 -c "
            import tomllib
            with open('python/ironcore-alloy/pyproject.toml', 'rb') as f:
                d = tomllib.load(f)
            for m in d['tool']['hatch']['envs']['hatch-test']['matrix']:
                for v in m['python']:
                    print(v[0] + '.' + v[1:])
                        ")
                        hatch python install $versions 2>/dev/null
                        # add the installed pythons to the path
                        for dir in "$HOME/Library/Application Support/hatch/pythons"/*/python/bin "$HOME/.local/share/hatch/pythons"/*/python/bin; do
                          [ -d "$dir" ] && export PATH="$dir:$PATH"
                        done
          '';
          LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
          JAVA_HOME = if pkgs.stdenv.isDarwin then "${pkgs.openjdk25}" else "${pkgs.openjdk25}/lib/openjdk";
          RUST_TEST_NOCAPTURE = 1;
        };

      });
}
