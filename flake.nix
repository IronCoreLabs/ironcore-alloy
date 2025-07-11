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
              # used when running python tests
              python310
              # used when building python distributions
              hatch
              # used when building java distributions
              openjdk21
              (callPackage gradle-packages.gradle_8 {
                java = openjdk21;
              })
              (pkgs.google-cloud-sdk.withExtraComponents [ pkgs.google-cloud-sdk.components.gke-gcloud-auth-plugin ])
            ];
          LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
          JAVA_HOME = if pkgs.stdenv.isDarwin then "${pkgs.openjdk21}" else "${pkgs.openjdk21}/lib/openjdk";
          RUST_TEST_NOCAPTURE = 1;
        };

      });
}
