{
  description = "Vector search POC";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
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
              pkgs.openssl
              # used when generating kotlin bindings in core
              pkgs.ktlint
              # used when running kotlin tests
              pkgs.kotlin
              # used when generating python bindings in core
              pkgs.yapf
              pkgs.curl
              # used when running python tests
              pkgs.python310
              # used when building python distributions
              pkgs.hatch
              (pkgs.google-cloud-sdk.withExtraComponents [ pkgs.google-cloud-sdk.components.gke-gcloud-auth-plugin ])
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
              [ pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
          LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
        };

      });
}
