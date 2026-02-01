{
  description = "Secure credential caching daemon for SSH_ASKPASS, GIT_ASKPASS, and SUDO_ASKPASS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    crane.url = "github:ipetkov/crane";

    flake-parts.url = "github:hercules-ci/flake-parts";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          craneLib = inputs.crane.mkLib pkgs;
        in
        {
          # Package outputs
          packages = {
            default = self'.packages.askpass-cache;
            askpass-cache = pkgs.callPackage ./nix/package.nix {
              inherit craneLib;
            };
          };

          # Development shell
          devShells.default = pkgs.callPackage ./nix/devshell.nix { };

          # Formatter for `nix fmt`
          formatter = pkgs.nixpkgs-fmt;
        };

      flake = {
        # NixOS module
        nixosModules.default = import ./nix/modules/nixos.nix;
        nixosModules.askpass-cache = import ./nix/modules/nixos.nix;

        # home-manager module
        homeManagerModules.default = import ./nix/modules/home-manager.nix;
        homeManagerModules.askpass-cache = import ./nix/modules/home-manager.nix;

        # Overlay for users who want to integrate into their pkgs
        overlays.default = final: prev: {
          askpass-cache = final.callPackage ./nix/package.nix {
            craneLib = inputs.crane.mkLib final;
          };
        };
      };
    };
}
