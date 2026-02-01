{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.askpass-cache;
in
{
  options.services.askpass-cache = {
    enable = mkEnableOption "askpass-cache credential caching daemon (system-wide package installation)";

    package = mkOption {
      type = types.package;
      default = pkgs.askpass-cache;
      defaultText = literalExpression "pkgs.askpass-cache";
      description = "The askpass-cache package to use.";
    };
  };

  config = mkIf cfg.enable {
    # Install system-wide
    environment.systemPackages = [ cfg.package ];

    # Note: Actual daemon runs per-user via home-manager
    warnings = [
      ''
        services.askpass-cache is enabled at the NixOS level, which only
        installs the package system-wide. The daemon should run as a user
        service for security. Use the home-manager module instead:

        In your home-manager configuration:
          services.askpass-cache.enable = true;

        See: https://github.com/rschaffar/askpass-cache/blob/main/README.md
      ''
    ];
  };
}
