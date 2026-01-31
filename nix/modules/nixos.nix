{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.secure-askpass;
in
{
  options.services.secure-askpass = {
    enable = mkEnableOption "secure-askpass credential caching daemon (system-wide package installation)";

    package = mkOption {
      type = types.package;
      default = pkgs.secure-askpass;
      defaultText = literalExpression "pkgs.secure-askpass";
      description = "The secure-askpass package to use.";
    };
  };

  config = mkIf cfg.enable {
    # Install system-wide
    environment.systemPackages = [ cfg.package ];

    # Note: Actual daemon runs per-user via home-manager
    warnings = [
      ''
        services.secure-askpass is enabled at the NixOS level, which only
        installs the package system-wide. The daemon should run as a user
        service for security. Use the home-manager module instead:

        In your home-manager configuration:
          services.secure-askpass.enable = true;

        See: https://github.com/rschaffar/secure-askpass/blob/main/README.md
      ''
    ];
  };
}
