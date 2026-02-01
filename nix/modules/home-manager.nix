{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.askpass-cache;

  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "config.toml" cfg.settings;
in
{
  options.services.askpass-cache = {
    enable = mkEnableOption "askpass-cache credential caching daemon";

    package = mkOption {
      type = types.package;
      default = pkgs.askpass-cache;
      defaultText = literalExpression "pkgs.askpass-cache";
      description = "The askpass-cache package to use.";
    };

    settings = mkOption {
      type = settingsFormat.type;
      default = { };
      description = ''
        Configuration for askpass-cache.
        See <https://github.com/rschaffar/askpass-cache/blob/main/CONCEPT.md>
        for available options.
      '';
      example = literalExpression ''
        {
          cache = {
            default_ttl = 3600;
            clear_on_lock = true;
            clear_on_suspend = true;
            
            ssh = {
              default_ttl = 1800;
              clear_on_lock = true;
            };
            
            git = {
              default_ttl = 7200;
              clear_on_lock = false;
            };
          };
          
          prompt = {
            timeout = 30;
            default_remember = true;
          };
          
          security = {
            encrypt_cache = true;
          };
        }
      '';
    };

    enableSshAskpass = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to set SSH_ASKPASS and SSH_ASKPASS_REQUIRE environment variables.
        When false, you can manually set SSH_ASKPASS where needed (e.g., on specific services).
      '';
    };

    enableGitAskpass = mkOption {
      type = types.bool;
      default = false;
      description = "Whether to set GIT_ASKPASS environment variable.";
    };

    enableSudoAskpass = mkOption {
      type = types.bool;
      default = false;
      description = "Whether to set SUDO_ASKPASS environment variable.";
    };
  };

  config = mkIf cfg.enable {
    # Install the package
    home.packages = [ cfg.package ];

    # Generate config file
    xdg.configFile."askpass-cache/config.toml" = mkIf (cfg.settings != { }) {
      source = configFile;
    };

    # Set environment variables (each can be enabled independently)
    home.sessionVariables = mkMerge [
      (mkIf cfg.enableSshAskpass {
        SSH_ASKPASS = "${cfg.package}/bin/askpass-client";
        SSH_ASKPASS_REQUIRE = "prefer";
      })
      (mkIf cfg.enableGitAskpass {
        GIT_ASKPASS = "${cfg.package}/bin/askpass-client";
      })
      (mkIf cfg.enableSudoAskpass {
        SUDO_ASKPASS = "${cfg.package}/bin/askpass-client";
      })
    ];

    # Systemd user service
    systemd.user.services.askpass-cached = {
      Unit = {
        Description = "Askpass Cache Daemon";
        Documentation = "https://github.com/rschaffar/askpass-cache";
        After = [ "graphical-session.target" ];
        PartOf = [ "graphical-session.target" ];
      };

      Service = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/askpass-cached";
        Restart = "on-failure";
        RestartSec = 5;

        # Note: The daemon doesn't need display environment variables.
        # The askpass-client handles all UI prompts and inherits display
        # environment from the calling process (SSH, Git, sudo).

        # Security hardening
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        LockPersonality = true;

        # Runtime directory for socket
        RuntimeDirectory = "askpass-cache";
      };

      Install = {
        WantedBy = [ "graphical-session.target" ];
      };
    };
  };
}
