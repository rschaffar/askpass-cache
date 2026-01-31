{
  lib,
  stdenv,
  craneLib,
  pkg-config,
  wrapGAppsHook4,
  gtk4,
  libadwaita,
  dbus,
  openssl,
  zlib,
}:

let
  # Filter source to only include Rust files
  src = lib.cleanSourceWith {
    src = craneLib.path ./..;
    filter =
      path: type: (craneLib.filterCargoSources path type) || (builtins.match ".*\\.md$" path != null);
  };

  # Common args for all crane builds
  commonArgs = {
    inherit src;

    pname = "secure-askpass";
    version = "0.1.0";

    strictDeps = true;

    buildInputs = [
      gtk4
      libadwaita
      dbus
      openssl
      zlib
    ];

    nativeBuildInputs = [
      pkg-config
      wrapGAppsHook4 # Automatically handles GTK wrapping
    ];

    # Use default Cargo features (libadwaita)
    cargoExtraArgs = "--workspace";
  };

  # Build dependencies only (for caching)
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # Build the actual package
  secure-askpass = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;

      # Skip tests in build (require display server)
      doCheck = false;

      meta = with lib; {
        description = "Secure credential caching daemon for askpass operations";
        longDescription = ''
          A secure, session-only credential caching daemon for Linux with proper
          memory protection (mlock, auto-zeroing). Provides caching for
          SSH_ASKPASS, GIT_ASKPASS, and SUDO_ASKPASS with per-cache-type
          configuration and security hardening.
        '';
        homepage = "https://github.com/rschaffar/secure-askpass";
        license = with licenses; [
          mit
          asl20
        ];
        maintainers = [ ];
        mainProgram = "secure-askpass-daemon";
        platforms = platforms.linux;
      };
    }
  );
in
secure-askpass
