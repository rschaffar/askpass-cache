{
  mkShell,
  pkg-config,
  gtk4,
  libadwaita,
  dbus,
  openssl,
  zlib,
  glib,
  gobject-introspection,
  wrapGAppsHook4,
  # Rust toolchain
  cargo,
  rustc,
  # Rust tooling
  rust-analyzer,
  clippy,
  rustfmt,
  # Cargo extensions
  cargo-watch,
  cargo-edit,
  cargo-audit,
  bacon,
  # Testing tools
  xvfb-run,
}:

mkShell {
  buildInputs = [
    # GTK4/libadwaita + dependencies
    gtk4
    libadwaita
    dbus
    openssl
    zlib
    glib
    gobject-introspection
  ];

  nativeBuildInputs = [
    pkg-config
    wrapGAppsHook4
  ];

  packages = [
    # Rust toolchain
    cargo
    rustc

    # Rust tooling
    rust-analyzer
    clippy
    rustfmt

    # Cargo extensions
    cargo-watch
    cargo-edit
    cargo-audit
    bacon

    # Testing tools
    xvfb-run
  ];

  # Environment variables for GTK development
  shellHook = ''
    echo "🔒 secure-askpass development environment"
    echo ""
    echo "Available commands:"
    echo "  cargo build              - Build the project"
    echo "  cargo test               - Run tests"
    echo "  cargo watch -x check     - Auto-check on file changes"
    echo "  bacon                    - Background code checker"
    echo "  cargo audit              - Check for security vulnerabilities"
    echo ""
    echo "GTK4 testing:"
    echo "  xvfb-run cargo test      - Run GTK tests in virtual X server"
    echo ""
    echo "Nix commands:"
    echo "  nix build                - Build with Nix"
    echo "  nix fmt                  - Format Nix files"
    echo ""
  '';
}
