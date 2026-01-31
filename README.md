# secure-askpass

A secure credential caching daemon for SSH_ASKPASS, GIT_ASKPASS, and SUDO_ASKPASS with proper memory protection (mlock, auto-zeroing).

**Status:** Infrastructure complete, Phase 1 implementation in progress - see [CONCEPT.md](CONCEPT.md) for design.

## Installation

### Using Nix (Recommended)

#### As a Flake Input

Add to your `flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager.url = "github:nix-community/home-manager";
    secure-askpass.url = "github:rschaffar/secure-askpass";
  };

  outputs = { nixpkgs, home-manager, secure-askpass, ... }: {
    homeConfigurations.yourusername = home-manager.lib.homeManagerConfiguration {
      modules = [
        secure-askpass.homeManagerModules.default
        {
          services.secure-askpass = {
            enable = true;
            settings = {
              cache.ssh.default_ttl = 1800;  # 30 minutes
              cache.git.clear_on_lock = false;
            };
          };
        }
      ];
    };
  };
}
```

#### Direct Run

```bash
nix run github:rschaffar/secure-askpass
```

### Using Cargo

```bash
cargo install --path crates/secure-askpass-daemon
```

## Development

### With Nix

```bash
# Enter development environment
nix develop

# Build
nix build

# Format Nix files
nix fmt
```

### With Cargo (Standard)

```bash
cargo build
cargo test
cargo run --bin secure-askpass-daemon
```

## Configuration

See [CONCEPT.md](CONCEPT.md) for detailed configuration options.

Example `~/.config/secure-askpass/config.toml`:

```toml
[cache.ssh]
default_ttl = 1800
clear_on_lock = true

[cache.git]
default_ttl = 7200
clear_on_lock = false
```

## License

MIT OR Apache-2.0 (standard Rust dual-license)
