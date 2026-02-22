{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }: 
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = with pkgs; mkShell {
          buildInputs = [
            rust
            pkg-config
            just
            git

            libllvm
            libclang
          ];

          shellHook = ''
            export PATH="${pkgs.libllvm}/bin:$PATH"
            echo "Using clang version: $(clang --version | head -n1)"
          '';
        };
      }
    );
}
