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

            llvmPackages_19.libllvm
            llvmPackages_19.stdenv
            llvmPackages_19.libcxx
            llvmPackages_19.libcxxStdenv
            llvmPackages_19.clang-unwrapped
          ];

          shellHook = ''
            export C_INCLUDE_PATH="${pkgs.llvmPackages_19.clang-unwrapped.lib}/lib/clang/19/include"
            export CPLUS_INCLUDE_PATH="${pkgs.llvmPackages_19.libcxx.dev}/include/c++/v1:${pkgs.llvmPackages_19.clang-unwrapped.lib}/lib/clang/19/include"

            export PATH="${pkgs.llvmPackages_19.clang-unwrapped}/bin:$PATH"
            echo "Using clang version: $(clang --version | head -n1)"
          '';
        };
      }
    );
}
