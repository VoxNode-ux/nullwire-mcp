{
  description = "NullWire-MCP: RAM-only traffic inspector for AI assistants that scrubs secrets first";

  # nixos-unstable, pinned to this commit
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/d5cc6833999746cffdfe0598f7bc801a57b887a9";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        nullwire-mcp = pkgs.callPackage ./packaging/nix/package.nix { src = self; };
        default = nullwire-mcp;
      });

      apps = forAll (pkgs: rec {
        nullwire-mcp = {
          type = "app";
          program = "${self.packages.${pkgs.system}.nullwire-mcp}/bin/nullwire-mcp";
        };
        default = nullwire-mcp;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.go pkgs.golangci-lint ]; };
      });
    };
}