# Used by flake.nix. The same file, with `src` replaced by fetchFromGitHub,
# is what goes into nixpkgs as pkgs/by-name/nu/nullwire-mcp/package.nix.
{ lib
, buildGoModule
, go_1_26 ? null
, src ? null
, fetchFromGitHub
}:

let
  version = "1.2.0";
  builder = if go_1_26 != null then buildGoModule.override { go = go_1_26; } else buildGoModule;
in
builder {
  pname = "nullwire-mcp";
  inherit version;

  src = if src != null then src else fetchFromGitHub {
    owner = "VoxNode-ux";
    repo = "nullwire-mcp";
    rev = "v${version}";
    hash = lib.fakeHash; # replace after the first build: Nix prints the real hash
  };

  # The project has no third-party dependencies, so there is nothing to vendor.
  vendorHash = null;

  env.CGO_ENABLED = "0";
  ldflags = [ "-s" "-w" ];

  # The tests bind local ports and need the network namespace of a normal machine.
  doCheck = false;

  meta = {
    description = "RAM-only traffic inspector for AI assistants that scrubs secrets first";
    homepage = "https://github.com/VoxNode-ux/nullwire-mcp";
    license = lib.licenses.mit;
    mainProgram = "nullwire-mcp";
    maintainers = [ ]; # add your nixpkgs maintainer handle before submitting
  };
}