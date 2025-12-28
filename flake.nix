{
  description = "SweetByte - A very small, very simple, yet very secure encryption tool.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      gomod2nix,
      ...
    }:
    let
      sweetbyteOverlay = final: prev: {
        sweetbyte = final.buildGoApplication {
          pname = "sweetbyte";
          version = "1.0.0";
          src = ./.;
          modules = ./gomod2nix.toml;

          nativeBuildInputs = with final; [ installShellFiles ];

          postInstall = ''
            installShellCompletion --cmd sweetbyte \
              --bash <($out/bin/sweetbyte completion bash) \
              --fish <($out/bin/sweetbyte completion fish) \
              --zsh <($out/bin/sweetbyte completion zsh)
          '';

          meta = with final.lib; {
            description = "A very small, very simple, yet very secure encryption tool";
            homepage = "https://github.com/hambosto/sweetbyte";
            license = licenses.mit;
            mainProgram = "sweetbyte";
          };
        };
      };
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            gomod2nix.overlays.default
            sweetbyteOverlay
          ];
        };
      in
      {
        packages.default = pkgs.sweetbyte;
      }
    )
    // {
      overlays.default = sweetbyteOverlay;
    };
}
