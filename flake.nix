{
  description = "SweetByte - A very small, very simple, yet very secure encryption tool.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.buildGoModule {
          pname = "sweetbyte";
          version = "1.0";

          src = ./.;

          vendorHash = "sha256-MwNUkEmdaVv1gGMHjdqKzTSDVD5I2bGqRKUQN3R7p+U=";

          env.CGO_ENABLED = 0;
          flags = [ "-trimpath" ];
          ldflags = [
            "-s"
            "-w"
            "-extldflags -static"
          ];

          nativeBuildInputs = [ pkgs.installShellFiles ];

          postInstall = ''
            installShellCompletion --cmd sweetbyte \
              --bash <($out/bin/sweetbyte completion bash) \
              --fish <($out/bin/sweetbyte completion fish) \
              --zsh <($out/bin/sweetbyte completion zsh)
          '';

          meta = with pkgs.lib; {
            description = "A very small, very simple, yet very secure encryption tool.";
            homepage = "https://github.com/yourusername/sweetbyte";
            license = licenses.mit;
            mainProgram = "sweetbyte";
          };
        };
      }
    );
}
