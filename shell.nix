let
  pkgs = import ./nix/pkgs.nix {};
in
  pkgs.mkShell {
    inputsFrom = [pkgs.dev-shell-with-node-yarn-berry];
    packages = with pkgs; [
      npm-publish
    ];
  }
