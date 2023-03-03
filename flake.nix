{
  description = "Haskell monocypher library";

  inputs = {
    by = {
      url = "github:k0001/by";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, by }:
    let
      haskellOverrides = pself: psuper: hself: hsuper: {
        by = hself.callPackage "${by}/by/pkg.nix" { };

        monocypher = hself.callPackage ./. { };
      };
      pkgsOverlay = pself: psuper: {
        monocypher = psuper.monocypher.overrideAttrs (_: _: {
          version = "4.0.0";
          src = ./c-monocypher;
          patches = [ ];
        });

        # TODO not rebrand haskell.packages.ghc944 to haskellPackages here
        haskellPackages = psuper.haskell.packages.ghc944.override {
          overrides = haskellOverrides pself psuper;
        };
      };
      pkgsFor = system:
        import nixpkgs {
          inherit system;
          overlays = [ pkgsOverlay ];
        };

    in {
      packages =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "aarch64-linux" ]
        (system:
          let pkgs = pkgsFor system;
          in {
            default = self.packages.${system}.hs;
            c = pkgs.monocypher;
            hs = pkgs.haskellPackages.monocypher;
          });
      devShells =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "aarch64-linux" ]
        (system:
          let pkgs = pkgsFor system;
          in {
            default = self.devShells.${system}.hs;
            c = pkgs.mkShell { inputsFrom = [ pkgs.monocypher ]; };
            hs = pkgs.haskellPackages.shellFor {
              packages = p: [ p.monocypher ];
              withHoogle = true;
              nativeBuildInputs = [ pkgs.cabal-install pkgs.cabal2nix ];
            };
          });
    };

}
