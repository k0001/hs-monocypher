{
  description = "Haskell monocypher library";

  outputs = { self, nixpkgs }:
    let
      pkgsOverlay = pself: psuper: {
        monocypher = psuper.monocypher.overrideAttrs (_: _: {
          version = "4.0.0";
          src = ./c-monocypher;
          patches = [ ];
        });
        haskell = psuper.haskell // {
          packageOverrides = hself: hsuper: {
            monocypher = hself.callPackage ./. { };
          };
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
            default = pkgs.releaseTools.aggregate {
              name = "every output from this flake";
              constituents = let
                p = self.packages.${system};
                s = self.devShells.${system};
              in [
                p.c_monocypher

                p.hs_monocypher__ghcDefault
                p.hs_monocypher__ghc925
                p.hs_monocypher__ghc943

                p.hs_monocypher__ghcDefault.doc
                p.hs_monocypher__ghc925.doc
                p.hs_monocypher__ghc943.doc

                s.hs_monocypher__ghcDefault
                s.hs_monocypher__ghc925
                s.hs_monocypher__ghc943
              ];
            };
            c_monocypher = pkgs.monocypher;
            hs_monocypher__ghcDefault = pkgs.haskellPackages.monocypher;
            hs_monocypher__ghc925 = pkgs.haskell.packages.ghc925.monocypher;
            hs_monocypher__ghc943 = pkgs.haskell.packages.ghc943.monocypher;
          });
      devShells =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "i686-linux" "aarch64-linux" ]
        (system:
          let
            pkgs = pkgsFor system;
            mkShellFor = hpkgs:
              pkgs.haskellPackages.shellFor {
                packages = p: [ p.monocypher ];
                withHoogle = true;
                nativeBuildInputs = [ pkgs.cabal-install pkgs.cabal2nix ];
              };
          in {
            default = self.devShells.${system}.hs_monocypher__ghcDefault;
            c_monocypher = pkgs.mkShell { inputsFrom = [ pkgs.monocypher ]; };
            hs_monocypher__ghcDefault = mkShellFor pkgs.haskellPackages;
            hs_monocypher__ghc925 = mkShellFor pkgs.haskell.packages.ghc925;
            hs_monocypher__ghc943 = mkShellFor pkgs.haskell.packages.ghc943;
          });
    };

}
