{ mkDerivation, lib, c2hs, base }:
mkDerivation {
  pname = "monocypher";
  version = "4.0.0.1";
  src = lib.sources.cleanSource ./.;
  libraryToolDepends = [ c2hs ];
  libraryHaskellDepends = [ base ];
  testHaskellDepends = [ base ];
  homepage = "https://github.com/k0001/hs-monocypher";
  description = "Low level bindings to the monocypher C library";
  license = [ lib.licenses.cc0 lib.licenses.bsd2 ];
}
