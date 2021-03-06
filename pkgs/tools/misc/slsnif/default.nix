{ lib, stdenv, fetchurl }:

stdenv.mkDerivation {
  name = "slsnif-0.4.4";

  src = fetchurl {
    url = "mirror://sourceforge/slsnif/slsnif-0.4.4.tar.gz";
    sha256 = "0gn8c5hj8m3sywpwdgn6w5xl4rzsvg0z7d2w8dxi6p152j5b0pii";
  };

  meta = {
    description = "Serial line sniffer";
    homepage = "http://slsnif.sourceforge.net/";
    license = lib.licenses.gpl2;
    platforms = lib.platforms.linux;
  };
}
