# Package

version       = "0.1.0"
author        = "Federico Ceratto"
description   = "Minivault"
license       = "GPL-3.0"
bin           = @["minivault"]


# Dependencies

requires "nim >= 0.19.0"
bin       = @["minivault"]
task build_deb, "build deb package":
  exec "dpkg-buildpackage -us -uc -b"
