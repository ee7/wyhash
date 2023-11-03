# Package

version       = "0.1.0"
author        = "ee7"
description   = "Nim implementation of wyhash version 4.1 (2023)"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.0.0"

task test, "Run tests":
  for backend in ["c", "cpp", "js"]:
    for def in ["", "-d:release"]:
      var cmd = "nim r --backend:" & backend & " "
      if def.len > 0:
        cmd.add def & " "
      cmd.add "./tests/test_wyhash.nim"
      exec cmd
