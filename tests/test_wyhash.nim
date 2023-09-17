# Ported from the tests [1][2] for the Zig stdlib implementation of wyhash,
# deliberately minimizing deviation in order to simplify maintenance.
#
# The Zig tests have the following license [3]:
#
#   The MIT License (Expat)
#
#   Copyright (c) Zig contributors
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#   THE SOFTWARE.
#
# [1] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/lib/std/hash/wyhash.zig#L209-L242
# [2] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/lib/std/hash/verify.zig#L25-L44
# [3] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/LICENSE
import std/unittest
import wyhash

func smhasherWyhash: uint32 =
  ## Returns the SMHasher verification code.
  ##
  ## Hashes keys of the form [0], [0, 1], [0, 1, 2]... up to N=255, using
  ## 256-N as the corresponding seed, to set values in `bufAll`.
  ##
  ## The verification code is the hash of `bufAll`, truncated to a uint32.
  const hashSize = 8 # Bytes.
  var buf {.noinit.}: array[256, byte]
  var bufAll {.noinit.}: array[256 * hashSize, byte]

  for i in 0..255:
    buf[i] = i.byte
    let h = toOpenArray(buf, 0, i - 1).wyhash((256 - i).uint64)
    copyMem(bufAll[i * hashSize].addr, h.addr, 8)

  result = bufAll.wyhash(0).uint32

proc main =
  # The below test vectors are from running the upstream `test_vector.cpp` [1].
  # Note that `etalons_v` is unused in that file.
  # The Zig implementation checks these vectors towards the bottom of wyhash.zig [2].
  #
  # [1] https://github.com/wangyi-fudan/wyhash/blob/77e50f267fbc7b8e2d09f2d455219adb70ad4749/test_vector.cpp
  # [2] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/lib/std/hash/wyhash.zig#L209-L217
  test "test vectors":
    const vectors = [
      (seed: 0'u64, expected: 0x409638ee2bde459'u64, input: ""),
      (seed: 1'u64, expected: 0xa8412d091b5fe0a9'u64, input: "a"),
      (seed: 2'u64, expected: 0x32dd92e4b2915153'u64, input: "abc"),
      (seed: 3'u64, expected: 0x8619124089a3a16b'u64, input: "message digest"),
      (seed: 4'u64, expected: 0x7a43afb61d7f5f40'u64, input: "abcdefghijklmnopqrstuvwxyz"),
      (seed: 5'u64, expected: 0xff42329b90e50d58'u64, input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
      (seed: 6'u64, expected: 0xc39cab13b115aad3'u64, input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
    ]

    for (seed, expected, input) in vectors:
      doAssert toOpenArrayByte(input, 0, input.high).wyhash(seed) == expected

  test "smhasher":
    doAssert smhasherWyhash() == 0xbd5e840c'u32

when isMainModule:
  main()
  # static: main()
