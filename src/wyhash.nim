# A Nim implementation of wyhash version 4.1 [1].
#
# This Nim code is ported from the Zig stdlib implementation [2], which is
# competitive with the C reference implementation.
#
# For now, an implementation of iterative hashing is omitted - it was
# deliberately removed from the C reference implementation. See the
# upstream issue [3].
#
# The Zig implementation has the following license [4]:
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
# [1] https://github.com/wangyi-fudan/wyhash/tree/77e50f267fbc7b8e2d09f2d455219adb70ad4749
# [2] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/lib/std/hash/wyhash.zig#L1-L197
# [3] https://github.com/wangyi-fudan/wyhash/issues/131
# [4] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/LICENSE
from std/private/dragonbox import mul128

const secret = [
    0xa0761d6478bd642f'u64,
    0xe7037ed1a0b428db'u64,
    0x8ebc6af09c88c6e3'u64,
    0x589965cc75374cc3'u64,
]

type
  Wyhash = object
    a: uint64
    b: uint64
    state: array[3, uint64]
    totalLen: uint64

func mum(a: var uint64, b: var uint64) =
  let x = mul128(a, b)
  a = x.lo
  b = x.hi

func mix(a: uint64, b: uint64): uint64 =
  var a = a
  var b = b
  mum(a, b)
  result = a xor b

func read(data: openArray[byte], numBytes: static int, start: int): uint64 =
  assert numBytes <= 8
  result = 0
  copyMem(result.addr, data[start].addr, numBytes)

func round(self: var Wyhash, input: openArray[byte]) =
  for i in 0..2:
    let a = input.read(8, 8 * 2 * i)
    let b = input.read(8, 8 * (2 * i + 1))
    self.state[i] = mix(a xor secret[i + 1], b xor self.state[i])

func final0(self: var Wyhash) =
  self.state[0] = self.state[0] xor self.state[1] xor self.state[2]

func final1(self: var Wyhash, inputLB: openArray[byte], startPos: int) =
  ## `inputLB` must be at least 16-bytes long (for shorter keys, the `smallKey`
  ## function is used instead of this one).
  assert inputLB.len >= 16
  assert inputLB.len - startPos <= 48
  let input = inputLB[startPos..^1]

  for i in countup(0, input.high - 16, 16):
    self.state[0] = mix(input.read(8, i) xor secret[1],
                        input.read(8, i + 8) xor self.state[0])

  self.a = inputLB.read(8, inputLB.len - 16)
  self.b = inputLB.read(8, inputLB.len - 8)

func final2(self: var Wyhash): uint64 =
  self.a = self.a xor secret[1]
  self.b = self.b xor self.state[0]
  mum(self.a, self.b)
  result = mix(self.a xor secret[0] xor self.totalLen, self.b xor secret[1])

func smallKey(self: var Wyhash, input: openArray[byte]) =
  assert input.len <= 16
  if input.len >= 4:
    let last = input.len - 4
    let quarter = (input.len shr 3) shl 2
    self.a = (input.read(4, 0) shl 32) or input.read(4, quarter)
    self.b = (input.read(4, last) shl 32) or input.read(4, last - quarter)
  elif input.len > 0:
    self.a = (input[0].uint64 shl 16) or (input[input.len shr 1].uint64 shl 8) or input[input.len - 1]
    self.b = 0
  else:
    self.a = 0
    self.b = 0

func init(T: typedesc[Wyhash], seed: uint64): T =
  result = T(
    totalLen: 0,
  )
  result.state[0] = seed xor mix(seed xor secret[0], secret[1])
  result.state[1] = result.state[0]
  result.state[2] = result.state[0]

func wyhash*(seed: uint64, input: openArray[byte]): uint64 =
  ## Returns a hash of `input` with the given `seed`.
  ##
  ## Implements Wyhash version 4.1 [1], a fast hash function with excellent
  ## output quality [2].
  ##
  ## Uses a fast path for `input`s up to (and including) 16 bytes long.
  ##
  ## [1] https://github.com/wangyi-fudan/wyhash/tree/77e50f267fbc7b8e2d09f2d455219adb70ad4749
  ## [2] https://github.com/rurban/smhasher
  var self = Wyhash.init(seed)

  if input.len <= 16:
    self.smallKey(input)
  else:
    var i = 0
    if input.len >= 48:
      while i + 48 < input.len:
        self.round toOpenArray(input, i, input.high)
        i += 48
      self.final0()
    self.final1(input, i)

  self.totalLen = input.len.uint64
  result = self.final2()
