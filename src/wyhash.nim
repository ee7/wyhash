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

func read4(data: openArray[byte], start: int): uint64 =
  when defined(copyMem):
    result = 0
    copyMem(result.addr, data[start].addr, 4)
  else:
    var j = 4
    while j > 0:
      dec j
      result = (result shl 8) or data[start+j].uint32

func read8(data: openArray[byte], start: int): uint64 {.noinit.} =
  when defined(copyMem):
    copyMem(result.addr, data[start].addr, 8)
  else:
    var j = 8
    while j > 0:
      dec j
      result = (result shl 8) or data[start+j].uint64

func round(self: var Wyhash, input: openArray[byte]) =
  var a = input.read8(0)
  var b = input.read8(8)
  self.state[0] = mix(a xor secret[1], b xor self.state[0])
  a = input.read8(16)
  b = input.read8(24)
  self.state[1] = mix(a xor secret[2], b xor self.state[1])
  a = input.read8(32)
  b = input.read8(40)
  self.state[2] = mix(a xor secret[3], b xor self.state[2])

func final0(self: var Wyhash) =
  self.state[0] = self.state[0] xor self.state[1] xor self.state[2]

func final1(self: var Wyhash, inputLB: openArray[byte], startPos: int) =
  ## `inputLB` must be at least 16-bytes long (for shorter keys, the `smallKey`
  ## function is used instead of this one).
  assert inputLB.len >= 16
  assert inputLB.len - startPos <= 48
  for i in countup(startPos, inputLB.high - 16, 16):
    self.state[0] = mix(inputLB.read8(i) xor secret[1],
                        inputLB.read8(i + 8) xor self.state[0])

  self.a = inputLB.read8(inputLB.len - 16)
  self.b = inputLB.read8(inputLB.len - 8)

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
    self.a = (input.read4(0) shl 32) or input.read4(quarter)
    self.b = (input.read4(last) shl 32) or input.read4(last - quarter)
  elif input.len > 0:
    self.a = (input[0].uint64 shl 16) or
                 (input[input.len shr 1].uint64 shl 8) or
                 input[input.len - 1]
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

func wyhash*(input: openArray[byte], seed: uint64): uint64 =
  ## Returns a hash of `input` with the given `seed`.
  ##
  ## Implements Wyhash version 4.1 [1], a fast hash function with excellent
  ## output quality [2].
  ##
  ## Uses a fast path for `input`s up to (and including) 16 bytes long.
  ##
  ## Supports use at run time, compile time, with the JavaScript backend, and
  ## with both little-endian and big-endian machines.
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

func wyhash*(input: openArray[char], seed: uint64): uint64 {.inline.} =
  input.toOpenArrayByte(0, input.high).wyhash(seed)
