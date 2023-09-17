# A Nim implementation of wyhash version 4.1 [1].
#
# This Nim code is ported from the Zig stdlib implementation [2], which is
# competitive with the C reference implementation.
#
# The Zig implementation has the following license [3]:
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
# [2] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/lib/std/hash/wyhash.zig
# [3] https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/LICENSE
from std/private/dragonbox import mul128

const secret = [
    0xa0761d6478bd642f'u64,
    0xe7037ed1a0b428db'u64,
    0x8ebc6af09c88c6e3'u64,
    0x589965cc75374cc3'u64,
]

type
  Usize = uint64

type
  Wyhash* = object
    a: uint64
    b: uint64
    state: array[3, uint64]
    totalLen: Usize
    buf: array[48, uint8]
    bufLen: Usize

func mum(a: var uint64, b: var uint64) {.inline.} =
  let x = mul128(a, b)
  a = x.lo
  b = x.hi

func mix(a: uint64, b: uint64): uint64 {.inline.} =
  var a = a
  var b = b
  mum(a, b)
  result = a xor b

func read(bytes: static Usize, data: openArray[uint8]): uint64 {.inline.} =
  assert bytes <= 8
  const T = std.meta.Int(.unsigned, 8 * bytes)
  result = std.mem.readIntLittle(T, data[0..<bytes]).uint64

func round(self: var Wyhash, input: array[48, uint8]) {.inline.} =
  for i in 0..2:
    let a = read(8, input[8 * (2 * i) .. ^1])
    let b = read(8, input[8 * (2 * i + 1) .. ^1])
    self.state[i] = mix(a xor secret[i + 1], b xor self.state[i])

func final0(self: var Wyhash) {.inline.} =
  self.state[0] = self.state[0] xor self.state[1] xor self.state[2]

func final1(self: var Wyhash, inputLB: openArray[uint8], startPos: Usize) {.inline.} =
  ## `inputLB` must be at least 16-bytes long (in shorter key cases the `smallKey`
  ## function will be used instead). We use an index into a slice to for
  ## compile-time processing as opposed to if we used pointers.
  assert inputLB.len >= 16
  assert inputLB.len - startPos.int <= 48
  let input = inputLB[startPos..^1]

  var i: Usize = 0
  while (i + 16 < input.len.Usize):
    self.state[0] = mix(read(8, input[i..^1]) xor secret[1], read(8, input[i + 8 .. ^1]) xor self.state[0])
    i += 16

  self.a = read(8, inputLB[inputLB.len - 16 .. ^1][0..<8])
  self.b = read(8, inputLB[inputLB.len - 8 .. ^1][0..<8])

func final2(self: var Wyhash): uint64 {.inline.} =
  self.a = self.a xor secret[1]
  self.b = self.b xor self.state[0]
  mum(self.a, self.b)
  result = mix(self.a xor secret[0] xor self.totalLen, self.b xor secret[1])

func smallKey(self: var Wyhash, input: openArray[uint8]) {.inline.} =
  assert input.len <= 16

  if (input.len >= 4):
    let last = input.len - 4
    let quarter = (input.len shr 3) shl 2
    self.a = (read(4, input[0..^1]) shl 32) or read(4, input[quarter..^1])
    self.b = (read(4, input[last..^1]) shl 32) or read(4, input[last - quarter .. ^1])
  elif (input.len > 0):
    self.a = (input[0].uint64 shl 16) or (input[input.len shr 1].uint64 shl 8) or input[input.len - 1]
    self.b = 0
  else:
    self.a = 0
    self.b = 0

func shallowCopy(self: var Wyhash): Wyhash {.inline.} =
  ## Copies the core wyhash state but not any internal buffers.
  Wyhash(
    a: self.a,
    b: self.b,
    state: self.state,
    totalLen: self.totalLen,
  )

func init*(T: typedesc[Wyhash], seed: uint64): T =
  result = T(
    totalLen: 0,
    bufLen: 0,
  )

  result.state[0] = seed xor mix(seed xor secret[0], secret[1])
  result.state[1] = result.state[0]
  result.state[2] = result.state[0]

func wyhash*(seed: uint64, input: openArray[uint8]): uint64 =
  var self = Wyhash.init(seed)

  if (input.len <= 16):
    self.smallKey(input)
  else:
    var i: Usize = 0
    if (input.len >= 48):
      while (i + 48 < input.len.Usize):
        self.round(input[i .. ^1][0 ..< 48])
        i += 48
      self.final0()
    self.final1(input, i)

  self.totalLen = input.len.Usize
  result = self.final2()

func update*(self: var Wyhash, input: openArray[uint8]) =
  ## This is subtly different from other hash function update calls. Wyhash requires the last
  ## full 48-byte block to be run through final1 if is exactly aligned to 48-bytes.
  self.totalLen += input.len.Usize

  if (input.len <= 48 - self.bufLen.int):
    copyMem(self.buf[self.bufLen .. ^1][0 ..< input.len], input)
    self.bufLen += input.len.Usize
    return

  var i: Usize = 0

  if (self.bufLen > 0):
    i = 48 - self.bufLen
    copyMem(self.buf[self.bufLen .. ^1][0 ..< i], input[0 ..< i])
    self.round(self.buf)
    self.bufLen = 0

  while (i + 48 < input.len.Usize):
    self.round(input[i .. ^1][0 ..< 48])
    i += 48

  let remainingBytes = input[i..^1]
  if (remainingBytes.len < 16 and i >= 48):
    let rem = 16 - remainingBytes.len
    copyMem(self.buf[self.buf.len - rem .. ^1], input[i - rem ..< i])
  copyMem(self.buf[0..<remainingBytes.len], remainingBytes)
  self.bufLen = remainingBytes.len.Usize

func final*(self: var Wyhash): uint64 =
  var input = self.buf[0 ..< self.bufLen]
  var newSelf = self.shallowCopy() # Ensure idempotency.

  if (self.totalLen <= 16):
    newSelf.smallKey(input)
  else:
    var offset: Usize = 0
    if (self.bufLen < 16):
      var scratch {.noinit.}: array[16, uint8]
      let rem = 16 - self.bufLen
      copyMem(scratch[0 ..< rem], self.buf[self.buf.len - rem .. ^1][0 ..< rem])
      copyMem(scratch[rem ..< 1][0 ..< self.bufLen], self.buf[0 ..< self.bufLen])

      # Same as input but with additional bytes preceeding start in case of a short buffer.
      input = scratch
      offset = rem

    newSelf.final0()
    newSelf.final1(input, offset)

  result = newSelf.final2()

when isMainModule:
  import std/unittest

  type
    TestVector = object
      seed: uint64
      expected: uint64
      input: string

  # Run https://github.com/wangyi-fudan/wyhash/blob/77e50f267fbc7b8e2d09f2d455219adb70ad4749/test_vector.cpp directly.
  const vectors = [
    TestVector(seed: 0'u64, expected: 0x409638ee2bde459'u64, input: ""),
    TestVector(seed: 1'u64, expected: 0xa8412d091b5fe0a9'u64, input: "a"),
    TestVector(seed: 2'u64, expected: 0x32dd92e4b2915153'u64, input: "abc"),
    TestVector(seed: 3'u64, expected: 0x8619124089a3a16b'u64, input: "message digest"),
    TestVector(seed: 4'u64, expected: 0x7a43afb61d7f5f40'u64, input: "abcdefghijklmnopqrstuvwxyz"),
    TestVector(seed: 5'u64, expected: 0xff42329b90e50d58'u64, input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    TestVector(seed: 6'u64, expected: 0xc39cab13b115aad3'u64, input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
  ]

  test "test vectors":
    for e in vectors:
      check wyhash(e.seed, e.input) == e.expected

  test "test vectors at compile time":
    static:
      for e in vectors:
        check wyhash(e.seed, e.input) == e.expected

  # test "smhasher":
  #   func do =
  #     check verify.smhasher(wyhash) == 0xBD5E840C
  #   do()
  #   static:
  #     do()

  # test "iterative api":
  #   func do() !void =
  #     try verify.iterativeApi(Wyhash)
  #   do()
  #   static:
  #     do()

  test "iterative maintains last sixteen":
    const input = 'Z'.repeat(48) & "01234567890abcdefg"
    const seed = 0

    for i in 0..16:
      let payload = input[0 ..< input.len - i]
      let nonIterativeHash = wyhash(seed, payload)

      var wh = Wyhash.init(seed)
      wh.update(payload)
      let iterativeHash = wh.final()

      check nonIterativeHash == iterativeHash
