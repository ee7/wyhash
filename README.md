# wyhash (Nim)

A pure [Nim][nim] implementation of [wyhash version 4.1][wyhash], a high-performance 64-bit hash function with excellent output quality (see [SMhasher][smhasher]).

The implementation supports use at run time, compile time, with the JavaScript backend, and on both little-endian and big-endian systems.
It has been tested under those conditions via the official test vectors, and via the SMhasher verification code.

This Nim implementation is ported from the [Zig][zig] standard library [implementation of wyhash][zig-wyhash], which is competitive with the C reference implementation (or slightly faster for some workloads).

The implementation currently requires Nim 2.0.0 (released 2023-08-01) or later.

## Example usage

To hash the string `"foo"` with a `seed` of `42`:

```nim
import wyhash

let hash = wyhash("foo", seed = 42)
```

The implementation produces the same hash at run time and compile time:

```nim
import wyhash

const s = "foo"
const seed = 42

let hashAtRunTime = wyhash(s, seed)
const hashAtCompileTime = wyhash(s, seed)

doAssert hashAtCompileTime == hashAtRunTime
doAssert hashAtRunTime == 4_295_045_158_484_017_618'u64
```

[nim]: https://nim-lang.org/
[smhasher]: https://github.com/rurban/smhasher
[wyhash]: https://github.com/wangyi-fudan/wyhash/tree/77e50f267fbc7b8e2d09f2d455219adb70ad4749
[zig]: https://ziglang.org/
[zig-wyhash]: https://github.com/ziglang/zig/blob/410be6995e4f0e7b41174f7c0bb4bf828b758871/lib/std/hash/wyhash.zig#L1-L197
