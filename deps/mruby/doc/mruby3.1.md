# User visible changes in `mruby3.1` from `mruby3.0`

# New Features

## Core Language Features

### Keyword Arguments

CRuby3.0 compatible keyword arguments are introduced.
Keyword arguments are basically separated from ordinal arguments.

### Other Language Enhancement

- Implement endless-def [Ruby:Feature#16746](https://bugs.ruby-lang.org/issues/16746)
- Replace `R-assignment` by `single-line pattern matching` [Ruby:Feature#15921](https://bugs.ruby-lang.org/issues/15921)
- Support squiggly heredocs. [#5246](https://github.com/mruby/mruby/pull/5246)
- Hash value omission [Ruby:Feature#14579](https://bugs.ruby-lang.org/issues/14579)

## Configuration Options Changed

Some configuration macros are available:

- `MRB_WORDBOX_NO_FLOAT_TRUNCATE`: by default, float values are packed in the word if possible, but define this macro to allocate float values in the heap.
- `MRB_USE_RO_DATA_P_ETEXT`: define this macro if `_etext` is available on your platform.
- `MRB_NO_DEFAULT_RO_DATA_P`: define this macro to avoid using predefined `mrb_ro_data_p()` function

---

# Updated Features

## New build configurations

We have added several new build configurations in the `build_config` directory.

- `cross-mingw-winetest.rb`
- `cross-mingw.rb`
- `nintendo_switch.rb`
- `serenity.rb`
- `minimal`: minimal configuration
- `host-f32`: compiles with `mrb_float` as 32 bit `float`
- `host-nofloat`: compiles with no float configuration
- `android_arm64_v8a.rb`: renamed from `android_arm64-v8a.rb`

## Core Libraries

### New Methods

- `Array#product`
- `Array#repeated_combination`
- `Array#repeated_permutation`
- `Kernel#__ENCODING__`
- `Random.bytes`
- `Random#bytes`
- `String#center`

### New Gem Enhancement

- `mrbgems/mruby-pack` now supports `M` directive (Q encoding)
- `mrbgems/mruby-pack` now supports `X` directive (back-up by bytes)
- `mrbgems/mruby-pack` now supports `@` directive (absolute position)
- `mrbgems/mruby-pack` now supports `w` directive (BER compression)

## Tools

- `mruby-config` now supports `--cc` and `--ld` options.
- Remove `OP_` prefix from `mruby -v` code dump output.
- Prohibit use of `OP_EXT{1,2,3}` by `mrbc` with `--no-ext-ops` option.

## Features for mruby Developer

- Add new specifier `c` to `mrb_get_args()` for receive Class/Module.

---

# Breaking Changes

## Incompatibly Changed Methods

- `Kernel#printf` (`mruby-sprintf`) Format specifiers `%a` and `%A` are removed.
- `Kernel#puts` (`mruby-print`) Now expand Array arguments.

## mruby VM and bytecode

Due to improvements in the binary format, mruby binaries are no longer backward compatible.
To run the mruby binaries on mruby 3.1, recompile with the mruby 3.1 `mrbc`.

- Upgrade mruby VM version `RITE_VM_VER` to `0300` (means mruby 3.0 or after).
- Upgrade mruby binary version `RITE_BINARY_FORMAT_VER` to `0300`.

## Reintroduced Instructions

`mruby3.0` removed `OP_EXT1`, `OP_EXT2`, `OP_EXT3` for operand extension. But the operand size limitations was too tight for real-world application.
`mruby3.1` reintroduces those extension instructions.

## Removed Instructions

`mruby3.1` removed following instructions.

- `OP_LOADL16`
- `OP_LOADSYM16`
- `OP_STRING16`
- `OP_LAMBDA16`
- `OP_BLOCK16`
- `OP_METHOD16`
- `OP_EXEC16`

Those instructions are no longer needed by reintroduction of extension instructions.

- `OP_SENDV`
- `OP_SENDVB`

Those instructions for method calls with variable number of arguments are no longer needed. They are covered by `OP_SEND` instruction with `n=15`.

## New Instructions

`mruby3.1` introduces following new instructions.

- `OP_GETIDX`: takes 1 operands `R[a][a+1]`
- `OP_SETIDX`: takes 1 operands `R[a][a+1]=R[a+2]`
- `OP_SSEND`: takes 3 operands `a=self.b(c...)`; see `OP_SEND`
- `OP_SSENDB`: takes 3 operands `a=self.b(c...){...}`; see `OP_SEND`
- `OP_SYMBOL`: takes 2 operands `R[a] = intern(Pool[b])`

### `OP_GETIDX` and `OP_SETIDX`

Execute `obj[int]` and `obj[int] = value` respectively, where `obj` is `string|array|hash`.

### `OP_SSEND` and `OP_SSENDB`

They are similar to `OP_SEND` and `OP_SENDB` respectively. They initialize the `R[a]` by `self` first so that we can skip one `OP_LOADSELF` instruction for each call.

### `OP_SYMBOL`

Extracts the character string placed in the pool as a symbol.

## Changed Instructions

### `OP_SEND` and `OP_SENDB`

Method calling instructions are unified. Now `OP_SEND` and `OP_SENDB` (method call with a block) can support both splat arguments and keyword arguments as well.

The brief description of the instructions:

|`OP_SEND`   | BBB | `R[a] = R[a].call(Syms[b],R[a+1..n],R[a+n+1],R[a+n+2]..nk) c=n|nk<<4`                    |
|`OP_SENDB`  | BBB | `R[a] = R[a].call(Syms[b],R[a+1..n],R[a+n+1..nk],R[a+n+2..nk],&R[a+n+2*nk+2]) c=n|nk<<4` |

Operand C specifies the number of arguments. Lower 4 bits (`n`) represents the number of ordinal arguments, and higher 4 bits (`nk`) represents the number of keyword arguments.
When `n == 15`, the method takes arguments packed in an array. When `nk == 15`, the method takes keyword arguments are packed in a hash.

### `OP_ARYPUSH`

Now takes 2 operands and pushes multiple entries to an array.

## Boxing Updated

### Word Boxing

`MRB_WORD_BOXING` now packs floating point numbers in the word, if the size of `mrb_float` is equal or smaller than the size of `mrb_int` by default.
If the size of `mrb_float` and `mrb_int` are same, the last 2 bits in the `mrb_float` are trimmed and used as flags. If you need full precision, you need to define `MRB_WORDBOX_NO_FLOAT_TRUNCATE` as described above.

### NaN Boxing

Previous NaN boxing packs values in NaN representation, but pointer retrievals are far more frequent than floating point number references. So we add constant offset to NaN representation to clear higher bits of pointer representation. This representation is called "Favor Pointer" NaN Boxing.

Also, previous NaN boxing limit the size of `mrb_int` to 4 bytes (32 bits) to fit in NaN values. Now we allocate integer values in the heap, if the value does not fit in the 32 bit range, just like we did in Word Boxing.

## Constant Folding

The code generator was updated to reduce the number of instructions, e.g.

```
a = 2 * 5
```

will be interpreted as

```
a = 10
```

In addition, we have improved peephole optimizations, for example:

```
GETIV R4 :@foo
MOVE R1 R4
```

to

```
GETIV R1 :@foo
```

## `String#hash` now use `FNV1a` algorithm

For better and faster hash values.

---

# Major bug fixes

- Fix infinite recursive call bugs in integer division [98799aa6](https://github.com/mruby/mruby/commit/98799aa6)
- Fix to raise TypeError with super inside instance_eval / class_eval [#5476](https://github.com/mruby/mruby/pull/5476)
- Fix to call `method_added` hooks on method definitions; [#2339](https://github.com/mruby/mruby/pull/2339)
- Fix a potential buffer overflow in `time_zonename` [26340a88](https://github.com/mruby/mruby/commit/26340a88)
- Fix `Module.instance_eval` bug [#5528](https://github.com/mruby/mruby/pull/5528)
- Fix fix `M` packing bug [bfe2bd49](https://github.com/mruby/mruby/commit/bfe2bd49)
- Fix a bug regarding attribute assignment with kargs [de2b4bd0](https://github.com/mruby/mruby/commit/de2b4bd0)
- Fix SIGSEGV with mrbgems/mruby-method [#5580](https://github.com/mruby/mruby/pull/5580)
- Fix print error before cleanup in `codegen_error()` [#5603](https://github.com/mruby/mruby/pull/5603)
- Fix a bug in unpacking BER [#5611](https://github.com/mruby/mruby/pull/5611)
- Fix a bug with numbered parameters as arguments [#5605](https://github.com/mruby/mruby/pull/5605)
- Fix `mrb_ary_shift_m` initialization bug [27d1e013](https://github.com/mruby/mruby/commit/27d1e013)
- Fix keyword argument with `super` [#5628](https://github.com/mruby/mruby/pull/5628)
- Fix a bug with numbered parameters on toplevel [7e7f1b2f](https://github.com/mruby/mruby/commit/7e7f1b2f)
- Fix keyword argument bug [#5632](https://github.com/mruby/mruby/issues/5632)
- Fix multiple assignments in parameters [#5647](https://github.com/mruby/mruby/issues/5647)
- Fix keyword parameters not passing through super [#5660](https://github.com/mruby/mruby/issues/5660)
- Fix infinite loop from unclosed here-doc [#5676](https://github.com/mruby/mruby/issues/5676)
- Fix negative integer division bug [#5678](https://github.com/mruby/mruby/issues/5678)

# CVEs

## Fixed CVEs

Following CVEs are fixed in this release.

- [CVE-2021-4110](https://nvd.nist.gov/vuln/detail/CVE-2021-4110)
- [CVE-2021-4188](https://nvd.nist.gov/vuln/detail/CVE-2021-4188)
- [CVE-2022-0080](https://nvd.nist.gov/vuln/detail/CVE-2022-0080)
- [CVE-2022-0240](https://nvd.nist.gov/vuln/detail/CVE-2022-0240)
- [CVE-2022-0326](https://nvd.nist.gov/vuln/detail/CVE-2022-0326)
- [CVE-2022-0481](https://nvd.nist.gov/vuln/detail/CVE-2022-0481)
- [CVE-2022-0631](https://nvd.nist.gov/vuln/detail/CVE-2022-0631)
- [CVE-2022-0632](https://nvd.nist.gov/vuln/detail/CVE-2022-0632)
- [CVE-2022-0890](https://nvd.nist.gov/vuln/detail/CVE-2022-0890)
- [CVE-2022-1071](https://nvd.nist.gov/vuln/detail/CVE-2022-1071)
- [CVE-2022-1106](https://nvd.nist.gov/vuln/detail/CVE-2022-1106)
- [CVE-2022-1201](https://nvd.nist.gov/vuln/detail/CVE-2022-1201)
- [CVE-2022-1427](https://nvd.nist.gov/vuln/detail/CVE-2022-1427)

## Unaffected CVEs

Following CVEs do not cause problems in this release. They are fixed in the later release.

- [CVE-2022-0481](https://nvd.nist.gov/vuln/detail/CVE-2022-0481)
- [CVE-2022-0525](https://nvd.nist.gov/vuln/detail/CVE-2022-0525)
- [CVE-2022-0570](https://nvd.nist.gov/vuln/detail/CVE-2022-0570)
- [CVE-2022-0614](https://nvd.nist.gov/vuln/detail/CVE-2022-0614)
- [CVE-2022-0623](https://nvd.nist.gov/vuln/detail/CVE-2022-0623)
- [CVE-2022-0630](https://nvd.nist.gov/vuln/detail/CVE-2022-0630)
- [CVE-2022-0717](https://nvd.nist.gov/vuln/detail/CVE-2022-0817)
- [CVE-2022-1212](https://nvd.nist.gov/vuln/detail/CVE-2022-1212)
- [CVE-2022-1276](https://nvd.nist.gov/vuln/detail/CVE-2022-1276)
- [CVE-2022-1286](https://nvd.nist.gov/vuln/detail/CVE-2022-1286)
