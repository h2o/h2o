# User visible changes in `mruby3.0`

# Build System

## `build_config` directory

Typical build configuration files are located in `build_config`
directory. For examples:

* `default`: the default configuration
* `host-gprof`: compiles with `gprof` for performance tuning
* `host-m32`: compiles in gcc 32bit mode on 64bit platforms
* `boxing`: compiles all three boxing options
* `clang-asan`: compiles with `clang`'s Address Sanitizer

You can specify the build configuration file with the
`MRUBY_CONFIG` environment variable (or `CONFIG` in short).
If the value specified by `MRUBY_CONFIG` is not the path to
the configuration file, `build_config/${MRUBY_CONFIG}.rb` is
used.  So you can specify it as `rake MRUBY_CONFIG=boxing`,
for example.

# Build Configuration Contribution

When you write a new build configuration description, please
contribute. We welcome your contribution as a GitHub
pull-request.

# Language Changes

## New Syntax

We have ported some new syntax from CRuby.

* Single line pattern matching (`12 => x`);
  mruby matches only with local variables at the moment
* Numbered block parameter (`x.map{_1 * 2}`)
* End-less `def` (`def double(x) = x*2`)

# Configuration Options Changed

## Renamed for consistency

Some configuration macro names are changed for consistency (use `MRB_USE_XXX`
 or `MRB_NO_XXX`).

|             mruby2             |          mruby3           |
|--------------------------------|---------------------------|
| `MRB_ENABLE_ALL_SYMBOLS`       | `MRB_USE_ALL_SYMBOLS`     |
| `MRB_ENABLE_CXX_ABI`           | `MRB_USE_CXX_ABI`         |
| `MRB_ENABLE_CXX_EXCEPTION`     | `MRB_USE_CXX_EXCEPTION`   |
| `MRB_ENABLE_DEBUG_HOOK`        | `MRB_USE_DEBUG_HOOK`      |
| `MRB_DISABLE_DIRECT_THREADING` | `MRB_NO_DIRECT_THREADING` |
| `MRB_DISABLE_STDIO`            | `MRB_NO_STDIO`            |
| `MRB_METHOD_T_STRUCT`          | `MRB_USE_METHOD_T_STRUCT` |
| `MRB_USE_FLOAT`                | `MRB_USE_FLOAT32`         |
| `MRB_WITHOUT_FLOAT`            | `MRB_NO_FLOAT`            |
| `ENABLE_LINENOISE`             | `MRB_USE_LINENOISE`       |
| `ENABLE_READLINE`              | `MRB_USE_READLINE`        |
| `DISABLE_MIRB_UNDERSCORE`      | `MRB_NO_MIRB_UNDERSCORE`  |

* `MRB_USE_FLOAT32` is changed from `MRB_USE_FLOAT` to make sure `float` here
   means using single precision float, and not the opposite of `MRB_NO_FLOAT`.
* `MRB_USE_METHOD_T_STRUCT` uses `struct` version of `mrb_method_t`. More
  portable but consumes more memory. Turned on by default on 32bit platforms.
* `MRB_` prefix is added to those without.

## `MRB_NO_BOXING`

Uses `struct` to represent `mrb_value`. Consumes more memory
but easier to investigate the internal and to debug. It used
to be default `mrb_value` representation. Now the default is
`MRB_WORD_BOXING`.

## `MRB_WORD_BOXING`

Pack `mrb_value` in an `intptr_t` integer. Consumes less
memory compared to `MRB_NO_BOXING` especially on 32 bit
platforms. `Fixnum` size is 31 bits so some integer values
does not fit in `Fixnum` integers.

## `MRB_NAN_BOXING`

Pack `mrb_value` in a floating pointer number. Nothing
changed from previous versions.

## `MRB_USE_MALLOC_TRIM`

Call `malloc_trim(0)` from mrb_full_gc() if this macro is defined.
If you are using glibc malloc, this macro could reduce memory consumption.

# Command Line Program

## `bin/mruby` (by mrbgems/mruby-bin-mruby)

The mruby3 now automatically detects `*.mrb` files without the `-b`
switch. Therefore, it can be mixed with the `*.rb` file in combination
with the `-r` switch and specified at the same time.
Here's an example that works fine:

```console
$ bin/mruby app.mrb
$ bin/mruby -r lib1.mrb -r lib2.rb app.rb
$ bin/mruby -r lib1.rb -r lib2.rb < app.mrb
```

# Internal Changes

## New Instructions

`mruby3` introduces a few new instructions.

Instructions that access pool[i]/syms[i] where i>255.

* `OP_LOADL16`
* `OP_STRING16`
* `OP_LOADSYM16`

Instructions that load a 32 bit integer.

* `OP_LOADI32`

Instruction that unwinds jump table for rescue/ensure.

* `OP_JMPUW`

Renamed from `OP_RAISE`

* `OP_RAISEIF`

Instruction that is reserved for the future keyword argument support.

* OP_SENDVK

## Removed Instructions

Instructions for old exception handling

* `OP_ONERR`
* `OP_POPERR`
* `OP_EPUSH`
* `OP_EPOP`

No more operand extension

* `OP_EXT1`
* `OP_EXT2`
* `OP_EXT3`

## Changed Instructions

Jump addresses used to be specified by absolute offset from the start of `iseq`. Now they are relative offset from the address of the next instruction.

## `Random` now use `xoshiro128++`.

For better and faster random number generation.

## Preallocated Symbol

Preallocated symbols are interned at compile-time. They can be accessed via symbols macros (e.g. `MRB_SYM()`).

See [Symbols](https://github.com/mruby/mruby/blob/master/doc/guides/symbol.md).
