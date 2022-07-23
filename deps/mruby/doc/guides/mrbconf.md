# mruby configuration macros

## How to use these macros

You can use mrbconfs with following ways:

* Write them in `mrbconf.h`.
  * Using compiler flags is preferred  when building a cross binaries or multiple mruby binaries
    since it's easier to use different mrbconf per each `MRuby::Build`.
  * Most flags can be enabled by just commenting in.
* Pass them as compiler flags.
  * Make sure you pass the same flags to all compilers since some mrbconf(e.g., `MRB_GC_FIXED_ARENA`)
    changes `struct` layout and cause memory access error when C and other language(e.g., C++) is mixed.

## stdio setting

`MRB_NO_STDIO`

* When defined `<stdio.h>` functions won't be used.
* Some features will be disabled when this is enabled:
  * `mrb_irep` load/dump from/to file.
  * Compiling mruby script from a file.
  * Printing features in **src/print.c**.

## Debug macros

`MRB_USE_DEBUG_HOOK`

* When defined code fetch hook and debug OP hook will be enabled.
* When using any of the hook set function pointer `code_fetch_hook` and/or `debug_op_hook` of `mrb_state`.
* Fetch hook will be called before any OP.
* Debug OP hook will be called when dispatching `OP_DEBUG`.

`MRB_DEBUG`

* When defined `mrb_assert*` macro will be defined with macros from `<assert.h>`.
* Could be enabled via `enable_debug` method of `MRuby::Build`.

## Stack configuration

`MRB_STACK_EXTEND_DOUBLING`

* If defined doubles the stack size when extending it.
* Else extends stack with `MRB_STACK_GROWTH`.

`MRB_STACK_GROWTH`

* Default value is `128`.
* Used in stack extending.
* Ignored when `MRB_STACK_EXTEND_DOUBLING` is defined.

`MRB_STACK_MAX`

* Default value is `0x40000 - MRB_STACK_GROWTH`.
* Raises `RuntimeError` when stack size exceeds this value.

## Primitive type configuration

`MRB_USE_FLOAT32`

* When defined single precision floating-point type(C type `float`) is used as `mrb_float`.
* Otherwise, double precision floating-point type(C type `double`) is used as `mrb_float`.

`MRB_NO_FLOAT`

* When defined removes floating-point numbers from mruby.
* It makes mruby easier to handle in "Microcontroller without FPU" and "Kernel Space".

`MRB_INT32`

* When defined, or `MRB_INT64` are not defined on 32-bit CPU mode, `mrb_int` will be defined as `int32_t`.
* Conflicts with `MRB_INT64`.

`MRB_INT64`

* When defined, or `MRB_INT32` are not defined on 64-bit CPU mode, `mrb_int` will be defined as `int64_t`.
* Conflicts with `MRB_INT32`.

## Garbage collector configuration

`MRB_GC_STRESS`

* When defined full GC is emitted per each `RBasic` allocation.
* Mainly used in memory manager debugging.

`MRB_GC_TURN_OFF_GENERATIONAL`

* When defined turns generational GC by default.

`MRB_GC_FIXED_ARENA`

* When defined used fixed size GC arena.
* Raises `RuntimeError` when this is defined and GC arena size exceeds `MRB_GC_ARENA_SIZE`.
* Useful tracking unnecessary mruby object allocation.

`MRB_GC_ARENA_SIZE`

* Default value is `100`.
* Ignored when `MRB_GC_FIXED_ARENA` isn't defined.
* Defines fixed GC arena size.

`MRB_HEAP_PAGE_SIZE`

* Defines value is `1024`.
* Specifies number of `RBasic` per each heap page.

## Memory pool configuration

`POOL_ALIGNMENT`

* Default value is `4`.
* If you're allocating data types that requires alignment more than default value define the
largest value of required alignment.

`POOL_PAGE_SIZE`

* Default value is `16000`.
* Specifies page size of pool page.
* Smaller the value is increases memory overhead.

## State atexit configuration

`MRB_FIXED_STATE_ATEXIT_STACK`

* If defined enables fixed size `mrb_state` atexit stack.
* Raises `RuntimeError` when `mrb_state_atexit` call count to same `mrb_state` exceeds
`MRB_FIXED_STATE_ATEXIT_STACK_SIZE`'s value.

`MRB_FIXED_STATE_ATEXIT_STACK_SIZE`

* Default value is `5`.
* If `MRB_FIXED_STATE_ATEXIT_STACK` isn't defined this macro is ignored.

## `mrb_value` configuration

`MRB_ENDIAN_BIG`

* If defined compiles mruby for big endian machines.
* Used in `MRB_NAN_BOXING`.
* Some mrbgem use this mrbconf.

`MRB_NAN_BOXING`

* If defined represent `mrb_value` in boxed `double`.
* Conflicts with `MRB_USE_FLOAT32` and `MRB_NO_FLOAT`.

`MRB_WORD_BOXING`

* If defined represent `mrb_value` as a word.
* If defined `Float` will be a mruby object with `RBasic`.

## Reduce heap memory configuration

`MRB_USE_ETEXT_RO_DATA_P`

* Use `etext` and `edata` section addresses defined by the linker to detect read-only data.
* Those addresses are widely available, but not portable, nor standardized.
* This macro is defined by default on User-mode Linux.

`MRB_NO_DEFAULT_RO_DATA_P`

* Define this macro when the default `mrb_ro_data_p()` does not work for any reason.

`MRB_USE_CUSTOM_RO_DATA_P`

* Please try if `MRB_USE_LINK_TIME_RO_DATA_P` is not available.
* The `mrb_ro_data_p()` function is implemented by the user in an arbitrary file.
* The prototype declaration is `mrb_bool mrb_ro_data_p(const char *ptr)`.
* Return `TRUE` if `ptr` is in the read-only section, otherwise return `FALSE`.

## Other configuration

`MRB_UTF8_STRING`

* Adds UTF-8 encoding support to character-oriented String instance methods.
* If it isn't defined, they only support the US-ASCII encoding.

`MRB_FUNCALL_ARGC_MAX`

* Default value is `16`.
* Specifies 4th argument(`argc`) max value of `mrb_funcall`.
* Raises `ArgumentError` when the `argc` argument is bigger then this value `mrb_funcall`.

`KHASH_DEFAULT_SIZE`

* Default value is `32`.
* Specifies default size of khash table bucket.
* Used in `kh_init_ ## name` function.

`MRB_NO_METHOD_CACHE`

* Disable method cache to save memory.

`MRB_METHOD_CACHE_SIZE`

* Default value is `256`.
* Ignored if `MRB_NO_METHOD_CACHE` is defined.
* Need to be the power of 2.

`MRB_USE_METHOD_T_STRUCT`

* Use C struct to represent `mrb_method_t`
* No `MRB_USE_METHOD_T_STRUCT` requires highest 2 bits of function pointers to be zero
* Define this macro on machines that use higher bits of pointers

`MRB_USE_ALL_SYMBOLS`

* Make it available `Symbol.all_symbols` in `mrbgems/mruby-symbol-ext`
* Increase heap memory usage.
