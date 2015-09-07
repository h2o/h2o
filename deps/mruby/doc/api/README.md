# C API Reference

This is a C API Reference.
The structure of this document will follow the directory structure of `include/` directory.

## Headers list
Header name|Features
-----------|--------
[mrbconf.h](../mrbconf/README.md)|Defines macros for mruby configurations.
[mruby.h](./mruby.h.md)|Main header of mruby C API. Include this first.
[mruby/array.h](./mruby/array.h.md)|`Array` class.
[mruby/class.h](./mruby/class.h.md)|`Class` class.
[mruby/compile.h](./mruby/compile.h.md)|mruby compiler.
[mruby/data.h](./mruby/data.h.md)|User defined object.
[mruby/debug.h](./mruby/debug.h.md)|Debugging.
[mruby/dump.h](./mruby/dump.h.md)|Dumping compiled mruby script.
[mruby/error.h](./mruby/error.h.md)|Error handling.
[mruby/gc.h](./mruby/gc.h.md)|Uncommon memory management stuffs.
[mruby/hash.h](./mruby/hash.h.md)|`Hash` class.
[mruby/irep.h](./mruby/irep.h.md)|Compiled mruby script.
[mruby/khash.h](./mruby/khash.h.md)|Defines of khash which is used in hash table of mruby.
[mruby/numeric.h](./mruby/numeric.h.md)|`Numeric` class and sub-classes of it.
[mruby/opode.h](./mruby/opcode.h.md)|Operation codes used in mruby VM.
[mruby/proc.h](./mruby/proc.h.md)|`Proc` class.
[mruby/range.h](./mruby/range.h.md)|`Range` class.
[mruby/re.h](./mruby/re.h.md)|`Regexp` class.
[mruby/string.h](./mruby/string.h.md)|`String` class.
[mruby/value.h](./mruby/value.h.md)|`mrb_value` functions and macros.
[mruby/variable.h](./mruby/variable.h.md)|Functions to access to mruby variables.
[mruby/version.h](./mruby/version.h.md)|Macros of mruby version.
