# Symbols

Symbols in `mruby` C source code is represented by `mrb_sym` which is alias of
`uint32_t`.  Lower 30 bits are used for symbols so that higher 2 bits can be
used as flags, e.g. `struct mt_elem` in `class.c`.

```c
struct mt_elem {
  union mt_ptr ptr;
  size_t func_p:1;
  size_t noarg_p:1;
  mrb_sym key:sizeof(mrb_sym)*8-2;
};
```

## C API

We provide following C API for symbols.

### Generate Symbols

#### `mrb_sym mrb_intern(mrb_state*,const char*,size_t)`

Get a symbol from a string.

#### `mrb_sym mrb_intern_check_cstr(mrb_state*,const char*)`

Get a symbol from a NULL terminated (C) string.

#### `mrb_sym mrb_intern_str(mrb_state*,mrb_value)`

Get a symbol from a Ruby string object.

#### `mrb_intern_lit(mrb_state*,const char*)`

Get a symbol from a C string literal. The second argument should be a C string
literal, otherwise you will get a compilation error. It does not copy C string
given the fact it's a literal.

#### `mrb_sym mrb_intern_check(mrb_state*,const char*,size_t)`

Get a symbol from a string if the string has been already registered as a
symbol, otherwise return `0`. We also provide variants `mrb_intern_check_str()`
(from Ruby string) and `mrb_intern_check_cstr()` (from C string).

#### `const char *mrb_sym_name(mrb_state*,mrb_sym)`

Get a string representation of a symbol as a C string.

#### `const char *mrb_sym_name_len(mrb_state*,mrb_sym,mrb_int*)`

Get a string representation of a symbol, and its length.

## Preallocate Symbols

To save RAM, `mruby` can use compile-time allocation of some symbols. You can
use following macros to get preallocated symbols by including `mruby/presym.h`
header.

* `MRB_SYM(xor)`    //=> xor    (Word characters)
* `MRB_SYM_B(xor)`  //=> xor!   (Method with Bang)
* `MRB_SYM_Q(xor)`  //=> xor?   (Method with Question mark)
* `MRB_SYM_E(xor)`  //=> xor=   (Method with Equal)
* `MRB_CVSYM(xor)`  //=> @@xor  (Class Variable)
* `MRB_IVSYM(xor)`  //=> @xor   (Instance Variable)
* `MRB_OPSYM(xor)`  //=> ^      (Operator)

For `MRB_OPSYM()`, specify the names corresponding to operators (see
`MRuby::Presym::OPERATORS` in `lib/mruby/presym.rb` for the names that
can be specified for it). Other than that, describe only word characters
excluding leading and ending punctuations.

These macros are converted to static symbol IDs at compile time, unless
preallocate symbols are disabled by  `conf.disable_presym`. In that case,
these macros are expanded to `mrb_intern_lit` calls, therefore the mruby state
variable is required. The above macros assume the variable name is `mrb`.  If
its name is not `mrb`, you need to use macros with `_2` suffix, such as
`MRB_SYM_2` to specify `mrb_state*` variable.

### Disabling Preallocated Symbols

You can disable preallocated symbols by specifying `conf.disable_presym` in the
configuration file.
