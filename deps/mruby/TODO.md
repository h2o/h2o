Thing to Do in the future
===

# After mruby 3.0

* replace `fp_fmt.c` by `float_format` (https://github.com/dhylands/format-float.git)
* multi-precision integer
* WORD_BOXING: Pack some floats in `mrb_value`
* NAN_BOXING: Allow `MRB_INT64` along with NaN boxing
* keyword arguments a la Ruby3.0 (using `OP_SENDVK`)
* parser and code generator independent from `mrb_state` (mmruby?)

# Things to do (Things that are not done yet)

* `begin ... end while cond` to behave as CRuby
* special variables ($1,$2..)
* super in aliased methods
