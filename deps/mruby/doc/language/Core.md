# Core Classes

## Array

ISO Code | Mixins | Source File
--- | --- | ---
15.2.12 |  n/a | src/array.c

### Class Methods

#### []

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.4.1 | src/array.c | mrb_ary_s_create

### Methods

#### *

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.2 | src/array.c | mrb_ary_times

#### +

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.1 | src/array.c | mrb_ary_plus

#### <<

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.3 | src/array.c | mrb_ary_push_m

#### []

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.4 | src/array.c | mrb_ary_aget

#### []=

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.5 | src/array.c | mrb_ary_aset

#### __ary_cmp

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/array.c | mrb_ary_cmp

#### __ary_eq

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/array.c | mrb_ary_eq

#### clear

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.6 | src/array.c | mrb_ary_clear

#### concat

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.8 | src/array.c | mrb_ary_concat_m

#### delete_at

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.9 | src/array.c | mrb_ary_delete_at

#### empty?

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.12 | src/array.c | mrb_ary_empty_p

#### first

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.13 | src/array.c | mrb_ary_first

#### index

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.14 | src/array.c | mrb_ary_index_m

#### initialize_copy

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.16 | src/array.c | mrb_ary_replace_m

#### join

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.17 | src/array.c | mrb_ary_join_m

#### last

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.18 | src/array.c | mrb_ary_last

#### length

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.19 | src/array.c | mrb_ary_size

#### pop

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.21 | src/array.c | mrb_ary_pop

#### push

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.22 | src/array.c | mrb_ary_push_m

#### replace

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.23 | src/array.c | mrb_ary_replace_m

#### reverse

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.24 | src/array.c | mrb_ary_reverse

#### reverse!

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.25 | src/array.c | mrb_ary_reverse_bang

#### rindex

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.26 | src/array.c | mrb_ary_rindex_m

#### shift

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.27 | src/array.c | mrb_ary_shift

#### size

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.28 | src/array.c | mrb_ary_size

#### slice

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.29 | src/array.c | mrb_ary_aget

#### unshift

ISO Code | Source File | C Function
--- | --- | ---
15.2.12.5.30 | src/array.c | mrb_ary_unshift_m

## Exception

ISO Code | Mixins | Source File
--- | --- | ---
15.2.22 |  n/a | src/error.c

### Class Methods

#### exception

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/class.c | mrb_instance_new

### Methods

#### ==

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/error.c | exc_equal

#### backtrace

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/backtrace.c | mrb_exc_backtrace

#### exception

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/error.c | exc_exception

#### initialize

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/error.c | exc_initialize

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/error.c | exc_inspect

#### message

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/error.c | exc_message

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/error.c | exc_to_s

## FalseClass

ISO Code | Mixins | Source File
--- | --- | ---
n/a |  n/a | src/object.c

### Methods

#### &

ISO Code | Source File | C Function
--- | --- | ---
15.2.6.3.1 | src/object.c | false_and

#### ^

ISO Code | Source File | C Function
--- | --- | ---
15.2.6.3.2 | src/object.c | false_xor

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/object.c | false_to_s

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.6.3.3 | src/object.c | false_to_s

#### |

ISO Code | Source File | C Function
--- | --- | ---
15.2.6.3.4 | src/object.c | false_or

## Fixnum

ISO Code | Mixins | Source File
--- | --- | ---
n/a |  n/a | src/numeric.c

### Methods

#### %

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.5 | src/numeric.c | fix_mod

#### &

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.9 | src/numeric.c | fix_and

#### *

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.3 | src/numeric.c | fix_mul

#### +

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.1 | src/numeric.c | fix_plus

#### -

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.2 | src/numeric.c | fix_minus

#### <<

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.12 | src/numeric.c | fix_lshift

#### ==

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.7 | src/numeric.c | fix_equal

#### >>

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.13 | src/numeric.c | fix_rshift

#### ^

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.11 | src/numeric.c | fix_xor

#### divmod

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.30 | src/numeric.c | fix_divmod

#### eql?

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.16 | src/numeric.c | fix_eql

#### hash

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.18 | src/numeric.c | flo_hash

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | fix_to_s

#### to_f

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.23 | src/numeric.c | fix_to_f

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.25 | src/numeric.c | fix_to_s

#### |

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.10 | src/numeric.c | fix_or

#### ~

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.8 | src/numeric.c | fix_rev

## Float

ISO Code | Mixins | Source File
--- | --- | ---
15.2.9 |  n/a | src/numeric.c

### Methods

#### %

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.5 | src/numeric.c | flo_mod

#### *

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.3 | src/numeric.c | flo_mul

#### +

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.1 | src/numeric.c | flo_plus

#### -

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.2 | src/numeric.c | flo_minus

#### ==

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.7 | src/numeric.c | flo_eq

#### ceil

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.8 | src/numeric.c | flo_ceil

#### divmod

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | flo_divmod

#### eql?

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.16 | src/numeric.c | flo_eql

#### finite?

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.9 | src/numeric.c | flo_finite_p

#### floor

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.10 | src/numeric.c | flo_floor

#### infinite?

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.11 | src/numeric.c | flo_infinite_p

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | flo_to_s

#### nan?

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | flo_nan_p

#### round

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.12 | src/numeric.c | flo_round

#### to_f

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.13 | src/numeric.c | flo_to_f

#### to_i

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.14 | src/numeric.c | flo_truncate

#### to_int

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | flo_truncate

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.16 | src/numeric.c | flo_to_s

#### truncate

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.15 | src/numeric.c | flo_truncate

## Hash

ISO Code | Mixins | Source File
--- | --- | ---
15.2.13 |  n/a | src/hash.c

### Methods

#### []

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.2 | src/hash.c | mrb_hash_aget

#### []=

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.3 | src/hash.c | mrb_hash_aset

#### __delete

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.8 | src/hash.c | mrb_hash_delete

#### clear

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.4 | src/hash.c | mrb_hash_clear

#### default

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.5 | src/hash.c | mrb_hash_default

#### default=

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.6 | src/hash.c | mrb_hash_set_default

#### default_proc

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.7 | src/hash.c | mrb_hash_default_proc

#### default_proc=

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.7 | src/hash.c | mrb_hash_set_default_proc

#### dup

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/hash.c | mrb_hash_dup

#### empty?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.12 | src/hash.c | mrb_hash_empty_p

#### has_key?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.13 | src/hash.c | mrb_hash_has_key

#### has_value?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.14 | src/hash.c | mrb_hash_has_value

#### include?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.15 | src/hash.c | mrb_hash_has_key

#### initialize

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.16 | src/hash.c | mrb_hash_init

#### key?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.18 | src/hash.c | mrb_hash_has_key

#### keys

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.19 | src/hash.c | mrb_hash_keys

#### length

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.20 | src/hash.c | mrb_hash_size_m

#### member?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.21 | src/hash.c | mrb_hash_has_key

#### shift

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.24 | src/hash.c | mrb_hash_shift

#### size

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.25 | src/hash.c | mrb_hash_size_m

#### store

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.26 | src/hash.c | mrb_hash_aset

#### to_hash

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.29 | src/hash.c | mrb_hash_to_hash

#### value?

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.27 | src/hash.c | mrb_hash_has_value

#### values

ISO Code | Source File | C Function
--- | --- | ---
15.2.13.4.28 | src/hash.c | mrb_hash_values

## Integer

ISO Code | Mixins | Source File
--- | --- | ---
15.2.8 |  n/a | src/numeric.c

### Methods

#### to_i

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.24 | src/numeric.c | int_to_i

#### to_int

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | int_to_i

## NilClass

ISO Code | Mixins | Source File
--- | --- | ---
n/a |  n/a | src/object.c

### Methods

#### &

ISO Code | Source File | C Function
--- | --- | ---
15.2.4.3.1 | src/object.c | false_and

#### ^

ISO Code | Source File | C Function
--- | --- | ---
15.2.4.3.2 | src/object.c | false_xor

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/object.c | nil_inspect

#### nil?

ISO Code | Source File | C Function
--- | --- | ---
15.2.4.3.4 | src/object.c | mrb_true

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.4.3.5 | src/object.c | nil_to_s

#### |

ISO Code | Source File | C Function
--- | --- | ---
15.2.4.3.3 | src/object.c | false_or

## Numeric

ISO Code | Mixins | Source File
--- | --- | ---
15.2.7 |  n/a | src/numeric.c

### Methods

#### **

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/numeric.c | num_pow

#### /

ISO Code | Source File | C Function
--- | --- | ---
15.2.8.3.4 | src/numeric.c | num_div

#### <=>

ISO Code | Source File | C Function
--- | --- | ---
15.2.9.3.6 | src/numeric.c | num_cmp

#### quo

ISO Code | Source File | C Function
--- | --- | ---
15.2.7.4.5 | src/numeric.c | num_div

## Proc

ISO Code | Mixins | Source File
--- | --- | ---
15.2.17 |  n/a | src/proc.c

### Methods

#### arity

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/proc.c | mrb_proc_arity

#### initialize

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/proc.c | mrb_proc_initialize

#### initialize_copy

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/proc.c | mrb_proc_init_copy

## Range

ISO Code | Mixins | Source File
--- | --- | ---
15.2.14 |  n/a | src/range.c

### Methods

#### ==

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.1 | src/range.c | mrb_range_eq

#### ===

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.2 | src/range.c | mrb_range_include

#### begin

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.3 | src/range.c | mrb_range_beg

#### end

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.5 | src/range.c | mrb_range_end

#### eql?

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.14 | src/range.c | range_eql

#### exclude_end?

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.6 | src/range.c | mrb_range_excl

#### first

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.7 | src/range.c | mrb_range_beg

#### include?

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.8 | src/range.c | mrb_range_include

#### initialize

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.9 | src/range.c | mrb_range_initialize

#### initialize_copy

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.15 | src/range.c | range_initialize_copy

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.13 | src/range.c | range_inspect

#### last

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.10 | src/range.c | mrb_range_end

#### member?

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.11 | src/range.c | mrb_range_include

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.14.4.12 | src/range.c | range_to_s

## RuntimeError

ISO Code | Mixins | Source File
--- | --- | ---
15.2.28 |  n/a | src/error.c

## ScriptError

ISO Code | Mixins | Source File
--- | --- | ---
15.2.37 |  n/a | src/error.c

## StandardError

ISO Code | Mixins | Source File
--- | --- | ---
15.2.23 |  n/a | src/error.c

## String

ISO Code | Mixins | Source File
--- | --- | ---
15.2.10 |  n/a | src/string.c

### Methods

#### *

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.5 | src/string.c | mrb_str_times

#### +

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.4 | src/string.c | mrb_str_plus_m

#### <=>

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.1 | src/string.c | mrb_str_cmp_m

#### ==

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.2 | src/string.c | mrb_str_equal_m

#### []

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.6 | src/string.c | mrb_str_aref_m

#### bytes

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/string.c | mrb_str_bytes

#### bytesize

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/string.c | mrb_str_size

#### capitalize

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.7 | src/string.c | mrb_str_capitalize

#### capitalize!

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.8 | src/string.c | mrb_str_capitalize_bang

#### chomp

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.9 | src/string.c | mrb_str_chomp

#### chomp!

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.10 | src/string.c | mrb_str_chomp_bang

#### chop

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.11 | src/string.c | mrb_str_chop

#### chop!

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.12 | src/string.c | mrb_str_chop_bang

#### downcase

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.13 | src/string.c | mrb_str_downcase

#### downcase!

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.14 | src/string.c | mrb_str_downcase_bang

#### empty?

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.16 | src/string.c | mrb_str_empty_p

#### eql?

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.17 | src/string.c | mrb_str_eql

#### hash

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.20 | src/string.c | mrb_str_hash_m

#### include?

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.21 | src/string.c | mrb_str_include

#### index

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.22 | src/string.c | mrb_str_index_m

#### initialize

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.23 | src/string.c | mrb_str_init

#### initialize_copy

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.24 | src/string.c | mrb_str_replace

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.46 | src/string.c | mrb_str_inspect

#### intern

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.25 | src/string.c | mrb_str_intern

#### length

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.26 | src/string.c | mrb_str_size

#### replace

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.28 | src/string.c | mrb_str_replace

#### reverse

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.29 | src/string.c | mrb_str_reverse

#### reverse!

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.30 | src/string.c | mrb_str_reverse_bang

#### rindex

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.31 | src/string.c | mrb_str_rindex_m

#### size

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.33 | src/string.c | mrb_str_size

#### slice

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.34 | src/string.c | mrb_str_aref_m

#### split

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.35 | src/string.c | mrb_str_split_m

#### to_f

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.38 | src/string.c | mrb_str_to_f

#### to_i

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.39 | src/string.c | mrb_str_to_i

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.40 | src/string.c | mrb_str_to_s

#### to_str

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/string.c | mrb_str_to_s

#### to_sym

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.41 | src/string.c | mrb_str_intern

#### upcase

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.42 | src/string.c | mrb_str_upcase

#### upcase!

ISO Code | Source File | C Function
--- | --- | ---
15.2.10.5.43 | src/string.c | mrb_str_upcase_bang

## Symbol

ISO Code | Mixins | Source File
--- | --- | ---
15.2.11 |  n/a | src/symbol.c

### Methods

#### <=>

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/symbol.c | sym_cmp

#### ===

ISO Code | Source File | C Function
--- | --- | ---
15.2.11.3.1 | src/symbol.c | sym_equal

#### id2name

ISO Code | Source File | C Function
--- | --- | ---
15.2.11.3.2 | src/symbol.c | mrb_sym_to_s

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
15.2.11.3.5 | src/symbol.c | sym_inspect

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.11.3.3 | src/symbol.c | mrb_sym_to_s

#### to_sym

ISO Code | Source File | C Function
--- | --- | ---
15.2.11.3.4 | src/symbol.c | sym_to_sym

## SyntaxError

ISO Code | Mixins | Source File
--- | --- | ---
15.2.38 |  n/a | src/error.c

## TrueClass

ISO Code | Mixins | Source File
--- | --- | ---
n/a |  n/a | src/object.c

### Methods

#### &

ISO Code | Source File | C Function
--- | --- | ---
15.2.5.3.1 | src/object.c | true_and

#### ^

ISO Code | Source File | C Function
--- | --- | ---
15.2.5.3.2 | src/object.c | true_xor

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/object.c | true_to_s

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.2.5.3.3 | src/object.c | true_to_s

#### |

ISO Code | Source File | C Function
--- | --- | ---
15.2.5.3.4 | src/object.c | true_or

# Core Modules

## Comparable

ISO Code | Source File
--- | ---
15.3.3 | src/compar.c

## Enumerable

ISO Code | Source File
--- | ---
15.3.2 | src/enum.c

## GC

ISO Code | Source File
--- | ---
n/a | src/gc.c

### Class Methods

#### disable

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_disable

#### enable

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_enable

#### generational_mode

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_generational_mode_get

#### generational_mode=

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_generational_mode_set

#### interval_ratio

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_interval_ratio_get

#### interval_ratio=

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_interval_ratio_set

#### start

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_start

#### step_ratio

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_step_ratio_get

#### step_ratio=

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_step_ratio_set

#### test

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/gc.c | gc_test

## Kernel

ISO Code | Source File
--- | ---
15.3.1 | src/kernel.c

### Class Methods

#### block_given?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.2.2 | src/kernel.c | mrb_f_block_given_p_m

#### global_variables

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.2.4 | src/kernel.c | mrb_f_global_variables

#### iterator?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.2.5 | src/kernel.c | mrb_f_block_given_p_m

#### local_variables

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.2.7 | src/kernel.c | mrb_local_variables

#### raise

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.2.12 | src/kernel.c | mrb_f_raise

### Methods

#### !=

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/kernel.c | mrb_obj_not_equal_m

#### ==

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.1 | src/kernel.c | mrb_obj_equal_m

#### ===

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.2 | src/kernel.c | mrb_equal_m

#### __case_eqq

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/kernel.c | mrb_obj_ceqq

#### __id__

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.3 | src/kernel.c | mrb_obj_id_m

#### __send__

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.4 | src/kernel.c | mrb_f_send

#### block_given?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.6 | src/kernel.c | mrb_f_block_given_p_m

#### class

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.7 | src/kernel.c | mrb_obj_class_m

#### clone

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.8 | src/kernel.c | mrb_obj_clone

#### define_singleton_method

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/kernel.c | mod_define_singleton_method

#### dup

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.9 | src/kernel.c | mrb_obj_dup

#### eql?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.10 | src/kernel.c | mrb_obj_equal_m

#### equal?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.11 | src/kernel.c | mrb_obj_equal_m

#### extend

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.13 | src/kernel.c | mrb_obj_extend_m

#### global_variables

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.14 | src/kernel.c | mrb_f_global_variables

#### hash

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.15 | src/kernel.c | mrb_obj_hash

#### initialize_copy

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.16 | src/kernel.c | mrb_obj_init_copy

#### inspect

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.17 | src/kernel.c | mrb_obj_inspect

#### instance_eval

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.18 | src/kernel.c | mrb_obj_instance_eval

#### instance_of?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.19 | src/kernel.c | obj_is_instance_of

#### instance_variable_defined?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.20 | src/kernel.c | mrb_obj_ivar_defined

#### instance_variable_get

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.21 | src/kernel.c | mrb_obj_ivar_get

#### instance_variable_set

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.22 | src/kernel.c | mrb_obj_ivar_set

#### instance_variables

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.23 | src/kernel.c | mrb_obj_instance_variables

#### is_a?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.24 | src/kernel.c | mrb_obj_is_kind_of_m

#### iterator?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.25 | src/kernel.c | mrb_f_block_given_p_m

#### kind_of?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.26 | src/kernel.c | mrb_obj_is_kind_of_m

#### local_variables

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.28 | src/kernel.c | mrb_local_variables

#### methods

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.31 | src/kernel.c | mrb_obj_methods_m

#### nil?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.32 | src/kernel.c | mrb_false

#### object_id

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.33 | src/kernel.c | mrb_obj_id_m

#### private_methods

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.36 | src/kernel.c | mrb_obj_private_methods

#### protected_methods

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.37 | src/kernel.c | mrb_obj_protected_methods

#### public_methods

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.38 | src/kernel.c | mrb_obj_public_methods

#### raise

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.40 | src/kernel.c | mrb_f_raise

#### remove_instance_variable

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.41 | src/kernel.c | mrb_obj_remove_instance_variable

#### respond_to?

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.43 | src/kernel.c | obj_respond_to

#### send

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.44 | src/kernel.c | mrb_f_send

#### singleton_class

ISO Code | Source File | C Function
--- | --- | ---
n/a | src/kernel.c | mrb_singleton_class

#### singleton_methods

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.45 | src/kernel.c | mrb_obj_singleton_methods_m

#### to_s

ISO Code | Source File | C Function
--- | --- | ---
15.3.1.3.46 | src/kernel.c | mrb_any_to_s

