# Boxing

The mruby objects and data are represented by C data type `mrb_value`. There are three options how to pack the data values in the `mrb_value`.

* Word Boxing
* NaN Boxing
* No Boxing

## Word Boxing

Word boxing packs the Ruby data in a word, which is a natural integer size that equals to the size of pointers (`intptr_t`). Word boxing can be specified by `MRB_WORD_BOXING`, and it's default configuration for most platforms.

Some values (called immediate values, e.g. integers, booleans, symbols, etc.) are directly packed in the word. The other data types are represented by pointers to the heap allocated structures.

The Word boxing packing bit patterns are like following:

| Types  | Bit Pattern                         |
|--------|-------------------------------------|
| object | xxxxxxxx xxxxxxxx xxxxxxxx xxxxx000 |
| fixnum | xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxx1 |
| nil    | 00000000 00000000 00000000 00000000 |
| true   | 00000000 00000000 00000000 00001100 |
| false  | 00000000 00000000 00000000 00000100 |
| undef  | 00000000 00000000 00000000 00010100 |
| symbol | xxxxxxxx xxxxxxxx xxxxxxxx xxxxxx10 |

On 64 bit platform (unless `MRB_WORDBOX_NO_FLOAT_TRUNCATE`), float values are also packed in the `mrb_value`. In that case, we drop least significant 2 bits from mantissa.
If you need full precision for floating point numbers, define `MRB_WORDBOX_NO_FLOAT_TRUNCATE`.

## NaN Boxing

NaN boxing packs the Ruby data in a floating point numbers, which represent NaN (Not a Number) values. Under IEEE753 definitions every value that exponent is all set are considered as NaN. That means NaN can represent `2^51` values. NaN boxing is a teaching to pack the values in those NaN representation. In theory, 64 bits pointers are too big to fit in NaN, but practically most OS uses only 48 bits at most for pointers (except for some OS e.g. Solaris).

The NaN boxing packing bit patterns are like following:

| Types  | Bit Pattern                                                             |
|--------|-------------------------------------------------------------------------|
| float  | SEEEEEEE EEEEFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF |
| +/-inf | S1111111 11110000 00000000 00000000 00000000 00000000 00000000 00000000 |
| nan    | 01111111 11111000 00000000 00000000 00000000 00000000 00000000 00000000 |
| fixnum | 01111111 11111001 00000000 00000000 IIIIIIII IIIIIIII IIIIIIII IIIIIIII |
| symbol | 01111111 11111110 00000000 00000000 SSSSSSSS SSSSSSSS SSSSSSSS SSSSSSSS |
| misc   | 01111111 11111111 00000000 00000000 00000000 00000000 00TTTTTT 0000MMMM |
| object | 01111111 11111100 PPPPPPPP PPPPPPPP PPPPPPPP PPPPPPPP PPPPPPPP PPPPPP00 |
| ptr    | 01111111 11111100 PPPPPPPP PPPPPPPP PPPPPPPP PPPPPPPP PPPPPPPP PPPPPP01 |
| nil    | 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 |

The object values appear far more frequently than floating point numbers, so we offset the value so that object pointers are unchanged. This technique is called "favor pointer"".

## No Boxing

No boxing represents `mrb_value` by the C struct with `type` and the value union. This is the most portable (but inefficient) representation. No boxing can be specified by `MRB_NO_BOXING`, and it's default for debugging configuration (e.g. `host-debug`).
