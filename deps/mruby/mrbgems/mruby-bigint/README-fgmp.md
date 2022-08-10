# fgmp

FGMP is a public domain implementation of a subset of the GNU gmp library with the same API.

WELCOME TO FGMP.

FGMP is a public domain implementation of a subset of the GNU gmp library
with the same API.

For instance, you can link the following trivial program with either
this code, or libgmp.a and get the same results.

``` C
#include <stdio.h>
#include "gmp.h"
main()
{
    MP_INT a; MP_INT b; MP_INT c;

    mpz_init_set_ui(&a,1); mpz_init_set_ui(&b,2); mpz_init(&c);
    mpz_add(&c,&a,&b);
    printf("\n%s\n", mpz_get_str(NULL,10,&c));
}
```

FGMP is really in the public domain. You can do whatever you want with
it.

I wrote FGMP so that we would all have access to a (truly free)
implementation of this subset of the API of GNU libgmp. I encourage
everyone to distribute this as widely as possible.

If you need more documentation, I suggest you look at the file
gmp.texi which is included with the GNU gmp library.

You can send me bug reports, implementations of missing functions, flames
and rants by Email.

Any submissions of new code to be integrated into fgmp must also be
placed in the public domain (For the particularly dense, you can
release a new fgmp yourself under different licensing terms. This
is a condition for including a submission in a release of FGMP that
I personally prepare).

Mark Henderson <markh@wimsey.bc.ca>

# This is the fifth BETA release. 1.0b5

I hearby place this file and all of FGMP in the public domain.

Thanks to Paul Rouse <par@r-cube.demon.co.uk> for changes to get fgmp
to work on a 286 MS-DOS compiler, the functions mpz_sqrt and
mpz_sqrtrem, plus other general bug fixes.

Thanks also to Erick Gallesio <eg@kaolin.unice.fr> for a fix
to mpz_init_set_str

Define B64 if your "long" type is 64 bits. Otherwise we assume 32
bit longs. (The 64 bit version hasn't been tested enough)

```
Platforms:
Linux 0.99 (gcc)
IBM RS6000/AIX 3.2 (IBM xlc compiler and gcc 2.3)
Sun OS 4.1, Sun 3/4
DEC Alpha OSF/1 (only lightly tested, 64 bit longs do make a difference,
    thanks to DEC for providing access via axposf.pa.dec.com). Define B64
    for this platform
MS-DOS 286 C compiler (see credits above)
```

# Some differences between gmp and fgmp

1. fgmp is considerably slower than gmp
2. fgmp does not implement the following:
    all mpq_*
    internal mpn_* functions
    mpz_perfect_square_p
    mpz_inp_raw, mpz_out_raw
    mp_set_memory_functions, mpz_out_str, mpz_inp_str
3. fgmp implements the following in addition to the routines in GNU gmp.
    `int mpz_jacobi(MP_INT *a, MP_INT *b)`
    - finds the jacobi symbol (a/b)
4. mpz_sizeinbase often overestimates the exact value

5. To convert your gmp based program to fgmp (subject to the
above)

- recompile your source. Make sure to include the gmp.h file included
  with fgmp rather than that included with gmp. (The point is to recompile
  all files which include gmp.h)
- link with gmp.o instead of libgmp.a

Here's a complete sorted list of function implemented in fgmp:

```
_mpz_realloc
mpz_abs
mpz_add
mpz_add_ui
mpz_and
mpz_clear
mpz_cmp
mpz_cmp_si
mpz_cmp_ui
mpz_div
mpz_div_2exp
mpz_div_ui
mpz_divmod
mpz_divmod_ui
mpz_fac_ui
mpz_gcd
mpz_gcdext
mpz_get_si
mpz_get_str
mpz_get_ui
mpz_init
mpz_init_set
mpz_init_set_si
mpz_init_set_str
mpz_init_set_ui
mpz_jacobi
mpz_mdiv
mpz_mdiv_ui
mpz_mdivmod
mpz_mdivmod_ui
mpz_mmod
mpz_mmod_ui
mpz_mod
mpz_mod_2exp
mpz_mod_ui
mpz_mul
mpz_mul_2exp
mpz_mul_ui
mpz_neg
mpz_or
mpz_pow_ui
mpz_powm
mpz_powm_ui
mpz_probab_prime_p
mpz_random
mpz_random2
mpz_set
mpz_set_si
mpz_set_str
mpz_set_ui
mpz_size
mpz_sizeinbase
mpz_sqrt
mpz_sqrtrem
mpz_sub
mpz_sub_ui
mpz_xor
```
