/*
** random.c - Random module
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/variable.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/array.h>
#include <mruby/istruct.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <time.h>

/*  Written in 2019 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <https://creativecommons.org/publicdomain/zero/1.0/>. */

/* This is xoshiro128++ 1.0, one of our 32-bit all-purpose, rock-solid
   generators. It has excellent speed, a state size (128 bits) that is
   large enough for mild parallelism, and it passes all tests we are aware
   of.

   For generating just single-precision (i.e., 32-bit) floating-point
   numbers, xoshiro128+ is even faster.

   The state must be seeded so that it is not everywhere zero. */


#ifdef MRB_32BIT
# define XORSHIFT96
# define NSEEDS 3
# define SEEDPOS 2
#else
# define NSEEDS 4
# define SEEDPOS 0
#endif
#define LASTSEED (NSEEDS-1)

typedef struct rand_state {
  uint32_t seed[NSEEDS];
} rand_state;

static void
rand_init(rand_state *t)
{
  t->seed[0] = 123456789;
  t->seed[1] = 362436069;
  t->seed[2] = 521288629;
#ifndef XORSHIFT96
  t->seed[3] = 88675123;
#endif
}

static uint32_t rand_uint32(rand_state *state);

static uint32_t
rand_seed(rand_state *t, uint32_t seed)
{
  uint32_t old_seed = t->seed[SEEDPOS];
  rand_init(t);
  t->seed[SEEDPOS] = seed;
  for (int i = 0; i < 10; i++) {
    rand_uint32(t);
  }
  return old_seed;
}

#ifndef XORSHIFT96
static inline uint32_t
rotl(const uint32_t x, int k) {
  return (x << k) | (x >> (32 - k));
}
#endif

static uint32_t
rand_uint32(rand_state *state)
{
#ifdef XORSHIFT96
  uint32_t *seed = state->seed;
  uint32_t x = seed[0];
  uint32_t y = seed[1];
  uint32_t z = seed[2];
  uint32_t t;

  t = (x ^ (x << 3)) ^ (y ^ (y >> 19)) ^ (z ^ (z << 6));
  x = y; y = z; z = t;
  seed[0] = x;
  seed[1] = y;
  seed[2] = z;

  return z;
#else
  uint32_t *s = state->seed;
  const uint32_t result = rotl(s[0] + s[3], 7) + s[0];
  const uint32_t t = s[1] << 9;

  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];

  s[2] ^= t;
  s[3] = rotl(s[3], 11);

  return result;
#endif  /* XORSHIFT96 */
  }

#ifndef MRB_NO_FLOAT
static double
rand_real(rand_state *t)
{
  uint32_t x = rand_uint32(t);
  return x*(1.0/4294967296.0);
}
#endif

static mrb_value
random_rand(mrb_state *mrb, rand_state *t, mrb_int max)
{
  if (max == 0) {
#ifndef MRB_NO_FLOAT
    return mrb_float_value(mrb, rand_real(t));
#else
    max = 100;
#endif
  }
  return mrb_int_value(mrb, rand_uint32(t) % max);
}

static mrb_int
random_rand_i(mrb_state *mrb, rand_state *t, mrb_int max)
{
  return rand_uint32(t) % max;
}

static mrb_int
get_opt(mrb_state* mrb)
{
  mrb_int arg;

  arg = 0;
  mrb_get_args(mrb, "|i", &arg);
  if (arg < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
  }
  return arg;
}

static mrb_value
random_default(mrb_state *mrb) {
  struct RClass *c = mrb_class_get_id(mrb, MRB_SYM(Random));
  mrb_value d = mrb_const_get(mrb, mrb_obj_value(c), MRB_SYM(DEFAULT));
  if (!mrb_obj_is_kind_of(mrb, d, c)) {
    mrb_raise(mrb, E_TYPE_ERROR, "Random::DEFAULT replaced");
  }
  return d;
}

#define random_ptr(v) (rand_state*)mrb_istruct_ptr(v)
#define random_default_state(mrb) random_ptr(random_default(mrb))

static mrb_value
random_m_init(mrb_state *mrb, mrb_value self)
{
  mrb_int seed;
  rand_state *t;

  t = random_ptr(self);
  if (mrb_get_args(mrb, "|i", &seed) == 0) {
    rand_init(t);
  }
  else {
    rand_seed(t, (uint32_t)seed);
  }

  return self;
}

static mrb_value
random_m_rand(mrb_state *mrb, mrb_value self)
{
  mrb_int max;
  rand_state *t = random_ptr(self);

  max = get_opt(mrb);
  return random_rand(mrb, t, max);
}

static mrb_value
random_m_srand(mrb_state *mrb, mrb_value self)
{
  uint32_t seed;
  uint32_t old_seed;
  mrb_int i;
  rand_state *t = random_ptr(self);

  if (mrb_get_args(mrb, "|i", &i) == 0) {
    seed = (uint32_t)time(NULL) + rand_uint32(t);
  }
  else {
    seed = (uint32_t)i;
  }
  old_seed = rand_seed(t, seed);

  return mrb_int_value(mrb, (mrb_int)old_seed);
}

static mrb_value
random_m_bytes(mrb_state *mrb, mrb_value self)
{
  rand_state *t = random_ptr(self);

  mrb_int i;
  mrb_get_args(mrb, "i", &i);

  mrb_value bytes = mrb_str_new(mrb, NULL, i);
  uint8_t *p = (uint8_t*)RSTRING_PTR(bytes);
  for (; i > 0; i--, p++) {
    *p = (uint8_t)rand_uint32(t);
  }

  return bytes;
}

/*
 *  call-seq:
 *     ary.shuffle!   ->   ary
 *
 *  Shuffles elements in self in place.
 */

static mrb_value
mrb_ary_shuffle_bang(mrb_state *mrb, mrb_value ary)
{
  mrb_int i, max;
  rand_state *random;

  if (RARRAY_LEN(ary) > 1) {
    struct RClass *c = mrb_class_get_id(mrb, MRB_SYM(Random));
    if (mrb_get_args(mrb, "|I", &random, c) == 0) {
      random = random_default_state(mrb);
    }
    mrb_ary_modify(mrb, mrb_ary_ptr(ary));
    max = RARRAY_LEN(ary);
    for (i = RARRAY_LEN(ary) - 1; i > 0; i--)  {
      mrb_int j;
      mrb_value *ptr = RARRAY_PTR(ary);
      mrb_value tmp;

      j = random_rand_i(mrb, random, max);

      tmp = ptr[i];
      ptr[i] = ptr[j];
      ptr[j] = tmp;
    }
  }

  return ary;
}

/*
 *  call-seq:
 *     ary.shuffle   ->   new_ary
 *
 *  Returns a new array with elements of self shuffled.
 */

static mrb_value
mrb_ary_shuffle(mrb_state *mrb, mrb_value ary)
{
  mrb_value new_ary = mrb_ary_new_from_values(mrb, RARRAY_LEN(ary), RARRAY_PTR(ary));
  mrb_ary_shuffle_bang(mrb, new_ary);

  return new_ary;
}

/*
 *  call-seq:
 *     ary.sample      ->   obj
 *     ary.sample(n)   ->   new_ary
 *
 *  Choose a random element or +n+ random elements from the array.
 *
 *  The elements are chosen by using random and unique indices into the array
 *  in order to ensure that an element doesn't repeat itself unless the array
 *  already contained duplicate elements.
 *
 *  If the array is empty the first form returns +nil+ and the second form
 *  returns an empty array.
 */

static mrb_value
mrb_ary_sample(mrb_state *mrb, mrb_value ary)
{
  mrb_int n = 0;
  mrb_bool given;
  rand_state *random;
  mrb_int len;
  struct RClass *c = mrb_class_get_id(mrb, MRB_SYM(Random));

  if (mrb_get_args(mrb, "|i?I", &n, &given, &random, c) < 2) {
    random = random_default_state(mrb);
  }
  len = RARRAY_LEN(ary);
  if (!given) {                 /* pick one element */
    switch (len) {
    case 0:
      return mrb_nil_value();
    case 1:
      return RARRAY_PTR(ary)[0];
    default:
      return RARRAY_PTR(ary)[rand_uint32(random) % len];
    }
  }
  else {
    mrb_value result;
    mrb_int i, j;

    if (n < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "negative sample number");
    if (n > len) n = len;
    result = mrb_ary_new_capa(mrb, n);
    for (i=0; i<n; i++) {
      mrb_int r;

      for (;;) {
      retry:
        r = (mrb_int)(rand_uint32(random) % len);

        for (j=0; j<i; j++) {
          if (mrb_integer(RARRAY_PTR(result)[j]) == r) {
            goto retry;         /* retry if duplicate */
          }
        }
        break;
      }
      mrb_ary_push(mrb, result, mrb_int_value(mrb, r));
    }
    for (i=0; i<n; i++) {
      mrb_int idx = mrb_integer(RARRAY_PTR(result)[i]);
      mrb_value elem = RARRAY_PTR(ary)[idx];
      mrb_ary_set(mrb, result, i, elem);
    }
    return result;
  }
}

static mrb_value
random_f_rand(mrb_state *mrb, mrb_value self)
{
  rand_state *t = random_default_state(mrb);
  return random_rand(mrb, t, get_opt(mrb));
}

static mrb_value
random_f_srand(mrb_state *mrb, mrb_value self)
{
  mrb_value random = random_default(mrb);
  return random_m_srand(mrb, random);
}

static mrb_value
random_f_bytes(mrb_state *mrb, mrb_value self)
{
  mrb_value random = random_default(mrb);
  return random_m_bytes(mrb, random);
}


void mrb_mruby_random_gem_init(mrb_state *mrb)
{
  struct RClass *random;
  struct RClass *array = mrb->array_class;

  mrb_static_assert(sizeof(rand_state) <= ISTRUCT_DATA_SIZE);

  mrb_define_method(mrb, mrb->kernel_module, "rand", random_f_rand, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, mrb->kernel_module, "srand", random_f_srand, MRB_ARGS_OPT(1));

  random = mrb_define_class(mrb, "Random", mrb->object_class);
  MRB_SET_INSTANCE_TT(random, MRB_TT_ISTRUCT);
  mrb_define_class_method(mrb, random, "rand", random_f_rand, MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, random, "srand", random_f_srand, MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, random, "bytes", random_f_bytes, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, random, "initialize", random_m_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, random, "rand", random_m_rand, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, random, "srand", random_m_srand, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, random, "bytes", random_m_bytes, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, array, "shuffle", mrb_ary_shuffle, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, array, "shuffle!", mrb_ary_shuffle_bang, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, array, "sample", mrb_ary_sample, MRB_ARGS_OPT(2));

  mrb_const_set(mrb, mrb_obj_value(random), MRB_SYM(DEFAULT),
          mrb_obj_new(mrb, random, 0, NULL));
}

void mrb_mruby_random_gem_final(mrb_state *mrb)
{
}
