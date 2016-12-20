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
#include "mt19937ar.h"

#include <time.h>

static char const MT_STATE_KEY[] = "$mrb_i_mt_state";

static const struct mrb_data_type mt_state_type = {
  MT_STATE_KEY, mrb_free,
};

static mrb_value mrb_random_rand(mrb_state *mrb, mrb_value self);
static mrb_value mrb_random_srand(mrb_state *mrb, mrb_value self);

static void
mt_srand(mt_state *t, unsigned long seed)
{
  mrb_random_init_genrand(t, seed);
}

static unsigned long
mt_rand(mt_state *t)
{
  return mrb_random_genrand_int32(t);
}

static double
mt_rand_real(mt_state *t)
{
  return mrb_random_genrand_real1(t);
}

static mrb_value
mrb_random_mt_srand(mrb_state *mrb, mt_state *t, mrb_value seed)
{
  if (mrb_nil_p(seed)) {
    seed = mrb_fixnum_value((mrb_int)(time(NULL) + mt_rand(t)));
    if (mrb_fixnum(seed) < 0) {
      seed = mrb_fixnum_value(0 - mrb_fixnum(seed));
    }
  }

  mt_srand(t, (unsigned) mrb_fixnum(seed));

  return seed;
}

static mrb_value
mrb_random_mt_rand(mrb_state *mrb, mt_state *t, mrb_value max)
{
  mrb_value value;

  if (mrb_fixnum(max) == 0) {
    value = mrb_float_value(mrb, mt_rand_real(t));
  }
  else {
    value = mrb_fixnum_value(mt_rand(t) % mrb_fixnum(max));
  }

  return value;
}

static mrb_value
get_opt(mrb_state* mrb)
{
  mrb_value arg;

  arg = mrb_nil_value();
  mrb_get_args(mrb, "|o", &arg);

  if (!mrb_nil_p(arg)) {
    arg = mrb_check_convert_type(mrb, arg, MRB_TT_FIXNUM, "Fixnum", "to_int");
    if (mrb_nil_p(arg)) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument type");
    }
    if (mrb_fixnum(arg) < 0) {
      arg = mrb_fixnum_value(0 - mrb_fixnum(arg));
    }
  }
  return arg;
}

static mrb_value
get_random(mrb_state *mrb) {
  return mrb_const_get(mrb,
             mrb_obj_value(mrb_class_get(mrb, "Random")),
             mrb_intern_lit(mrb, "DEFAULT"));
}

static mt_state *
get_random_state(mrb_state *mrb)
{
  mrb_value random_val = get_random(mrb);
  return DATA_GET_PTR(mrb, random_val, &mt_state_type, mt_state);
}

static mrb_value
mrb_random_g_rand(mrb_state *mrb, mrb_value self)
{
  mrb_value random = get_random(mrb);
  return mrb_random_rand(mrb, random);
}

static mrb_value
mrb_random_g_srand(mrb_state *mrb, mrb_value self)
{
  mrb_value random = get_random(mrb);
  return mrb_random_srand(mrb, random);
}

static mrb_value
mrb_random_init(mrb_state *mrb, mrb_value self)
{
  mrb_value seed;
  mt_state *t;

  /* avoid memory leaks */
  t = (mt_state*)DATA_PTR(self);
  if (t) {
    mrb_free(mrb, t);
  }
  mrb_data_init(self, NULL, &mt_state_type);

  t = (mt_state *)mrb_malloc(mrb, sizeof(mt_state));
  t->mti = N + 1;

  seed = get_opt(mrb);
  seed = mrb_random_mt_srand(mrb, t, seed);
  if (mrb_nil_p(seed)) {
    t->has_seed = FALSE;
  }
  else {
    mrb_assert(mrb_fixnum_p(seed));
    t->has_seed = TRUE;
    t->seed = mrb_fixnum(seed);
  }

  mrb_data_init(self, t, &mt_state_type);

  return self;
}

static void
mrb_random_rand_seed(mrb_state *mrb, mt_state *t)
{
  if (!t->has_seed) {
    mrb_random_mt_srand(mrb, t, mrb_nil_value());
  }
}

static mrb_value
mrb_random_rand(mrb_state *mrb, mrb_value self)
{
  mrb_value max;
  mt_state *t = DATA_GET_PTR(mrb, self, &mt_state_type, mt_state);

  max = get_opt(mrb);
  mrb_random_rand_seed(mrb, t);
  return mrb_random_mt_rand(mrb, t, max);
}

static mrb_value
mrb_random_srand(mrb_state *mrb, mrb_value self)
{
  mrb_value seed;
  mrb_value old_seed;
  mt_state *t = DATA_GET_PTR(mrb, self, &mt_state_type, mt_state);

  seed = get_opt(mrb);
  seed = mrb_random_mt_srand(mrb, t, seed);
  old_seed = t->has_seed? mrb_fixnum_value(t->seed) : mrb_nil_value();
  if (mrb_nil_p(seed)) {
    t->has_seed = FALSE;
  }
  else {
    mrb_assert(mrb_fixnum_p(seed));
    t->has_seed = TRUE;
    t->seed = mrb_fixnum(seed);
  }

  return old_seed;
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
  mrb_int i;
  mt_state *random = NULL;

  if (RARRAY_LEN(ary) > 1) {
    mrb_get_args(mrb, "|d", &random, &mt_state_type);

    if (random == NULL) {
      random = get_random_state(mrb);
    }
    mrb_random_rand_seed(mrb, random);

    mrb_ary_modify(mrb, mrb_ary_ptr(ary));

    for (i = RARRAY_LEN(ary) - 1; i > 0; i--)  {
      mrb_int j;
      mrb_value tmp;

      j = mrb_fixnum(mrb_random_mt_rand(mrb, random, mrb_fixnum_value(RARRAY_LEN(ary))));

      tmp = RARRAY_PTR(ary)[i];
      mrb_ary_ptr(ary)->ptr[i] = RARRAY_PTR(ary)[j];
      mrb_ary_ptr(ary)->ptr[j] = tmp;
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
  mt_state *random = NULL;
  mrb_int len;

  mrb_get_args(mrb, "|i?d", &n, &given, &random, &mt_state_type);
  if (random == NULL) {
    random = get_random_state(mrb);
  }
  mrb_random_rand_seed(mrb, random);
  mt_rand(random);
  len = RARRAY_LEN(ary);
  if (!given) {                 /* pick one element */
    switch (len) {
    case 0:
      return mrb_nil_value();
    case 1:
      return RARRAY_PTR(ary)[0];
    default:
      return RARRAY_PTR(ary)[mt_rand(random) % len];
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
        r = mt_rand(random) % len;

        for (j=0; j<i; j++) {
          if (mrb_fixnum(RARRAY_PTR(result)[j]) == r) {
            goto retry;         /* retry if duplicate */
          }
        }
        break;
      }
      mrb_ary_push(mrb, result, mrb_fixnum_value(r));
    }
    for (i=0; i<n; i++) {
      mrb_ary_set(mrb, result, i, RARRAY_PTR(ary)[mrb_fixnum(RARRAY_PTR(result)[i])]);
    }
    return result;
  }
}


void mrb_mruby_random_gem_init(mrb_state *mrb)
{
  struct RClass *random;
  struct RClass *array = mrb->array_class;

  mrb_define_method(mrb, mrb->kernel_module, "rand", mrb_random_g_rand, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, mrb->kernel_module, "srand", mrb_random_g_srand, MRB_ARGS_OPT(1));

  random = mrb_define_class(mrb, "Random", mrb->object_class);
  MRB_SET_INSTANCE_TT(random, MRB_TT_DATA);
  mrb_define_class_method(mrb, random, "rand", mrb_random_g_rand, MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, random, "srand", mrb_random_g_srand, MRB_ARGS_OPT(1));

  mrb_define_method(mrb, random, "initialize", mrb_random_init, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, random, "rand", mrb_random_rand, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, random, "srand", mrb_random_srand, MRB_ARGS_OPT(1));

  mrb_define_method(mrb, array, "shuffle", mrb_ary_shuffle, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, array, "shuffle!", mrb_ary_shuffle_bang, MRB_ARGS_OPT(1));
  mrb_define_method(mrb, array, "sample", mrb_ary_sample, MRB_ARGS_OPT(2));

  mrb_const_set(mrb, mrb_obj_value(random), mrb_intern_lit(mrb, "DEFAULT"),
          mrb_obj_new(mrb, random, 0, NULL));
}

void mrb_mruby_random_gem_final(mrb_state *mrb)
{
}
