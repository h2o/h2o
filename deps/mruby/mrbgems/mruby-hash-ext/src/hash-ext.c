/*
** hash.c - Hash class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/hash.h>

/*
 * call-seq:
 *   hsh.values_at(key, ...)   -> array
 *
 * Return an array containing the values associated with the given keys.
 * Also see <code>Hash.select</code>.
 *
 *   h = { "cat" => "feline", "dog" => "canine", "cow" => "bovine" }
 *   h.values_at("cow", "cat")  #=> ["bovine", "feline"]
 */

static mrb_value
hash_values_at(mrb_state *mrb, mrb_value hash)
{
  const mrb_value *argv;
  mrb_value result;
  mrb_int argc, i;
  int ai;

  mrb_get_args(mrb, "*", &argv, &argc);
  result = mrb_ary_new_capa(mrb, argc);
  ai = mrb_gc_arena_save(mrb);
  for (i = 0; i < argc; i++) {
    mrb_ary_push(mrb, result, mrb_hash_get(mrb, hash, argv[i]));
    mrb_gc_arena_restore(mrb, ai);
  }
  return result;
}

/*
 *  call-seq:
 *     hsh.slice(*keys) -> a_hash
 *
 *  Returns a hash containing only the given keys and their values.
 *
 *     h = { a: 100, b: 200, c: 300 }
 *     h.slice(:a)           #=> {:a=>100}
 *     h.slice(:b, :c, :d)   #=> {:b=>200, :c=>300}
 */
static mrb_value
hash_slice(mrb_state *mrb, mrb_value hash)
{
  const mrb_value *argv;
  mrb_value result;
  mrb_int argc, i;

  mrb_get_args(mrb, "*", &argv, &argc);
  result = mrb_hash_new_capa(mrb, argc);
  if (argc == 0) return result; /* empty hash */
  for (i = 0; i < argc; i++) {
    mrb_value key = argv[i];
    mrb_value val;

    val = mrb_hash_fetch(mrb, hash, key, mrb_undef_value());
    if (!mrb_undef_p(val)) {
      mrb_hash_set(mrb, result, key, val);
    }
  }
  return result;
}

/*
 *  call-seq:
 *     hsh.except(*keys) -> a_hash
 *
 *  Returns a hash excluding the given keys and their values.
 *
 *     h = { a: 100, b: 200, c: 300 }
 *     h.except(:a)          #=> {:b=>200, :c=>300}
 *     h.except(:b, :c, :d)  #=> {:a=>100}
 */
static mrb_value
hash_except(mrb_state *mrb, mrb_value hash)
{
  const mrb_value *argv;
  mrb_value result;
  mrb_int argc, i;

  mrb_get_args(mrb, "*", &argv, &argc);
  result = mrb_hash_dup(mrb, hash);
  for (i = 0; i < argc; i++) {
    mrb_hash_delete_key(mrb, result, argv[i]);
  }
  return result;
}

void
mrb_mruby_hash_ext_gem_init(mrb_state *mrb)
{
  struct RClass *h;

  h = mrb->hash_class;
  mrb_define_method(mrb, h, "values_at", hash_values_at, MRB_ARGS_ANY());
  mrb_define_method(mrb, h, "slice",     hash_slice, MRB_ARGS_ANY());
  mrb_define_method(mrb, h, "except",    hash_except, MRB_ARGS_ANY());
}

void
mrb_mruby_hash_ext_gem_final(mrb_state *mrb)
{
}
