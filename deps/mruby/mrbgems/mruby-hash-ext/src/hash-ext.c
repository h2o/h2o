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
  mrb_value *argv, result;
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
 * call-seq:
 *   hsh.compact!    -> hsh
 *
 * Removes all nil values from the hash. Returns the hash.
 *
 *   h = { a: 1, b: false, c: nil }
 *   h.compact!     #=> { a: 1, b: false }
 */
static mrb_value
hash_compact_bang(mrb_state *mrb, mrb_value hash)
{
  khiter_t k;
  khash_t(ht) *h = RHASH_TBL(hash);
  mrb_int n = -1;

  if (!h) return mrb_nil_value();
  for (k = kh_begin(h); k != kh_end(h); k++) {
    if (kh_exist(h, k)) {
      mrb_value val = kh_value(h, k).v;
      khiter_t k2;

      if (mrb_nil_p(val)) {
        kh_del(ht, mrb, h, k);
        n = kh_value(h, k).n;
        for (k2 = kh_begin(h); k2 != kh_end(h); k2++) {
          if (!kh_exist(h, k2)) continue;
          if (kh_value(h, k2).n > n) kh_value(h, k2).n--;
        }
      }
    }
  }
  if (n < 0) return mrb_nil_value();
  return hash;
}

void
mrb_mruby_hash_ext_gem_init(mrb_state *mrb)
{
  struct RClass *h;

  h = mrb->hash_class;
  mrb_define_method(mrb, h, "values_at", hash_values_at, MRB_ARGS_ANY());
  mrb_define_method(mrb, h, "compact!",  hash_compact_bang, MRB_ARGS_NONE());
}

void
mrb_mruby_hash_ext_gem_final(mrb_state *mrb)
{
}
