#include <mruby.h>
#include <mruby/gc.h>
#include <mruby/hash.h>
#include <mruby/class.h>

struct os_count_struct {
  mrb_int total;
  mrb_int freed;
  mrb_int counts[MRB_TT_MAXDEFINE+1];
};

static void
os_count_object_type(mrb_state *mrb, struct RBasic *obj, void *data)
{
  struct os_count_struct *obj_count;
  obj_count = (struct os_count_struct*)data;

  obj_count->total++;

  if (mrb_object_dead_p(mrb, obj)) {
    obj_count->freed++;
  }
  else {
    obj_count->counts[obj->tt]++;
  }
}

/*
 *  call-seq:
 *     ObjectSpace.count_objects([result_hash]) -> hash
 *
 *  Counts objects for each type.
 *
 *  It returns a hash, such as:
 *  {
 *    :TOTAL=>10000,
 *    :FREE=>3011,
 *    :T_OBJECT=>6,
 *    :T_CLASS=>404,
 *    # ...
 *  }
 *
 *  If the optional argument +result_hash+ is given,
 *  it is overwritten and returned. This is intended to avoid probe effect.
 *
 */

static mrb_value
os_count_objects(mrb_state *mrb, mrb_value self)
{
  struct os_count_struct obj_count = { 0 };
  mrb_int i;
  mrb_value hash;

  if (mrb_get_args(mrb, "|H", &hash) == 0) {
    hash = mrb_hash_new(mrb);
  }

  if (!mrb_test(mrb_hash_empty_p(mrb, hash))) {
    mrb_hash_clear(mrb, hash);
  }

  mrb_objspace_each_objects(mrb, os_count_object_type, &obj_count);

  mrb_hash_set(mrb, hash, mrb_symbol_value(mrb_intern_lit(mrb, "TOTAL")), mrb_fixnum_value(obj_count.total));
  mrb_hash_set(mrb, hash, mrb_symbol_value(mrb_intern_lit(mrb, "FREE")), mrb_fixnum_value(obj_count.freed));

  for (i = MRB_TT_FALSE; i < MRB_TT_MAXDEFINE; i++) {
    mrb_value type;
    switch (i) {
#define COUNT_TYPE(t) case (MRB_T ## t): type = mrb_symbol_value(mrb_intern_lit(mrb, #t)); break;
      COUNT_TYPE(T_FALSE);
      COUNT_TYPE(T_FREE);
      COUNT_TYPE(T_TRUE);
      COUNT_TYPE(T_FIXNUM);
      COUNT_TYPE(T_SYMBOL);
      COUNT_TYPE(T_UNDEF);
      COUNT_TYPE(T_FLOAT);
      COUNT_TYPE(T_CPTR);
      COUNT_TYPE(T_OBJECT);
      COUNT_TYPE(T_CLASS);
      COUNT_TYPE(T_MODULE);
      COUNT_TYPE(T_ICLASS);
      COUNT_TYPE(T_SCLASS);
      COUNT_TYPE(T_PROC);
      COUNT_TYPE(T_ARRAY);
      COUNT_TYPE(T_HASH);
      COUNT_TYPE(T_STRING);
      COUNT_TYPE(T_RANGE);
      COUNT_TYPE(T_EXCEPTION);
      COUNT_TYPE(T_FILE);
      COUNT_TYPE(T_ENV);
      COUNT_TYPE(T_DATA);
      COUNT_TYPE(T_FIBER);
#undef COUNT_TYPE
    default:
      type = mrb_fixnum_value(i); break;
    }
    if (obj_count.counts[i])
      mrb_hash_set(mrb, hash, type, mrb_fixnum_value(obj_count.counts[i]));
  }

  return hash;
}

struct os_each_object_data {
  mrb_value block;
  struct RClass *target_module;
  mrb_int count;
};

static void
os_each_object_cb(mrb_state *mrb, struct RBasic *obj, void *ud)
{
  struct os_each_object_data *d = (struct os_each_object_data*)ud;

  /* filter dead objects */
  if (mrb_object_dead_p(mrb, obj)) {
    return;
  }

  /* filter internal objects */
  switch (obj->tt) {
  case MRB_TT_ENV:
  case MRB_TT_ICLASS:
    return;
  default:
    break;
  }

  /* filter half baked (or internal) objects */
  if (!obj->c) return;

  /* filter class kind if target module defined */
  if (d->target_module && !mrb_obj_is_kind_of(mrb, mrb_obj_value(obj), d->target_module)) {
    return;
  }

  mrb_yield(mrb, d->block, mrb_obj_value(obj));
  ++d->count;
}

/*
 *  call-seq:
 *     ObjectSpace.each_object([module]) {|obj| ... } -> fixnum
 *
 *  Calls the block once for each object in this Ruby process.
 *  Returns the number of objects found.
 *  If the optional argument +module+ is given,
 *  calls the block for only those classes or modules
 *  that match (or are a subclass of) +module+.
 *
 *  If no block is given, ArgumentError is raised.
 *
 */

static mrb_value
os_each_object(mrb_state *mrb, mrb_value self)
{
  mrb_value cls = mrb_nil_value();
  struct os_each_object_data d;
  mrb_get_args(mrb, "&|C", &d.block, &cls);

  if (mrb_nil_p(d.block)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Expected block in ObjectSpace.each_object.");
  }

  d.target_module = mrb_nil_p(cls) ? NULL : mrb_class_ptr(cls);
  d.count = 0;
  mrb_objspace_each_objects(mrb, os_each_object_cb, &d);
  return mrb_fixnum_value(d.count);
}

void
mrb_mruby_objectspace_gem_init(mrb_state *mrb)
{
  struct RClass *os = mrb_define_module(mrb, "ObjectSpace");
  mrb_define_class_method(mrb, os, "count_objects", os_count_objects, MRB_ARGS_OPT(1));
  mrb_define_class_method(mrb, os, "each_object", os_each_object, MRB_ARGS_OPT(1));
}

void
mrb_mruby_objectspace_gem_final(mrb_state *mrb)
{
}
