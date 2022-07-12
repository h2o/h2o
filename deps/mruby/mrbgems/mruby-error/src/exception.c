#include <mruby.h>
#include <mruby/error.h>

struct protect_data {
  mrb_func_t body;
  mrb_value data;
};

static mrb_value
protect_body(mrb_state *mrb, void *p)
{
  struct protect_data *dp = (struct protect_data*)p;
  return dp->body(mrb, dp->data);
}

MRB_API mrb_value
mrb_protect(mrb_state *mrb, mrb_func_t body, mrb_value data, mrb_bool *state)
{
  struct protect_data protect_data = { body, data };
  return mrb_protect_error(mrb, protect_body, &protect_data, state);
}

MRB_API mrb_value
mrb_ensure(mrb_state *mrb, mrb_func_t body, mrb_value b_data, mrb_func_t ensure, mrb_value e_data)
{
  int ai = mrb_gc_arena_save(mrb);
  struct protect_data protect_data = { body, b_data };
  mrb_bool error;
  mrb_value result = mrb_protect_error(mrb, protect_body, &protect_data, &error);
  ensure(mrb, e_data);
  mrb_gc_arena_restore(mrb, ai);
  mrb_gc_protect(mrb, result);
  if (error) {
    mrb_exc_raise(mrb, result); /* rethrow caught exceptions */
  }
  return result;
}

MRB_API mrb_value
mrb_rescue(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
           mrb_func_t rescue, mrb_value r_data)
{
  return mrb_rescue_exceptions(mrb, body, b_data, rescue, r_data, 1, &mrb->eStandardError_class);
}

MRB_API mrb_value
mrb_rescue_exceptions(mrb_state *mrb, mrb_func_t body, mrb_value b_data, mrb_func_t rescue, mrb_value r_data,
                      mrb_int len, struct RClass **classes)
{
  int ai = mrb_gc_arena_save(mrb);
  struct protect_data protect_data = { body, b_data };
  mrb_bool error;
  mrb_value result = mrb_protect_error(mrb, protect_body, &protect_data, &error);
  if (error) {
    mrb_bool error_matched = FALSE;
    for (mrb_int i = 0; i < len; ++i) {
      if (mrb_obj_is_kind_of(mrb, result, classes[i])) {
        error_matched = TRUE;
        break;
      }
    }

    if (!error_matched) { mrb_exc_raise(mrb, result); }

    mrb->exc = NULL;
    result = rescue(mrb, r_data);
    mrb_gc_arena_restore(mrb, ai);
    mrb_gc_protect(mrb, result);
  }
  return result;
}

void
mrb_mruby_error_gem_init(mrb_state *mrb)
{
}

void
mrb_mruby_error_gem_final(mrb_state *mrb)
{
}
