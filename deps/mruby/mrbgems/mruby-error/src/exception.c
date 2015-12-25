#include <mruby.h>
#include <mruby/throw.h>
#include <mruby/error.h>

MRB_API mrb_value
mrb_protect(mrb_state *mrb, mrb_func_t body, mrb_value data, mrb_bool *state)
{
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  mrb_value result = mrb_nil_value();

  if (state) { *state = FALSE; }

  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;
    result = body(mrb, data);
    mrb->jmp = prev_jmp;
  } MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;
    result = mrb_obj_value(mrb->exc);
    mrb->exc = NULL;
    if (state) { *state = TRUE; }
  } MRB_END_EXC(&c_jmp);

  mrb_gc_protect(mrb, result);
  return result;
}

MRB_API mrb_value
mrb_ensure(mrb_state *mrb, mrb_func_t body, mrb_value b_data, mrb_func_t ensure, mrb_value e_data)
{
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  mrb_value result;

  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;
    result = body(mrb, b_data);
    mrb->jmp = prev_jmp;
  } MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;
    ensure(mrb, e_data);
    MRB_THROW(mrb->jmp); /* rethrow catched exceptions */
  } MRB_END_EXC(&c_jmp);

  ensure(mrb, e_data);
  mrb_gc_protect(mrb, result);
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
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  mrb_value result;
  mrb_bool error_matched = FALSE;
  mrb_int i;

  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;
    result = body(mrb, b_data);
    mrb->jmp = prev_jmp;
  } MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;

    for (i = 0; i < len; ++i) {
      if (mrb_obj_is_kind_of(mrb, mrb_obj_value(mrb->exc), classes[i])) {
        error_matched = TRUE;
        break;
      }
    }

    if (!error_matched) { MRB_THROW(mrb->jmp); }

    mrb->exc = NULL;
    result = rescue(mrb, r_data);
  } MRB_END_EXC(&c_jmp);

  mrb_gc_protect(mrb, result);
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
