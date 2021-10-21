/*
** mruby/error.h - Exception class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_ERROR_H
#define MRUBY_ERROR_H

#include "common.h"

/**
 * MRuby error handling.
 */
MRB_BEGIN_DECL

struct RException {
  MRB_OBJECT_HEADER;
  struct iv_tbl *iv;
};

#define mrb_exc_ptr(v) ((struct RException*)mrb_ptr(v))

MRB_API void mrb_sys_fail(mrb_state *mrb, const char *mesg);
MRB_API mrb_value mrb_exc_new_str(mrb_state *mrb, struct RClass* c, mrb_value str);
#define mrb_exc_new_str_lit(mrb, c, lit) mrb_exc_new_str(mrb, c, mrb_str_new_lit(mrb, lit))
MRB_API mrb_value mrb_make_exception(mrb_state *mrb, mrb_int argc, const mrb_value *argv);
MRB_API mrb_value mrb_exc_backtrace(mrb_state *mrb, mrb_value exc);
MRB_API mrb_value mrb_get_backtrace(mrb_state *mrb);
MRB_API mrb_noreturn void mrb_no_method_error(mrb_state *mrb, mrb_sym id, mrb_value args, const char *fmt, ...);

/* declaration for fail method */
MRB_API mrb_value mrb_f_raise(mrb_state*, mrb_value);

struct RBreak {
  MRB_OBJECT_HEADER;
  struct RProc *proc;
  mrb_value val;
};

/**
 * Protect
 *
 * @mrbgem mruby-error
 */
MRB_API mrb_value mrb_protect(mrb_state *mrb, mrb_func_t body, mrb_value data, mrb_bool *state);

/**
 * Ensure
 *
 * @mrbgem mruby-error
 */
MRB_API mrb_value mrb_ensure(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
                             mrb_func_t ensure, mrb_value e_data);

/**
 * Rescue
 *
 * @mrbgem mruby-error
 */
MRB_API mrb_value mrb_rescue(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
                             mrb_func_t rescue, mrb_value r_data);

/**
 * Rescue exception
 *
 * @mrbgem mruby-error
 */
MRB_API mrb_value mrb_rescue_exceptions(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
                                        mrb_func_t rescue, mrb_value r_data,
                                        mrb_int len, struct RClass **classes);

MRB_END_DECL

#endif  /* MRUBY_ERROR_H */
