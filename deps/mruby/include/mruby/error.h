/**
** @file mruby/error.h - Exception class
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
  struct RString *mesg;
};

#define mrb_exc_ptr(v) ((struct RException*)mrb_ptr(v))
#define MRB_EXC_MESG_STRING_FLAG 0x100

MRB_API void mrb_sys_fail(mrb_state *mrb, const char *mesg);
MRB_API mrb_value mrb_exc_new_str(mrb_state *mrb, struct RClass* c, mrb_value str);
#define mrb_exc_new_lit(mrb, c, lit) mrb_exc_new_str(mrb, c, mrb_str_new_lit(mrb, lit))
#define mrb_exc_new_str_lit(mrb, c, lit) mrb_exc_new_lit(mrb, c, lit)
MRB_API mrb_value mrb_make_exception(mrb_state *mrb, mrb_int argc, const mrb_value *argv);
mrb_value mrb_exc_backtrace(mrb_state *mrb, mrb_value exc);
mrb_value mrb_get_backtrace(mrb_state *mrb);

MRB_API mrb_noreturn void mrb_no_method_error(mrb_state *mrb, mrb_sym id, mrb_value args, const char *fmt, ...);

/* declaration for `fail` method */
MRB_API mrb_value mrb_f_raise(mrb_state*, mrb_value);

#if defined(MRB_64BIT) || defined(MRB_USE_FLOAT32) || defined(MRB_NAN_BOXING) || defined(MRB_WORD_BOXING)
struct RBreak {
  MRB_OBJECT_HEADER;
  const struct RProc *proc;
  mrb_value val;
};
#define mrb_break_value_get(brk) ((brk)->val)
#define mrb_break_value_set(brk, v) ((brk)->val = v)
#else
struct RBreak {
  MRB_OBJECT_HEADER;
  const struct RProc *proc;
  union mrb_value_union value;
};
#define RBREAK_VALUE_TT_MASK ((1 << 8) - 1)
static inline mrb_value
mrb_break_value_get(struct RBreak *brk)
{
  mrb_value val;
  val.value = brk->value;
  val.tt = (enum mrb_vtype)(brk->flags & RBREAK_VALUE_TT_MASK);
  return val;
}
static inline void
mrb_break_value_set(struct RBreak *brk, mrb_value val)
{
  brk->value = val.value;
  brk->flags &= ~RBREAK_VALUE_TT_MASK;
  brk->flags |= val.tt;
}
#endif  /* MRB_64BIT || MRB_USE_FLOAT32 || MRB_NAN_BOXING || MRB_WORD_BOXING */
#define mrb_break_proc_get(brk) ((brk)->proc)
#define mrb_break_proc_set(brk, p) ((brk)->proc = p)

#define RBREAK_TAG_FOREACH(f) \
  f(RBREAK_TAG_BREAK, 0) \
  f(RBREAK_TAG_BREAK_UPPER, 1) \
  f(RBREAK_TAG_BREAK_INTARGET, 2) \
  f(RBREAK_TAG_RETURN_BLOCK, 3) \
  f(RBREAK_TAG_RETURN, 4) \
  f(RBREAK_TAG_RETURN_TOPLEVEL, 5) \
  f(RBREAK_TAG_JUMP, 6) \
  f(RBREAK_TAG_STOP, 7)

#define RBREAK_TAG_DEFINE(tag, i) tag = i,
enum {
  RBREAK_TAG_FOREACH(RBREAK_TAG_DEFINE)
};
#undef RBREAK_TAG_DEFINE

#define RBREAK_TAG_BIT          3
#define RBREAK_TAG_BIT_OFF      8
#define RBREAK_TAG_MASK         (~(~UINT32_C(0) << RBREAK_TAG_BIT))

static inline uint32_t
mrb_break_tag_get(struct RBreak *brk)
{
  return (brk->flags >> RBREAK_TAG_BIT_OFF) & RBREAK_TAG_MASK;
}

static inline void
mrb_break_tag_set(struct RBreak *brk, uint32_t tag)
{
  brk->flags &= ~(RBREAK_TAG_MASK << RBREAK_TAG_BIT_OFF);
  brk->flags |= (tag & RBREAK_TAG_MASK) << RBREAK_TAG_BIT_OFF;
}

/**
 * Protect
 *
 */
typedef mrb_value mrb_protect_error_func(mrb_state *mrb, void *userdata);
MRB_API mrb_value mrb_protect_error(mrb_state *mrb, mrb_protect_error_func *body, void *userdata, mrb_bool *error);

/**
 * Protect (takes mrb_value for body argument)
 *
 * Implemented in the mruby-error mrbgem
 */
MRB_API mrb_value mrb_protect(mrb_state *mrb, mrb_func_t body, mrb_value data, mrb_bool *state);

/**
 * Ensure
 *
 * Implemented in the mruby-error mrbgem
 */
MRB_API mrb_value mrb_ensure(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
                             mrb_func_t ensure, mrb_value e_data);

/**
 * Rescue
 *
 * Implemented in the mruby-error mrbgem
 */
MRB_API mrb_value mrb_rescue(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
                             mrb_func_t rescue, mrb_value r_data);

/**
 * Rescue exception
 *
 * Implemented in the mruby-error mrbgem
 */
MRB_API mrb_value mrb_rescue_exceptions(mrb_state *mrb, mrb_func_t body, mrb_value b_data,
                                        mrb_func_t rescue, mrb_value r_data,
                                        mrb_int len, struct RClass **classes);

MRB_END_DECL

#endif  /* MRUBY_ERROR_H */
