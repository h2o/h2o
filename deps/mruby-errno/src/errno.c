#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/hash.h"
#include "mruby/numeric.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#if MRUBY_RELEASE_NO < 10000
static struct RClass *
mrb_module_get(mrb_state *mrb, const char *name)
{
  return mrb_class_get(mrb, name);
}
#endif

static mrb_value
mrb_sce_init(mrb_state *mrb, mrb_value self)
{
  mrb_value c, e2c, m, str;
  mrb_int n;
  int argc, no_errno = 0;
  char buf[20];

  argc = mrb_get_args(mrb, "o|i", &m, &n);
  if (argc == 1) {
    if (mrb_type(m) == MRB_TT_FIXNUM) {
      n = mrb_fixnum(m);
      m = mrb_nil_value();
    } else {
      no_errno = 1;
    }
  }
  if (!no_errno) {
    e2c = mrb_const_get(mrb, mrb_obj_value(mrb_module_get(mrb, "Errno")), mrb_intern_lit(mrb, "Errno2class"));
    c = mrb_hash_fetch(mrb, e2c, mrb_fixnum_value(n), mrb_nil_value());
    if (!mrb_nil_p(c)) {
      mrb_basic_ptr(self)->c = mrb_class_ptr(c);
      str = mrb_str_new_cstr(mrb, strerror(n));
    } else {
      mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "errno"), mrb_fixnum_value(n));
      str = mrb_str_new_cstr(mrb, "Unknown error: ");
      snprintf(buf, sizeof(buf), "%d", (int)n);
      mrb_str_cat2(mrb, str, buf);
    }
  } else {
    str = mrb_str_new_cstr(mrb, "unknown error");
  }
  if (!mrb_nil_p(m)) {
    mrb_str_cat2(mrb, str, " - ");
    mrb_str_append(mrb, str, m);
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "mesg"), str);
  return self;
}

static mrb_value
mrb_sce_errno(mrb_state *mrb, mrb_value self)
{
  struct RClass *c;
  mrb_sym sym;

  c = mrb_class(mrb, self);
  sym = mrb_intern_lit(mrb, "Errno");
#if MRUBY_RELEASE_NO < 10000
  if (mrb_const_defined_at(mrb, c, sym)) {
#else
  if (mrb_const_defined_at(mrb, mrb_obj_value(c), sym)) {
#endif
    return mrb_const_get(mrb, mrb_obj_value(c), sym);
  } else {
    sym = mrb_intern_lit(mrb, "errno");
    return mrb_attr_get(mrb, self, sym);
  }
}

static mrb_value
mrb_sce_to_s(mrb_state *mrb, mrb_value self)
{
  return mrb_attr_get(mrb, self, mrb_intern_lit(mrb, "mesg"));
}

static mrb_value
mrb_sce_sys_fail(mrb_state *mrb, mrb_value cls)
{
  struct RClass *cl, *sce;
  mrb_value e, msg;
  mrb_int no;
  int argc;
  char name[8];

  sce = mrb_class_get(mrb, "SystemCallError");
  argc = mrb_get_args(mrb, "i|S", &no, &msg);
  if (argc == 1) {
    e = mrb_funcall(mrb, mrb_obj_value(sce), "new", 1, mrb_fixnum_value(no));
  } else {
    e = mrb_funcall(mrb, mrb_obj_value(sce), "new", 2, msg, mrb_fixnum_value(no));
  }
  if (mrb_obj_class(mrb, e) == sce) {
    snprintf(name, sizeof(name), "E%03ld", (long)no);
    cl = mrb_define_class_under(mrb, mrb_module_get(mrb, "Errno"), name, sce);
    mrb_define_const(mrb, cl, "Errno", mrb_fixnum_value(no));
    mrb_basic_ptr(e)->c = cl;
  }
  mrb_exc_raise(mrb, e);
  return mrb_nil_value();  /* NOTREACHED */
}

static mrb_value
mrb_exxx_init(mrb_state *mrb, mrb_value self)
{
  mrb_value m, no, str;

  no = mrb_const_get(mrb, mrb_obj_value(mrb_class(mrb, self)), mrb_intern_lit(mrb, "Errno"));
  str = mrb_str_new_cstr(mrb, strerror(mrb_fixnum(no)));

  m = mrb_nil_value();
  mrb_get_args(mrb, "|S", &m);
  if (!mrb_nil_p(m)) {
    mrb_str_cat2(mrb, str, " - ");
    mrb_str_append(mrb, str, m);
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "mesg"), str);
  return self;
}

void
mrb_mruby_errno_gem_init(mrb_state *mrb)
{
  struct RClass *e, *eno, *sce, *ste;
  mrb_value h, noerror;

  ste = mrb_class_get(mrb, "StandardError");

  sce = mrb_define_class(mrb, "SystemCallError", ste);
  mrb_define_class_method(mrb, sce, "_sys_fail", mrb_sce_sys_fail, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, sce, "errno", mrb_sce_errno, MRB_ARGS_NONE());
  mrb_define_method(mrb, sce, "to_s", mrb_sce_to_s, MRB_ARGS_NONE());
  mrb_define_method(mrb, sce, "initialize", mrb_sce_init, MRB_ARGS_ARG(1, 1));

  eno = mrb_define_module(mrb, "Errno");
  h = mrb_hash_new(mrb);
  mrb_define_const(mrb, eno, "Errno2class", h);

  e = mrb_define_class_under(mrb, eno, "NOERROR", sce);
  mrb_define_const(mrb, e, "Errno", mrb_fixnum_value(0));
  mrb_define_method(mrb, e, "initialize", mrb_exxx_init, MRB_ARGS_OPT(1));
  //mrb_define_method(mrb, e, "===", mrb_exxx_cmp, MRB_ARGS_REQ(1));
  noerror = mrb_obj_value(e);

#define itsdefined(SYM) \
  do {									\
    int ai = mrb_gc_arena_save(mrb);					\
    e = mrb_define_class_under(mrb, eno, #SYM, sce);			\
    mrb_define_const(mrb, e, "Errno", mrb_fixnum_value(SYM));		\
    mrb_define_method(mrb, e, "initialize", mrb_exxx_init, MRB_ARGS_OPT(1)); \
    mrb_hash_set(mrb, h, mrb_fixnum_value(SYM), mrb_obj_value(e));	\
    mrb_gc_arena_restore(mrb, ai);					\
  } while (0)

#define itsnotdefined(SYM) \
  do {									\
    mrb_define_const(mrb, eno, #SYM, noerror);				\
  } while (0)

#include "known_errors_def.cstub"
}

void
mrb_mruby_errno_gem_final(mrb_state *mrb)
{
}
