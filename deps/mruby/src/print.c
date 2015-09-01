/*
** print.c - Kernel.#p
**
** See Copyright Notice in mruby.h
*/

#include "mruby.h"
#include "mruby/string.h"
#include "mruby/variable.h"

#ifdef ENABLE_STDIO
static void
printstr(mrb_value obj, FILE *stream)
{
  if (mrb_string_p(obj)) {
    fwrite(RSTRING_PTR(obj), RSTRING_LEN(obj), 1, stream);
    putc('\n', stream);
  }
}
#else
# define printstr(obj, stream) (void)0
#endif

MRB_API void
mrb_p(mrb_state *mrb, mrb_value obj)
{
  mrb_value val = mrb_inspect(mrb, obj);

  printstr(val, stdout);
}

MRB_API void
mrb_print_error(mrb_state *mrb)
{
  mrb_value s;

  mrb_print_backtrace(mrb);
  s = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
  printstr(s, stderr);
}

MRB_API void
mrb_show_version(mrb_state *mrb)
{
  mrb_value msg;

  msg = mrb_const_get(mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "MRUBY_DESCRIPTION"));
  printstr(msg, stdout);
}

MRB_API void
mrb_show_copyright(mrb_state *mrb)
{
  mrb_value msg;

  msg = mrb_const_get(mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "MRUBY_COPYRIGHT"));
  printstr(msg, stdout);
}
