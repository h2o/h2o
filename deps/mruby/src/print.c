/*
** print.c - Kernel.#p
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/error.h>
#include <string.h>

#ifndef MRB_DISABLE_STDIO
static void
printcstr(const char *str, size_t len, FILE *stream)
{
  if (str) {
    fwrite(str, len, 1, stream);
    putc('\n', stream);
  }
}

static void
printstr(mrb_value obj, FILE *stream)
{
  if (mrb_string_p(obj)) {
    printcstr(RSTRING_PTR(obj), RSTRING_LEN(obj), stream);
  }
}
#else
# define printcstr(str, len, stream) (void)0
# define printstr(obj, stream) (void)0
#endif

void
mrb_core_init_printabort(void)
{
  static const char *str = "Failed mruby core initialization";
  printcstr(str, strlen(str), stdout);
}

MRB_API void
mrb_p(mrb_state *mrb, mrb_value obj)
{
  if (mrb_type(obj) == MRB_TT_EXCEPTION && mrb_obj_ptr(obj) == mrb->nomem_err) {
    static const char *str = "Out of memory";
    printcstr(str, strlen(str), stdout);
  }
  else {
    printstr(mrb_inspect(mrb, obj), stdout);
  }
}

MRB_API void
mrb_print_error(mrb_state *mrb)
{
  mrb_print_backtrace(mrb);
}

MRB_API void
mrb_show_version(mrb_state *mrb)
{
  printstr(mrb_const_get(mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "MRUBY_DESCRIPTION")), stdout);
}

MRB_API void
mrb_show_copyright(mrb_state *mrb)
{
  printstr(mrb_const_get(mrb, mrb_obj_value(mrb->object_class), mrb_intern_lit(mrb, "MRUBY_COPYRIGHT")), stdout);
}
