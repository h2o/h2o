/*
** apiprint.c
**
*/

#include <string.h>
#include "mrdb.h"
#include <mruby/value.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/error.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include "apiprint.h"

static void
mrdb_check_syntax(mrb_state *mrb, mrb_debug_context *dbg, const char *expr, size_t len)
{
  mrbc_context *c;

  c = mrbc_context_new(mrb);
  c->no_exec = TRUE;
  c->capture_errors = TRUE;
  c->filename = (char*)dbg->prvfile;
  c->lineno = dbg->prvline;

  /* Load program */
  mrb_load_nstring_cxt(mrb, expr, len, c);

  mrbc_context_free(mrb, c);
}

mrb_value
mrb_debug_eval(mrb_state *mrb, mrb_debug_context *dbg, const char *expr, size_t len, mrb_bool *exc)
{
  void (*tmp)(struct mrb_state *, struct mrb_irep *, mrb_code *, mrb_value *);
  mrb_value ruby_code;
  mrb_value s;
  mrb_value v;
  mrb_value recv;

  /* disable code_fetch_hook */
  tmp = mrb->code_fetch_hook;
  mrb->code_fetch_hook = NULL;

  mrdb_check_syntax(mrb, dbg, expr, len);
  if (mrb->exc) {
    v = mrb_obj_value(mrb->exc);
    mrb->exc = 0;
  }
  else {
    /*
     * begin
     *   expr
     * rescue => e
     *   e
     * end
     */
    ruby_code = mrb_str_new_lit(mrb, "begin\n");
    ruby_code = mrb_str_cat(mrb, ruby_code, expr, len);
    ruby_code = mrb_str_cat_lit(mrb, ruby_code, "\nrescue => e\ne\nend");

    recv = dbg->regs[0];

    v =  mrb_funcall(mrb, recv, "instance_eval", 1, ruby_code);
  }

  if (exc) {
    *exc = mrb_obj_is_kind_of(mrb, v, mrb->eException_class);
  }

  s = mrb_funcall(mrb, v, "inspect", 0);

  /* enable code_fetch_hook */
  mrb->code_fetch_hook = tmp;

  return s;
}
