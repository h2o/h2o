/*
** cmdprint.c - mruby debugger print command functions
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

dbgcmd_state
dbgcmd_print(mrb_state *mrb, mrdb_state *mrdb)
{
  mrb_value expr;
  mrb_value result;
  mrb_value s;
  uint8_t wcnt;
  int ai;

  if (mrdb->wcnt <= 1) {
    puts("Parameter not specified.");
    return DBGST_PROMPT;
  }

  ai = mrb_gc_arena_save(mrb);

  /* eval expr */
  expr = mrb_str_new_cstr(mrb, NULL);
  for (wcnt=1; wcnt<mrdb->wcnt; wcnt++) {
    expr = mrb_str_cat_lit(mrb, expr, " ");
    expr = mrb_str_cat_cstr(mrb, expr, mrdb->words[wcnt]);
  }

  result = mrb_debug_eval(mrb, mrdb->dbg, RSTRING_PTR(expr), RSTRING_LEN(expr), NULL);

  /* $print_no = result */
  s = mrb_str_cat_lit(mrb, result, "\0");
  printf("$%lu = %s\n", (unsigned long)mrdb->print_no++, RSTRING_PTR(s));

  if (mrdb->print_no == 0) {
    mrdb->print_no = 1;
  }

  mrb_gc_arena_restore(mrb, ai);

  return DBGST_PROMPT;
}

dbgcmd_state
dbgcmd_eval(mrb_state *mrb, mrdb_state *mrdb)
{
  return dbgcmd_print(mrb, mrdb);
}
