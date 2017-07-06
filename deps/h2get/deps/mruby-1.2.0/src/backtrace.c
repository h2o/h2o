/*
** backtrace.c -
**
** See Copyright Notice in mruby.h
*/

#include "mruby.h"
#include "mruby/variable.h"
#include "mruby/proc.h"
#include "mruby/array.h"
#include "mruby/string.h"
#include "mruby/class.h"
#include "mruby/debug.h"
#include "mruby/error.h"
#include "mruby/numeric.h"

struct backtrace_location {
  int i;
  int lineno;
  const char *filename;
  const char *method;
  const char *sep;
  const char *class_name;
};

typedef void (*output_stream_func)(mrb_state*, struct backtrace_location*, void*);

#ifndef MRB_DISABLE_STDIO

struct print_backtrace_args {
  FILE *stream;
  int tracehead;
};

static void
print_backtrace_i(mrb_state *mrb, struct backtrace_location *loc, void *data)
{
  struct print_backtrace_args *args;

  args = (struct print_backtrace_args*)data;

  if (args->tracehead) {
    fprintf(args->stream, "trace:\n");
    args->tracehead = FALSE;
  }

  fprintf(args->stream, "\t[%d] %s:%d", loc->i, loc->filename, loc->lineno);

  if (loc->method) {
    if (loc->class_name) {
      fprintf(args->stream, ":in %s%s%s", loc->class_name, loc->sep, loc->method);
    }
    else {
      fprintf(args->stream, ":in %s", loc->method);
    }
  }

  fprintf(args->stream, "\n");
}

#endif

static void
get_backtrace_i(mrb_state *mrb, struct backtrace_location *loc, void *data)
{
  mrb_value ary, str;
  int ai;

  ai = mrb_gc_arena_save(mrb);
  ary = mrb_obj_value((struct RArray*)data);

  str = mrb_str_new_cstr(mrb, loc->filename);
  mrb_str_cat_lit(mrb, str, ":");
  mrb_str_concat(mrb, str, mrb_fixnum_to_str(mrb, mrb_fixnum_value(loc->lineno), 10));

  if (loc->method) {
    mrb_str_cat_lit(mrb, str, ":in ");

    if (loc->class_name) {
      mrb_str_cat_cstr(mrb, str, loc->class_name);
      mrb_str_cat_cstr(mrb, str, loc->sep);
    }

    mrb_str_cat_cstr(mrb, str, loc->method);
  }

  mrb_ary_push(mrb, ary, str);
  mrb_gc_arena_restore(mrb, ai);
}

static void
output_backtrace(mrb_state *mrb, mrb_int ciidx, mrb_code *pc0, output_stream_func func, void *data)
{
  int i;

  if (ciidx >= mrb->c->ciend - mrb->c->cibase)
    ciidx = 10; /* ciidx is broken... */

  for (i = ciidx; i >= 0; i--) {
    struct backtrace_location loc;
    mrb_callinfo *ci;
    mrb_irep *irep;
    mrb_code *pc;

    ci = &mrb->c->cibase[i];

    if (!ci->proc) continue;
    if (MRB_PROC_CFUNC_P(ci->proc)) continue;

    irep = ci->proc->body.irep;

    if (mrb->c->cibase[i].err) {
      pc = mrb->c->cibase[i].err;
    }
    else if (i+1 <= ciidx) {
      pc = mrb->c->cibase[i+1].pc - 1;
    }
    else {
      pc = pc0;
    }
    loc.filename = mrb_debug_get_filename(irep, (uint32_t)(pc - irep->iseq));
    loc.lineno = mrb_debug_get_line(irep, (uint32_t)(pc - irep->iseq));

    if (loc.lineno == -1) continue;

    if (ci->target_class == ci->proc->target_class) {
      loc.sep = ".";
    }
    else {
      loc.sep = "#";
    }

    if (!loc.filename) {
      loc.filename = "(unknown)";
    }

    loc.method = mrb_sym2name(mrb, ci->mid);
    loc.class_name = mrb_class_name(mrb, ci->proc->target_class);
    loc.i = i;
    func(mrb, &loc, data);
  }
}

static void
exc_output_backtrace(mrb_state *mrb, struct RObject *exc, output_stream_func func, void *stream)
{
  mrb_value lastpc;
  mrb_code *code;

  lastpc = mrb_obj_iv_get(mrb, exc, mrb_intern_lit(mrb, "lastpc"));
  if (mrb_nil_p(lastpc)) {
    code = NULL;
  } else {
    code = (mrb_code*)mrb_cptr(lastpc);
  }

  output_backtrace(mrb, mrb_fixnum(mrb_obj_iv_get(mrb, exc, mrb_intern_lit(mrb, "ciidx"))),
                   code, func, stream);
}

/* mrb_print_backtrace/mrb_get_backtrace:

   function to retrieve backtrace information from the exception.
   note that if you call method after the exception, call stack will be
   overwritten.  So invoke these functions just after detecting exceptions.
*/

#ifndef MRB_DISABLE_STDIO

MRB_API void
mrb_print_backtrace(mrb_state *mrb)
{
  struct print_backtrace_args args;

  if (!mrb->exc || mrb_obj_is_kind_of(mrb, mrb_obj_value(mrb->exc), E_SYSSTACK_ERROR)) {
    return;
  }

  args.stream = stderr;
  args.tracehead = TRUE;
  exc_output_backtrace(mrb, mrb->exc, print_backtrace_i, (void*)&args);
}

#else

MRB_API void
mrb_print_backtrace(mrb_state *mrb)
{
}

#endif

MRB_API mrb_value
mrb_exc_backtrace(mrb_state *mrb, mrb_value self)
{
  mrb_value ary;

  ary = mrb_ary_new(mrb);
  exc_output_backtrace(mrb, mrb_obj_ptr(self), get_backtrace_i, (void*)mrb_ary_ptr(ary));

  return ary;
}

MRB_API mrb_value
mrb_get_backtrace(mrb_state *mrb)
{
  mrb_value ary;
  mrb_callinfo *ci = mrb->c->ci;
  mrb_code *pc = ci->pc;
  mrb_int ciidx = (mrb_int)(ci - mrb->c->cibase - 1);

  if (ciidx < 0) ciidx = 0;
  ary = mrb_ary_new(mrb);
  output_backtrace(mrb, ciidx, pc, get_backtrace_i, (void*)mrb_ary_ptr(ary));

  return ary;
}
