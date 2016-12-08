/*
** backtrace.c -
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/variable.h>
#include <mruby/proc.h>
#include <mruby/array.h>
#include <mruby/string.h>
#include <mruby/class.h>
#include <mruby/debug.h>
#include <mruby/error.h>
#include <mruby/numeric.h>

struct backtrace_location_raw {
  int i;
  int lineno;
  const char *filename;
  mrb_sym method_id;
  char sep;
  struct RClass *klass;
};

struct backtrace_location {
  int i;
  int lineno;
  const char *filename;
  const char *method;
  char sep;
  const char *class_name;
};

typedef void (*each_backtrace_func)(mrb_state*, struct backtrace_location_raw*, void*);
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
      fprintf(args->stream, ":in %s%c%s", loc->class_name, loc->sep, loc->method);
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
      mrb_str_cat(mrb, str, &loc->sep, 1);
    }

    mrb_str_cat_cstr(mrb, str, loc->method);
  }

  mrb_ary_push(mrb, ary, str);
  mrb_gc_arena_restore(mrb, ai);
}

static void
each_backtrace(mrb_state *mrb, mrb_int ciidx, mrb_code *pc0, each_backtrace_func func, void *data)
{
  int i;

  if (ciidx >= mrb->c->ciend - mrb->c->cibase)
    ciidx = 10; /* ciidx is broken... */

  for (i = ciidx; i >= 0; i--) {
    struct backtrace_location_raw loc;
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
      loc.sep = '.';
    }
    else {
      loc.sep = '#';
    }

    if (!loc.filename) {
      loc.filename = "(unknown)";
    }

    loc.method_id = ci->mid;
    loc.klass = ci->proc->target_class;
    loc.i = i;
    func(mrb, &loc, data);
  }
}

struct output_backtrace_args {
  output_stream_func func;
  void *data;
};

static void
output_backtrace_i(mrb_state *mrb, struct backtrace_location_raw *loc_raw, void *data)
{
  struct backtrace_location loc;
  struct output_backtrace_args *args = (struct output_backtrace_args *)data;

  loc.i          = loc_raw->i;
  loc.lineno     = loc_raw->lineno;
  loc.filename   = loc_raw->filename;
  loc.method     = mrb_sym2name(mrb, loc_raw->method_id);
  loc.sep        = loc_raw->sep;
  loc.class_name = mrb_class_name(mrb, loc_raw->klass);

  args->func(mrb, &loc, args->data);
}

static void
output_backtrace(mrb_state *mrb, mrb_int ciidx, mrb_code *pc0, output_stream_func func, void *data)
{
  struct output_backtrace_args args;
  args.func = func;
  args.data = data;
  each_backtrace(mrb, ciidx, pc0, output_backtrace_i, &args);
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

static void
print_backtrace(mrb_state *mrb, mrb_value backtrace)
{
  int i, n;
  FILE *stream = stderr;

  fprintf(stream, "trace:\n");

  n = RARRAY_LEN(backtrace);
  for (i = 0; i < n; i++) {
    mrb_value entry = RARRAY_PTR(backtrace)[i];

    fprintf(stream, "\t[%d] %.*s\n", i, (int)RSTRING_LEN(entry), RSTRING_PTR(entry));
  }
}

static void
print_backtrace_saved(mrb_state *mrb)
{
  int i;
  FILE *stream = stderr;

  fprintf(stream, "trace:\n");
  for (i = 0; i < mrb->backtrace.n; i++) {
    mrb_backtrace_entry *entry;

    entry = &(mrb->backtrace.entries[i]);
    fprintf(stream, "\t[%d] %s:%d", i, entry->filename, entry->lineno);

    if (entry->method_id != 0) {
      const char *method_name;

      method_name = mrb_sym2name(mrb, entry->method_id);
      if (entry->klass) {
        fprintf(stream, ":in %s%c%s",
                mrb_class_name(mrb, entry->klass),
                entry->sep,
                method_name);
      }
      else {
        fprintf(stream, ":in %s", method_name);
      }
    }

    fprintf(stream, "\n");
  }
}

MRB_API void
mrb_print_backtrace(mrb_state *mrb)
{
  mrb_value backtrace;

  if (!mrb->exc || mrb_obj_is_kind_of(mrb, mrb_obj_value(mrb->exc), E_SYSSTACK_ERROR)) {
    return;
  }

  backtrace = mrb_obj_iv_get(mrb, mrb->exc, mrb_intern_lit(mrb, "backtrace"));
  if (!mrb_nil_p(backtrace)) {
    print_backtrace(mrb, backtrace);
  }
  else if (mrb->backtrace.n > 0) {
    print_backtrace_saved(mrb);
  }
  else {
    struct print_backtrace_args args;
    args.stream = stderr;
    args.tracehead = TRUE;
    exc_output_backtrace(mrb, mrb->exc, print_backtrace_i, (void*)&args);
  }
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

void
mrb_free_backtrace(mrb_state *mrb)
{
  mrb->backtrace.exc = 0;
  mrb->backtrace.n = 0;
  mrb->backtrace.n_allocated = 0;
  mrb_free(mrb, mrb->backtrace.entries);
}

static void
save_backtrace_i(mrb_state *mrb,
                 struct backtrace_location_raw *loc_raw,
                 void *data)
{
  mrb_backtrace_entry *entry;

  if (mrb->backtrace.n >= mrb->backtrace.n_allocated) {
    int new_n_allocated;
    if (mrb->backtrace.n_allocated == 0) {
      new_n_allocated = 8;
    }
    else {
      new_n_allocated = mrb->backtrace.n_allocated * 2;
    }
    mrb->backtrace.entries = (mrb_backtrace_entry *)
      mrb_realloc(mrb,
                  mrb->backtrace.entries,
                  sizeof(mrb_backtrace_entry) * new_n_allocated);
    mrb->backtrace.n_allocated = new_n_allocated;
  }

  entry = &mrb->backtrace.entries[mrb->backtrace.n];
  entry->filename  = loc_raw->filename;
  entry->lineno    = loc_raw->lineno;
  entry->klass     = loc_raw->klass;
  entry->sep       = loc_raw->sep;
  entry->method_id = loc_raw->method_id;

  mrb->backtrace.n++;
}

void
mrb_save_backtrace(mrb_state *mrb)
{
  mrb_value lastpc;
  mrb_code *code;
  mrb_int ciidx;

  mrb->backtrace.n = 0;
  mrb->backtrace.exc = 0;

  if (!mrb->exc)
    return;

  mrb->backtrace.exc = mrb->exc;

  lastpc = mrb_obj_iv_get(mrb, mrb->exc, mrb_intern_lit(mrb, "lastpc"));
  if (mrb_nil_p(lastpc)) {
    code = NULL;
  }
  else {
    code = (mrb_code*)mrb_cptr(lastpc);
  }

  ciidx = mrb_fixnum(mrb_obj_iv_get(mrb, mrb->exc, mrb_intern_lit(mrb, "ciidx")));

  each_backtrace(mrb, ciidx, code, save_backtrace_i, NULL);
}

mrb_value
mrb_restore_backtrace(mrb_state *mrb)
{
  int i;
  mrb_value backtrace;

  backtrace = mrb_ary_new(mrb);
  for (i = 0; i < mrb->backtrace.n; i++) {
    int ai;
    mrb_backtrace_entry *entry;
    mrb_value mrb_entry;

    ai = mrb_gc_arena_save(mrb);
    entry = &(mrb->backtrace.entries[i]);

    mrb_entry = mrb_str_new_cstr(mrb, entry->filename);
    mrb_str_cat_lit(mrb, mrb_entry, ":");
    mrb_str_concat(mrb, mrb_entry,
                   mrb_fixnum_to_str(mrb,
                                     mrb_fixnum_value(entry->lineno),
                                     10));
    if (entry->method_id != 0) {
      mrb_str_cat_lit(mrb, mrb_entry, ":in ");

      if (entry->klass) {
        mrb_str_cat_cstr(mrb, mrb_entry, mrb_class_name(mrb, entry->klass));
        mrb_str_cat(mrb, mrb_entry, &entry->sep, 1);
      }

      mrb_str_cat_cstr(mrb, mrb_entry, mrb_sym2name(mrb, entry->method_id));
    }

    mrb_ary_push(mrb, backtrace, mrb_entry);

    mrb_gc_arena_restore(mrb, ai);
  }

  return backtrace;
}
