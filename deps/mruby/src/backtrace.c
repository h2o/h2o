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
#include <mruby/data.h>

struct backtrace_location {
  int lineno;
  const char *filename;
  mrb_sym method_id;
};

typedef void (*each_backtrace_func)(mrb_state*, int i, struct backtrace_location*, void*);

static const mrb_data_type bt_type = { "Backtrace", mrb_free };

static void
each_backtrace(mrb_state *mrb, mrb_int ciidx, mrb_code *pc0, each_backtrace_func func, void *data)
{
  int i, j;

  if (ciidx >= mrb->c->ciend - mrb->c->cibase)
    ciidx = 10; /* ciidx is broken... */

  for (i=ciidx, j=0; i >= 0; i--,j++) {
    struct backtrace_location loc;
    mrb_callinfo *ci;
    mrb_irep *irep;
    mrb_code *pc;

    ci = &mrb->c->cibase[i];

    if (!ci->proc) continue;
    if (MRB_PROC_CFUNC_P(ci->proc)) continue;

    irep = ci->proc->body.irep;
    if (!irep) continue;

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

    if (!loc.filename) {
      loc.filename = "(unknown)";
    }

    loc.method_id = ci->mid;
    func(mrb, j, &loc, data);
  }
}

#ifndef MRB_DISABLE_STDIO

static void
print_backtrace(mrb_state *mrb, mrb_value backtrace)
{
  int i, n;
  FILE *stream = stderr;

  if (!mrb_array_p(backtrace)) return;
  fprintf(stream, "trace:\n");

  n = RARRAY_LEN(backtrace);
  for (i=0; n--; i++) {
    mrb_value entry = RARRAY_PTR(backtrace)[n];

    if (mrb_string_p(entry)) {
      fprintf(stream, "\t[%d] %.*s\n", i, (int)RSTRING_LEN(entry), RSTRING_PTR(entry));
    }
  }
}

static void
print_packed_backtrace(mrb_state *mrb, mrb_value packed)
{
  FILE *stream = stderr;
  struct backtrace_location *bt;
  int n, i;

  bt = (struct backtrace_location*)mrb_data_check_get_ptr(mrb, packed, &bt_type);
  if (bt == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "broken backtrace");
  }
  n = (mrb_int)RDATA(packed)->flags;

  fprintf(stream, "trace:\n");
  for (i = 0; n--; i++) {
    int ai = mrb_gc_arena_save(mrb);
    struct backtrace_location *entry = &bt[n];
    if (entry->filename == NULL) continue;
    fprintf(stream, "\t[%d] %s:%d", (int)i, entry->filename, entry->lineno);
    if (entry->method_id != 0) {
      const char *method_name;

      method_name = mrb_sym2name(mrb, entry->method_id);
      fprintf(stream, ":in %s", method_name);
      mrb_gc_arena_restore(mrb, ai);
    }
    fprintf(stream, "\n");
  }
}

/* mrb_print_backtrace

   function to retrieve backtrace information from the last exception.
*/

MRB_API void
mrb_print_backtrace(mrb_state *mrb)
{
  mrb_value backtrace;

  if (!mrb->exc) {
    return;
  }

  backtrace = mrb_obj_iv_get(mrb, mrb->exc, mrb_intern_lit(mrb, "backtrace"));
  if (mrb_nil_p(backtrace)) return;
  if (mrb_array_p(backtrace)) {
    print_backtrace(mrb, backtrace);
  }
  else {
    print_packed_backtrace(mrb, backtrace);
  }
}
#else

MRB_API void
mrb_print_backtrace(mrb_state *mrb)
{
}

#endif

static void
pack_backtrace_i(mrb_state *mrb,
                 int i,
                 struct backtrace_location *loc,
                 void *data)
{
  struct backtrace_location *entry = (struct backtrace_location*)data;

  entry[i] = *loc;
}

static mrb_value
packed_backtrace(mrb_state *mrb)
{
  struct RData *backtrace;
  ptrdiff_t ciidx = mrb->c->ci - mrb->c->cibase;
  mrb_int len = (ciidx+1)*sizeof(struct backtrace_location);
  void *ptr;

  ptr = mrb_malloc(mrb, len);
  memset(ptr, 0, len);
  backtrace = mrb_data_object_alloc(mrb, NULL, ptr, &bt_type);
  backtrace->flags = (unsigned int)ciidx+1;
  each_backtrace(mrb, ciidx, mrb->c->ci->pc, pack_backtrace_i, ptr);
  return mrb_obj_value(backtrace);
}

void
mrb_keep_backtrace(mrb_state *mrb, mrb_value exc)
{
  mrb_value backtrace;
  int ai = mrb_gc_arena_save(mrb);

  backtrace = packed_backtrace(mrb);
  mrb_iv_set(mrb, exc, mrb_intern_lit(mrb, "backtrace"), backtrace);
  mrb_gc_arena_restore(mrb, ai);
}

mrb_value
mrb_unpack_backtrace(mrb_state *mrb, mrb_value backtrace)
{
  struct backtrace_location *bt;
  mrb_int n, i;

  if (mrb_nil_p(backtrace)) return mrb_ary_new_capa(mrb, 0);
  if (mrb_array_p(backtrace)) return backtrace;
  bt = (struct backtrace_location*)mrb_data_check_get_ptr(mrb, backtrace, &bt_type);
  if (bt == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "broken backtrace");
  }
  n = (mrb_int)RDATA(backtrace)->flags;
  backtrace = mrb_ary_new_capa(mrb, n);
  for (i = 0; i < n; i++) {
    int ai = mrb_gc_arena_save(mrb);
    struct backtrace_location *entry = &bt[i];
    mrb_value btline;

    if (entry->filename == NULL) continue;
    btline = mrb_format(mrb, "%S:%S",
                              mrb_str_new_cstr(mrb, entry->filename),
                              mrb_fixnum_value(entry->lineno));
    if (entry->method_id != 0) {
      mrb_str_cat_lit(mrb, btline, ":in ");
      mrb_str_cat_cstr(mrb, btline, mrb_sym2name(mrb, entry->method_id));
    }
    mrb_ary_push(mrb, backtrace, btline);
    mrb_gc_arena_restore(mrb, ai);
  }

  return backtrace;
}

MRB_API mrb_value
mrb_exc_backtrace(mrb_state *mrb, mrb_value exc)
{
  mrb_sym attr_name;
  mrb_value backtrace;

  attr_name = mrb_intern_lit(mrb, "backtrace");
  backtrace = mrb_iv_get(mrb, exc, attr_name);
  if (mrb_nil_p(backtrace) || mrb_array_p(backtrace)) {
    return backtrace;
  }
  backtrace = mrb_unpack_backtrace(mrb, backtrace);
  mrb_iv_set(mrb, exc, attr_name, backtrace);
  return backtrace;
}

MRB_API mrb_value
mrb_get_backtrace(mrb_state *mrb)
{
  return mrb_unpack_backtrace(mrb, packed_backtrace(mrb));
}
