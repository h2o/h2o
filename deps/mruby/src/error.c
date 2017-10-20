/*
** error.c - Exception class
**
** See Copyright Notice in mruby.h
*/

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/debug.h>
#include <mruby/error.h>
#include <mruby/class.h>
#include <mruby/throw.h>

MRB_API mrb_value
mrb_exc_new(mrb_state *mrb, struct RClass *c, const char *ptr, size_t len)
{
  mrb_value arg = mrb_str_new(mrb, ptr, len);
  return mrb_obj_new(mrb, c, 1, &arg);
}

MRB_API mrb_value
mrb_exc_new_str(mrb_state *mrb, struct RClass* c, mrb_value str)
{
  str = mrb_str_to_str(mrb, str);
  return mrb_obj_new(mrb, c, 1, &str);
}

/*
 * call-seq:
 *    Exception.new(msg = nil)   ->  exception
 *
 *  Construct a new Exception object, optionally passing in
 *  a message.
 */

static mrb_value
exc_initialize(mrb_state *mrb, mrb_value exc)
{
  mrb_value mesg;
  mrb_int argc;
  mrb_value *argv;

  if (mrb_get_args(mrb, "|o*!", &mesg, &argv, &argc) >= 1) {
    mrb_iv_set(mrb, exc, mrb_intern_lit(mrb, "mesg"), mesg);
  }
  return exc;
}

/*
 *  Document-method: exception
 *
 *  call-seq:
 *     exc.exception(string)  ->  an_exception or exc
 *
 *  With no argument, or if the argument is the same as the receiver,
 *  return the receiver. Otherwise, create a new
 *  exception object of the same class as the receiver, but with a
 *  message equal to <code>string</code>.
 *
 */

static mrb_value
exc_exception(mrb_state *mrb, mrb_value self)
{
  mrb_value exc;
  mrb_value a;
  int argc;

  argc = mrb_get_args(mrb, "|o", &a);
  if (argc == 0) return self;
  if (mrb_obj_equal(mrb, self, a)) return self;
  exc = mrb_obj_clone(mrb, self);
  mrb_iv_set(mrb, exc, mrb_intern_lit(mrb, "mesg"), a);

  return exc;
}

/*
 * call-seq:
 *   exception.to_s   ->  string
 *
 * Returns exception's message (or the name of the exception if
 * no message is set).
 */

static mrb_value
exc_to_s(mrb_state *mrb, mrb_value exc)
{
  mrb_value mesg = mrb_attr_get(mrb, exc, mrb_intern_lit(mrb, "mesg"));
  struct RObject *p;

  if (!mrb_string_p(mesg)) {
    return mrb_str_new_cstr(mrb, mrb_obj_classname(mrb, exc));
  }
  p = mrb_obj_ptr(mesg);
  if (!p->c) {
    p->c = mrb->string_class;
  }
  return mesg;
}

/*
 * call-seq:
 *   exception.message   ->  string
 *
 * Returns the result of invoking <code>exception.to_s</code>.
 * Normally this returns the exception's message or name.
 */

static mrb_value
exc_message(mrb_state *mrb, mrb_value exc)
{
  return mrb_funcall(mrb, exc, "to_s", 0);
}

/*
 * call-seq:
 *   exception.inspect   -> string
 *
 * Returns this exception's file name, line number,
 * message and class name.
 * If file name or line number is not set,
 * returns message and class name.
 */

static mrb_value
exc_inspect(mrb_state *mrb, mrb_value exc)
{
  mrb_value str, mesg, file, line;
  mrb_bool append_mesg;
  const char *cname;

  mesg = mrb_attr_get(mrb, exc, mrb_intern_lit(mrb, "mesg"));
  file = mrb_attr_get(mrb, exc, mrb_intern_lit(mrb, "file"));
  line = mrb_attr_get(mrb, exc, mrb_intern_lit(mrb, "line"));

  append_mesg = !mrb_nil_p(mesg);
  if (append_mesg) {
    mesg = mrb_obj_as_string(mrb, mesg);
    append_mesg = RSTRING_LEN(mesg) > 0;
  }

  cname = mrb_obj_classname(mrb, exc);
  str = mrb_str_new_cstr(mrb, cname);
  if (mrb_string_p(file) && mrb_fixnum_p(line)) {
    if (append_mesg) {
      str = mrb_format(mrb, "%S:%S: %S (%S)", file, line, mesg, str);
    }
    else {
      str = mrb_format(mrb, "%S:%S: %S", file, line, str);
    }
  }
  else if (append_mesg) {
    str = mrb_format(mrb, "%S: %S", str, mesg);
  }
  return str;
}

void mrb_keep_backtrace(mrb_state *mrb, mrb_value exc);

static void
set_backtrace(mrb_state *mrb, mrb_value exc, mrb_value backtrace)
{
  if (!mrb_array_p(backtrace)) {
  type_err:
    mrb_raise(mrb, E_TYPE_ERROR, "backtrace must be Array of String");
  }
  else {
    const mrb_value *p = RARRAY_PTR(backtrace);
    const mrb_value *pend = p + RARRAY_LEN(backtrace);

    while (p < pend) {
      if (!mrb_string_p(*p)) goto type_err;
      p++;
    }
  }
  mrb_iv_set(mrb, exc, mrb_intern_lit(mrb, "backtrace"), backtrace);
}

static mrb_value
exc_set_backtrace(mrb_state *mrb, mrb_value exc)
{
  mrb_value backtrace;

  mrb_get_args(mrb, "o", &backtrace);
  set_backtrace(mrb, exc, backtrace);
  return backtrace;
}

static void
exc_debug_info(mrb_state *mrb, struct RObject *exc)
{
  mrb_callinfo *ci = mrb->c->ci;
  mrb_code *pc = ci->pc;

  while (ci >= mrb->c->cibase) {
    mrb_code *err = ci->err;

    if (!err && pc) err = pc - 1;
    if (err && ci->proc && !MRB_PROC_CFUNC_P(ci->proc)) {
      mrb_irep *irep = ci->proc->body.irep;

      int32_t const line = mrb_debug_get_line(irep, err - irep->iseq);
      char const* file = mrb_debug_get_filename(irep, err - irep->iseq);
      if (line != -1 && file) {
        mrb_obj_iv_set(mrb, exc, mrb_intern_lit(mrb, "file"), mrb_str_new_cstr(mrb, file));
        mrb_obj_iv_set(mrb, exc, mrb_intern_lit(mrb, "line"), mrb_fixnum_value(line));
        return;
      }
    }
    pc = ci->pc;
    ci--;
  }
}

void
mrb_exc_set(mrb_state *mrb, mrb_value exc)
{
  if (mrb_nil_p(exc)) {
    mrb->exc = 0;
  }
  else {
    mrb->exc = mrb_obj_ptr(exc);
    if (!mrb->gc.out_of_memory) {
      exc_debug_info(mrb, mrb->exc);
      mrb_keep_backtrace(mrb, exc);
    }
  }
}

MRB_API mrb_noreturn void
mrb_exc_raise(mrb_state *mrb, mrb_value exc)
{
  if (!mrb_obj_is_kind_of(mrb, exc, mrb->eException_class)) {
    mrb_raise(mrb, E_TYPE_ERROR, "exception object expected");
  }
  mrb_exc_set(mrb, exc);
  if (!mrb->jmp) {
    mrb_p(mrb, exc);
    abort();
  }
  MRB_THROW(mrb->jmp);
}

MRB_API mrb_noreturn void
mrb_raise(mrb_state *mrb, struct RClass *c, const char *msg)
{
  mrb_exc_raise(mrb, mrb_exc_new_str(mrb, c, mrb_str_new_cstr(mrb, msg)));
}

MRB_API mrb_value
mrb_vformat(mrb_state *mrb, const char *format, va_list ap)
{
  const char *p = format;
  const char *b = p;
  ptrdiff_t size;
  mrb_value ary = mrb_ary_new_capa(mrb, 4);
  int ai = mrb_gc_arena_save(mrb);

  while (*p) {
    const char c = *p++;

    if (c == '%') {
      if (*p == 'S') {
        mrb_value val;

        size = p - b - 1;
        mrb_ary_push(mrb, ary, mrb_str_new(mrb, b, size));
        val = va_arg(ap, mrb_value);
        mrb_ary_push(mrb, ary, mrb_obj_as_string(mrb, val));
        b = p + 1;
      }
    }
    else if (c == '\\') {
      if (*p) {
        size = p - b - 1;
        mrb_ary_push(mrb, ary, mrb_str_new(mrb, b, size));
        mrb_ary_push(mrb, ary, mrb_str_new(mrb, p, 1));
        b = ++p;
      }
      else {
        break;
      }
    }
    mrb_gc_arena_restore(mrb, ai);
  }
  if (b == format) {
    return mrb_str_new_cstr(mrb, format);
  }
  else {
    size = p - b;
    if (size > 0) {
      mrb_ary_push(mrb, ary, mrb_str_new(mrb, b, size));
      mrb_gc_arena_restore(mrb, ai);
    }
    return mrb_ary_join(mrb, ary, mrb_nil_value());
  }
}

MRB_API mrb_value
mrb_format(mrb_state *mrb, const char *format, ...)
{
  va_list ap;
  mrb_value str;

  va_start(ap, format);
  str = mrb_vformat(mrb, format, ap);
  va_end(ap);

  return str;
}

static mrb_noreturn void
raise_va(mrb_state *mrb, struct RClass *c, const char *fmt, va_list ap, int argc, mrb_value *argv)
{
  mrb_value mesg;

  mesg = mrb_vformat(mrb, fmt, ap);
  if (argv == NULL) {
    argv = &mesg;
  }
  else {
    argv[0] = mesg;
  }
  mrb_exc_raise(mrb, mrb_obj_new(mrb, c, argc+1, argv));
}

MRB_API mrb_noreturn void
mrb_raisef(mrb_state *mrb, struct RClass *c, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  raise_va(mrb, c, fmt, args, 0, NULL);
  va_end(args);
}

MRB_API mrb_noreturn void
mrb_name_error(mrb_state *mrb, mrb_sym id, const char *fmt, ...)
{
  mrb_value argv[2];
  va_list args;

  va_start(args, fmt);
  argv[1] = mrb_symbol_value(id);
  raise_va(mrb, E_NAME_ERROR, fmt, args, 1, argv);
  va_end(args);
}

MRB_API void
mrb_warn(mrb_state *mrb, const char *fmt, ...)
{
#ifndef MRB_DISABLE_STDIO
  va_list ap;
  mrb_value str;

  va_start(ap, fmt);
  str = mrb_vformat(mrb, fmt, ap);
  fputs("warning: ", stderr);
  fwrite(RSTRING_PTR(str), RSTRING_LEN(str), 1, stderr);
  va_end(ap);
#endif
}

MRB_API mrb_noreturn void
mrb_bug(mrb_state *mrb, const char *fmt, ...)
{
#ifndef MRB_DISABLE_STDIO
  va_list ap;
  mrb_value str;

  va_start(ap, fmt);
  str = mrb_vformat(mrb, fmt, ap);
  fputs("bug: ", stderr);
  fwrite(RSTRING_PTR(str), RSTRING_LEN(str), 1, stderr);
  va_end(ap);
#endif
  exit(EXIT_FAILURE);
}

MRB_API mrb_value
mrb_make_exception(mrb_state *mrb, int argc, const mrb_value *argv)
{
  mrb_value mesg;
  int n;

  mesg = mrb_nil_value();
  switch (argc) {
    case 0:
    break;
    case 1:
      if (mrb_nil_p(argv[0]))
        break;
      if (mrb_string_p(argv[0])) {
        mesg = mrb_exc_new_str(mrb, E_RUNTIME_ERROR, argv[0]);
        break;
      }
      n = 0;
      goto exception_call;

    case 2:
    case 3:
      n = 1;
exception_call:
      {
        mrb_sym exc = mrb_intern_lit(mrb, "exception");
        if (mrb_respond_to(mrb, argv[0], exc)) {
          mesg = mrb_funcall_argv(mrb, argv[0], exc, n, argv+1);
        }
        else {
          /* undef */
          mrb_raise(mrb, E_TYPE_ERROR, "exception class/object expected");
        }
      }

      break;
    default:
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "wrong number of arguments (%S for 0..3)", mrb_fixnum_value(argc));
      break;
  }
  if (argc > 0) {
    if (!mrb_obj_is_kind_of(mrb, mesg, mrb->eException_class))
      mrb_raise(mrb, mrb->eException_class, "exception object expected");
    if (argc > 2)
      set_backtrace(mrb, mesg, argv[2]);
  }

  return mesg;
}

MRB_API void
mrb_sys_fail(mrb_state *mrb, const char *mesg)
{
  struct RClass *sce;
  mrb_int no;

  no = (mrb_int)errno;
  if (mrb_class_defined(mrb, "SystemCallError")) {
    sce = mrb_class_get(mrb, "SystemCallError");
    if (mesg != NULL) {
      mrb_funcall(mrb, mrb_obj_value(sce), "_sys_fail", 2, mrb_fixnum_value(no), mrb_str_new_cstr(mrb, mesg));
    }
    else {
      mrb_funcall(mrb, mrb_obj_value(sce), "_sys_fail", 1, mrb_fixnum_value(no));
    }
  }
  else {
    mrb_raise(mrb, E_RUNTIME_ERROR, mesg);
  }
}

MRB_API mrb_noreturn void
mrb_no_method_error(mrb_state *mrb, mrb_sym id, mrb_value args, char const* fmt, ...)
{
  mrb_value exc;
  mrb_value argv[3];
  va_list ap;

  va_start(ap, fmt);
  argv[0] = mrb_vformat(mrb, fmt, ap);
  argv[1] = mrb_symbol_value(id);
  argv[2] = args;
  va_end(ap);
  exc = mrb_obj_new(mrb, E_NOMETHOD_ERROR, 3, argv);
  mrb_exc_raise(mrb, exc);
}

void
mrb_init_exception(mrb_state *mrb)
{
  struct RClass *exception, *script_error, *stack_error, *nomem_error;

  mrb->eException_class = exception = mrb_define_class(mrb, "Exception", mrb->object_class); /* 15.2.22 */
  MRB_SET_INSTANCE_TT(exception, MRB_TT_EXCEPTION);
  mrb_define_class_method(mrb, exception, "exception", mrb_instance_new,  MRB_ARGS_ANY());
  mrb_define_method(mrb, exception, "exception",       exc_exception,     MRB_ARGS_ANY());
  mrb_define_method(mrb, exception, "initialize",      exc_initialize,    MRB_ARGS_ANY());
  mrb_define_method(mrb, exception, "to_s",            exc_to_s,          MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "message",         exc_message,       MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "inspect",         exc_inspect,       MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "backtrace",       mrb_exc_backtrace, MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "set_backtrace",   exc_set_backtrace, MRB_ARGS_REQ(1));

  mrb->eStandardError_class = mrb_define_class(mrb, "StandardError", mrb->eException_class); /* 15.2.23 */
  mrb_define_class(mrb, "RuntimeError", mrb->eStandardError_class);          /* 15.2.28 */
  script_error = mrb_define_class(mrb, "ScriptError", mrb->eException_class);                /* 15.2.37 */
  mrb_define_class(mrb, "SyntaxError", script_error);                                        /* 15.2.38 */
  stack_error = mrb_define_class(mrb, "SystemStackError", exception);
  mrb->stack_err = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, stack_error, "stack level too deep"));

  nomem_error = mrb_define_class(mrb, "NoMemoryError", exception);
  mrb->nomem_err = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, nomem_error, "Out of memory"));
#ifdef MRB_GC_FIXED_ARENA
  mrb->arena_err = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, nomem_error, "arena overflow error"));
#endif
}
