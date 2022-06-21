/*
** error.c - Exception class
**
** See Copyright Notice in mruby.h
*/

#include <errno.h>
#include <stdlib.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/error.h>
#include <mruby/class.h>
#include <mruby/throw.h>
#include <mruby/presym.h>

static void
exc_mesg_set(mrb_state *mrb, struct RException *exc, mrb_value mesg)
{
  if (mrb_string_p(mesg)) {
    exc->flags |= MRB_EXC_MESG_STRING_FLAG;
    exc->mesg = RSTRING(mesg);
    mrb_field_write_barrier_value(mrb, (struct RBasic*)exc, mesg);
  }
  else {
    exc->flags &= ~MRB_EXC_MESG_STRING_FLAG;
    if (mrb_nil_p(mesg)) {
      exc->mesg = 0;
    }
    else {
      mrb_obj_iv_set(mrb, (struct RObject*)exc, MRB_SYM(mesg), mesg);
    }
  }
}

static mrb_value
exc_mesg_get(mrb_state *mrb, struct RException *exc)
{
  if ((exc->flags & MRB_EXC_MESG_STRING_FLAG) != 0) {
    return mrb_obj_value(exc->mesg);
  }
  else {
    return mrb_obj_iv_get(mrb, (struct RObject*)exc, MRB_SYM(mesg));
  }
}

MRB_API mrb_value
mrb_exc_new_str(mrb_state *mrb, struct RClass* c, mrb_value str)
{
  mrb_ensure_string_type(mrb, str);

  struct RBasic* e = mrb_obj_alloc(mrb, MRB_TT_EXCEPTION, c);
  mrb_value exc = mrb_obj_value(e);
  mrb_iv_set(mrb, exc, MRB_SYM(mesg), str);
  return exc;
}

MRB_API mrb_value
mrb_exc_new(mrb_state *mrb, struct RClass *c, const char *ptr, size_t len)
{
  return mrb_exc_new_str(mrb, c, mrb_str_new(mrb, ptr, len));
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

  if (mrb_get_args(mrb, "|o", &mesg) == 1) {
    exc_mesg_set(mrb, mrb_exc_ptr(exc), mesg);
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
  mrb_int argc;

  argc = mrb_get_args(mrb, "|o", &a);
  if (argc == 0) return self;
  if (mrb_obj_equal(mrb, self, a)) return self;
  exc = mrb_obj_clone(mrb, self);
  exc_mesg_set(mrb, mrb_exc_ptr(exc), a);

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
  mrb_value mesg = exc_mesg_get(mrb, mrb_exc_ptr(exc));
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
  return mrb_funcall_id(mrb, exc, MRB_SYM(to_s), 0);
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

mrb_value
mrb_exc_inspect(mrb_state *mrb, mrb_value exc)
{
  mrb_value mesg = exc_mesg_get(mrb, mrb_exc_ptr(exc));
  mrb_value cname = mrb_mod_to_s(mrb, mrb_obj_value(mrb_obj_class(mrb, exc)));
  mesg = mrb_obj_as_string(mrb, mesg);
  return RSTRING_LEN(mesg) == 0 ? cname : mrb_format(mrb, "%v (%v)", mesg, cname);
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
  mrb_iv_set(mrb, exc, MRB_SYM(backtrace), backtrace);
}

static mrb_value
exc_set_backtrace(mrb_state *mrb, mrb_value exc)
{
  mrb_value backtrace = mrb_get_arg1(mrb);

  set_backtrace(mrb, exc, backtrace);
  return backtrace;
}

void
mrb_exc_set(mrb_state *mrb, mrb_value exc)
{
  if (mrb_nil_p(exc)) {
    mrb->exc = 0;
  }
  else {
    mrb->exc = mrb_obj_ptr(exc);
    if (mrb->gc.arena_idx > 0 &&
        (struct RBasic*)mrb->exc == mrb->gc.arena[mrb->gc.arena_idx-1]) {
      mrb->gc.arena_idx--;
    }
    if (!mrb->gc.out_of_memory && !mrb_frozen_p(mrb->exc)) {
      mrb_keep_backtrace(mrb, exc);
    }
  }
}

static mrb_noreturn void
exc_throw(mrb_state *mrb, mrb_value exc)
{
  if (!mrb->jmp) {
    mrb_p(mrb, exc);
    abort();
  }
  MRB_THROW(mrb->jmp);
}

MRB_API mrb_noreturn void
mrb_exc_raise(mrb_state *mrb, mrb_value exc)
{
  if (mrb_break_p(exc)) {
    mrb->exc = mrb_obj_ptr(exc);
  }
  else {
    if (!mrb_obj_is_kind_of(mrb, exc, mrb->eException_class)) {
      mrb_raise(mrb, E_TYPE_ERROR, "exception object expected");
    }
    mrb_exc_set(mrb, exc);
  }
  exc_throw(mrb, exc);
}

MRB_API mrb_noreturn void
mrb_raise(mrb_state *mrb, struct RClass *c, const char *msg)
{
  mrb_exc_raise(mrb, mrb_exc_new_str(mrb, c, mrb_str_new_cstr(mrb, msg)));
}

/*
 * <code>vsprintf</code> like formatting.
 *
 * The syntax of a format sequence is as follows.
 *
 *   %[modifier]specifier
 *
 * The modifiers are:
 *
 *   ----------+------------------------------------------------------------
 *   Modifier  | Meaning
 *   ----------+------------------------------------------------------------
 *       !     | Convert to string by corresponding `inspect` instead of
 *             | corresponding `to_s`.
 *   ----------+------------------------------------------------------------
 *
 * The specifiers are:
 *
 *   ----------+----------------+--------------------------------------------
 *   Specifier | Argument Type  | Note
 *   ----------+----------------+--------------------------------------------
 *       c     | char           |
 *       d     | int            |
 *       f     | mrb_float      |
 *       i     | mrb_int        |
 *       l     | char*, size_t  | Arguments are string and length.
 *       n     | mrb_sym        |
 *       s     | char*          | Argument is NUL terminated string.
 *       t     | mrb_value      | Convert to type (class) of object.
 *      v,S    | mrb_value      |
 *       C     | struct RClass* |
 *       T     | mrb_value      | Convert to real type (class) of object.
 *       Y     | mrb_value      | Same as `!v` if argument is `true`, `false`
 *             |                | or `nil`, otherwise same as `T`.
 *       %     | -              | Convert to percent sign itself (no argument
 *             |                | taken).
 *   ----------+----------------+--------------------------------------------
 */
MRB_API mrb_value
mrb_vformat(mrb_state *mrb, const char *format, va_list ap)
{
  const char *chars, *p = format, *b = format, *e;
  char ch;
  size_t len;
  mrb_int i;
  struct RClass *cls;
  mrb_bool inspect = FALSE;
  mrb_value result = mrb_str_new_capa(mrb, 128), obj, str;
  int ai = mrb_gc_arena_save(mrb);

  while (*p) {
    const char c = *p++;
    e = p;
    if (c == '%') {
      if (*p == '!') {
        inspect = TRUE;
        ++p;
      }
      if (!*p) break;
      switch (*p) {
        case 'c':
          ch = (char)va_arg(ap, int);
          chars = &ch;
          len = 1;
          goto L_cat;
        case 'd': case 'i':
#if MRB_INT_MAX < INT_MAX
          i = (mrb_int)va_arg(ap, int);
#else
          i = *p == 'd' ? (mrb_int)va_arg(ap, int) : va_arg(ap, mrb_int);
#endif
          obj = mrb_int_value(mrb, i);
          goto L_cat_obj;
#ifndef MRB_NO_FLOAT
        case 'f':
          obj = mrb_float_value(mrb, (mrb_float)va_arg(ap, double));
          goto L_cat_obj;
#endif
        case 'l':
          chars = va_arg(ap, char*);
          len = va_arg(ap, size_t);
        L_cat:
          if (inspect) {
            obj = mrb_str_new(mrb, chars, len);
            goto L_cat_obj;
          }
        L_cat_plain:
          mrb_str_cat(mrb, result, b,  e - b - 1);
          mrb_str_cat(mrb, result, chars, len);
          b = ++p;
          mrb_gc_arena_restore(mrb, ai);
          break;
        case 'n':
#if UINT32_MAX < INT_MAX
          obj = mrb_symbol_value((mrb_sym)va_arg(ap, int));
#else
          obj = mrb_symbol_value(va_arg(ap, mrb_sym));
#endif
          goto L_cat_obj;
        case 's':
          chars = va_arg(ap, char*);
          len = strlen(chars);
          goto L_cat;
        case 't':
          cls = mrb_class(mrb, va_arg(ap, mrb_value));
          goto L_cat_class;
        case 'v': case 'S':
          obj = va_arg(ap, mrb_value);
        L_cat_obj:
          str = (inspect ? mrb_inspect : mrb_obj_as_string)(mrb, obj);
          if (mrb_type(str) != MRB_TT_STRING) {
            chars = "void (no string conversion)";
            len = strlen(chars);
          }
          else {
            chars = RSTRING_PTR(str);
            len = RSTRING_LEN(str);
          }
          goto L_cat_plain;
        case 'C':
          cls = va_arg(ap, struct RClass*);
        L_cat_class:
          obj = mrb_obj_value(cls);
          goto L_cat_obj;
        case 'T':
          obj = va_arg(ap, mrb_value);
        L_cat_real_class_of:
          cls = mrb_obj_class(mrb, obj);
          goto L_cat_class;
        case 'Y':
          obj = va_arg(ap, mrb_value);
          if (!mrb_test(obj) || mrb_true_p(obj)) {
            inspect = TRUE;
            goto L_cat_obj;
          }
          else {
            goto L_cat_real_class_of;
          }
        case '%':
        L_cat_current:
          chars = p;
          len = 1;
          goto L_cat_plain;
        default:
          mrb_raisef(mrb, E_ARGUMENT_ERROR, "malformed format string - %%%c", *p);
      }
    }
    else if (c == '\\') {
      if (!*p) break;
      goto L_cat_current;

    }
  }

  mrb_str_cat(mrb, result, b, p - b);
  return result;
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

static mrb_value
error_va(mrb_state *mrb, struct RClass *c, const char *fmt, va_list ap)
{
  mrb_value mesg = mrb_vformat(mrb, fmt, ap);
  return mrb_exc_new_str(mrb, c, mesg);
}

MRB_API mrb_noreturn void
mrb_raisef(mrb_state *mrb, struct RClass *c, const char *fmt, ...)
{
  va_list ap;
  mrb_value exc;

  va_start(ap, fmt);
  exc = error_va(mrb, c, fmt, ap);
  va_end(ap);

  mrb_exc_raise(mrb, exc);
}

MRB_API mrb_noreturn void
mrb_name_error(mrb_state *mrb, mrb_sym id, const char *fmt, ...)
{
  va_list ap;
  mrb_value exc;

  va_start(ap, fmt);
  exc = error_va(mrb, E_NAME_ERROR, fmt, ap);
  va_end(ap);
  mrb_iv_set(mrb, exc, MRB_IVSYM(name), mrb_symbol_value(id));
  mrb_exc_raise(mrb, exc);
}

MRB_API void
mrb_warn(mrb_state *mrb, const char *fmt, ...)
{
#ifndef MRB_NO_STDIO
  va_list ap;
  mrb_value str;

  va_start(ap, fmt);
  str = mrb_vformat(mrb, fmt, ap);
  fputs("warning: ", stderr);
  fwrite(RSTRING_PTR(str), RSTRING_LEN(str), 1, stderr);
  putc('\n', stderr);
  va_end(ap);
#endif
}

MRB_API mrb_noreturn void
mrb_bug(mrb_state *mrb, const char *fmt, ...)
{
#ifndef MRB_NO_STDIO
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
mrb_make_exception(mrb_state *mrb, mrb_int argc, const mrb_value *argv)
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
        mrb_sym exc = MRB_SYM(exception);
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
      mrb_argnum_error(mrb, argc, 0, 3);
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
  va_list ap;
  mrb_value exc;

  va_start(ap, fmt);
  exc = error_va(mrb, E_NOMETHOD_ERROR, fmt, ap);
  va_end(ap);
  mrb_iv_set(mrb, exc, MRB_IVSYM(name), mrb_symbol_value(id));
  mrb_iv_set(mrb, exc, MRB_IVSYM(args), args);
  mrb_exc_raise(mrb, exc);
}

MRB_API mrb_noreturn void
mrb_frozen_error(mrb_state *mrb, void *frozen_obj)
{
  mrb_raisef(mrb, E_FROZEN_ERROR, "can't modify frozen %t", mrb_obj_value(frozen_obj));
}

MRB_API mrb_noreturn void
mrb_argnum_error(mrb_state *mrb, mrb_int argc, int min, int max)
{
#define FMT(exp) "wrong number of arguments (given %i, expected " exp ")"
  if (min == max)
    mrb_raisef(mrb, E_ARGUMENT_ERROR, FMT("%d"), argc, min);
  else if (max < 0)
    mrb_raisef(mrb, E_ARGUMENT_ERROR, FMT("%d+"), argc, min);
  else
    mrb_raisef(mrb, E_ARGUMENT_ERROR, FMT("%d..%d"), argc, min, max);
#undef FMT
}

void mrb_core_init_printabort(void);

int
mrb_core_init_protect(mrb_state *mrb, void (*body)(mrb_state *, void *), void *opaque)
{
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  int err = 1;

  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;
    body(mrb, opaque);
    err = 0;
  } MRB_CATCH(&c_jmp) {
    if (mrb->exc) {
      mrb_p(mrb, mrb_obj_value(mrb->exc));
      mrb->exc = NULL;
    }
    else {
      mrb_core_init_printabort();
    }
  } MRB_END_EXC(&c_jmp);

  mrb->jmp = prev_jmp;

  return err;
}

mrb_noreturn void
mrb_core_init_abort(mrb_state *mrb)
{
  mrb->exc = NULL;
  exc_throw(mrb, mrb_nil_value());
}

void
mrb_protect_atexit(mrb_state *mrb)
{
  if (mrb->atexit_stack_len > 0) {
    struct mrb_jmpbuf *prev_jmp = mrb->jmp;
    struct mrb_jmpbuf c_jmp;
    for (int i = mrb->atexit_stack_len; i > 0; --i) {
      MRB_TRY(&c_jmp) {
        mrb->jmp = &c_jmp;
        mrb->atexit_stack[i - 1](mrb);
        mrb->jmp = prev_jmp;
      } MRB_CATCH(&c_jmp) {
        /* ignore atexit errors */
      } MRB_END_EXC(&c_jmp);
    }
#ifndef MRB_FIXED_STATE_ATEXIT_STACK
    mrb_free(mrb, mrb->atexit_stack);
#endif
    mrb->jmp = prev_jmp;
  }
}

mrb_noreturn void
mrb_raise_nomemory(mrb_state *mrb)
{
  if (mrb->nomem_err) {
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
  else {
    mrb_core_init_abort(mrb);
  }
}

void
mrb_init_exception(mrb_state *mrb)
{
  struct RClass *exception, *script_error, *stack_error, *nomem_error;

  mrb->eException_class = exception = mrb_define_class(mrb, "Exception", mrb->object_class); /* 15.2.22 */
  MRB_SET_INSTANCE_TT(exception, MRB_TT_EXCEPTION);
  mrb_define_class_method(mrb, exception, "exception", mrb_instance_new,  MRB_ARGS_OPT(1));
  mrb_define_method(mrb, exception, "exception",       exc_exception,     MRB_ARGS_OPT(1));
  mrb_define_method(mrb, exception, "initialize",      exc_initialize,    MRB_ARGS_OPT(1));
  mrb_define_method(mrb, exception, "to_s",            exc_to_s,          MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "message",         exc_message,       MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "inspect",         mrb_exc_inspect,   MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "backtrace",       mrb_exc_backtrace, MRB_ARGS_NONE());
  mrb_define_method(mrb, exception, "set_backtrace",   exc_set_backtrace, MRB_ARGS_REQ(1));

  mrb->eStandardError_class = mrb_define_class(mrb, "StandardError", mrb->eException_class); /* 15.2.23 */
  mrb_define_class(mrb, "RuntimeError", mrb->eStandardError_class);          /* 15.2.28 */
  script_error = mrb_define_class(mrb, "ScriptError", mrb->eException_class);                /* 15.2.37 */
  mrb_define_class(mrb, "SyntaxError", script_error);                                        /* 15.2.38 */
  stack_error = mrb_define_class(mrb, "SystemStackError", exception);
  mrb->stack_err = mrb_obj_ptr(mrb_exc_new_lit(mrb, stack_error, "stack level too deep"));

  nomem_error = mrb_define_class(mrb, "NoMemoryError", exception);
  mrb->nomem_err = mrb_obj_ptr(mrb_exc_new_lit(mrb, nomem_error, "Out of memory"));
#ifdef MRB_GC_FIXED_ARENA
  mrb->arena_err = mrb_obj_ptr(mrb_exc_new_lit(mrb, nomem_error, "arena overflow error"));
#endif
}
