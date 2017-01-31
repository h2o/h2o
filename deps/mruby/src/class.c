/*
** class.c - Class class
**
** See Copyright Notice in mruby.h
*/

#include <stdarg.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/numeric.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/error.h>
#include <mruby/data.h>
#include <mruby/istruct.h>

KHASH_DEFINE(mt, mrb_sym, struct RProc*, TRUE, kh_int_hash_func, kh_int_hash_equal)

void
mrb_gc_mark_mt(mrb_state *mrb, struct RClass *c)
{
  khiter_t k;
  khash_t(mt) *h = c->mt;

  if (!h) return;
  for (k = kh_begin(h); k != kh_end(h); k++) {
    if (kh_exist(h, k)) {
      struct RProc *m = kh_value(h, k);
      if (m) {
        mrb_gc_mark(mrb, (struct RBasic*)m);
      }
    }
  }
}

size_t
mrb_gc_mark_mt_size(mrb_state *mrb, struct RClass *c)
{
  khash_t(mt) *h = c->mt;

  if (!h) return 0;
  return kh_size(h);
}

void
mrb_gc_free_mt(mrb_state *mrb, struct RClass *c)
{
  kh_destroy(mt, mrb, c->mt);
}

static void
name_class(mrb_state *mrb, struct RClass *c, mrb_sym name)
{
  mrb_obj_iv_set(mrb, (struct RObject*)c,
                 mrb_intern_lit(mrb, "__classid__"), mrb_symbol_value(name));
}

static void
setup_class(mrb_state *mrb, struct RClass *outer, struct RClass *c, mrb_sym id)
{
  name_class(mrb, c, id);
  mrb_obj_iv_set(mrb, (struct RObject*)outer, id, mrb_obj_value(c));
  if (outer != mrb->object_class) {
    mrb_obj_iv_set(mrb, (struct RObject*)c, mrb_intern_lit(mrb, "__outer__"),
                   mrb_obj_value(outer));
  }
}

#define make_metaclass(mrb, c) prepare_singleton_class((mrb), (struct RBasic*)(c))

static void
prepare_singleton_class(mrb_state *mrb, struct RBasic *o)
{
  struct RClass *sc, *c;

  if (o->c->tt == MRB_TT_SCLASS) return;
  sc = (struct RClass*)mrb_obj_alloc(mrb, MRB_TT_SCLASS, mrb->class_class);
  sc->mt = kh_init(mt, mrb);
  sc->iv = 0;
  if (o->tt == MRB_TT_CLASS) {
    c = (struct RClass*)o;
    if (!c->super) {
      sc->super = mrb->class_class;
    }
    else {
      sc->super = c->super->c;
    }
  }
  else if (o->tt == MRB_TT_SCLASS) {
    c = (struct RClass*)o;
    while (c->super->tt == MRB_TT_ICLASS)
      c = c->super;
    make_metaclass(mrb, c->super);
    sc->super = c->super->c;
  }
  else {
    sc->super = o->c;
  }
  o->c = sc;
  mrb_field_write_barrier(mrb, (struct RBasic*)o, (struct RBasic*)sc);
  mrb_field_write_barrier(mrb, (struct RBasic*)sc, (struct RBasic*)o);
  mrb_obj_iv_set(mrb, (struct RObject*)sc, mrb_intern_lit(mrb, "__attached__"), mrb_obj_value(o));
}

static struct RClass *
class_from_sym(mrb_state *mrb, struct RClass *klass, mrb_sym id)
{
  mrb_value c = mrb_const_get(mrb, mrb_obj_value(klass), id);

  mrb_check_type(mrb, c, MRB_TT_CLASS);
  return mrb_class_ptr(c);
}

static struct RClass *
module_from_sym(mrb_state *mrb, struct RClass *klass, mrb_sym id)
{
  mrb_value c = mrb_const_get(mrb, mrb_obj_value(klass), id);

  mrb_check_type(mrb, c, MRB_TT_MODULE);
  return mrb_class_ptr(c);
}

MRB_API struct RClass*
mrb_class_outer_module(mrb_state *mrb, struct RClass *c)
{
  mrb_value outer;

  outer = mrb_obj_iv_get(mrb, (struct RObject*)c, mrb_intern_lit(mrb, "__outer__"));
  if (mrb_nil_p(outer)) return NULL;
  return mrb_class_ptr(outer);
}

static void
check_if_class_or_module(mrb_state *mrb, mrb_value obj)
{
  switch (mrb_type(obj)) {
  case MRB_TT_CLASS:
  case MRB_TT_SCLASS:
  case MRB_TT_MODULE:
    return;
  default:
    mrb_raisef(mrb, E_TYPE_ERROR, "%S is not a class/module", mrb_inspect(mrb, obj));
  }
}

static struct RClass*
define_module(mrb_state *mrb, mrb_sym name, struct RClass *outer)
{
  struct RClass *m;

  if (mrb_const_defined_at(mrb, mrb_obj_value(outer), name)) {
    return module_from_sym(mrb, outer, name);
  }
  m = mrb_module_new(mrb);
  setup_class(mrb, outer, m, name);

  return m;
}

MRB_API struct RClass*
mrb_define_module_id(mrb_state *mrb, mrb_sym name)
{
  return define_module(mrb, name, mrb->object_class);
}

MRB_API struct RClass*
mrb_define_module(mrb_state *mrb, const char *name)
{
  return define_module(mrb, mrb_intern_cstr(mrb, name), mrb->object_class);
}

MRB_API struct RClass*
mrb_vm_define_module(mrb_state *mrb, mrb_value outer, mrb_sym id)
{
  check_if_class_or_module(mrb, outer);
  if (mrb_const_defined_at(mrb, outer, id)) {
    mrb_value old = mrb_const_get(mrb, outer, id);

    if (mrb_type(old) != MRB_TT_MODULE) {
      mrb_raisef(mrb, E_TYPE_ERROR, "%S is not a module", mrb_inspect(mrb, old));
    }
    return mrb_class_ptr(old);
  }
  return define_module(mrb, id, mrb_class_ptr(outer));
}

MRB_API struct RClass*
mrb_define_module_under(mrb_state *mrb, struct RClass *outer, const char *name)
{
  mrb_sym id = mrb_intern_cstr(mrb, name);
  struct RClass * c = define_module(mrb, id, outer);

  setup_class(mrb, outer, c, id);
  return c;
}

static struct RClass*
find_origin(struct RClass *c)
{
  MRB_CLASS_ORIGIN(c);
  return c;
}

static struct RClass*
define_class(mrb_state *mrb, mrb_sym name, struct RClass *super, struct RClass *outer)
{
  struct RClass * c;

  if (mrb_const_defined_at(mrb, mrb_obj_value(outer), name)) {
    c = class_from_sym(mrb, outer, name);
    MRB_CLASS_ORIGIN(c);
    if (super && mrb_class_real(c->super) != super) {
      mrb_raisef(mrb, E_TYPE_ERROR, "superclass mismatch for Class %S (%S not %S)",
                 mrb_sym2str(mrb, name),
                 mrb_obj_value(c->super), mrb_obj_value(super));
    }
    return c;
  }

  c = mrb_class_new(mrb, super);
  setup_class(mrb, outer, c, name);

  return c;
}

MRB_API struct RClass*
mrb_define_class_id(mrb_state *mrb, mrb_sym name, struct RClass *super)
{
  if (!super) {
    mrb_warn(mrb, "no super class for '%S', Object assumed", mrb_sym2str(mrb, name));
  }
  return define_class(mrb, name, super, mrb->object_class);
}

MRB_API struct RClass*
mrb_define_class(mrb_state *mrb, const char *name, struct RClass *super)
{
  return mrb_define_class_id(mrb, mrb_intern_cstr(mrb, name), super);
}

static void
mrb_class_inherited(mrb_state *mrb, struct RClass *super, struct RClass *klass)
{
  if (!super)
    super = mrb->object_class;
  mrb_funcall(mrb, mrb_obj_value(super), "inherited", 1, mrb_obj_value(klass));
}

MRB_API struct RClass*
mrb_vm_define_class(mrb_state *mrb, mrb_value outer, mrb_value super, mrb_sym id)
{
  struct RClass *s;
  struct RClass *c;

  if (!mrb_nil_p(super)) {
    if (mrb_type(super) != MRB_TT_CLASS) {
      mrb_raisef(mrb, E_TYPE_ERROR, "superclass must be a Class (%S given)", super);
    }
    s = mrb_class_ptr(super);
  }
  else {
    s = 0;
  }
  check_if_class_or_module(mrb, outer);
  if (mrb_const_defined_at(mrb, outer, id)) {
    mrb_value old = mrb_const_get(mrb, outer, id);

    if (mrb_type(old) != MRB_TT_CLASS) {
      mrb_raisef(mrb, E_TYPE_ERROR, "%S is not a class", mrb_inspect(mrb, old));
    }
    c = mrb_class_ptr(old);
    if (s) {
      /* check super class */
      if (mrb_class_real(c->super) != s) {
        mrb_raisef(mrb, E_TYPE_ERROR, "superclass mismatch for class %S", old);
      }
    }
    return c;
  }
  c = define_class(mrb, id, s, mrb_class_ptr(outer));
  mrb_class_inherited(mrb, mrb_class_real(c->super), c);

  return c;
}

MRB_API mrb_bool
mrb_class_defined(mrb_state *mrb, const char *name)
{
  mrb_value sym = mrb_check_intern_cstr(mrb, name);
  if (mrb_nil_p(sym)) {
    return FALSE;
  }
  return mrb_const_defined(mrb, mrb_obj_value(mrb->object_class), mrb_symbol(sym));
}

MRB_API mrb_bool
mrb_class_defined_under(mrb_state *mrb, struct RClass *outer, const char *name)
{
  mrb_value sym = mrb_check_intern_cstr(mrb, name);
  if (mrb_nil_p(sym)) {
    return FALSE;
  }
  return mrb_const_defined_at(mrb, mrb_obj_value(outer), mrb_symbol(sym));
}

MRB_API struct RClass *
mrb_class_get_under(mrb_state *mrb, struct RClass *outer, const char *name)
{
  return class_from_sym(mrb, outer, mrb_intern_cstr(mrb, name));
}

MRB_API struct RClass *
mrb_class_get(mrb_state *mrb, const char *name)
{
  return mrb_class_get_under(mrb, mrb->object_class, name);
}

MRB_API struct RClass *
mrb_module_get_under(mrb_state *mrb, struct RClass *outer, const char *name)
{
  return module_from_sym(mrb, outer, mrb_intern_cstr(mrb, name));
}

MRB_API struct RClass *
mrb_module_get(mrb_state *mrb, const char *name)
{
  return mrb_module_get_under(mrb, mrb->object_class, name);
}

/*!
 * Defines a class under the namespace of \a outer.
 * \param outer  a class which contains the new class.
 * \param id     name of the new class
 * \param super  a class from which the new class will derive.
 *               NULL means \c Object class.
 * \return the created class
 * \throw TypeError if the constant name \a name is already taken but
 *                  the constant is not a \c Class.
 * \throw NameError if the class is already defined but the class can not
 *                  be reopened because its superclass is not \a super.
 * \post top-level constant named \a name refers the returned class.
 *
 * \note if a class named \a name is already defined and its superclass is
 *       \a super, the function just returns the defined class.
 */
MRB_API struct RClass *
mrb_define_class_under(mrb_state *mrb, struct RClass *outer, const char *name, struct RClass *super)
{
  mrb_sym id = mrb_intern_cstr(mrb, name);
  struct RClass * c;

#if 0
  if (!super) {
    mrb_warn(mrb, "no super class for '%S::%S', Object assumed",
             mrb_obj_value(outer), mrb_sym2str(mrb, id));
  }
#endif
  c = define_class(mrb, id, super, outer);
  setup_class(mrb, outer, c, id);
  return c;
}

MRB_API void
mrb_define_method_raw(mrb_state *mrb, struct RClass *c, mrb_sym mid, struct RProc *p)
{
  khash_t(mt) *h;
  khiter_t k;
  MRB_CLASS_ORIGIN(c);
  h = c->mt;

  if (MRB_FROZEN_P(c)) {
    if (c->tt == MRB_TT_MODULE)
      mrb_raise(mrb, E_RUNTIME_ERROR, "can't modify frozen module");
    else
      mrb_raise(mrb, E_RUNTIME_ERROR, "can't modify frozen class");
  }
  if (!h) h = c->mt = kh_init(mt, mrb);
  k = kh_put(mt, mrb, h, mid);
  kh_value(h, k) = p;
  if (p) {
    mrb_field_write_barrier(mrb, (struct RBasic *)c, (struct RBasic *)p);
  }
}

MRB_API void
mrb_define_method_id(mrb_state *mrb, struct RClass *c, mrb_sym mid, mrb_func_t func, mrb_aspec aspec)
{
  struct RProc *p;
  int ai = mrb_gc_arena_save(mrb);

  p = mrb_proc_new_cfunc(mrb, func);
  p->target_class = c;
  mrb_define_method_raw(mrb, c, mid, p);
  mrb_gc_arena_restore(mrb, ai);
}

MRB_API void
mrb_define_method(mrb_state *mrb, struct RClass *c, const char *name, mrb_func_t func, mrb_aspec aspec)
{
  mrb_define_method_id(mrb, c, mrb_intern_cstr(mrb, name), func, aspec);
}

/* a function to raise NotImplementedError with current method name */
MRB_API void
mrb_notimplement(mrb_state *mrb)
{
  const char *str;
  mrb_int len;
  mrb_callinfo *ci = mrb->c->ci;

  if (ci->mid) {
    str = mrb_sym2name_len(mrb, ci->mid, &len);
    mrb_raisef(mrb, E_NOTIMP_ERROR,
      "%S() function is unimplemented on this machine",
      mrb_str_new_static(mrb, str, (size_t)len));
  }
}

/* a function to be replacement of unimplemented method */
MRB_API mrb_value
mrb_notimplement_m(mrb_state *mrb, mrb_value self)
{
  mrb_notimplement(mrb);
  /* not reached */
  return mrb_nil_value();
}

static mrb_value
check_type(mrb_state *mrb, mrb_value val, enum mrb_vtype t, const char *c, const char *m)
{
  mrb_value tmp;

  tmp = mrb_check_convert_type(mrb, val, t, c, m);
  if (mrb_nil_p(tmp)) {
    mrb_raisef(mrb, E_TYPE_ERROR, "expected %S", mrb_str_new_cstr(mrb, c));
  }
  return tmp;
}

static mrb_value
to_str(mrb_state *mrb, mrb_value val)
{
  return check_type(mrb, val, MRB_TT_STRING, "String", "to_str");
}

static mrb_value
to_ary(mrb_state *mrb, mrb_value val)
{
  return check_type(mrb, val, MRB_TT_ARRAY, "Array", "to_ary");
}

static mrb_value
to_hash(mrb_state *mrb, mrb_value val)
{
  return check_type(mrb, val, MRB_TT_HASH, "Hash", "to_hash");
}

static mrb_sym
to_sym(mrb_state *mrb, mrb_value ss)
{
  if (mrb_type(ss) == MRB_TT_SYMBOL) {
    return mrb_symbol(ss);
  }
  else if (mrb_string_p(ss)) {
    return mrb_intern_str(mrb, to_str(mrb, ss));
  }
  else {
    mrb_value obj = mrb_funcall(mrb, ss, "inspect", 0);
    mrb_raisef(mrb, E_TYPE_ERROR, "%S is not a symbol", obj);
    /* not reached */
    return 0;
  }
}

/*
  retrieve arguments from mrb_state.

  mrb_get_args(mrb, format, ...)

  returns number of arguments parsed.

  format specifiers:

    string  mruby type     C type                 note
    ----------------------------------------------------------------------------------------------
    o:      Object         [mrb_value]
    C:      class/module   [mrb_value]
    S:      String         [mrb_value]            when ! follows, the value may be nil
    A:      Array          [mrb_value]            when ! follows, the value may be nil
    H:      Hash           [mrb_value]            when ! follows, the value may be nil
    s:      String         [char*,mrb_int]        Receive two arguments; s! gives (NULL,0) for nil
    z:      String         [char*]                NUL terminated string; z! gives NULL for nil
    a:      Array          [mrb_value*,mrb_int]   Receive two arguments; a! gives (NULL,0) for nil
    f:      Float          [mrb_float]
    i:      Integer        [mrb_int]
    b:      Boolean        [mrb_bool]
    n:      Symbol         [mrb_sym]
    d:      Data           [void*,mrb_data_type const] 2nd argument will be used to check data type so it won't be modified
    I:      Inline struct  [void*]
    &:      Block          [mrb_value]
    *:      rest argument  [mrb_value*,mrb_int]   Receive the rest of the arguments as an array.
    |:      optional                              Next argument of '|' and later are optional.
    ?:      optional given [mrb_bool]             true if preceding argument (optional) is given.
 */
MRB_API mrb_int
mrb_get_args(mrb_state *mrb, const char *format, ...)
{
  char c;
  int i = 0;
  va_list ap;
  int argc = mrb->c->ci->argc;
  int arg_i = 0;
  mrb_bool array_argv;
  mrb_bool opt = FALSE;
  mrb_bool given = TRUE;

  va_start(ap, format);
  if (argc < 0) {
    struct RArray *a = mrb_ary_ptr(mrb->c->stack[1]);

    argc = a->len;
    array_argv = TRUE;
  } else {
    array_argv = FALSE;
  }

#define ARGV \
  (array_argv ? mrb_ary_ptr(mrb->c->stack[1])->ptr : (mrb->c->stack + 1))

  while ((c = *format++)) {
    switch (c) {
    case '|': case '*': case '&': case '?':
      break;
    default:
      if (argc <= i) {
        if (opt) {
          given = FALSE;
        }
        else {
          mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong number of arguments");
        }
      }
      break;
    }

    switch (c) {
    case 'o':
      {
        mrb_value *p;

        p = va_arg(ap, mrb_value*);
        if (i < argc) {
          *p = ARGV[arg_i++];
          i++;
        }
      }
      break;
    case 'C':
      {
        mrb_value *p;

        p = va_arg(ap, mrb_value*);
        if (i < argc) {
          mrb_value ss;

          ss = ARGV[arg_i++];
          switch (mrb_type(ss)) {
          case MRB_TT_CLASS:
          case MRB_TT_MODULE:
          case MRB_TT_SCLASS:
            break;
          default:
            mrb_raisef(mrb, E_TYPE_ERROR, "%S is not class/module", ss);
            break;
          }
          *p = ss;
          i++;
        }
      }
      break;
    case 'S':
      {
        mrb_value *p;

        p = va_arg(ap, mrb_value*);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *p = ARGV[arg_i++];
            i++;
            break;
          }
        }
        if (i < argc) {
          *p = to_str(mrb, ARGV[arg_i++]);
          i++;
        }
      }
      break;
    case 'A':
      {
        mrb_value *p;

        p = va_arg(ap, mrb_value*);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *p = ARGV[arg_i++];
            i++;
            break;
          }
        }
        if (i < argc) {
          *p = to_ary(mrb, ARGV[arg_i++]);
          i++;
        }
      }
      break;
    case 'H':
      {
        mrb_value *p;

        p = va_arg(ap, mrb_value*);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *p = ARGV[arg_i++];
            i++;
            break;
          }
        }
        if (i < argc) {
          *p = to_hash(mrb, ARGV[arg_i++]);
          i++;
        }
      }
      break;
    case 's':
      {
        mrb_value ss;
        char **ps = 0;
        mrb_int *pl = 0;

        ps = va_arg(ap, char**);
        pl = va_arg(ap, mrb_int*);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *ps = NULL;
            *pl = 0;
            i++;
            break;
          }
        }
        if (i < argc) {
          ss = to_str(mrb, ARGV[arg_i++]);
          *ps = RSTRING_PTR(ss);
          *pl = RSTRING_LEN(ss);
          i++;
        }
      }
      break;
    case 'z':
      {
        mrb_value ss;
        const char **ps;

        ps = va_arg(ap, const char**);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *ps = NULL;
            i++; arg_i++;
            break;
          }
        }
        if (i < argc) {
          ss = to_str(mrb, ARGV[arg_i++]);
          *ps = mrb_string_value_cstr(mrb, &ss);
          i++;
        }
      }
      break;
    case 'a':
      {
        mrb_value aa;
        struct RArray *a;
        mrb_value **pb;
        mrb_int *pl;

        pb = va_arg(ap, mrb_value**);
        pl = va_arg(ap, mrb_int*);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *pb = 0;
            *pl = 0;
            i++; arg_i++;
            break;
          }
        }
        if (i < argc) {
          aa = to_ary(mrb, ARGV[arg_i++]);
          a = mrb_ary_ptr(aa);
          *pb = a->ptr;
          *pl = a->len;
          i++;
        }
      }
      break;
    case 'I':
      {
        void* *p;
        mrb_value ss;

        p = va_arg(ap, void**);
        if (i < argc) {
          ss = ARGV[arg_i];
          if (mrb_type(ss) != MRB_TT_ISTRUCT)
          {
            mrb_raisef(mrb, E_TYPE_ERROR, "%S is not inline struct", ss);
          }
          *p = mrb_istruct_ptr(ss);
          arg_i++;
          i++;
        }
      }
      break;
    case 'f':
      {
        mrb_float *p;

        p = va_arg(ap, mrb_float*);
        if (i < argc) {
          *p = mrb_to_flo(mrb, ARGV[arg_i]);
          arg_i++;
          i++;
        }
      }
      break;
    case 'i':
      {
        mrb_int *p;

        p = va_arg(ap, mrb_int*);
        if (i < argc) {
          switch (mrb_type(ARGV[arg_i])) {
            case MRB_TT_FIXNUM:
              *p = mrb_fixnum(ARGV[arg_i]);
              break;
            case MRB_TT_FLOAT:
              {
                mrb_float f = mrb_float(ARGV[arg_i]);

                if (!FIXABLE(f)) {
                  mrb_raise(mrb, E_RANGE_ERROR, "float too big for int");
                }
                *p = (mrb_int)f;
              }
              break;
            case MRB_TT_STRING:
              mrb_raise(mrb, E_TYPE_ERROR, "no implicit conversion of String into Integer");
              break;
            default:
              *p = mrb_fixnum(mrb_Integer(mrb, ARGV[arg_i]));
              break;
          }
          arg_i++;
          i++;
        }
      }
      break;
    case 'b':
      {
        mrb_bool *boolp = va_arg(ap, mrb_bool*);

        if (i < argc) {
          mrb_value b = ARGV[arg_i++];
          *boolp = mrb_test(b);
          i++;
        }
      }
      break;
    case 'n':
      {
        mrb_sym *symp;

        symp = va_arg(ap, mrb_sym*);
        if (i < argc) {
          mrb_value ss;

          ss = ARGV[arg_i++];
          *symp = to_sym(mrb, ss);
          i++;
        }
      }
      break;
    case 'd':
      {
        void** datap;
        struct mrb_data_type const* type;

        datap = va_arg(ap, void**);
        type = va_arg(ap, struct mrb_data_type const*);
        if (*format == '!') {
          format++;
          if (i < argc && mrb_nil_p(ARGV[arg_i])) {
            *datap = 0;
            i++; arg_i++;
            break;
          }
        }
        if (i < argc) {
          *datap = mrb_data_get_ptr(mrb, ARGV[arg_i++], type);
          ++i;
        }
      }
      break;

    case '&':
      {
        mrb_value *p, *bp;

        p = va_arg(ap, mrb_value*);
        if (mrb->c->ci->argc < 0) {
          bp = mrb->c->stack + 2;
        }
        else {
          bp = mrb->c->stack + mrb->c->ci->argc + 1;
        }
        *p = *bp;
      }
      break;
    case '|':
      opt = TRUE;
      break;
    case '?':
      {
        mrb_bool *p;

        p = va_arg(ap, mrb_bool*);
        *p = given;
      }
      break;

    case '*':
      {
        mrb_value **var;
        mrb_int *pl;

        var = va_arg(ap, mrb_value**);
        pl = va_arg(ap, mrb_int*);
        if (argc > i) {
          *pl = argc-i;
          if (*pl > 0) {
            *var = ARGV + arg_i;
          }
          i = argc;
          arg_i += *pl;
        }
        else {
          *pl = 0;
          *var = NULL;
        }
      }
      break;
    default:
      mrb_raisef(mrb, E_ARGUMENT_ERROR, "invalid argument specifier %S", mrb_str_new(mrb, &c, 1));
      break;
    }
  }

#undef ARGV

  if (!c && argc > i) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong number of arguments");
  }
  va_end(ap);
  return i;
}

static struct RClass*
boot_defclass(mrb_state *mrb, struct RClass *super)
{
  struct RClass *c;

  c = (struct RClass*)mrb_obj_alloc(mrb, MRB_TT_CLASS, mrb->class_class);
  if (super) {
    c->super = super;
    mrb_field_write_barrier(mrb, (struct RBasic*)c, (struct RBasic*)super);
  }
  else {
    c->super = mrb->object_class;
  }
  c->mt = kh_init(mt, mrb);
  return c;
}

static void
boot_initmod(mrb_state *mrb, struct RClass *mod)
{
  mod->mt = kh_init(mt, mrb);
}

static struct RClass*
include_class_new(mrb_state *mrb, struct RClass *m, struct RClass *super)
{
  struct RClass *ic = (struct RClass*)mrb_obj_alloc(mrb, MRB_TT_ICLASS, mrb->class_class);
  if (m->tt == MRB_TT_ICLASS) {
    m = m->c;
  }
  MRB_CLASS_ORIGIN(m);
  ic->iv = m->iv;
  ic->mt = m->mt;
  ic->super = super;
  if (m->tt == MRB_TT_ICLASS) {
    ic->c = m->c;
  } else {
    ic->c = m;
  }
  return ic;
}

static int
include_module_at(mrb_state *mrb, struct RClass *c, struct RClass *ins_pos, struct RClass *m, int search_super)
{
  struct RClass *p, *ic;
  void *klass_mt = find_origin(c)->mt;

  while (m) {
    int superclass_seen = 0;

    if (m->flags & MRB_FLAG_IS_PREPENDED)
      goto skip;

    if (klass_mt && klass_mt == m->mt)
      return -1;

    p = c->super;
    while(p) {
      if (p->tt == MRB_TT_ICLASS) {
        if (p->mt == m->mt) {
          if (!superclass_seen) {
            ins_pos = p; // move insert point
          }
          goto skip;
        }
      } else if (p->tt == MRB_TT_CLASS) {
        if (!search_super) break;
        superclass_seen = 1;
      }
      p = p->super;
    }

    ic = include_class_new(mrb, m, ins_pos->super);
    ins_pos->super = ic;
    mrb_field_write_barrier(mrb, (struct RBasic*)ins_pos, (struct RBasic*)ins_pos->super);
    ins_pos = ic;
  skip:
    m = m->super;
  }
  return 0;
}

MRB_API void
mrb_include_module(mrb_state *mrb, struct RClass *c, struct RClass *m)
{
  int changed = include_module_at(mrb, c, find_origin(c), m, 1);
  if (changed < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "cyclic include detected");
  }
}

MRB_API void
mrb_prepend_module(mrb_state *mrb, struct RClass *c, struct RClass *m)
{
  struct RClass *origin;
  int changed = 0;

  if (!(c->flags & MRB_FLAG_IS_PREPENDED)) {
    origin = (struct RClass*)mrb_obj_alloc(mrb, MRB_TT_ICLASS, c);
    origin->flags |= MRB_FLAG_IS_ORIGIN;
    origin->super = c->super;
    c->super = origin;
    origin->mt = c->mt;
    c->mt = kh_init(mt, mrb);
    mrb_field_write_barrier(mrb, (struct RBasic*)c, (struct RBasic*)origin);
    c->flags |= MRB_FLAG_IS_PREPENDED;
  }
  changed = include_module_at(mrb, c, c, m, 0);
  if (changed < 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "cyclic prepend detected");
  }
}

static mrb_value
mrb_mod_prepend_features(mrb_state *mrb, mrb_value mod)
{
  mrb_value klass;

  mrb_check_type(mrb, mod, MRB_TT_MODULE);
  mrb_get_args(mrb, "C", &klass);
  mrb_prepend_module(mrb, mrb_class_ptr(klass), mrb_class_ptr(mod));
  return mod;
}

static mrb_value
mrb_mod_append_features(mrb_state *mrb, mrb_value mod)
{
  mrb_value klass;

  mrb_check_type(mrb, mod, MRB_TT_MODULE);
  mrb_get_args(mrb, "C", &klass);
  mrb_include_module(mrb, mrb_class_ptr(klass), mrb_class_ptr(mod));
  return mod;
}

/* 15.2.2.4.28 */
/*
 *  call-seq:
 *     mod.include?(module)    -> true or false
 *
 *  Returns <code>true</code> if <i>module</i> is included in
 *  <i>mod</i> or one of <i>mod</i>'s ancestors.
 *
 *     module A
 *     end
 *     class B
 *       include A
 *     end
 *     class C < B
 *     end
 *     B.include?(A)   #=> true
 *     C.include?(A)   #=> true
 *     A.include?(A)   #=> false
 */
static mrb_value
mrb_mod_include_p(mrb_state *mrb, mrb_value mod)
{
  mrb_value mod2;
  struct RClass *c = mrb_class_ptr(mod);

  mrb_get_args(mrb, "C", &mod2);
  mrb_check_type(mrb, mod2, MRB_TT_MODULE);

  while (c) {
    if (c->tt == MRB_TT_ICLASS) {
      if (c->c == mrb_class_ptr(mod2)) return mrb_true_value();
    }
    c = c->super;
  }
  return mrb_false_value();
}

static mrb_value
mrb_mod_ancestors(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  struct RClass *c = mrb_class_ptr(self);
  result = mrb_ary_new(mrb);
  while (c) {
    if (c->tt == MRB_TT_ICLASS) {
      mrb_ary_push(mrb, result, mrb_obj_value(c->c));
    }
    else if (!(c->flags & MRB_FLAG_IS_PREPENDED)) {
      mrb_ary_push(mrb, result, mrb_obj_value(c));
    }
    c = c->super;
  }

  return result;
}

static mrb_value
mrb_mod_extend_object(mrb_state *mrb, mrb_value mod)
{
  mrb_value obj;

  mrb_check_type(mrb, mod, MRB_TT_MODULE);
  mrb_get_args(mrb, "o", &obj);
  mrb_include_module(mrb, mrb_class_ptr(mrb_singleton_class(mrb, obj)), mrb_class_ptr(mod));
  return mod;
}

static mrb_value
mrb_mod_included_modules(mrb_state *mrb, mrb_value self)
{
  mrb_value result;
  struct RClass *c = mrb_class_ptr(self);
  struct RClass *origin = c;

  MRB_CLASS_ORIGIN(origin);
  result = mrb_ary_new(mrb);
  while (c) {
    if (c != origin && c->tt == MRB_TT_ICLASS) {
      if (c->c->tt == MRB_TT_MODULE) {
        mrb_ary_push(mrb, result, mrb_obj_value(c->c));
      }
    }
    c = c->super;
  }

  return result;
}

static mrb_value
mrb_mod_initialize(mrb_state *mrb, mrb_value mod)
{
  mrb_value b;
  struct RClass *m = mrb_class_ptr(mod);
  boot_initmod(mrb, m); // bootstrap a newly initialized module
  mrb_get_args(mrb, "|&", &b);
  if (!mrb_nil_p(b)) {
    mrb_yield_with_class(mrb, b, 1, &mod, mod, m);
  }
  return mod;
}

mrb_value mrb_class_instance_method_list(mrb_state*, mrb_bool, struct RClass*, int);

/* 15.2.2.4.33 */
/*
 *  call-seq:
 *     mod.instance_methods(include_super=true)   -> array
 *
 *  Returns an array containing the names of the public and protected instance
 *  methods in the receiver. For a module, these are the public and protected methods;
 *  for a class, they are the instance (not singleton) methods. With no
 *  argument, or with an argument that is <code>false</code>, the
 *  instance methods in <i>mod</i> are returned, otherwise the methods
 *  in <i>mod</i> and <i>mod</i>'s superclasses are returned.
 *
 *     module A
 *       def method1()  end
 *     end
 *     class B
 *       def method2()  end
 *     end
 *     class C < B
 *       def method3()  end
 *     end
 *
 *     A.instance_methods                #=> [:method1]
 *     B.instance_methods(false)         #=> [:method2]
 *     C.instance_methods(false)         #=> [:method3]
 *     C.instance_methods(true).length   #=> 43
 */

static mrb_value
mrb_mod_instance_methods(mrb_state *mrb, mrb_value mod)
{
  struct RClass *c = mrb_class_ptr(mod);
  mrb_bool recur = TRUE;
  mrb_get_args(mrb, "|b", &recur);
  return mrb_class_instance_method_list(mrb, recur, c, 0);
}

/* implementation of module_eval/class_eval */
mrb_value mrb_mod_module_eval(mrb_state*, mrb_value);

static mrb_value
mrb_mod_dummy_visibility(mrb_state *mrb, mrb_value mod)
{
  return mod;
}

MRB_API mrb_value
mrb_singleton_class(mrb_state *mrb, mrb_value v)
{
  struct RBasic *obj;

  switch (mrb_type(v)) {
  case MRB_TT_FALSE:
    if (mrb_nil_p(v))
      return mrb_obj_value(mrb->nil_class);
    return mrb_obj_value(mrb->false_class);
  case MRB_TT_TRUE:
    return mrb_obj_value(mrb->true_class);
  case MRB_TT_CPTR:
    return mrb_obj_value(mrb->object_class);
  case MRB_TT_SYMBOL:
  case MRB_TT_FIXNUM:
  case MRB_TT_FLOAT:
    mrb_raise(mrb, E_TYPE_ERROR, "can't define singleton");
    return mrb_nil_value();    /* not reached */
  default:
    break;
  }
  obj = mrb_basic_ptr(v);
  prepare_singleton_class(mrb, obj);
  if (mrb->c && mrb->c->ci && mrb->c->ci->target_class) {
    mrb_obj_iv_set(mrb, (struct RObject*)obj->c, mrb_intern_lit(mrb, "__outer__"),
                   mrb_obj_value(mrb->c->ci->target_class));
  }
  return mrb_obj_value(obj->c);
}

MRB_API void
mrb_define_singleton_method(mrb_state *mrb, struct RObject *o, const char *name, mrb_func_t func, mrb_aspec aspec)
{
  prepare_singleton_class(mrb, (struct RBasic*)o);
  mrb_define_method_id(mrb, o->c, mrb_intern_cstr(mrb, name), func, aspec);
}

MRB_API void
mrb_define_class_method(mrb_state *mrb, struct RClass *c, const char *name, mrb_func_t func, mrb_aspec aspec)
{
  mrb_define_singleton_method(mrb, (struct RObject*)c, name, func, aspec);
}

MRB_API void
mrb_define_module_function(mrb_state *mrb, struct RClass *c, const char *name, mrb_func_t func, mrb_aspec aspec)
{
  mrb_define_class_method(mrb, c, name, func, aspec);
  mrb_define_method(mrb, c, name, func, aspec);
}

MRB_API struct RProc*
mrb_method_search_vm(mrb_state *mrb, struct RClass **cp, mrb_sym mid)
{
  khiter_t k;
  struct RProc *m;
  struct RClass *c = *cp;

  while (c) {
    khash_t(mt) *h = c->mt;

    if (h) {
      k = kh_get(mt, mrb, h, mid);
      if (k != kh_end(h)) {
        m = kh_value(h, k);
        if (!m) break;
        *cp = c;
        return m;
      }
    }
    c = c->super;
  }
  return NULL;                  /* no method */
}

MRB_API struct RProc*
mrb_method_search(mrb_state *mrb, struct RClass* c, mrb_sym mid)
{
  struct RProc *m;

  m = mrb_method_search_vm(mrb, &c, mid);
  if (!m) {
    mrb_value inspect = mrb_funcall(mrb, mrb_obj_value(c), "inspect", 0);
    if (mrb_string_p(inspect) && RSTRING_LEN(inspect) > 64) {
      inspect = mrb_any_to_s(mrb, mrb_obj_value(c));
    }
    mrb_name_error(mrb, mid, "undefined method '%S' for class %S",
               mrb_sym2str(mrb, mid), inspect);
  }
  return m;
}

static mrb_value
attr_reader(mrb_state *mrb, mrb_value obj)
{
  mrb_value name = mrb_proc_cfunc_env_get(mrb, 0);
  return mrb_iv_get(mrb, obj, to_sym(mrb, name));
}

static mrb_value
mrb_mod_attr_reader(mrb_state *mrb, mrb_value mod)
{
  struct RClass *c = mrb_class_ptr(mod);
  mrb_value *argv;
  mrb_int argc, i;
  int ai;

  mrb_get_args(mrb, "*", &argv, &argc);
  ai = mrb_gc_arena_save(mrb);
  for (i=0; i<argc; i++) {
    mrb_value name, str;
    mrb_sym method, sym;

    method = to_sym(mrb, argv[i]);
    name = mrb_sym2str(mrb, method);
    str = mrb_str_buf_new(mrb, RSTRING_LEN(name)+1);
    mrb_str_cat_lit(mrb, str, "@");
    mrb_str_cat_str(mrb, str, name);
    sym = mrb_intern_str(mrb, str);
    mrb_iv_check(mrb, sym);
    name = mrb_symbol_value(sym);
    mrb_define_method_raw(mrb, c, method,
                          mrb_proc_new_cfunc_with_env(mrb, attr_reader, 1, &name));
    mrb_gc_arena_restore(mrb, ai);
  }
  return mrb_nil_value();
}

static mrb_value
attr_writer(mrb_state *mrb, mrb_value obj)
{
  mrb_value name = mrb_proc_cfunc_env_get(mrb, 0);
  mrb_value val;

  mrb_get_args(mrb, "o", &val);
  mrb_iv_set(mrb, obj, to_sym(mrb, name), val);
  return val;
}

static mrb_value
mrb_mod_attr_writer(mrb_state *mrb, mrb_value mod)
{
  struct RClass *c = mrb_class_ptr(mod);
  mrb_value *argv;
  mrb_int argc, i;
  int ai;

  mrb_get_args(mrb, "*", &argv, &argc);
  ai = mrb_gc_arena_save(mrb);
  for (i=0; i<argc; i++) {
    mrb_value name, str, attr;
    mrb_sym method, sym;

    method = to_sym(mrb, argv[i]);

    /* prepare iv name (@name) */
    name = mrb_sym2str(mrb, method);
    str = mrb_str_buf_new(mrb, RSTRING_LEN(name)+1);
    mrb_str_cat_lit(mrb, str, "@");
    mrb_str_cat_str(mrb, str, name);
    sym = mrb_intern_str(mrb, str);
    mrb_iv_check(mrb, sym);
    attr = mrb_symbol_value(sym);

    /* prepare method name (name=) */
    str = mrb_str_buf_new(mrb, RSTRING_LEN(str));
    mrb_str_cat_str(mrb, str, name);
    mrb_str_cat_lit(mrb, str, "=");
    method = mrb_intern_str(mrb, str);

    mrb_define_method_raw(mrb, c, method,
                          mrb_proc_new_cfunc_with_env(mrb, attr_writer, 1, &attr));
    mrb_gc_arena_restore(mrb, ai);
  }
  return mrb_nil_value();
}

static mrb_value
mrb_instance_alloc(mrb_state *mrb, mrb_value cv)
{
  struct RClass *c = mrb_class_ptr(cv);
  struct RObject *o;
  enum mrb_vtype ttype = MRB_INSTANCE_TT(c);

  if (c->tt == MRB_TT_SCLASS)
    mrb_raise(mrb, E_TYPE_ERROR, "can't create instance of singleton class");

  if (ttype == 0) ttype = MRB_TT_OBJECT;
  if (ttype <= MRB_TT_CPTR) {
    mrb_raisef(mrb, E_TYPE_ERROR, "can't create instance of %S", cv);
  }
  o = (struct RObject*)mrb_obj_alloc(mrb, ttype, c);
  return mrb_obj_value(o);
}

/*
 *  call-seq:
 *     class.new(args, ...)    ->  obj
 *
 *  Creates a new object of <i>class</i>'s class, then
 *  invokes that object's <code>initialize</code> method,
 *  passing it <i>args</i>. This is the method that ends
 *  up getting called whenever an object is constructed using
 *  `.new`.
 *
 */

MRB_API mrb_value
mrb_instance_new(mrb_state *mrb, mrb_value cv)
{
  mrb_value obj, blk;
  mrb_value *argv;
  mrb_int argc;

  mrb_get_args(mrb, "*&", &argv, &argc, &blk);
  obj = mrb_instance_alloc(mrb, cv);
  mrb_funcall_with_block(mrb, obj, mrb_intern_lit(mrb, "initialize"), argc, argv, blk);

  return obj;
}

MRB_API mrb_value
mrb_obj_new(mrb_state *mrb, struct RClass *c, mrb_int argc, const mrb_value *argv)
{
  mrb_value obj;

  obj = mrb_instance_alloc(mrb, mrb_obj_value(c));
  mrb_funcall_argv(mrb, obj, mrb_intern_lit(mrb, "initialize"), argc, argv);

  return obj;
}

static mrb_value
mrb_class_initialize(mrb_state *mrb, mrb_value c)
{
  mrb_value a, b;

  mrb_get_args(mrb, "|C&", &a, &b);
  if (!mrb_nil_p(b)) {
    mrb_yield_with_class(mrb, b, 1, &c, c, mrb_class_ptr(c));
  }
  return c;
}

static mrb_value
mrb_class_new_class(mrb_state *mrb, mrb_value cv)
{
  mrb_int n;
  mrb_value super, blk;
  mrb_value new_class;

  n = mrb_get_args(mrb, "|C&", &super, &blk);
  if (n == 0) {
    super = mrb_obj_value(mrb->object_class);
  }
  new_class = mrb_obj_value(mrb_class_new(mrb, mrb_class_ptr(super)));
  mrb_funcall_with_block(mrb, new_class, mrb_intern_lit(mrb, "initialize"), n, &super, blk);
  mrb_class_inherited(mrb, mrb_class_ptr(super), mrb_class_ptr(new_class));
  return new_class;
}

static mrb_value
mrb_class_superclass(mrb_state *mrb, mrb_value klass)
{
  struct RClass *c;

  c = mrb_class_ptr(klass);
  c = find_origin(c)->super;
  while (c && c->tt == MRB_TT_ICLASS) {
    c = find_origin(c)->super;
  }
  if (!c) return mrb_nil_value();
  return mrb_obj_value(c);
}

static mrb_value
mrb_bob_init(mrb_state *mrb, mrb_value cv)
{
  return mrb_nil_value();
}

static mrb_value
mrb_bob_not(mrb_state *mrb, mrb_value cv)
{
  return mrb_bool_value(!mrb_test(cv));
}

void
mrb_method_missing(mrb_state *mrb, mrb_sym name, mrb_value self, mrb_value args)
{
  mrb_sym inspect;
  mrb_value repr;

  inspect = mrb_intern_lit(mrb, "inspect");
  if (mrb->c->ci > mrb->c->cibase && mrb->c->ci[-1].mid == inspect) {
    /* method missing in inspect; avoid recursion */
    repr = mrb_any_to_s(mrb, self);
  }
  else if (mrb_respond_to(mrb, self, inspect) && mrb->c->ci - mrb->c->cibase < 64) {
    repr = mrb_funcall_argv(mrb, self, inspect, 0, 0);
    if (mrb_string_p(repr) && RSTRING_LEN(repr) > 64) {
      repr = mrb_any_to_s(mrb, self);
    }
  }
  else {
    repr = mrb_any_to_s(mrb, self);
  }

  mrb_no_method_error(mrb, name, args, "undefined method '%S' for %S",
                      mrb_sym2str(mrb, name), repr);
}

/* 15.3.1.3.30 */
/*
 *  call-seq:
 *     obj.method_missing(symbol [, *args] )   -> result
 *
 *  Invoked by Ruby when <i>obj</i> is sent a message it cannot handle.
 *  <i>symbol</i> is the symbol for the method called, and <i>args</i>
 *  are any arguments that were passed to it. By default, the interpreter
 *  raises an error when this method is called. However, it is possible
 *  to override the method to provide more dynamic behavior.
 *  If it is decided that a particular method should not be handled, then
 *  <i>super</i> should be called, so that ancestors can pick up the
 *  missing method.
 *  The example below creates
 *  a class <code>Roman</code>, which responds to methods with names
 *  consisting of roman numerals, returning the corresponding integer
 *  values.
 *
 *     class Roman
 *       def romanToInt(str)
 *         # ...
 *       end
 *       def method_missing(methId)
 *         str = methId.id2name
 *         romanToInt(str)
 *       end
 *     end
 *
 *     r = Roman.new
 *     r.iv      #=> 4
 *     r.xxiii   #=> 23
 *     r.mm      #=> 2000
 */
static mrb_value
mrb_bob_missing(mrb_state *mrb, mrb_value mod)
{
  mrb_sym name;
  mrb_value *a;
  mrb_int alen;

  mrb_get_args(mrb, "n*", &name, &a, &alen);
  mrb_method_missing(mrb, name, mod, mrb_ary_new_from_values(mrb, alen, a));
  /* not reached */
  return mrb_nil_value();
}

MRB_API mrb_bool
mrb_obj_respond_to(mrb_state *mrb, struct RClass* c, mrb_sym mid)
{
  khiter_t k;

  while (c) {
    khash_t(mt) *h = c->mt;

    if (h) {
      k = kh_get(mt, mrb, h, mid);
      if (k != kh_end(h)) {
        if (kh_value(h, k)) {
          return TRUE;  /* method exists */
        }
        else {
          return FALSE; /* undefined method */
        }
      }
    }
    c = c->super;
  }
  return FALSE;         /* no method */
}

MRB_API mrb_bool
mrb_respond_to(mrb_state *mrb, mrb_value obj, mrb_sym mid)
{
  return mrb_obj_respond_to(mrb, mrb_class(mrb, obj), mid);
}

MRB_API mrb_value
mrb_class_path(mrb_state *mrb, struct RClass *c)
{
  mrb_value path;
  const char *name;
  mrb_sym classpath = mrb_intern_lit(mrb, "__classpath__");

  path = mrb_obj_iv_get(mrb, (struct RObject*)c, classpath);
  if (mrb_nil_p(path)) {
    struct RClass *outer = mrb_class_outer_module(mrb, c);
    mrb_sym sym = mrb_class_sym(mrb, c, outer);
    mrb_int len;

    if (sym == 0) {
      return mrb_nil_value();
    }
    else if (outer && outer != mrb->object_class) {
      mrb_value base = mrb_class_path(mrb, outer);
      path = mrb_str_buf_new(mrb, 0);
      if (mrb_nil_p(base)) {
        mrb_str_cat_lit(mrb, path, "#<Class:");
        mrb_str_concat(mrb, path, mrb_ptr_to_str(mrb, outer));
        mrb_str_cat_lit(mrb, path, ">");
      }
      else {
        mrb_str_concat(mrb, path, base);
      }
      mrb_str_cat_lit(mrb, path, "::");
      name = mrb_sym2name_len(mrb, sym, &len);
      mrb_str_cat(mrb, path, name, len);
    }
    else {
      name = mrb_sym2name_len(mrb, sym, &len);
      path = mrb_str_new(mrb, name, len);
    }
    if (!MRB_FROZEN_P(c)) {
      mrb_obj_iv_set(mrb, (struct RObject*)c, classpath, path);
    }
  }
  return mrb_str_dup(mrb, path);
}

MRB_API struct RClass *
mrb_class_real(struct RClass* cl)
{
  if (cl == 0)
    return NULL;
  while ((cl->tt == MRB_TT_SCLASS) || (cl->tt == MRB_TT_ICLASS)) {
    cl = cl->super;
  }
  return cl;
}

MRB_API const char*
mrb_class_name(mrb_state *mrb, struct RClass* c)
{
  mrb_value path = mrb_class_path(mrb, c);
  if (mrb_nil_p(path)) {
    path = mrb_str_new_lit(mrb, "#<Class:");
    mrb_str_concat(mrb, path, mrb_ptr_to_str(mrb, c));
    mrb_str_cat_lit(mrb, path, ">");
  }
  return RSTRING_PTR(path);
}

MRB_API const char*
mrb_obj_classname(mrb_state *mrb, mrb_value obj)
{
  return mrb_class_name(mrb, mrb_obj_class(mrb, obj));
}

/*!
 * Ensures a class can be derived from super.
 *
 * \param super a reference to an object.
 * \exception TypeError if \a super is not a Class or \a super is a singleton class.
 */
static void
mrb_check_inheritable(mrb_state *mrb, struct RClass *super)
{
  if (super->tt != MRB_TT_CLASS) {
    mrb_raisef(mrb, E_TYPE_ERROR, "superclass must be a Class (%S given)", mrb_obj_value(super));
  }
  if (super->tt == MRB_TT_SCLASS) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't make subclass of singleton class");
  }
  if (super == mrb->class_class) {
    mrb_raise(mrb, E_TYPE_ERROR, "can't make subclass of Class");
  }
}

/*!
 * Creates a new class.
 * \param super     a class from which the new class derives.
 * \exception TypeError \a super is not inheritable.
 * \exception TypeError \a super is the Class class.
 */
MRB_API struct RClass*
mrb_class_new(mrb_state *mrb, struct RClass *super)
{
  struct RClass *c;

  if (super) {
    mrb_check_inheritable(mrb, super);
  }
  c = boot_defclass(mrb, super);
  if (super) {
    MRB_SET_INSTANCE_TT(c, MRB_INSTANCE_TT(super));
  }
  make_metaclass(mrb, c);

  return c;
}

/*!
 * Creates a new module.
 */
MRB_API struct RClass*
mrb_module_new(mrb_state *mrb)
{
  struct RClass *m = (struct RClass*)mrb_obj_alloc(mrb, MRB_TT_MODULE, mrb->module_class);
  boot_initmod(mrb, m);
  return m;
}

/*
 *  call-seq:
 *     obj.class    => class
 *
 *  Returns the class of <i>obj</i>, now preferred over
 *  <code>Object#type</code>, as an object's type in Ruby is only
 *  loosely tied to that object's class. This method must always be
 *  called with an explicit receiver, as <code>class</code> is also a
 *  reserved word in Ruby.
 *
 *     1.class      #=> Fixnum
 *     self.class   #=> Object
 */

MRB_API struct RClass*
mrb_obj_class(mrb_state *mrb, mrb_value obj)
{
  return mrb_class_real(mrb_class(mrb, obj));
}

MRB_API void
mrb_alias_method(mrb_state *mrb, struct RClass *c, mrb_sym a, mrb_sym b)
{
  struct RProc *m = mrb_method_search(mrb, c, b);

  mrb_define_method_raw(mrb, c, a, m);
}

/*!
 * Defines an alias of a method.
 * \param klass  the class which the original method belongs to
 * \param name1  a new name for the method
 * \param name2  the original name of the method
 */
MRB_API void
mrb_define_alias(mrb_state *mrb, struct RClass *klass, const char *name1, const char *name2)
{
  mrb_alias_method(mrb, klass, mrb_intern_cstr(mrb, name1), mrb_intern_cstr(mrb, name2));
}

/*
 * call-seq:
 *   mod.to_s   -> string
 *
 * Return a string representing this module or class. For basic
 * classes and modules, this is the name. For singletons, we
 * show information on the thing we're attached to as well.
 */

static mrb_value
mrb_mod_to_s(mrb_state *mrb, mrb_value klass)
{
  mrb_value str;

  if (mrb_type(klass) == MRB_TT_SCLASS) {
    mrb_value v = mrb_iv_get(mrb, klass, mrb_intern_lit(mrb, "__attached__"));

    str = mrb_str_new_lit(mrb, "#<Class:");

    switch (mrb_type(v)) {
      case MRB_TT_CLASS:
      case MRB_TT_MODULE:
      case MRB_TT_SCLASS:
        mrb_str_cat_str(mrb, str, mrb_inspect(mrb, v));
        break;
      default:
        mrb_str_cat_str(mrb, str, mrb_any_to_s(mrb, v));
        break;
    }
    return mrb_str_cat_lit(mrb, str, ">");
  }
  else {
    struct RClass *c;
    mrb_value path;

    str = mrb_str_buf_new(mrb, 32);
    c = mrb_class_ptr(klass);
    path = mrb_class_path(mrb, c);

    if (mrb_nil_p(path)) {
      switch (mrb_type(klass)) {
        case MRB_TT_CLASS:
          mrb_str_cat_lit(mrb, str, "#<Class:");
          break;

        case MRB_TT_MODULE:
          mrb_str_cat_lit(mrb, str, "#<Module:");
          break;

        default:
          /* Shouldn't be happened? */
          mrb_str_cat_lit(mrb, str, "#<??????:");
          break;
      }
      mrb_str_concat(mrb, str, mrb_ptr_to_str(mrb, c));
      return mrb_str_cat_lit(mrb, str, ">");
    }
    else {
      return path;
    }
  }
}

static mrb_value
mrb_mod_alias(mrb_state *mrb, mrb_value mod)
{
  struct RClass *c = mrb_class_ptr(mod);
  mrb_sym new_name, old_name;

  mrb_get_args(mrb, "nn", &new_name, &old_name);
  mrb_alias_method(mrb, c, new_name, old_name);
  return mrb_nil_value();
}

static void
undef_method(mrb_state *mrb, struct RClass *c, mrb_sym a)
{
  if (!mrb_obj_respond_to(mrb, c, a)) {
    mrb_name_error(mrb, a, "undefined method '%S' for class '%S'", mrb_sym2str(mrb, a), mrb_obj_value(c));
  }
  else {
    mrb_define_method_raw(mrb, c, a, NULL);
  }
}

MRB_API void
mrb_undef_method(mrb_state *mrb, struct RClass *c, const char *name)
{
  undef_method(mrb, c, mrb_intern_cstr(mrb, name));
}

MRB_API void
mrb_undef_class_method(mrb_state *mrb, struct RClass *c, const char *name)
{
  mrb_undef_method(mrb,  mrb_class_ptr(mrb_singleton_class(mrb, mrb_obj_value(c))), name);
}

static mrb_value
mrb_mod_undef(mrb_state *mrb, mrb_value mod)
{
  struct RClass *c = mrb_class_ptr(mod);
  mrb_int argc;
  mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);
  while (argc--) {
    undef_method(mrb, c, to_sym(mrb, *argv));
    argv++;
  }
  return mrb_nil_value();
}

static mrb_value
mod_define_method(mrb_state *mrb, mrb_value self)
{
  struct RClass *c = mrb_class_ptr(self);
  struct RProc *p;
  mrb_sym mid;
  mrb_value proc = mrb_undef_value();
  mrb_value blk;

  mrb_get_args(mrb, "n|o&", &mid, &proc, &blk);
  switch (mrb_type(proc)) {
    case MRB_TT_PROC:
      blk = proc;
      break;
    case MRB_TT_UNDEF:
      /* ignored */
      break;
    default:
      mrb_raisef(mrb, E_TYPE_ERROR, "wrong argument type %S (expected Proc)", mrb_obj_value(mrb_obj_class(mrb, proc)));
      break;
  }
  if (mrb_nil_p(blk)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  p = (struct RProc*)mrb_obj_alloc(mrb, MRB_TT_PROC, mrb->proc_class);
  mrb_proc_copy(p, mrb_proc_ptr(blk));
  p->flags |= MRB_PROC_STRICT;
  mrb_define_method_raw(mrb, c, mid, p);
  return mrb_symbol_value(mid);
}

static void
check_cv_name_str(mrb_state *mrb, mrb_value str)
{
  const char *s = RSTRING_PTR(str);
  mrb_int len = RSTRING_LEN(str);

  if (len < 3 || !(s[0] == '@' && s[1] == '@')) {
    mrb_name_error(mrb, mrb_intern_str(mrb, str), "'%S' is not allowed as a class variable name", str);
  }
}

static void
check_cv_name_sym(mrb_state *mrb, mrb_sym id)
{
  check_cv_name_str(mrb, mrb_sym2str(mrb, id));
}

/* 15.2.2.4.16 */
/*
 *  call-seq:
 *     obj.class_variable_defined?(symbol)    -> true or false
 *
 *  Returns <code>true</code> if the given class variable is defined
 *  in <i>obj</i>.
 *
 *     class Fred
 *       @@foo = 99
 *     end
 *     Fred.class_variable_defined?(:@@foo)    #=> true
 *     Fred.class_variable_defined?(:@@bar)    #=> false
 */

static mrb_value
mrb_mod_cvar_defined(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_cv_name_sym(mrb, id);
  return mrb_bool_value(mrb_cv_defined(mrb, mod, id));
}

/* 15.2.2.4.17 */
/*
 *  call-seq:
 *     mod.class_variable_get(symbol)    -> obj
 *
 *  Returns the value of the given class variable (or throws a
 *  <code>NameError</code> exception). The <code>@@</code> part of the
 *  variable name should be included for regular class variables
 *
 *     class Fred
 *       @@foo = 99
 *     end
 *     Fred.class_variable_get(:@@foo)     #=> 99
 */

static mrb_value
mrb_mod_cvar_get(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_cv_name_sym(mrb, id);
  return mrb_cv_get(mrb, mod, id);
}

/* 15.2.2.4.18 */
/*
 *  call-seq:
 *     obj.class_variable_set(symbol, obj)    -> obj
 *
 *  Sets the class variable names by <i>symbol</i> to
 *  <i>object</i>.
 *
 *     class Fred
 *       @@foo = 99
 *       def foo
 *         @@foo
 *       end
 *     end
 *     Fred.class_variable_set(:@@foo, 101)     #=> 101
 *     Fred.new.foo                             #=> 101
 */

static mrb_value
mrb_mod_cvar_set(mrb_state *mrb, mrb_value mod)
{
  mrb_value value;
  mrb_sym id;

  mrb_get_args(mrb, "no", &id, &value);
  check_cv_name_sym(mrb, id);
  mrb_cv_set(mrb, mod, id, value);
  return value;
}

/* 15.2.2.4.39 */
/*
 *  call-seq:
 *     remove_class_variable(sym)    -> obj
 *
 *  Removes the definition of the <i>sym</i>, returning that
 *  constant's value.
 *
 *     class Dummy
 *       @@var = 99
 *       puts @@var
 *       p class_variables
 *       remove_class_variable(:@@var)
 *       p class_variables
 *     end
 *
 *  <em>produces:</em>
 *
 *     99
 *     [:@@var]
 *     []
 */

static mrb_value
mrb_mod_remove_cvar(mrb_state *mrb, mrb_value mod)
{
  mrb_value val;
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_cv_name_sym(mrb, id);

  val = mrb_iv_remove(mrb, mod, id);
  if (!mrb_undef_p(val)) return val;

  if (mrb_cv_defined(mrb, mod, id)) {
    mrb_name_error(mrb, id, "cannot remove %S for %S",
                   mrb_sym2str(mrb, id), mod);
  }

  mrb_name_error(mrb, id, "class variable %S not defined for %S",
                 mrb_sym2str(mrb, id), mod);

 /* not reached */
 return mrb_nil_value();
}

/* 15.2.2.4.34 */
/*
 *  call-seq:
 *     mod.method_defined?(symbol)    -> true or false
 *
 *  Returns +true+ if the named method is defined by
 *  _mod_ (or its included modules and, if _mod_ is a class,
 *  its ancestors). Public and protected methods are matched.
 *
 *     module A
 *       def method1()  end
 *     end
 *     class B
 *       def method2()  end
 *     end
 *     class C < B
 *       include A
 *       def method3()  end
 *     end
 *
 *     A.method_defined? :method1    #=> true
 *     C.method_defined? "method1"   #=> true
 *     C.method_defined? "method2"   #=> true
 *     C.method_defined? "method3"   #=> true
 *     C.method_defined? "method4"   #=> false
 */

static mrb_value
mrb_mod_method_defined(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  return mrb_bool_value(mrb_obj_respond_to(mrb, mrb_class_ptr(mod), id));
}

static void
remove_method(mrb_state *mrb, mrb_value mod, mrb_sym mid)
{
  struct RClass *c = mrb_class_ptr(mod);
  khash_t(mt) *h = find_origin(c)->mt;
  khiter_t k;

  if (h) {
    k = kh_get(mt, mrb, h, mid);
    if (k != kh_end(h)) {
      kh_del(mt, mrb, h, k);
      mrb_funcall(mrb, mod, "method_removed", 1, mrb_symbol_value(mid));
      return;
    }
  }

  mrb_name_error(mrb, mid, "method '%S' not defined in %S",
    mrb_sym2str(mrb, mid), mod);
}

/* 15.2.2.4.41 */
/*
 *  call-seq:
 *     remove_method(symbol)   -> self
 *
 *  Removes the method identified by _symbol_ from the current
 *  class. For an example, see <code>Module.undef_method</code>.
 */

static mrb_value
mrb_mod_remove_method(mrb_state *mrb, mrb_value mod)
{
  mrb_int argc;
  mrb_value *argv;

  mrb_get_args(mrb, "*", &argv, &argc);
  while (argc--) {
    remove_method(mrb, mod, to_sym(mrb, *argv));
    argv++;
  }
  return mod;
}



static void
check_const_name_str(mrb_state *mrb, mrb_value str)
{
  if (RSTRING_LEN(str) < 1 || !ISUPPER(*RSTRING_PTR(str))) {
    mrb_name_error(mrb, mrb_intern_str(mrb, str), "wrong constant name %S", str);
  }
}

static void
check_const_name_sym(mrb_state *mrb, mrb_sym id)
{
  check_const_name_str(mrb, mrb_sym2str(mrb, id));
}

static mrb_value
const_defined(mrb_state *mrb, mrb_value mod, mrb_sym id, mrb_bool inherit)
{
  if (inherit) {
    return mrb_bool_value(mrb_const_defined(mrb, mod, id));
  }
  return mrb_bool_value(mrb_const_defined_at(mrb, mod, id));
}

static mrb_value
mrb_mod_const_defined(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;
  mrb_bool inherit = TRUE;

  mrb_get_args(mrb, "n|b", &id, &inherit);
  check_const_name_sym(mrb, id);
  return const_defined(mrb, mod, id, inherit);
}

static mrb_value
mrb_mod_const_get(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;

  mrb_get_args(mrb, "n", &id);
  check_const_name_sym(mrb, id);
  return mrb_const_get(mrb, mod, id);
}

static mrb_value
mrb_mod_const_set(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;
  mrb_value value;

  mrb_get_args(mrb, "no", &id, &value);
  check_const_name_sym(mrb, id);
  mrb_const_set(mrb, mod, id, value);
  return value;
}

static mrb_value
mrb_mod_remove_const(mrb_state *mrb, mrb_value mod)
{
  mrb_sym id;
  mrb_value val;

  mrb_get_args(mrb, "n", &id);
  check_const_name_sym(mrb, id);
  val = mrb_iv_remove(mrb, mod, id);
  if (mrb_undef_p(val)) {
    mrb_name_error(mrb, id, "constant %S not defined", mrb_sym2str(mrb, id));
  }
  return val;
}

static mrb_value
mrb_mod_const_missing(mrb_state *mrb, mrb_value mod)
{
  mrb_sym sym;

  mrb_get_args(mrb, "n", &sym);

  if (mrb_class_real(mrb_class_ptr(mod)) != mrb->object_class) {
    mrb_name_error(mrb, sym, "uninitialized constant %S::%S",
                   mod,
                   mrb_sym2str(mrb, sym));
  }
  else {
    mrb_name_error(mrb, sym, "uninitialized constant %S",
                   mrb_sym2str(mrb, sym));
  }
  /* not reached */
  return mrb_nil_value();
}

static mrb_value
mrb_mod_s_constants(mrb_state *mrb, mrb_value mod)
{
  mrb_raise(mrb, E_NOTIMP_ERROR, "Module.constants not implemented");
  return mrb_nil_value();       /* not reached */
}

static mrb_value
mrb_mod_eqq(mrb_state *mrb, mrb_value mod)
{
  mrb_value obj;
  mrb_bool eqq;

  mrb_get_args(mrb, "o", &obj);
  eqq = mrb_obj_is_kind_of(mrb, obj, mrb_class_ptr(mod));

  return mrb_bool_value(eqq);
}

MRB_API mrb_value
mrb_mod_module_function(mrb_state *mrb, mrb_value mod)
{
  mrb_value *argv;
  mrb_int argc, i;
  mrb_sym mid;
  struct RProc *method_rproc;
  struct RClass *rclass;
  int ai;

  mrb_check_type(mrb, mod, MRB_TT_MODULE);

  mrb_get_args(mrb, "*", &argv, &argc);
  if(argc == 0) {
    /* set MODFUNC SCOPE if implemented */
    return mod;
  }

  /* set PRIVATE method visibility if implemented */
  /* mrb_mod_dummy_visibility(mrb, mod); */

  for (i=0; i<argc; i++) {
    mrb_check_type(mrb, argv[i], MRB_TT_SYMBOL);

    mid = mrb_symbol(argv[i]);
    rclass = mrb_class_ptr(mod);
    method_rproc = mrb_method_search(mrb, rclass, mid);

    prepare_singleton_class(mrb, (struct RBasic*)rclass);
    ai = mrb_gc_arena_save(mrb);
    mrb_define_method_raw(mrb, rclass->c, mid, method_rproc);
    mrb_gc_arena_restore(mrb, ai);
  }

  return mod;
}

void
mrb_init_class(mrb_state *mrb)
{
  struct RClass *bob;           /* BasicObject */
  struct RClass *obj;           /* Object */
  struct RClass *mod;           /* Module */
  struct RClass *cls;           /* Class */

  /* boot class hierarchy */
  bob = boot_defclass(mrb, 0);
  obj = boot_defclass(mrb, bob); mrb->object_class = obj;
  mod = boot_defclass(mrb, obj); mrb->module_class = mod;/* obj -> mod */
  cls = boot_defclass(mrb, mod); mrb->class_class = cls; /* obj -> cls */
  /* fix-up loose ends */
  bob->c = obj->c = mod->c = cls->c = cls;
  make_metaclass(mrb, bob);
  make_metaclass(mrb, obj);
  make_metaclass(mrb, mod);
  make_metaclass(mrb, cls);

  /* name basic classes */
  mrb_define_const(mrb, bob, "BasicObject", mrb_obj_value(bob));
  mrb_define_const(mrb, obj, "BasicObject", mrb_obj_value(bob));
  mrb_define_const(mrb, obj, "Object",      mrb_obj_value(obj));
  mrb_define_const(mrb, obj, "Module",      mrb_obj_value(mod));
  mrb_define_const(mrb, obj, "Class",       mrb_obj_value(cls));

  /* name each classes */
  name_class(mrb, bob, mrb_intern_lit(mrb, "BasicObject"));
  name_class(mrb, obj, mrb_intern_lit(mrb, "Object"));           /* 15.2.1 */
  name_class(mrb, mod, mrb_intern_lit(mrb, "Module"));           /* 15.2.2 */
  name_class(mrb, cls, mrb_intern_lit(mrb, "Class"));            /* 15.2.3 */

  mrb->proc_class = mrb_define_class(mrb, "Proc", mrb->object_class);  /* 15.2.17 */
  MRB_SET_INSTANCE_TT(mrb->proc_class, MRB_TT_PROC);

  MRB_SET_INSTANCE_TT(cls, MRB_TT_CLASS);
  mrb_define_method(mrb, bob, "initialize",              mrb_bob_init,             MRB_ARGS_NONE());
  mrb_define_method(mrb, bob, "!",                       mrb_bob_not,              MRB_ARGS_NONE());
  mrb_define_method(mrb, bob, "method_missing",          mrb_bob_missing,          MRB_ARGS_ANY());  /* 15.3.1.3.30 */

  mrb_define_class_method(mrb, cls, "new",               mrb_class_new_class,      MRB_ARGS_OPT(1));
  mrb_define_method(mrb, cls, "superclass",              mrb_class_superclass,     MRB_ARGS_NONE()); /* 15.2.3.3.4 */
  mrb_define_method(mrb, cls, "new",                     mrb_instance_new,         MRB_ARGS_ANY());  /* 15.2.3.3.3 */
  mrb_define_method(mrb, cls, "initialize",              mrb_class_initialize,     MRB_ARGS_OPT(1)); /* 15.2.3.3.1 */
  mrb_define_method(mrb, cls, "inherited",               mrb_bob_init,             MRB_ARGS_REQ(1));

  MRB_SET_INSTANCE_TT(mod, MRB_TT_MODULE);
  mrb_define_method(mrb, mod, "class_variable_defined?", mrb_mod_cvar_defined,     MRB_ARGS_REQ(1)); /* 15.2.2.4.16 */
  mrb_define_method(mrb, mod, "class_variable_get",      mrb_mod_cvar_get,         MRB_ARGS_REQ(1)); /* 15.2.2.4.17 */
  mrb_define_method(mrb, mod, "class_variable_set",      mrb_mod_cvar_set,         MRB_ARGS_REQ(2)); /* 15.2.2.4.18 */
  mrb_define_method(mrb, mod, "extend_object",           mrb_mod_extend_object,    MRB_ARGS_REQ(1)); /* 15.2.2.4.25 */
  mrb_define_method(mrb, mod, "extended",                mrb_bob_init,             MRB_ARGS_REQ(1)); /* 15.2.2.4.26 */
  mrb_define_method(mrb, mod, "prepended",               mrb_bob_init,             MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mod, "prepend_features",        mrb_mod_prepend_features, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mod, "include?",                mrb_mod_include_p,        MRB_ARGS_REQ(1)); /* 15.2.2.4.28 */
  mrb_define_method(mrb, mod, "append_features",         mrb_mod_append_features,  MRB_ARGS_REQ(1)); /* 15.2.2.4.10 */
  mrb_define_method(mrb, mod, "class_eval",              mrb_mod_module_eval,      MRB_ARGS_ANY());  /* 15.2.2.4.15 */
  mrb_define_method(mrb, mod, "included",                mrb_bob_init,             MRB_ARGS_REQ(1)); /* 15.2.2.4.29 */
  mrb_define_method(mrb, mod, "included_modules",        mrb_mod_included_modules, MRB_ARGS_NONE()); /* 15.2.2.4.30 */
  mrb_define_method(mrb, mod, "initialize",              mrb_mod_initialize,       MRB_ARGS_NONE()); /* 15.2.2.4.31 */
  mrb_define_method(mrb, mod, "instance_methods",        mrb_mod_instance_methods, MRB_ARGS_ANY());  /* 15.2.2.4.33 */
  mrb_define_method(mrb, mod, "method_defined?",         mrb_mod_method_defined,   MRB_ARGS_REQ(1)); /* 15.2.2.4.34 */
  mrb_define_method(mrb, mod, "module_eval",             mrb_mod_module_eval,      MRB_ARGS_ANY());  /* 15.2.2.4.35 */
  mrb_define_method(mrb, mod, "module_function",         mrb_mod_module_function,  MRB_ARGS_ANY());
  mrb_define_method(mrb, mod, "private",                 mrb_mod_dummy_visibility, MRB_ARGS_ANY());  /* 15.2.2.4.36 */
  mrb_define_method(mrb, mod, "protected",               mrb_mod_dummy_visibility, MRB_ARGS_ANY());  /* 15.2.2.4.37 */
  mrb_define_method(mrb, mod, "public",                  mrb_mod_dummy_visibility, MRB_ARGS_ANY());  /* 15.2.2.4.38 */
  mrb_define_method(mrb, mod, "remove_class_variable",   mrb_mod_remove_cvar,      MRB_ARGS_REQ(1)); /* 15.2.2.4.39 */
  mrb_define_method(mrb, mod, "remove_method",           mrb_mod_remove_method,    MRB_ARGS_ANY());  /* 15.2.2.4.41 */
  mrb_define_method(mrb, mod, "method_removed",          mrb_bob_init,             MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mod, "attr_reader",             mrb_mod_attr_reader,      MRB_ARGS_ANY());  /* 15.2.2.4.13 */
  mrb_define_method(mrb, mod, "attr_writer",             mrb_mod_attr_writer,      MRB_ARGS_ANY());  /* 15.2.2.4.14 */
  mrb_define_method(mrb, mod, "to_s",                    mrb_mod_to_s,             MRB_ARGS_NONE());
  mrb_define_method(mrb, mod, "inspect",                 mrb_mod_to_s,             MRB_ARGS_NONE());
  mrb_define_method(mrb, mod, "alias_method",            mrb_mod_alias,            MRB_ARGS_ANY());  /* 15.2.2.4.8 */
  mrb_define_method(mrb, mod, "ancestors",               mrb_mod_ancestors,        MRB_ARGS_NONE()); /* 15.2.2.4.9 */
  mrb_define_method(mrb, mod, "undef_method",            mrb_mod_undef,            MRB_ARGS_ANY());  /* 15.2.2.4.41 */
  mrb_define_method(mrb, mod, "const_defined?",          mrb_mod_const_defined,    MRB_ARGS_ARG(1,1)); /* 15.2.2.4.20 */
  mrb_define_method(mrb, mod, "const_get",               mrb_mod_const_get,        MRB_ARGS_REQ(1)); /* 15.2.2.4.21 */
  mrb_define_method(mrb, mod, "const_set",               mrb_mod_const_set,        MRB_ARGS_REQ(2)); /* 15.2.2.4.23 */
  mrb_define_method(mrb, mod, "constants",               mrb_mod_constants,        MRB_ARGS_OPT(1)); /* 15.2.2.4.24 */
  mrb_define_method(mrb, mod, "remove_const",            mrb_mod_remove_const,     MRB_ARGS_REQ(1)); /* 15.2.2.4.40 */
  mrb_define_method(mrb, mod, "const_missing",           mrb_mod_const_missing,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mod, "define_method",           mod_define_method,        MRB_ARGS_ARG(1,1));
  mrb_define_method(mrb, mod, "class_variables",         mrb_mod_class_variables,  MRB_ARGS_NONE()); /* 15.2.2.4.19 */
  mrb_define_method(mrb, mod, "===",                     mrb_mod_eqq,              MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, mod, "constants",         mrb_mod_s_constants,      MRB_ARGS_ANY());  /* 15.2.2.3.1 */

  mrb_undef_method(mrb, cls, "append_features");
  mrb_undef_method(mrb, cls, "extend_object");
}
