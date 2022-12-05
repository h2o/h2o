/*
** etc.c
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/numeric.h>

MRB_API struct RData*
mrb_data_object_alloc(mrb_state *mrb, struct RClass *klass, void *ptr, const mrb_data_type *type)
{
  struct RData *data;

  data = MRB_OBJ_ALLOC(mrb, MRB_TT_DATA, klass);
  data->data = ptr;
  data->type = type;

  return data;
}

MRB_API void
mrb_data_check_type(mrb_state *mrb, mrb_value obj, const mrb_data_type *type)
{
  if (!mrb_data_p(obj)) {
    mrb_check_type(mrb, obj, MRB_TT_DATA);
  }
  if (DATA_TYPE(obj) != type) {
    const mrb_data_type *t2 = DATA_TYPE(obj);

    if (t2) {
      mrb_raisef(mrb, E_TYPE_ERROR, "wrong argument type %s (expected %s)",
                 t2->struct_name, type->struct_name);
    }
    else {
      mrb_raisef(mrb, E_TYPE_ERROR, "uninitialized %t (expected %s)",
                 obj, type->struct_name);
    }
  }
}

MRB_API void*
mrb_data_check_get_ptr(mrb_state *mrb, mrb_value obj, const mrb_data_type *type)
{
  if (!mrb_data_p(obj)) {
    return NULL;
  }
  if (DATA_TYPE(obj) != type) {
    return NULL;
  }
  return DATA_PTR(obj);
}

MRB_API void*
mrb_data_get_ptr(mrb_state *mrb, mrb_value obj, const mrb_data_type *type)
{
  mrb_data_check_type(mrb, obj, type);
  return DATA_PTR(obj);
}

MRB_API mrb_sym
mrb_obj_to_sym(mrb_state *mrb, mrb_value name)
{
  if (mrb_symbol_p(name)) return mrb_symbol(name);
  if (mrb_string_p(name)) return mrb_intern_str(mrb, name);
  mrb_raisef(mrb, E_TYPE_ERROR, "%!v is not a symbol nor a string", name);
  return 0;  /* not reached */
}

static mrb_int
make_num_id(const char *p, size_t len)
{
  uint32_t id = 0;

  while (len--) {
    id = id*65599 + *p;
    p++;
  }
  id = id + (id>>5);

  return (mrb_int)id;
}

MRB_API mrb_int
mrb_int_id(mrb_int n)
{
  return make_num_id((const char*)&n, sizeof(n));
}

#ifndef MRB_NO_FLOAT
MRB_API mrb_int
mrb_float_id(mrb_float f)
{
  /* normalize -0.0 to 0.0 */
  if (f == 0) f = 0.0;
  return make_num_id((const char*)&f, sizeof(f));
}
#endif

MRB_API mrb_int
mrb_obj_id(mrb_value obj)
{
#if defined(MRB_NAN_BOXING)
#ifdef MRB_INT64
  return obj.u;
#else
  uint64_t u = obj.u;
  return (mrb_int)(u>>32)^u;
#endif
#elif defined(MRB_WORD_BOXING)
  if (!mrb_immediate_p(obj)) {
    if (mrb_integer_p(obj)) return mrb_integer(obj);
#ifndef MRB_NO_FLOAT
    if (mrb_float_p(obj)) {
      return mrb_float_id(mrb_float(obj));
    }
#endif
  }
  return (mrb_int)obj.w;
#else  /* MRB_NO_BOXING */

#define MakeID(p,t) (mrb_int)(((intptr_t)(p))^(t))

  enum mrb_vtype tt = mrb_type(obj);

  switch (tt) {
  case MRB_TT_FREE:
  case MRB_TT_UNDEF:
    return MakeID(0, tt); /* should not happen */
  case MRB_TT_FALSE:
    if (mrb_nil_p(obj))
      return MakeID(4, tt);
    else
      return MakeID(0, tt);
  case MRB_TT_TRUE:
    return MakeID(2, tt);
  case MRB_TT_SYMBOL:
    return MakeID(mrb_symbol(obj), tt);
  case MRB_TT_INTEGER:
    return MakeID(mrb_int_id(mrb_integer(obj)), tt);
#ifndef MRB_NO_FLOAT
  case MRB_TT_FLOAT:
    return MakeID(mrb_float_id(mrb_float(obj)), tt);
#endif
  case MRB_TT_STRING:
  case MRB_TT_OBJECT:
  case MRB_TT_CLASS:
  case MRB_TT_MODULE:
  case MRB_TT_ICLASS:
  case MRB_TT_SCLASS:
  case MRB_TT_PROC:
  case MRB_TT_ARRAY:
  case MRB_TT_HASH:
  case MRB_TT_RANGE:
  case MRB_TT_EXCEPTION:
  case MRB_TT_DATA:
  case MRB_TT_ISTRUCT:
  default:
    return MakeID(mrb_ptr(obj), tt);
  }
#endif
}

#ifdef MRB_WORD_BOXING
#ifndef MRB_NO_FLOAT
MRB_API mrb_value
mrb_word_boxing_float_value(mrb_state *mrb, mrb_float f)
{
  union mrb_value_ v;

#ifdef MRB_WORDBOX_NO_FLOAT_TRUNCATE
  v.p = mrb_obj_alloc(mrb, MRB_TT_FLOAT, mrb->float_class);
  v.fp->f = f;
  MRB_SET_FROZEN_FLAG(v.bp);
#elif defined(MRB_64BIT) && defined(MRB_USE_FLOAT32)
  v.w = 0;
  v.f = f;
  v.w = ((v.w<<2) & ~3) | 2;
#else
  v.f = f;
  v.w = (v.w & ~3) | 2;
#endif
  return v.value;
}


#ifndef MRB_WORDBOX_NO_FLOAT_TRUNCATE
MRB_API mrb_float
mrb_word_boxing_value_float(mrb_value v)
{
  union mrb_value_ u;
  u.value = v;
  u.w = u.w & ~3;
#if defined(MRB_64BIT) && defined(MRB_USE_FLOAT32)
  u.w >>= 2;
#endif
  return u.f;
}
#endif
#endif  /* MRB_NO_FLOAT */

MRB_API mrb_value
mrb_word_boxing_cptr_value(mrb_state *mrb, void *p)
{
  mrb_value v;
  struct RCptr *cptr = MRB_OBJ_ALLOC(mrb, MRB_TT_CPTR, mrb->object_class);

  SET_OBJ_VALUE(v, cptr);
  cptr->p = p;
  return v;
}
#endif  /* MRB_WORD_BOXING */

#if defined(MRB_WORD_BOXING) || (defined(MRB_NAN_BOXING) && defined(MRB_INT64))
MRB_API mrb_value
mrb_boxing_int_value(mrb_state *mrb, mrb_int n)
{
  if (FIXABLE(n)) return mrb_fixnum_value(n);
  else {
    mrb_value v;
    struct RInteger *p;

    p = (struct RInteger*)mrb_obj_alloc(mrb, MRB_TT_INTEGER, mrb->integer_class);
    p->i = n;
    MRB_SET_FROZEN_FLAG((struct RBasic*)p);
    SET_OBJ_VALUE(v, p);
    return v;
  }
}
#endif

#if defined _MSC_VER && _MSC_VER < 1900

#ifndef va_copy
static void
mrb_msvc_va_copy(va_list *dest, va_list src)
{
  *dest = src;
}
#define va_copy(dest, src) mrb_msvc_va_copy(&(dest), src)
#endif

MRB_API int
mrb_msvc_vsnprintf(char *s, size_t n, const char *format, va_list arg)
{
  int cnt;
  va_list argcp;
  va_copy(argcp, arg);
  if (n == 0 || (cnt = _vsnprintf_s(s, n, _TRUNCATE, format, argcp)) < 0) {
    cnt = _vscprintf(format, arg);
  }
  va_end(argcp);
  return cnt;
}

MRB_API int
mrb_msvc_snprintf(char *s, size_t n, const char *format, ...)
{
  va_list arg;
  int ret;
  va_start(arg, format);
  ret = mrb_msvc_vsnprintf(s, n, format, arg);
  va_end(arg);
  return ret;
}

#endif  /* defined _MSC_VER && _MSC_VER < 1900 */
