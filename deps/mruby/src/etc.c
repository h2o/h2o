/*
** etc.c -
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/re.h>
#include <mruby/irep.h>

MRB_API struct RData*
mrb_data_object_alloc(mrb_state *mrb, struct RClass *klass, void *ptr, const mrb_data_type *type)
{
  struct RData *data;

  data = (struct RData*)mrb_obj_alloc(mrb, MRB_TT_DATA, klass);
  data->data = ptr;
  data->type = type;

  return data;
}

MRB_API void
mrb_data_check_type(mrb_state *mrb, mrb_value obj, const mrb_data_type *type)
{
  if (mrb_type(obj) != MRB_TT_DATA) {
    mrb_check_type(mrb, obj, MRB_TT_DATA);
  }
  if (DATA_TYPE(obj) != type) {
    const mrb_data_type *t2 = DATA_TYPE(obj);

    if (t2) {
      mrb_raisef(mrb, E_TYPE_ERROR, "wrong argument type %S (expected %S)",
                 mrb_str_new_cstr(mrb, t2->struct_name), mrb_str_new_cstr(mrb, type->struct_name));
    }
    else {
      struct RClass *c = mrb_class(mrb, obj);

      mrb_raisef(mrb, E_TYPE_ERROR, "uninitialized %S (expected %S)",
                 mrb_obj_value(c), mrb_str_new_cstr(mrb, type->struct_name));
    }
  }
}

MRB_API void*
mrb_data_check_get_ptr(mrb_state *mrb, mrb_value obj, const mrb_data_type *type)
{
  if (mrb_type(obj) != MRB_TT_DATA) {
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
  mrb_sym id;

  switch (mrb_type(name)) {
    default:
      name = mrb_check_string_type(mrb, name);
      if (mrb_nil_p(name)) {
        name = mrb_inspect(mrb, name);
        mrb_raisef(mrb, E_TYPE_ERROR, "%S is not a symbol", name);
        /* not reached */
      }
      /* fall through */
    case MRB_TT_STRING:
      name = mrb_str_intern(mrb, name);
      /* fall through */
    case MRB_TT_SYMBOL:
      id = mrb_symbol(name);
  }
  return id;
}

MRB_API mrb_int
#ifdef MRB_WITHOUT_FLOAT
mrb_fixnum_id(mrb_int f)
#else
mrb_float_id(mrb_float f)
#endif
{
  const char *p = (const char*)&f;
  int len = sizeof(f);
  uint32_t id = 0;

#ifndef MRB_WITHOUT_FLOAT
  /* normalize -0.0 to 0.0 */
  if (f == 0) f = 0.0;
#endif
  while (len--) {
    id = id*65599 + *p;
    p++;
  }
  id = id + (id>>5);

  return (mrb_int)id;
}

MRB_API mrb_int
mrb_obj_id(mrb_value obj)
{
  mrb_int tt = mrb_type(obj);

#define MakeID2(p,t) (mrb_int)(((intptr_t)(p))^(t))
#define MakeID(p)    MakeID2(p,tt)

  switch (tt) {
  case MRB_TT_FREE:
  case MRB_TT_UNDEF:
    return MakeID(0); /* not define */
  case MRB_TT_FALSE:
    if (mrb_nil_p(obj))
      return MakeID(1);
    return MakeID(0);
  case MRB_TT_TRUE:
    return MakeID(1);
  case MRB_TT_SYMBOL:
    return MakeID(mrb_symbol(obj));
  case MRB_TT_FIXNUM:
#ifdef MRB_WITHOUT_FLOAT
    return MakeID(mrb_fixnum_id(mrb_fixnum(obj)));
#else
    return MakeID2(mrb_float_id((mrb_float)mrb_fixnum(obj)), MRB_TT_FLOAT);
  case MRB_TT_FLOAT:
    return MakeID(mrb_float_id(mrb_float(obj)));
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
  case MRB_TT_FILE:
  case MRB_TT_DATA:
  case MRB_TT_ISTRUCT:
  default:
    return MakeID(mrb_ptr(obj));
  }
}

#ifdef MRB_WORD_BOXING
#ifndef MRB_WITHOUT_FLOAT
MRB_API mrb_value
mrb_word_boxing_float_value(mrb_state *mrb, mrb_float f)
{
  mrb_value v;

  v.value.p = mrb_obj_alloc(mrb, MRB_TT_FLOAT, mrb->float_class);
  v.value.fp->f = f;
  return v;
}

MRB_API mrb_value
mrb_word_boxing_float_pool(mrb_state *mrb, mrb_float f)
{
  struct RFloat *nf = (struct RFloat *)mrb_malloc(mrb, sizeof(struct RFloat));
  nf->tt = MRB_TT_FLOAT;
  nf->c = mrb->float_class;
  nf->f = f;
  return mrb_obj_value(nf);
}
#endif  /* MRB_WITHOUT_FLOAT */

MRB_API mrb_value
mrb_word_boxing_cptr_value(mrb_state *mrb, void *p)
{
  mrb_value v;

  v.value.p = mrb_obj_alloc(mrb, MRB_TT_CPTR, mrb->object_class);
  v.value.vp->p = p;
  return v;
}
#endif  /* MRB_WORD_BOXING */

MRB_API mrb_bool
mrb_regexp_p(mrb_state *mrb, mrb_value v)
{
  if (mrb->flags & MRB_STATE_NO_REGEXP) {
    return FALSE;
  }
  if ((mrb->flags & MRB_STATE_REGEXP) || mrb_class_defined(mrb, REGEXP_CLASS)) {
    mrb->flags |= MRB_STATE_REGEXP;
    return mrb_obj_is_kind_of(mrb, v, mrb_class_get(mrb, REGEXP_CLASS));
  }
  else {
    mrb->flags |= MRB_STATE_REGEXP;
    mrb->flags |= MRB_STATE_NO_REGEXP;
  }
  return FALSE;
}

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
