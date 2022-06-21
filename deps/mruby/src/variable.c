/*
** variable.c - mruby variables
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/presym.h>

/* Instance variable table structure */
typedef struct iv_tbl {
  int size, alloc;
  mrb_value *ptr;
} iv_tbl;

#define IV_EMPTY 0
#define IV_DELETED (1UL<<31)
#define IV_KEY_P(k) (((k)&~((uint32_t)IV_DELETED))!=0)

/* Creates the instance variable table. */
static iv_tbl*
iv_new(mrb_state *mrb)
{
  iv_tbl *t;

  t = (iv_tbl*)mrb_malloc(mrb, sizeof(iv_tbl));
  t->size = 0;
  t->alloc = 0;
  t->ptr = NULL;

  return t;
}

static void iv_put(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value val);

static void
iv_rehash(mrb_state *mrb, iv_tbl *t)
{
  int old_alloc = t->alloc;
  int new_alloc = old_alloc+4;
  mrb_value *old_ptr = t->ptr;

  khash_power2(new_alloc);
  if (old_alloc == new_alloc) return;

  t->size = 0;
  t->alloc = new_alloc;
  t->ptr = (mrb_value*)mrb_calloc(mrb, sizeof(mrb_value)+sizeof(mrb_sym), new_alloc);
  if (old_alloc == 0) return;

  mrb_sym *keys = (mrb_sym*)&old_ptr[old_alloc];
  mrb_value *vals = old_ptr;
  for (int i = 0; i < old_alloc; i++) {
    if (IV_KEY_P(keys[i])) {
      iv_put(mrb, t, keys[i], vals[i]);
    }
  }
  mrb_free(mrb, old_ptr);
}

/* Set the value for the symbol in the instance variable table. */
static void
iv_put(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value val)
{
  int hash, pos, start, dpos = -1;

  if (t == NULL) return;
  if (t->alloc == 0) {
    iv_rehash(mrb, t);
  }

  mrb_sym *keys = (mrb_sym*)&t->ptr[t->alloc];
  mrb_value *vals = t->ptr;
  hash = kh_int_hash_func(mrb, sym);
  start = pos = hash & (t->alloc-1);
  for (;;) {
    mrb_sym key = keys[pos];
    if (key == sym) {
      vals[pos] = val;
      return;
    }
    else if (key == IV_EMPTY) {
      t->size++;
      keys[pos] = sym;
      vals[pos] = val;
      return;
    }
    else if (key == IV_DELETED && dpos < 0) {
      dpos = pos;
    }
    pos = (pos+1) & (t->alloc-1);
    if (pos == start) {         /* not found */
      if (dpos >= 0) {
        t->size++;
        keys[dpos] = sym;
        vals[dpos] = val;
        return;
      }
      /* no room */
      iv_rehash(mrb, t);
      keys = (mrb_sym*)&t->ptr[t->alloc];
      vals = t->ptr;
      start = pos = hash & (t->alloc-1);
    }
  }
}

/* Get a value for a symbol from the instance variable table. */
static int
iv_get(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value *vp)
{
  int hash, pos, start;

  if (t == NULL) return FALSE;
  if (t->alloc == 0) return FALSE;
  if (t->size == 0) return FALSE;

  mrb_sym *keys = (mrb_sym*)&t->ptr[t->alloc];
  mrb_value *vals = t->ptr;
  hash = kh_int_hash_func(mrb, sym);
  start = pos = hash & (t->alloc-1);
  for (;;) {
    mrb_sym key = keys[pos];
    if (key == sym) {
      if (vp) *vp = vals[pos];
      return pos+1;
    }
    else if (key == IV_EMPTY) {
      return 0;
    }
    pos = (pos+1) & (t->alloc-1);
    if (pos == start) {         /* not found */
      return 0;
    }
  }
}

/* Deletes the value for the symbol from the instance variable table. */
static mrb_bool
iv_del(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value *vp)
{
  int hash, pos, start;

  if (t == NULL) return FALSE;
  if (t->alloc == 0) return FALSE;
  if (t->size == 0) return FALSE;

  mrb_sym *keys = (mrb_sym*)&t->ptr[t->alloc];
  mrb_value *vals = t->ptr;
  hash = kh_int_hash_func(mrb, sym);
  start = pos = hash & (t->alloc-1);
  for (;;) {
    mrb_sym key = keys[pos];
    if (key == sym) {
      if (vp) *vp = vals[pos];
      t->size--;
      keys[pos] = IV_DELETED;
      return TRUE;
    }
    else if (key == IV_EMPTY) {
      return FALSE;
    }
    pos = (pos+1) & (t->alloc-1);
    if (pos == start) {         /* not found */
      return FALSE;
    }
  }
}

/* Iterates over the instance variable table. */
static void
iv_foreach(mrb_state *mrb, iv_tbl *t, mrb_iv_foreach_func *func, void *p)
{
  int i;

  if (t == NULL) return;
  if (t->alloc == 0) return;
  if (t->size == 0) return;

  mrb_sym *keys = (mrb_sym*)&t->ptr[t->alloc];
  mrb_value *vals = t->ptr;
  for (i=0; i<t->alloc; i++) {
    if (IV_KEY_P(keys[i])) {
      if ((*func)(mrb, keys[i], vals[i], p) != 0) {
        return;
      }
    }
  }
  return;
}

/* Get the size of the instance variable table. */
/* Size is approximated by the allocated table size. */
static size_t
iv_size(mrb_state *mrb, iv_tbl *t)
{
  if (t == NULL) return 0;
  return (size_t)t->size;
}

/* Copy the instance variable table. */
static iv_tbl*
iv_copy(mrb_state *mrb, iv_tbl *t)
{
  iv_tbl *t2;
  int i;

  if (t == NULL) return NULL;
  if (t->alloc == 0) return NULL;
  if (t->size == 0) return NULL;

  mrb_sym *keys = (mrb_sym*)&t->ptr[t->alloc];
  mrb_value *vals = t->ptr;
  t2 = iv_new(mrb);
  for (i=0; i<t->alloc; i++) {
    if (IV_KEY_P(keys[i])) {
      iv_put(mrb, t2, keys[i], vals[i]);
    }
  }
  return t2;
}

/* Free memory of the instance variable table. */
static void
iv_free(mrb_state *mrb, iv_tbl *t)
{
  mrb_free(mrb, t->ptr);
  mrb_free(mrb, t);
}

static int
iv_mark_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_gc_mark_value(mrb, v);
  return 0;
}

static void
mark_tbl(mrb_state *mrb, iv_tbl *t)
{
  iv_foreach(mrb, t, iv_mark_i, 0);
}

void
mrb_gc_mark_gv(mrb_state *mrb)
{
  mark_tbl(mrb, mrb->globals);
}

void
mrb_gc_free_gv(mrb_state *mrb)
{
  if (mrb->globals)
    iv_free(mrb, mrb->globals);
}

void
mrb_gc_mark_iv(mrb_state *mrb, struct RObject *obj)
{
  mark_tbl(mrb, obj->iv);
}

size_t
mrb_gc_mark_iv_size(mrb_state *mrb, struct RObject *obj)
{
  return iv_size(mrb, obj->iv);
}

void
mrb_gc_free_iv(mrb_state *mrb, struct RObject *obj)
{
  if (obj->iv) {
    iv_free(mrb, obj->iv);
  }
}

mrb_value
mrb_vm_special_get(mrb_state *mrb, mrb_sym i)
{
  return mrb_fixnum_value(0);
}

void
mrb_vm_special_set(mrb_state *mrb, mrb_sym i, mrb_value v)
{
}

static mrb_bool
obj_iv_p(mrb_value obj)
{
  switch (mrb_type(obj)) {
    case MRB_TT_OBJECT:
    case MRB_TT_CLASS:
    case MRB_TT_MODULE:
    case MRB_TT_SCLASS:
    case MRB_TT_HASH:
    case MRB_TT_DATA:
    case MRB_TT_EXCEPTION:
      return TRUE;
    default:
      return FALSE;
  }
}

MRB_API mrb_value
mrb_obj_iv_get(mrb_state *mrb, struct RObject *obj, mrb_sym sym)
{
  mrb_value v;

  if (obj->iv && iv_get(mrb, obj->iv, sym, &v))
    return v;
  return mrb_nil_value();
}

MRB_API mrb_value
mrb_iv_get(mrb_state *mrb, mrb_value obj, mrb_sym sym)
{
  if (obj_iv_p(obj)) {
    return mrb_obj_iv_get(mrb, mrb_obj_ptr(obj), sym);
  }
  return mrb_nil_value();
}

static inline void assign_class_name(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v);

void
mrb_obj_iv_set_force(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v)
{
  assign_class_name(mrb, obj, sym, v);
  if (!obj->iv) {
    obj->iv = iv_new(mrb);
  }
  iv_put(mrb, obj->iv, sym, v);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)obj, v);
}

MRB_API void
mrb_obj_iv_set(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v)
{
  mrb_check_frozen(mrb, obj);
  mrb_obj_iv_set_force(mrb, obj, sym, v);
}

/* Iterates over the instance variable table. */
MRB_API void
mrb_iv_foreach(mrb_state *mrb, mrb_value obj, mrb_iv_foreach_func *func, void *p)
{
  if (!obj_iv_p(obj)) return;
  iv_foreach(mrb, mrb_obj_ptr(obj)->iv, func, p);
}

static inline mrb_bool
namespace_p(enum mrb_vtype tt)
{
  return tt == MRB_TT_CLASS || tt == MRB_TT_MODULE ? TRUE : FALSE;
}

static inline void
assign_class_name(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v)
{
  if (namespace_p(obj->tt) && namespace_p(mrb_type(v))) {
    struct RObject *c = mrb_obj_ptr(v);
    if (obj != c && ISUPPER(mrb_sym_name_len(mrb, sym, NULL)[0])) {
      mrb_sym id_classname = MRB_SYM(__classname__);
      mrb_value o = mrb_obj_iv_get(mrb, c, id_classname);

      if (mrb_nil_p(o)) {
        mrb_sym id_outer = MRB_SYM(__outer__);
        o = mrb_obj_iv_get(mrb, c, id_outer);

        if (mrb_nil_p(o)) {
          if ((struct RClass *)obj == mrb->object_class) {
            mrb_obj_iv_set_force(mrb, c, id_classname, mrb_symbol_value(sym));
          }
          else {
            mrb_obj_iv_set_force(mrb, c, id_outer, mrb_obj_value(obj));
          }
        }
      }
    }
  }
}

MRB_API void
mrb_iv_set(mrb_state *mrb, mrb_value obj, mrb_sym sym, mrb_value v)
{
  if (obj_iv_p(obj)) {
    mrb_obj_iv_set(mrb, mrb_obj_ptr(obj), sym, v);
  }
  else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "cannot set instance variable");
  }
}

MRB_API mrb_bool
mrb_obj_iv_defined(mrb_state *mrb, struct RObject *obj, mrb_sym sym)
{
  iv_tbl *t;

  t = obj->iv;
  if (t && iv_get(mrb, t, sym, NULL)) return TRUE;
  return FALSE;
}

MRB_API mrb_bool
mrb_iv_defined(mrb_state *mrb, mrb_value obj, mrb_sym sym)
{
  if (!obj_iv_p(obj)) return FALSE;
  return mrb_obj_iv_defined(mrb, mrb_obj_ptr(obj), sym);
}

MRB_API mrb_bool
mrb_iv_name_sym_p(mrb_state *mrb, mrb_sym iv_name)
{
  const char *s;
  mrb_int len;

  s = mrb_sym_name_len(mrb, iv_name, &len);
  if (len < 2) return FALSE;
  if (s[0] != '@') return FALSE;
  if (ISDIGIT(s[1])) return FALSE;
  return mrb_ident_p(s+1, len-1);
}

MRB_API void
mrb_iv_name_sym_check(mrb_state *mrb, mrb_sym iv_name)
{
  if (!mrb_iv_name_sym_p(mrb, iv_name)) {
    mrb_name_error(mrb, iv_name, "'%n' is not allowed as an instance variable name", iv_name);
  }
}

MRB_API void
mrb_iv_copy(mrb_state *mrb, mrb_value dest, mrb_value src)
{
  struct RObject *d = mrb_obj_ptr(dest);
  struct RObject *s = mrb_obj_ptr(src);

  if (d->iv) {
    iv_free(mrb, d->iv);
    d->iv = 0;
  }
  if (s->iv) {
    mrb_write_barrier(mrb, (struct RBasic*)d);
    d->iv = iv_copy(mrb, s->iv);
  }
}

static int
inspect_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_value str = *(mrb_value*)p;
  const char *s;
  mrb_int len;
  mrb_value ins;
  char *sp = RSTRING_PTR(str);

  /* need not to show internal data */
  if (sp[0] == '-') { /* first element */
    sp[0] = '#';
    mrb_str_cat_lit(mrb, str, " ");
  }
  else {
    mrb_str_cat_lit(mrb, str, ", ");
  }
  s = mrb_sym_name_len(mrb, sym, &len);
  mrb_str_cat(mrb, str, s, len);
  mrb_str_cat_lit(mrb, str, "=");
  if (mrb_object_p(v)) {
    ins = mrb_any_to_s(mrb, v);
  }
  else {
    ins = mrb_inspect(mrb, v);
  }
  mrb_str_cat_str(mrb, str, ins);
  return 0;
}

mrb_value
mrb_obj_iv_inspect(mrb_state *mrb, struct RObject *obj)
{
  iv_tbl *t = obj->iv;
  int len = iv_size(mrb, t);

  if (len > 0) {
    const char *cn = mrb_obj_classname(mrb, mrb_obj_value(obj));
    mrb_value str = mrb_str_new_capa(mrb, 30);

    mrb_str_cat_lit(mrb, str, "-<");
    mrb_str_cat_cstr(mrb, str, cn);
    mrb_str_cat_lit(mrb, str, ":");
    mrb_str_cat_str(mrb, str, mrb_ptr_to_str(mrb, obj));

    iv_foreach(mrb, t, inspect_i, &str);
    mrb_str_cat_lit(mrb, str, ">");
    return str;
  }
  return mrb_any_to_s(mrb, mrb_obj_value(obj));
}

MRB_API mrb_value
mrb_iv_remove(mrb_state *mrb, mrb_value obj, mrb_sym sym)
{
  if (obj_iv_p(obj)) {
    iv_tbl *t = mrb_obj_ptr(obj)->iv;
    mrb_value val;

    mrb_check_frozen(mrb, mrb_obj_ptr(obj));
    if (iv_del(mrb, t, sym, &val)) {
      return val;
    }
  }
  return mrb_undef_value();
}

static int
iv_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_value ary;
  const char* s;
  mrb_int len;

  ary = *(mrb_value*)p;
  s = mrb_sym_name_len(mrb, sym, &len);
  if (len > 1 && s[0] == '@' && s[1] != '@') {
    mrb_ary_push(mrb, ary, mrb_symbol_value(sym));
  }
  return 0;
}

/* 15.3.1.3.23 */
/*
 *  call-seq:
 *     obj.instance_variables    -> array
 *
 *  Returns an array of instance variable names for the receiver. Note
 *  that simply defining an accessor does not create the corresponding
 *  instance variable.
 *
 *     class Fred
 *       attr_accessor :a1
 *       def initialize
 *         @iv = 3
 *       end
 *     end
 *     Fred.new.instance_variables   #=> [:@iv]
 */
mrb_value
mrb_obj_instance_variables(mrb_state *mrb, mrb_value self)
{
  mrb_value ary;

  ary = mrb_ary_new(mrb);
  if (obj_iv_p(self)) {
    iv_foreach(mrb, mrb_obj_ptr(self)->iv, iv_i, &ary);
  }
  return ary;
}

static int
cv_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_value ary;
  const char* s;
  mrb_int len;

  ary = *(mrb_value*)p;
  s = mrb_sym_name_len(mrb, sym, &len);
  if (len > 2 && s[0] == '@' && s[1] == '@') {
    mrb_ary_push(mrb, ary, mrb_symbol_value(sym));
  }
  return 0;
}

/* 15.2.2.4.19 */
/*
 *  call-seq:
 *     mod.class_variables(inherit=true)   -> array
 *
 *  Returns an array of the names of class variables in <i>mod</i>.
 *
 *     class One
 *       @@var1 = 1
 *     end
 *     class Two < One
 *       @@var2 = 2
 *     end
 *     One.class_variables   #=> [:@@var1]
 *     Two.class_variables   #=> [:@@var2]
 */
mrb_value
mrb_mod_class_variables(mrb_state *mrb, mrb_value mod)
{
  mrb_value ary;
  struct RClass *c;
  mrb_bool inherit = TRUE;

  mrb_get_args(mrb, "|b", &inherit);
  ary = mrb_ary_new(mrb);
  c = mrb_class_ptr(mod);
  while (c) {
    iv_foreach(mrb, c->iv, cv_i, &ary);
    if (!inherit) break;
    c = c->super;
  }
  return ary;
}

mrb_value
mrb_mod_cv_get(mrb_state *mrb, struct RClass *c, mrb_sym sym)
{
  struct RClass * cls = c;
  mrb_value v;
  int given = FALSE;

  while (c) {
    if (c->iv && iv_get(mrb, c->iv, sym, &v)) {
      given = TRUE;
    }
    c = c->super;
  }
  if (given) return v;
  if (cls && cls->tt == MRB_TT_SCLASS) {
    mrb_value klass;

    klass = mrb_obj_iv_get(mrb, (struct RObject *)cls, MRB_SYM(__attached__));
    c = mrb_class_ptr(klass);
    if (c->tt == MRB_TT_CLASS || c->tt == MRB_TT_MODULE) {
      given = FALSE;
      while (c) {
        if (c->iv && iv_get(mrb, c->iv, sym, &v)) {
          given = TRUE;
        }
        c = c->super;
      }
      if (given) return v;
    }
  }
  mrb_name_error(mrb, sym, "uninitialized class variable %n in %C", sym, cls);
  /* not reached */
  return mrb_nil_value();
}

MRB_API mrb_value
mrb_cv_get(mrb_state *mrb, mrb_value mod, mrb_sym sym)
{
  return mrb_mod_cv_get(mrb, mrb_class_ptr(mod), sym);
}

MRB_API void
mrb_mod_cv_set(mrb_state *mrb, struct RClass *c, mrb_sym sym, mrb_value v)
{
  struct RClass * cls = c;

  while (c) {
    iv_tbl *t = c->iv;
    int pos = iv_get(mrb, t, sym, NULL);

    if (pos) {
      mrb_check_frozen(mrb, c);
      t->ptr[pos-1] = v;        /* iv_get returns pos+1 to put */
      mrb_field_write_barrier_value(mrb, (struct RBasic*)c, v);
      return;
    }
    c = c->super;
  }

  if (cls && cls->tt == MRB_TT_SCLASS) {
    mrb_value klass;

    klass = mrb_obj_iv_get(mrb, (struct RObject*)cls, MRB_SYM(__attached__));
    switch (mrb_type(klass)) {
    case MRB_TT_CLASS:
    case MRB_TT_MODULE:
    case MRB_TT_SCLASS:
      c = mrb_class_ptr(klass);
      break;
    default:
      c = cls;
      break;
    }
  }
  else{
    c = cls;
  }

  mrb_check_frozen(mrb, c);
  if (!c->iv) {
    c->iv = iv_new(mrb);
  }

  iv_put(mrb, c->iv, sym, v);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)c, v);
}

MRB_API void
mrb_cv_set(mrb_state *mrb, mrb_value mod, mrb_sym sym, mrb_value v)
{
  mrb_mod_cv_set(mrb, mrb_class_ptr(mod), sym, v);
}

mrb_bool
mrb_mod_cv_defined(mrb_state *mrb, struct RClass * c, mrb_sym sym)
{
  while (c) {
    iv_tbl *t = c->iv;
    if (iv_get(mrb, t, sym, NULL)) return TRUE;
    c = c->super;
  }

  return FALSE;
}

MRB_API mrb_bool
mrb_cv_defined(mrb_state *mrb, mrb_value mod, mrb_sym sym)
{
  return mrb_mod_cv_defined(mrb, mrb_class_ptr(mod), sym);
}

mrb_value
mrb_vm_cv_get(mrb_state *mrb, mrb_sym sym)
{
  struct RClass *c;

  const struct RProc *p = mrb->c->ci->proc;

  for (;;) {
    c = MRB_PROC_TARGET_CLASS(p);
    if (c && c->tt != MRB_TT_SCLASS) break;
    p = p->upper;
  }
  return mrb_mod_cv_get(mrb, c, sym);
}

void
mrb_vm_cv_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  struct RClass *c;
  const struct RProc *p = mrb->c->ci->proc;

  for (;;) {
    c = MRB_PROC_TARGET_CLASS(p);
    if (c && c->tt != MRB_TT_SCLASS) break;
    p = p->upper;
  }
  mrb_mod_cv_set(mrb, c, sym, v);
}

static void
mod_const_check(mrb_state *mrb, mrb_value mod)
{
  switch (mrb_type(mod)) {
  case MRB_TT_CLASS:
  case MRB_TT_MODULE:
  case MRB_TT_SCLASS:
    break;
  default:
    mrb_raise(mrb, E_TYPE_ERROR, "constant look-up for non class/module");
    break;
  }
}

static mrb_value
const_get(mrb_state *mrb, struct RClass *base, mrb_sym sym, mrb_bool skip)
{
  struct RClass *c = base;
  mrb_value v;
  mrb_bool retry = FALSE;
  mrb_value name;

  if (skip) c = c->super;
L_RETRY:
  while (c) {
    if (!MRB_FLAG_TEST(c, MRB_FL_CLASS_IS_PREPENDED) && c->iv) {
      if (iv_get(mrb, c->iv, sym, &v))
        return v;
    }
    c = c->super;
  }
  if (!retry && base->tt == MRB_TT_MODULE) {
    c = mrb->object_class;
    retry = TRUE;
    goto L_RETRY;
  }
  name = mrb_symbol_value(sym);
  return mrb_funcall_argv(mrb, mrb_obj_value(base), MRB_SYM(const_missing), 1, &name);
}

MRB_API mrb_value
mrb_const_get(mrb_state *mrb, mrb_value mod, mrb_sym sym)
{
  mod_const_check(mrb, mod);
  return const_get(mrb, mrb_class_ptr(mod), sym, FALSE);
}

mrb_value
mrb_vm_const_get(mrb_state *mrb, mrb_sym sym)
{
  struct RClass *c;
  struct RClass *c2;
  mrb_value v;
  const struct RProc *proc = mrb->c->ci->proc;

  c = MRB_PROC_TARGET_CLASS(proc);
  if (!c) c = mrb->object_class;
  if (iv_get(mrb, c->iv, sym, &v)) {
    return v;
  }
  c2 = c;
  while (c2 && c2->tt == MRB_TT_SCLASS) {
    mrb_value klass;

    if (!iv_get(mrb, c2->iv, MRB_SYM(__attached__), &klass)) {
      c2 = NULL;
      break;
    }
    c2 = mrb_class_ptr(klass);
  }
  if (c2 && (c2->tt == MRB_TT_CLASS || c2->tt == MRB_TT_MODULE)) c = c2;
  proc = proc->upper;
  while (proc) {
    c2 = MRB_PROC_TARGET_CLASS(proc);
    if (c2 && iv_get(mrb, c2->iv, sym, &v)) {
      return v;
    }
    proc = proc->upper;
  }
  return const_get(mrb, c, sym, TRUE);
}

MRB_API void
mrb_const_set(mrb_state *mrb, mrb_value mod, mrb_sym sym, mrb_value v)
{
  mod_const_check(mrb, mod);
  if (mrb_type(v) == MRB_TT_CLASS || mrb_type(v) == MRB_TT_MODULE) {
    mrb_class_name_class(mrb, mrb_class_ptr(mod), mrb_class_ptr(v), sym);
  }
  mrb_iv_set(mrb, mod, sym, v);
}

void
mrb_vm_const_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  struct RClass *c;

  c = MRB_PROC_TARGET_CLASS(mrb->c->ci->proc);
  if (!c) c = mrb->object_class;
  mrb_obj_iv_set(mrb, (struct RObject*)c, sym, v);
}

MRB_API void
mrb_const_remove(mrb_state *mrb, mrb_value mod, mrb_sym sym)
{
  mod_const_check(mrb, mod);
  mrb_iv_remove(mrb, mod, sym);
}

MRB_API void
mrb_define_const_id(mrb_state *mrb, struct RClass *mod, mrb_sym name, mrb_value v)
{
  mrb_obj_iv_set(mrb, (struct RObject*)mod, name, v);
}

MRB_API void
mrb_define_const(mrb_state *mrb, struct RClass *mod, const char *name, mrb_value v)
{
  mrb_obj_iv_set(mrb, (struct RObject*)mod, mrb_intern_cstr(mrb, name), v);
}

MRB_API void
mrb_define_global_const(mrb_state *mrb, const char *name, mrb_value val)
{
  mrb_define_const(mrb, mrb->object_class, name, val);
}

static int
const_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_value ary;
  const char* s;
  mrb_int len;

  ary = *(mrb_value*)p;
  s = mrb_sym_name_len(mrb, sym, &len);
  if (len >= 1 && ISUPPER(s[0])) {
    mrb_int i, alen = RARRAY_LEN(ary);

    for (i=0; i<alen; i++) {
      if (mrb_symbol(RARRAY_PTR(ary)[i]) == sym)
        break;
    }
    if (i==alen) {
      mrb_ary_push(mrb, ary, mrb_symbol_value(sym));
    }
  }
  return 0;
}

/* 15.2.2.4.24 */
/*
 *  call-seq:
 *     mod.constants    -> array
 *
 *  Returns an array of all names of constants defined in the receiver.
 */
mrb_value
mrb_mod_constants(mrb_state *mrb, mrb_value mod)
{
  mrb_value ary;
  mrb_bool inherit = TRUE;
  struct RClass *c = mrb_class_ptr(mod);

  mrb_get_args(mrb, "|b", &inherit);
  ary = mrb_ary_new(mrb);
  while (c) {
    iv_foreach(mrb, c->iv, const_i, &ary);
    if (!inherit) break;
    c = c->super;
    if (c == mrb->object_class) break;
  }
  return ary;
}

MRB_API mrb_value
mrb_gv_get(mrb_state *mrb, mrb_sym sym)
{
  mrb_value v;

  if (iv_get(mrb, mrb->globals, sym, &v))
    return v;
  return mrb_nil_value();
}

MRB_API void
mrb_gv_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  iv_tbl *t;

  if (!mrb->globals) {
    mrb->globals = iv_new(mrb);
  }
  t = mrb->globals;
  iv_put(mrb, t, sym, v);
}

MRB_API void
mrb_gv_remove(mrb_state *mrb, mrb_sym sym)
{
  iv_del(mrb, mrb->globals, sym, NULL);
}

static int
gv_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_value ary;

  ary = *(mrb_value*)p;
  mrb_ary_push(mrb, ary, mrb_symbol_value(sym));
  return 0;
}

/* 15.3.1.2.4  */
/* 15.3.1.3.14 */
/*
 *  call-seq:
 *     global_variables    -> array
 *
 *  Returns an array of the names of global variables.
 *
 *     global_variables.grep /std/   #=> [:$stdin, :$stdout, :$stderr]
 */
mrb_value
mrb_f_global_variables(mrb_state *mrb, mrb_value self)
{
  iv_tbl *t = mrb->globals;
  mrb_value ary = mrb_ary_new(mrb);

  iv_foreach(mrb, t, gv_i, &ary);
  return ary;
}

static mrb_bool
mrb_const_defined_0(mrb_state *mrb, mrb_value mod, mrb_sym id, mrb_bool exclude, mrb_bool recurse)
{
  struct RClass *klass = mrb_class_ptr(mod);
  struct RClass *tmp;
  mrb_bool mod_retry = FALSE;

  tmp = klass;
retry:
  while (tmp) {
    if (iv_get(mrb, tmp->iv, id, NULL)) {
      return TRUE;
    }
    if (!recurse && (klass != mrb->object_class)) break;
    tmp = tmp->super;
  }
  if (!exclude && !mod_retry && (klass->tt == MRB_TT_MODULE)) {
    mod_retry = TRUE;
    tmp = mrb->object_class;
    goto retry;
  }
  return FALSE;
}

MRB_API mrb_bool
mrb_const_defined(mrb_state *mrb, mrb_value mod, mrb_sym id)
{
  return mrb_const_defined_0(mrb, mod, id, TRUE, TRUE);
}

MRB_API mrb_bool
mrb_const_defined_at(mrb_state *mrb, mrb_value mod, mrb_sym id)
{
  return mrb_const_defined_0(mrb, mod, id, TRUE, FALSE);
}

MRB_API mrb_value
mrb_attr_get(mrb_state *mrb, mrb_value obj, mrb_sym id)
{
  return mrb_iv_get(mrb, obj, id);
}

struct csym_arg {
  struct RClass *c;
  mrb_sym sym;
};

static int
csym_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  struct csym_arg *a = (struct csym_arg*)p;
  struct RClass *c = a->c;

  if (mrb_type(v) == c->tt && mrb_class_ptr(v) == c) {
    a->sym = sym;
    return 1;     /* stop iteration */
  }
  return 0;
}

static mrb_sym
find_class_sym(mrb_state *mrb, struct RClass *outer, struct RClass *c)
{
  struct csym_arg arg;

  if (!outer) return 0;
  if (outer == c) return 0;
  arg.c = c;
  arg.sym = 0;
  iv_foreach(mrb, outer->iv, csym_i, &arg);
  return arg.sym;
}

static struct RClass*
outer_class(mrb_state *mrb, struct RClass *c)
{
  mrb_value ov;

  ov = mrb_obj_iv_get(mrb, (struct RObject*)c, MRB_SYM(__outer__));
  if (mrb_nil_p(ov)) return NULL;
  switch (mrb_type(ov)) {
  case MRB_TT_CLASS:
  case MRB_TT_MODULE:
    return mrb_class_ptr(ov);
  default:
    break;
  }
  return NULL;
}

static mrb_bool
detect_outer_loop(mrb_state *mrb, struct RClass *c)
{
  struct RClass *t = c;         /* tortoise */
  struct RClass *h = c;         /* hare */

  for (;;) {
    if (h == NULL) return FALSE;
    h = outer_class(mrb, h);
    if (h == NULL) return FALSE;
    h = outer_class(mrb, h);
    t = outer_class(mrb, t);
    if (t == h) return TRUE;
  }
}

mrb_value
mrb_class_find_path(mrb_state *mrb, struct RClass *c)
{
  struct RClass *outer;
  mrb_value path;
  mrb_sym name;
  const char *str;
  mrb_int len;

  if (detect_outer_loop(mrb, c)) return mrb_nil_value();
  outer = outer_class(mrb, c);
  if (outer == NULL) return mrb_nil_value();
  name = find_class_sym(mrb, outer, c);
  if (name == 0) return mrb_nil_value();
  str = mrb_class_name(mrb, outer);
  path = mrb_str_new_capa(mrb, 40);
  mrb_str_cat_cstr(mrb, path, str);
  mrb_str_cat_cstr(mrb, path, "::");

  str = mrb_sym_name_len(mrb, name, &len);
  mrb_str_cat(mrb, path, str, len);
  if (RSTRING_PTR(path)[0] != '#') {
    iv_del(mrb, c->iv, MRB_SYM(__outer__), NULL);
    iv_put(mrb, c->iv, MRB_SYM(__classname__), path);
    mrb_field_write_barrier_value(mrb, (struct RBasic*)c, path);
    path = mrb_str_dup(mrb, path);
  }
  return path;
}

size_t
mrb_obj_iv_tbl_memsize(mrb_value obj)
{
  iv_tbl *t = mrb_obj_ptr(obj)->iv;
  if (t == NULL) return 0;
  return sizeof(iv_tbl) + t->alloc*(sizeof(mrb_value)+sizeof(mrb_sym));
}

#define identchar(c) (ISALNUM(c) || (c) == '_' || !ISASCII(c))

mrb_bool
mrb_ident_p(const char *s, mrb_int len)
{
  mrb_int i;

  for (i = 0; i < len; i++) {
    if (!identchar(s[i])) return FALSE;
  }
  return TRUE;
}
