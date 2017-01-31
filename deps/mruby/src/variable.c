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

typedef int (iv_foreach_func)(mrb_state*,mrb_sym,mrb_value,void*);

#ifdef MRB_USE_IV_SEGLIST

#ifndef MRB_SEGMENT_SIZE
#define MRB_SEGMENT_SIZE 4
#endif

typedef struct segment {
  mrb_sym key[MRB_SEGMENT_SIZE];
  mrb_value val[MRB_SEGMENT_SIZE];
  struct segment *next;
} segment;

/* Instance variable table structure */
typedef struct iv_tbl {
  segment *rootseg;
  size_t size;
  size_t last_len;
} iv_tbl;

/*
 * Creates the instance variable table.
 *
 * Parameters
 *   mrb
 * Returns
 *   the instance variable table.
 */
static iv_tbl*
iv_new(mrb_state *mrb)
{
  iv_tbl *t;

  t = (iv_tbl*)mrb_malloc(mrb, sizeof(iv_tbl));
  t->size = 0;
  t->rootseg =  NULL;
  t->last_len = 0;

  return t;
}

/*
 * Set the value for the symbol in the instance variable table.
 *
 * Parameters
 *   mrb
 *   t     the instance variable table to be set in.
 *   sym   the symbol to be used as the key.
 *   val   the value to be set.
 */
static void
iv_put(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value val)
{
  segment *seg = t->rootseg;
  segment *prev = NULL;
  segment *matched_seg = NULL;
  size_t matched_idx = 0;
  size_t i;

  while (seg) {
    for (i=0; i<MRB_SEGMENT_SIZE; i++) {
      mrb_sym key = seg->key[i];
      /* Found room in last segment after last_len */
      if (!seg->next && i >= t->last_len) {
        seg->key[i] = sym;
        seg->val[i] = val;
        t->last_len = i+1;
        t->size++;
        return;
      }
      if (!matched_seg && key == 0) {
        matched_seg = seg;
        matched_idx = i;
      }
      else if (key == sym) {
        seg->val[i] = val;
        return;
      }
    }
    prev = seg;
    seg = seg->next;
  }

  /* Not found */
  t->size++;
  if (matched_seg) {
    matched_seg->key[matched_idx] = sym;
    matched_seg->val[matched_idx] = val;
    return;
  }

  seg = (segment*)mrb_malloc(mrb, sizeof(segment));
  if (!seg) return;
  seg->next = NULL;
  seg->key[0] = sym;
  seg->val[0] = val;
  t->last_len = 1;
  if (prev) {
    prev->next = seg;
  }
  else {
    t->rootseg = seg;
  }
}

/*
 * Get a value for a symbol from the instance variable table.
 *
 * Parameters
 *   mrb
 *   t     the variable table to be searched.
 *   sym   the symbol to be used as the key.
 *   vp    the value pointer. Receives the value if the specified symbol is
 *         contained in the instance variable table.
 * Returns
 *   true if the specified symbol is contained in the instance variable table.
 */
static mrb_bool
iv_get(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value *vp)
{
  segment *seg;
  size_t i;

  seg = t->rootseg;
  while (seg) {
    for (i=0; i<MRB_SEGMENT_SIZE; i++) {
      mrb_sym key = seg->key[i];

      if (!seg->next && i >= t->last_len) {
        return FALSE;
      }
      if (key == sym) {
        if (vp) *vp = seg->val[i];
        return TRUE;
      }
    }
    seg = seg->next;
  }
  return FALSE;
}

/*
 * Deletes the value for the symbol from the instance variable table.
 *
 * Parameters
 *   t    the variable table to be searched.
 *   sym  the symbol to be used as the key.
 *   vp   the value pointer. Receive the deleted value if the symbol is
 *        contained in the instance variable table.
 * Returns
 *   true if the specified symbol is contained in the instance variable table.
 */
static mrb_bool
iv_del(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value *vp)
{
  segment *seg;
  size_t i;

  seg = t->rootseg;
  while (seg) {
    for (i=0; i<MRB_SEGMENT_SIZE; i++) {
      mrb_sym key = seg->key[i];

      if (!seg->next && i >= t->last_len) {
        return FALSE;
      }
      if (key == sym) {
        t->size--;
        seg->key[i] = 0;
        if (vp) *vp = seg->val[i];
        return TRUE;
      }
    }
    seg = seg->next;
  }
  return FALSE;
}

static mrb_bool
iv_foreach(mrb_state *mrb, iv_tbl *t, iv_foreach_func *func, void *p)
{
  segment *seg;
  size_t i;
  int n;

  seg = t->rootseg;
  while (seg) {
    for (i=0; i<MRB_SEGMENT_SIZE; i++) {
      mrb_sym key = seg->key[i];

      /* no value in last segment after last_len */
      if (!seg->next && i >= t->last_len) {
        return FALSE;
      }
      if (key != 0) {
        n =(*func)(mrb, key, seg->val[i], p);
        if (n > 0) return FALSE;
        if (n < 0) {
          t->size--;
          seg->key[i] = 0;
        }
      }
    }
    seg = seg->next;
  }
  return TRUE;
}

static size_t
iv_size(mrb_state *mrb, iv_tbl *t)
{
  segment *seg;
  size_t size = 0;

  if (!t) return 0;
  if (t->size > 0) return t->size;
  seg = t->rootseg;
  while (seg) {
    if (seg->next == NULL) {
      size += t->last_len;
      return size;
    }
    seg = seg->next;
    size += MRB_SEGMENT_SIZE;
  }
  /* empty iv_tbl */
  return 0;
}

static iv_tbl*
iv_copy(mrb_state *mrb, iv_tbl *t)
{
  segment *seg;
  iv_tbl *t2;

  size_t i;

  seg = t->rootseg;
  t2 = iv_new(mrb);

  while (seg != NULL) {
    for (i=0; i<MRB_SEGMENT_SIZE; i++) {
      mrb_sym key = seg->key[i];
      mrb_value val = seg->val[i];

      if ((seg->next == NULL) && (i >= t->last_len)) {
        return t2;
      }
      iv_put(mrb, t2, key, val);
    }
    seg = seg->next;
  }
  return t2;
}

static void
iv_free(mrb_state *mrb, iv_tbl *t)
{
  segment *seg;

  seg = t->rootseg;
  while (seg) {
    segment *p = seg;
    seg = seg->next;
    mrb_free(mrb, p);
  }
  mrb_free(mrb, t);
}

#else

#include <mruby/khash.h>

#ifndef MRB_IVHASH_INIT_SIZE
#define MRB_IVHASH_INIT_SIZE 8
#endif

KHASH_DECLARE(iv, mrb_sym, mrb_value, TRUE)
KHASH_DEFINE(iv, mrb_sym, mrb_value, TRUE, kh_int_hash_func, kh_int_hash_equal)

typedef struct iv_tbl {
  khash_t(iv) h;
} iv_tbl;

static iv_tbl*
iv_new(mrb_state *mrb)
{
  return (iv_tbl*)kh_init_size(iv, mrb, MRB_IVHASH_INIT_SIZE);
}

static void
iv_put(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value val)
{
  khash_t(iv) *h = &t->h;
  khiter_t k;

  k = kh_put(iv, mrb, h, sym);
  kh_value(h, k) = val;
}

static mrb_bool
iv_get(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value *vp)
{
  khash_t(iv) *h = &t->h;
  khiter_t k;

  k = kh_get(iv, mrb, h, sym);
  if (k != kh_end(h)) {
    if (vp) *vp = kh_value(h, k);
    return TRUE;
  }
  return FALSE;
}

static mrb_bool
iv_del(mrb_state *mrb, iv_tbl *t, mrb_sym sym, mrb_value *vp)
{
  khash_t(iv) *h = &t->h;
  khiter_t k;

  if (h) {
    k = kh_get(iv, mrb, h, sym);
    if (k != kh_end(h)) {
      mrb_value val = kh_value(h, k);
      kh_del(iv, mrb, h, k);
      if (vp) *vp = val;
      return TRUE;
    }
  }
  return FALSE;
}

static mrb_bool
iv_foreach(mrb_state *mrb, iv_tbl *t, iv_foreach_func *func, void *p)
{
  khash_t(iv) *h = &t->h;
  khiter_t k;
  int n;

  if (h) {
    for (k = kh_begin(h); k != kh_end(h); k++) {
      if (kh_exist(h, k)) {
        n = (*func)(mrb, kh_key(h, k), kh_value(h, k), p);
        if (n > 0) return FALSE;
        if (n < 0) {
          kh_del(iv, mrb, h, k);
        }
      }
    }
  }
  return TRUE;
}

static size_t
iv_size(mrb_state *mrb, iv_tbl *t)
{
  khash_t(iv) *h;

  if (t && (h = &t->h)) {
    return kh_size(h);
  }
  return 0;
}

static iv_tbl*
iv_copy(mrb_state *mrb, iv_tbl *t)
{
  return (iv_tbl*)kh_copy(iv, mrb, &t->h);
}

static void
iv_free(mrb_state *mrb, iv_tbl *t)
{
  kh_destroy(iv, mrb, &t->h);
}

#endif

static int
iv_mark_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_gc_mark_value(mrb, v);
  return 0;
}

static void
mark_tbl(mrb_state *mrb, iv_tbl *t)
{
  if (t) {
    iv_foreach(mrb, t, iv_mark_i, 0);
  }
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

MRB_API void
mrb_obj_iv_set(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v)
{
  iv_tbl *t = obj->iv;

  if (MRB_FROZEN_P(obj)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "can't modify frozen %S", mrb_obj_value(obj));
  }
  if (!t) {
    t = obj->iv = iv_new(mrb);
  }
  mrb_write_barrier(mrb, (struct RBasic*)obj);
  iv_put(mrb, t, sym, v);
}

MRB_API void
mrb_obj_iv_ifnone(mrb_state *mrb, struct RObject *obj, mrb_sym sym, mrb_value v)
{
  iv_tbl *t = obj->iv;

  if (!t) {
    t = obj->iv = iv_new(mrb);
  }
  else if (iv_get(mrb, t, sym, &v)) {
    return;
  }
  mrb_write_barrier(mrb, (struct RBasic*)obj);
  iv_put(mrb, t, sym, v);
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
  if (t) {
    return iv_get(mrb, t, sym, NULL);
  }
  return FALSE;
}

MRB_API mrb_bool
mrb_iv_defined(mrb_state *mrb, mrb_value obj, mrb_sym sym)
{
  if (!obj_iv_p(obj)) return FALSE;
  return mrb_obj_iv_defined(mrb, mrb_obj_ptr(obj), sym);
}

#define identchar(c) (ISALNUM(c) || (c) == '_' || !ISASCII(c))

MRB_API mrb_bool
mrb_iv_p(mrb_state *mrb, mrb_sym iv_name)
{
  const char *s;
  mrb_int i, len;

  s = mrb_sym2name_len(mrb, iv_name, &len);
  if (len < 2) return FALSE;
  if (s[0] != '@') return FALSE;
  if (s[1] == '@') return FALSE;
  for (i=1; i<len; i++) {
    if (!identchar(s[i])) return FALSE;
  }
  return TRUE;
}

MRB_API void
mrb_iv_check(mrb_state *mrb, mrb_sym iv_name)
{
  if (!mrb_iv_p(mrb, iv_name)) {
    mrb_name_error(mrb, iv_name, "'%S' is not allowed as an instance variable name", mrb_sym2str(mrb, iv_name));
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
  s = mrb_sym2name_len(mrb, sym, &len);
  mrb_str_cat(mrb, str, s, len);
  mrb_str_cat_lit(mrb, str, "=");
  if (mrb_type(v) == MRB_TT_OBJECT) {
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
  size_t len = iv_size(mrb, t);

  if (len > 0) {
    const char *cn = mrb_obj_classname(mrb, mrb_obj_value(obj));
    mrb_value str = mrb_str_buf_new(mrb, 30);

    mrb_str_cat_lit(mrb, str, "-<");
    mrb_str_cat_cstr(mrb, str, cn);
    mrb_str_cat_lit(mrb, str, ":");
    mrb_str_concat(mrb, str, mrb_ptr_to_str(mrb, obj));

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

    if (t && iv_del(mrb, t, sym, &val)) {
      return val;
    }
  }
  return mrb_undef_value();
}

mrb_value
mrb_vm_iv_get(mrb_state *mrb, mrb_sym sym)
{
  /* get self */
  return mrb_iv_get(mrb, mrb->c->stack[0], sym);
}

void
mrb_vm_iv_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  /* get self */
  mrb_iv_set(mrb, mrb->c->stack[0], sym, v);
}

static int
iv_i(mrb_state *mrb, mrb_sym sym, mrb_value v, void *p)
{
  mrb_value ary;
  const char* s;
  mrb_int len;

  ary = *(mrb_value*)p;
  s = mrb_sym2name_len(mrb, sym, &len);
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
  if (obj_iv_p(self) && mrb_obj_ptr(self)->iv) {
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
  s = mrb_sym2name_len(mrb, sym, &len);
  if (len > 2 && s[0] == '@' && s[1] == '@') {
    mrb_ary_push(mrb, ary, mrb_symbol_value(sym));
  }
  return 0;
}

/* 15.2.2.4.19 */
/*
 *  call-seq:
 *     mod.class_variables   -> array
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

  ary = mrb_ary_new(mrb);
  c = mrb_class_ptr(mod);
  while (c) {
    if (c->iv) {
      iv_foreach(mrb, c->iv, cv_i, &ary);
    }
    c = c->super;
  }
  return ary;
}

MRB_API mrb_value
mrb_mod_cv_get(mrb_state *mrb, struct RClass * c, mrb_sym sym)
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

    klass = mrb_obj_iv_get(mrb, (struct RObject *)cls,
                           mrb_intern_lit(mrb, "__attached__"));
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
  mrb_name_error(mrb, sym, "uninitialized class variable %S in %S",
                 mrb_sym2str(mrb, sym), mrb_obj_value(cls));
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
    if (c->iv) {
      iv_tbl *t = c->iv;

      if (iv_get(mrb, t, sym, NULL)) {
        mrb_write_barrier(mrb, (struct RBasic*)c);
        iv_put(mrb, t, sym, v);
        return;
      }
    }
    c = c->super;
  }

  if (!cls->iv) {
    cls->iv = iv_new(mrb);
  }

  mrb_write_barrier(mrb, (struct RBasic*)cls);
  iv_put(mrb, cls->iv, sym, v);
}

MRB_API void
mrb_cv_set(mrb_state *mrb, mrb_value mod, mrb_sym sym, mrb_value v)
{
  mrb_mod_cv_set(mrb, mrb_class_ptr(mod), sym, v);
}

MRB_API mrb_bool
mrb_mod_cv_defined(mrb_state *mrb, struct RClass * c, mrb_sym sym)
{
  while (c) {
    if (c->iv) {
      iv_tbl *t = c->iv;
      if (iv_get(mrb, t, sym, NULL)) return TRUE;
    }
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
  struct RClass *c = mrb->c->ci->proc->target_class;

  if (!c) c = mrb->c->ci->target_class;

  return mrb_mod_cv_get(mrb, c, sym);
}

void
mrb_vm_cv_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  struct RClass *c = mrb->c->ci->proc->target_class;

  if (!c) c = mrb->c->ci->target_class;
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
const_get(mrb_state *mrb, struct RClass *base, mrb_sym sym)
{
  struct RClass *c = base;
  mrb_value v;
  iv_tbl *t;
  mrb_bool retry = FALSE;
  mrb_value name;

L_RETRY:
  while (c) {
    if (c->iv) {
      t = c->iv;
      if (iv_get(mrb, t, sym, &v))
        return v;
    }
    c = c->super;
  }
  if (!retry && base && base->tt == MRB_TT_MODULE) {
    c = mrb->object_class;
    retry = TRUE;
    goto L_RETRY;
  }
  name = mrb_symbol_value(sym);
  return mrb_funcall_argv(mrb, mrb_obj_value(base), mrb_intern_lit(mrb, "const_missing"), 1, &name);
}

MRB_API mrb_value
mrb_const_get(mrb_state *mrb, mrb_value mod, mrb_sym sym)
{
  mod_const_check(mrb, mod);
  return const_get(mrb, mrb_class_ptr(mod), sym);
}

mrb_value
mrb_vm_const_get(mrb_state *mrb, mrb_sym sym)
{
  struct RClass *c = mrb->c->ci->proc->target_class;

  if (!c) c = mrb->c->ci->target_class;
  if (c) {
    struct RClass *c2;
    mrb_value v;

    if (c->iv && iv_get(mrb, c->iv, sym, &v)) {
      return v;
    }
    if (c->tt == MRB_TT_SCLASS) {
      mrb_value klass;
      klass = mrb_obj_iv_get(mrb, (struct RObject *)c,
                             mrb_intern_lit(mrb, "__attached__"));
      c2 = mrb_class_ptr(klass);
      if (c2->tt == MRB_TT_CLASS)
        c = c2;
    }
    c2 = c;
    for (;;) {
      c2 = mrb_class_outer_module(mrb, c2);
      if (!c2) break;
      if (c2->iv && iv_get(mrb, c2->iv, sym, &v)) {
        return v;
      }
    }
  }
  return const_get(mrb, c, sym);
}

MRB_API void
mrb_const_set(mrb_state *mrb, mrb_value mod, mrb_sym sym, mrb_value v)
{
  mod_const_check(mrb, mod);
  mrb_iv_set(mrb, mod, sym, v);
}

void
mrb_vm_const_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  struct RClass *c = mrb->c->ci->proc->target_class;

  if (!c) c = mrb->c->ci->target_class;
  mrb_obj_iv_set(mrb, (struct RObject*)c, sym, v);
}

MRB_API void
mrb_const_remove(mrb_state *mrb, mrb_value mod, mrb_sym sym)
{
  mod_const_check(mrb, mod);
  mrb_iv_remove(mrb, mod, sym);
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
  s = mrb_sym2name_len(mrb, sym, &len);
  if (len >= 1 && ISUPPER(s[0])) {
    mrb_ary_push(mrb, ary, mrb_symbol_value(sym));
  }
  return 0;
}

/* 15.2.2.4.24 */
/*
 *  call-seq:
 *     mod.constants    -> array
 *
 *  Returns an array of all names of contants defined in the receiver.
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
    if (c->iv) {
      iv_foreach(mrb, c->iv, const_i, &ary);
    }
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

  if (!mrb->globals) {
    return mrb_nil_value();
  }
  if (iv_get(mrb, mrb->globals, sym, &v))
    return v;
  return mrb_nil_value();
}

MRB_API void
mrb_gv_set(mrb_state *mrb, mrb_sym sym, mrb_value v)
{
  iv_tbl *t;

  if (!mrb->globals) {
    t = mrb->globals = iv_new(mrb);
  }
  else {
    t = mrb->globals;
  }
  iv_put(mrb, t, sym, v);
}

MRB_API void
mrb_gv_remove(mrb_state *mrb, mrb_sym sym)
{
  if (!mrb->globals) {
    return;
  }
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
  size_t i;
  char buf[3];

  if (t) {
    iv_foreach(mrb, t, gv_i, &ary);
  }
  buf[0] = '$';
  buf[2] = 0;
  for (i = 1; i <= 9; ++i) {
    buf[1] = (char)(i + '0');
    mrb_ary_push(mrb, ary, mrb_symbol_value(mrb_intern(mrb, buf, 2)));
  }
  return ary;
}

static mrb_bool
mrb_const_defined_0(mrb_state *mrb, mrb_value mod, mrb_sym id, mrb_bool exclude, mrb_bool recurse)
{
  struct RClass *klass = mrb_class_ptr(mod);
  struct RClass *tmp;
  mrb_bool mod_retry = 0;

  tmp = klass;
retry:
  while (tmp) {
    if (tmp->iv && iv_get(mrb, tmp->iv, id, NULL)) {
      return TRUE;
    }
    if (!recurse && (klass != mrb->object_class)) break;
    tmp = tmp->super;
  }
  if (!exclude && !mod_retry && (klass->tt == MRB_TT_MODULE)) {
    mod_retry = 1;
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

mrb_sym
mrb_class_sym(mrb_state *mrb, struct RClass *c, struct RClass *outer)
{
  mrb_value name;

  name = mrb_obj_iv_get(mrb, (struct RObject*)c, mrb_intern_lit(mrb, "__classid__"));
  if (mrb_nil_p(name)) {

    if (!outer) return 0;
    else {
      struct csym_arg arg;

      arg.c = c;
      arg.sym = 0;
      iv_foreach(mrb, outer->iv, csym_i, &arg);
      return arg.sym;
    }
  }
  return mrb_symbol(name);
}
