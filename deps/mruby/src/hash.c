/*
** hash.c - Hash class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#ifndef MRB_WITHOUT_FLOAT
/* a function to get hash value of a float number */
mrb_int mrb_float_id(mrb_float f);
#endif

#ifndef MRB_HT_INIT_SIZE
#define MRB_HT_INIT_SIZE 4
#endif
#define HT_SEG_INCREASE_RATIO 6 / 5

struct segkv {
  mrb_value key;
  mrb_value val;
};

typedef struct segment {
  uint16_t size;
  struct segment *next;
  struct segkv e[];
} segment;

typedef struct segindex {
  size_t size;
  size_t capa;
  struct segkv *table[];
} segindex;

/* hash table structure */
typedef struct htable {
  segment *rootseg;
  segment *lastseg;
  mrb_int size;
  uint16_t last_len;
  segindex *index;
} htable;

static /* inline */ size_t
ht_hash_func(mrb_state *mrb, htable *t, mrb_value key)
{
  enum mrb_vtype tt = mrb_type(key);
  mrb_value hv;
  size_t h;
  segindex *index = t->index;
  size_t capa = index ? index->capa : 0;

  switch (tt) {
  case MRB_TT_STRING:
    h = mrb_str_hash(mrb, key);
    break;

  case MRB_TT_TRUE:
  case MRB_TT_FALSE:
  case MRB_TT_SYMBOL:
  case MRB_TT_FIXNUM:
#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
#endif
    h = (size_t)mrb_obj_id(key);
    break;

  default:
    hv = mrb_funcall(mrb, key, "hash", 0);
    h = (size_t)t ^ (size_t)mrb_fixnum(hv);
    break;
  }
  if (index && (index != t->index || capa != index->capa)) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "hash modified");
  }
  return ((h)^((h)<<2)^((h)>>2));
}

static inline mrb_bool
ht_hash_equal(mrb_state *mrb, htable *t, mrb_value a, mrb_value b)
{
  enum mrb_vtype tt = mrb_type(a);

  switch (tt) {
  case MRB_TT_STRING:
    return mrb_str_equal(mrb, a, b);

  case MRB_TT_SYMBOL:
    if (!mrb_symbol_p(b)) return FALSE;
    return mrb_symbol(a) == mrb_symbol(b);

  case MRB_TT_FIXNUM:
    switch (mrb_type(b)) {
    case MRB_TT_FIXNUM:
      return mrb_fixnum(a) == mrb_fixnum(b);
#ifndef MRB_WITHOUT_FLOAT
    case MRB_TT_FLOAT:
      return (mrb_float)mrb_fixnum(a) == mrb_float(b);
#endif
    default:
      return FALSE;
    }

#ifndef MRB_WITHOUT_FLOAT
  case MRB_TT_FLOAT:
    switch (mrb_type(b)) {
    case MRB_TT_FIXNUM:
      return mrb_float(a) == (mrb_float)mrb_fixnum(b);
    case MRB_TT_FLOAT:
      return mrb_float(a) == mrb_float(b);
    default:
      return FALSE;
    }
#endif

  default:
    {
      segindex *index = t->index;
      size_t capa = index ? index->capa : 0;
      mrb_bool eql = mrb_eql(mrb, a, b);
      if (index && (index != t->index || capa != index->capa)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "hash modified");
      }
      return eql;
    }
  } 
}

/* Creates the hash table. */
static htable*
ht_new(mrb_state *mrb)
{
  htable *t;

  t = (htable*)mrb_malloc(mrb, sizeof(htable));
  t->size = 0;
  t->rootseg =  NULL;
  t->lastseg =  NULL;
  t->last_len = 0;
  t->index = NULL;

  return t;
}

#define power2(v) do { \
  v--;\
  v |= v >> 1;\
  v |= v >> 2;\
  v |= v >> 4;\
  v |= v >> 8;\
  v |= v >> 16;\
  v++;\
} while (0)

#ifndef UPPER_BOUND
#define UPPER_BOUND(x) ((x)>>2|(x)>>1)
#endif

#define HT_MASK(index) ((index->capa)-1)

/* Build index for the hash table */
static void
ht_index(mrb_state *mrb, htable *t)
{
  size_t size = (size_t)t->size;
  size_t mask;
  segindex *index = t->index;
  segment *seg;
  size_t i;

  /* allocate index table */
  if (index && index->size >= UPPER_BOUND(index->capa)) {
    size = index->capa+1;
  }
  power2(size);
  if (!index || index->capa < size) {
    index = (segindex*)mrb_realloc_simple(mrb, index, sizeof(segindex)+sizeof(struct segkv*)*size);
    if (index == NULL) {
      mrb_free(mrb, t->index);
      t->index = NULL;
      return;
    }
    t->index = index;
  }
  index->size = t->size;
  index->capa = size;
  for (i=0; i<size; i++) {
    index->table[i] = NULL;
  }

  /* rebuld index */
  mask = HT_MASK(index);
  seg = t->rootseg;
  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value key;
      size_t k, step = 0;

      if (!seg->next && i >= (size_t)t->last_len) {
        return;
      }
      key = seg->e[i].key;
      if (mrb_undef_p(key)) continue;
      k = ht_hash_func(mrb, t, key) & mask;
      while (index->table[k]) {
        k = (k+(++step)) & mask;
      }
      index->table[k] = &seg->e[i];
    }
    seg = seg->next;
  }
}

/* Compacts the hash table removing deleted entries. */
static void
ht_compact(mrb_state *mrb, htable *t)
{
  segment *seg;
  uint16_t i, i2;
  segment *seg2 = NULL;
  mrb_int size = 0;

  if (t == NULL) return;
  seg = t->rootseg;
  if (t->index && (size_t)t->size == t->index->size) {
    ht_index(mrb, t);
    return;
  }
  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value k = seg->e[i].key;

      if (!seg->next && i >= t->last_len) {
        goto exit;
      }
      if (mrb_undef_p(k)) {     /* found deleted key */
        if (seg2 == NULL) {
          seg2 = seg;
          i2 = i;
        }
      }
      else {
        size++;
        if (seg2 != NULL) {
          seg2->e[i2++] = seg->e[i];
          if (i2 >= seg2->size) {
            seg2 = seg2->next;
            i2 = 0;
          }
        }
      }
    }
    seg = seg->next;
  }
 exit:
  /* reached at end */
  t->size = size;
  if (seg2) {
    seg = seg2->next;
    seg2->next = NULL;
    t->last_len = i2;
    t->lastseg = seg2;
    while (seg) {
      seg2 = seg->next;
      mrb_free(mrb, seg);
      seg = seg2;
    }
  }
  if (t->index) {
    ht_index(mrb, t);
  }
}

static segment*
segment_alloc(mrb_state *mrb, segment *seg)
{
  uint32_t size;

  if (!seg) size = MRB_HT_INIT_SIZE;
  else {
    size = seg->size*HT_SEG_INCREASE_RATIO + 1;
    if (size > UINT16_MAX) size = UINT16_MAX;
  }

  seg = (segment*)mrb_malloc(mrb, sizeof(segment)+sizeof(struct segkv)*size);
  seg->size = size;
  seg->next = NULL;

  return seg;
}

/* Set the value for the key in the indexed table. */
static void
ht_index_put(mrb_state *mrb, htable *t, mrb_value key, mrb_value val)
{
  segindex *index = t->index;
  size_t k, sp, step = 0, mask;
  segment *seg;

  if (index->size >= UPPER_BOUND(index->capa)) {
    /* need to expand table */
    ht_compact(mrb, t);
    index = t->index;
  }
  mask = HT_MASK(index);
  sp = index->capa;
  k = ht_hash_func(mrb, t, key) & mask;
  while (index->table[k]) {
    mrb_value key2 = index->table[k]->key;
    if (mrb_undef_p(key2)) {
      if (sp == index->capa) sp = k;
    }
    else if (ht_hash_equal(mrb, t, key, key2)) {
      index->table[k]->val = val;
      return;
    }
    k = (k+(++step)) & mask;
  }
  if (sp < index->capa) {
    k = sp;
  }

  /* put the value at the last */
  seg = t->lastseg;
  if (t->last_len < seg->size) {
    index->table[k] = &seg->e[t->last_len++];
  }
  else {                        /* append a new segment */
    seg->next = segment_alloc(mrb, seg);
    seg = seg->next;
    seg->next = NULL;
    t->lastseg = seg;
    t->last_len = 1;
    index->table[k] = &seg->e[0];
  }
  index->table[k]->key = key;
  index->table[k]->val = val;
  index->size++;
  t->size++;
}

/* Set the value for the key in the hash table. */
static void
ht_put(mrb_state *mrb, htable *t, mrb_value key, mrb_value val)
{
  segment *seg;
  mrb_int i, deleted = 0;

  if (t == NULL) return;
  if (t->index) {
    ht_index_put(mrb, t, key, val);
    return;
  }
  seg = t->rootseg;
  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value k = seg->e[i].key;
      /* Found room in last segment after last_len */
      if (!seg->next && i >= t->last_len) {
        seg->e[i].key = key;
        seg->e[i].val = val;
        t->last_len = (uint16_t)i+1;
        t->size++;
        return;
      }
      if (mrb_undef_p(k)) {
        deleted++;
        continue;
      }
      if (ht_hash_equal(mrb, t, key, k)) {
        seg->e[i].val = val;
        return;
      }
    }
    seg = seg->next;
  }
  /* Not found */

  /* Compact if last segment has room */
  if (deleted > 0 && deleted > MRB_HT_INIT_SIZE) {
    ht_compact(mrb, t);
  }
  t->size++;

  /* check if thre's room after compaction */
  if (t->lastseg && t->last_len < t->lastseg->size) {
    seg = t->lastseg;
    i = t->last_len;
  }
  else {
    /* append new segment */
    seg = segment_alloc(mrb, t->lastseg);
    i = 0;
    if (t->rootseg == NULL) {
      t->rootseg = seg;
    }
    else {
      t->lastseg->next = seg;
    }
    t->lastseg = seg;
  }
  seg->e[i].key = key;
  seg->e[i].val = val;
  t->last_len = (uint16_t)i+1;
  if (t->index == NULL && t->size > MRB_HT_INIT_SIZE*4) {
    ht_index(mrb, t);
  }
}

/* Get a value for a key from the indexed table. */
static mrb_bool
ht_index_get(mrb_state *mrb, htable *t, mrb_value key, mrb_value *vp)
{
  segindex *index = t->index;
  size_t mask = HT_MASK(index);
  size_t k = ht_hash_func(mrb, t, key) & mask;
  size_t step = 0;

  while (index->table[k]) {
    mrb_value key2 = index->table[k]->key;
    if (!mrb_undef_p(key2) && ht_hash_equal(mrb, t, key, key2)) {
      if (vp) *vp = index->table[k]->val;
      return TRUE;
    }
    k = (k+(++step)) & mask;
  }
  return FALSE;
}

/* Get a value for a key from the hash table. */
static mrb_bool
ht_get(mrb_state *mrb, htable *t, mrb_value key, mrb_value *vp)
{
  segment *seg;
  mrb_int i;

  if (t == NULL) return FALSE;
  if (t->index) {
    return ht_index_get(mrb, t, key, vp);
  }

  seg = t->rootseg;
  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value k = seg->e[i].key;

      if (!seg->next && i >= t->last_len) {
        return FALSE;
      }
      if (mrb_undef_p(k)) continue;
      if (ht_hash_equal(mrb, t, key, k)) {
        if (vp) *vp = seg->e[i].val;
        return TRUE;
      }
    }
    seg = seg->next;
  }
  return FALSE;
}

/* Deletes the value for the symbol from the hash table. */
/* Deletion is done by overwriting keys by `undef`. */
static mrb_bool
ht_del(mrb_state *mrb, htable *t, mrb_value key, mrb_value *vp)
{
  segment *seg;
  mrb_int i;

  if (t == NULL) return FALSE;
  seg = t->rootseg;
  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value key2;

      if (!seg->next && i >= t->last_len) {
        /* not found */
        return FALSE;
      }
      key2 = seg->e[i].key;
      if (!mrb_undef_p(key2) && ht_hash_equal(mrb, t, key, key2)) {
        if (vp) *vp = seg->e[i].val;
        seg->e[i].key = mrb_undef_value();
        t->size--;
        return TRUE;
      }
    }
    seg = seg->next;
  }
  return FALSE;
}

/* Iterates over the hash table. */
static void
ht_foreach(mrb_state *mrb, htable *t, mrb_hash_foreach_func *func, void *p)
{
  segment *seg;
  mrb_int i;

  if (t == NULL) return;
  seg = t->rootseg;
  while (seg) {
    for (i=0; i<seg->size; i++) {
      /* no value in last segment after last_len */
      if (!seg->next && i >= t->last_len) {
        return;
      }
      if (mrb_undef_p(seg->e[i].key)) continue;
      if ((*func)(mrb, seg->e[i].key, seg->e[i].val, p) != 0)
        return;
    }
    seg = seg->next;
  }
}

/* Iterates over the hash table. */
MRB_API void
mrb_hash_foreach(mrb_state *mrb, struct RHash *hash, mrb_hash_foreach_func *func, void *p)
{
  ht_foreach(mrb, hash->ht, func, p);
}

/* Copy the hash table. */
static htable*
ht_copy(mrb_state *mrb, htable *t)
{
  segment *seg;
  htable *t2;
  mrb_int i;

  seg = t->rootseg;
  t2 = ht_new(mrb);
  if (t->size == 0) return t2;

  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value key = seg->e[i].key;
      mrb_value val = seg->e[i].val;

      if ((seg->next == NULL) && (i >= t->last_len)) {
        return t2;
      }
      if (mrb_undef_p(key)) continue; /* skip deleted key */
      ht_put(mrb, t2, key, val);
    }
    seg = seg->next;
  }
  return t2;
}

/* Free memory of the hash table. */
static void
ht_free(mrb_state *mrb, htable *t)
{
  segment *seg;

  if (!t) return;
  seg = t->rootseg;
  while (seg) {
    segment *p = seg;
    seg = seg->next;
    mrb_free(mrb, p);
  }
  if (t->index) mrb_free(mrb, t->index);
  mrb_free(mrb, t);
}

static void mrb_hash_modify(mrb_state *mrb, mrb_value hash);

static inline mrb_value
ht_key(mrb_state *mrb, mrb_value key)
{
  if (mrb_string_p(key) && !mrb_frozen_p(mrb_str_ptr(key))) {
    key = mrb_str_dup(mrb, key);
    MRB_SET_FROZEN_FLAG(mrb_str_ptr(key));
  }
  return key;
}

#define KEY(key) ht_key(mrb, key)

static int
hash_mark_i(mrb_state *mrb, mrb_value key, mrb_value val, void *p)
{
  mrb_gc_mark_value(mrb, key);
  mrb_gc_mark_value(mrb, val);
  return 0;
}

void
mrb_gc_mark_hash(mrb_state *mrb, struct RHash *hash)
{
  ht_foreach(mrb, hash->ht, hash_mark_i, NULL);
}

size_t
mrb_gc_mark_hash_size(mrb_state *mrb, struct RHash *hash)
{
  if (!hash->ht) return 0;
  return hash->ht->size*2;
}

void
mrb_gc_free_hash(mrb_state *mrb, struct RHash *hash)
{
  ht_free(mrb, hash->ht);
}

MRB_API mrb_value
mrb_hash_new(mrb_state *mrb)
{
  struct RHash *h;

  h = (struct RHash*)mrb_obj_alloc(mrb, MRB_TT_HASH, mrb->hash_class);
  h->ht = 0;
  h->iv = 0;
  return mrb_obj_value(h);
}

MRB_API mrb_value
mrb_hash_new_capa(mrb_state *mrb, mrb_int capa)
{
  struct RHash *h;

  h = (struct RHash*)mrb_obj_alloc(mrb, MRB_TT_HASH, mrb->hash_class);
  /* preallocate hash table */
  h->ht = ht_new(mrb);
  /* capacity ignored */
  h->iv = 0;
  return mrb_obj_value(h);
}

static mrb_value mrb_hash_default(mrb_state *mrb, mrb_value hash);
static mrb_value hash_default(mrb_state *mrb, mrb_value hash, mrb_value key);

static mrb_value
mrb_hash_init_copy(mrb_state *mrb, mrb_value self)
{
  mrb_value orig = mrb_get_arg1(mrb);
  struct RHash* copy;
  htable *orig_h;
  mrb_value ifnone, vret;

  if (mrb_obj_equal(mrb, self, orig)) return self;
  if ((mrb_type(self) != mrb_type(orig)) || (mrb_obj_class(mrb, self) != mrb_obj_class(mrb, orig))) {
      mrb_raise(mrb, E_TYPE_ERROR, "initialize_copy should take same class object");
  }

  orig_h = RHASH_TBL(self);
  copy = (struct RHash*)mrb_obj_alloc(mrb, MRB_TT_HASH, mrb->hash_class);
  copy->ht = ht_copy(mrb, orig_h);

  if (MRB_RHASH_DEFAULT_P(self)) {
    copy->flags |= MRB_HASH_DEFAULT;
  }
  if (MRB_RHASH_PROCDEFAULT_P(self)) {
    copy->flags |= MRB_HASH_PROC_DEFAULT;
  }
  vret = mrb_obj_value(copy);
  ifnone = RHASH_IFNONE(self);
  if (!mrb_nil_p(ifnone)) {
      mrb_iv_set(mrb, vret, mrb_intern_lit(mrb, "ifnone"), ifnone);
  }
  return vret;
}

static int
check_kdict_i(mrb_state *mrb, mrb_value key, mrb_value val, void *data)
{
  if (!mrb_symbol_p(key)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "keyword argument hash with non symbol keys");
  }
  return 0;
}

void
mrb_hash_check_kdict(mrb_state *mrb, mrb_value self)
{
  htable *t;

  t = RHASH_TBL(self);
  if (!t || t->size == 0) return;
  ht_foreach(mrb, t, check_kdict_i, NULL);
}

MRB_API mrb_value
mrb_hash_dup(mrb_state *mrb, mrb_value self)
{
  struct RHash* copy;
  htable *orig_h;

  orig_h = RHASH_TBL(self);
  copy = (struct RHash*)mrb_obj_alloc(mrb, MRB_TT_HASH, mrb->hash_class);
  copy->ht = orig_h ? ht_copy(mrb, orig_h) : NULL;
  return mrb_obj_value(copy);
}

MRB_API mrb_value
mrb_hash_get(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  mrb_value val;
  mrb_sym mid;

  if (ht_get(mrb, RHASH_TBL(hash), key, &val)) {
    return val;
  }

  mid = mrb_intern_lit(mrb, "default");
  if (mrb_func_basic_p(mrb, hash, mid, mrb_hash_default)) {
    return hash_default(mrb, hash, key);
  }
  /* xxx mrb_funcall_tailcall(mrb, hash, "default", 1, key); */
  return mrb_funcall_argv(mrb, hash, mid, 1, &key);
}

MRB_API mrb_value
mrb_hash_fetch(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value def)
{
  mrb_value val;

  if (ht_get(mrb, RHASH_TBL(hash), key, &val)) {
    return val;
  }
  /* not found */
  return def;
}

MRB_API void
mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val)
{
  mrb_hash_modify(mrb, hash);

  key = KEY(key);
  ht_put(mrb, RHASH_TBL(hash), key, val);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)RHASH(hash), key);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)RHASH(hash), val);
  return;
}

static void
mrb_hash_modify(mrb_state *mrb, mrb_value hash)
{
  mrb_check_frozen(mrb, mrb_hash_ptr(hash));
  if (!RHASH_TBL(hash)) {
    RHASH_TBL(hash) = ht_new(mrb);
  }
}

/* 15.2.13.4.16 */
/*
 *  call-seq:
 *     Hash.new                          -> new_hash
 *     Hash.new(obj)                     -> new_hash
 *     Hash.new {|hash, key| block }     -> new_hash
 *
 *  Returns a new, empty hash. If this hash is subsequently accessed by
 *  a key that doesn't correspond to a hash entry, the value returned
 *  depends on the style of <code>new</code> used to create the hash. In
 *  the first form, the access returns <code>nil</code>. If
 *  <i>obj</i> is specified, this single object will be used for
 *  all <em>default values</em>. If a block is specified, it will be
 *  called with the hash object and the key, and should return the
 *  default value. It is the block's responsibility to store the value
 *  in the hash if required.
 *
 *      h = Hash.new("Go Fish")
 *      h["a"] = 100
 *      h["b"] = 200
 *      h["a"]           #=> 100
 *      h["c"]           #=> "Go Fish"
 *      # The following alters the single default object
 *      h["c"].upcase!   #=> "GO FISH"
 *      h["d"]           #=> "GO FISH"
 *      h.keys           #=> ["a", "b"]
 *
 *      # While this creates a new default object each time
 *      h = Hash.new { |hash, key| hash[key] = "Go Fish: #{key}" }
 *      h["c"]           #=> "Go Fish: c"
 *      h["c"].upcase!   #=> "GO FISH: C"
 *      h["d"]           #=> "Go Fish: d"
 *      h.keys           #=> ["c", "d"]
 *
 */

static mrb_value
mrb_hash_init(mrb_state *mrb, mrb_value hash)
{
  mrb_value block, ifnone;
  mrb_bool ifnone_p;

  ifnone = mrb_nil_value();
  mrb_get_args(mrb, "&|o?", &block, &ifnone, &ifnone_p);
  mrb_hash_modify(mrb, hash);
  if (!mrb_nil_p(block)) {
    if (ifnone_p) {
      mrb_argnum_error(mrb, 1, 0, 0);
    }
    RHASH(hash)->flags |= MRB_HASH_PROC_DEFAULT;
    ifnone = block;
  }
  if (!mrb_nil_p(ifnone)) {
    RHASH(hash)->flags |= MRB_HASH_DEFAULT;
    mrb_iv_set(mrb, hash, mrb_intern_lit(mrb, "ifnone"), ifnone);
  }
  return hash;
}

/* 15.2.13.4.2  */
/*
 *  call-seq:
 *     hsh[key]    ->  value
 *
 *  Element Reference---Retrieves the <i>value</i> object corresponding
 *  to the <i>key</i> object. If not found, returns the default value (see
 *  <code>Hash::new</code> for details).
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h["a"]   #=> 100
 *     h["c"]   #=> nil
 *
 */
static mrb_value
mrb_hash_aget(mrb_state *mrb, mrb_value self)
{
  mrb_value key = mrb_get_arg1(mrb);

  return mrb_hash_get(mrb, self, key);
}

static mrb_value
hash_default(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  if (MRB_RHASH_DEFAULT_P(hash)) {
    if (MRB_RHASH_PROCDEFAULT_P(hash)) {
      return mrb_funcall(mrb, RHASH_PROCDEFAULT(hash), "call", 2, hash, key);
    }
    else {
      return RHASH_IFNONE(hash);
    }
  }
  return mrb_nil_value();
}

/* 15.2.13.4.5  */
/*
 *  call-seq:
 *     hsh.default(key=nil)   -> obj
 *
 *  Returns the default value, the value that would be returned by
 *  <i>hsh</i>[<i>key</i>] if <i>key</i> did not exist in <i>hsh</i>.
 *  See also <code>Hash::new</code> and <code>Hash#default=</code>.
 *
 *     h = Hash.new                            #=> {}
 *     h.default                               #=> nil
 *     h.default(2)                            #=> nil
 *
 *     h = Hash.new("cat")                     #=> {}
 *     h.default                               #=> "cat"
 *     h.default(2)                            #=> "cat"
 *
 *     h = Hash.new {|h,k| h[k] = k.to_i*10}   #=> {}
 *     h.default                               #=> nil
 *     h.default(2)                            #=> 20
 */

static mrb_value
mrb_hash_default(mrb_state *mrb, mrb_value hash)
{
  mrb_value key;
  mrb_bool given;

  mrb_get_args(mrb, "|o?", &key, &given);
  if (MRB_RHASH_DEFAULT_P(hash)) {
    if (MRB_RHASH_PROCDEFAULT_P(hash)) {
      if (!given) return mrb_nil_value();
      return mrb_funcall(mrb, RHASH_PROCDEFAULT(hash), "call", 2, hash, key);
    }
    else {
      return RHASH_IFNONE(hash);
    }
  }
  return mrb_nil_value();
}

/* 15.2.13.4.6  */
/*
 *  call-seq:
 *     hsh.default = obj     -> obj
 *
 *  Sets the default value, the value returned for a key that does not
 *  exist in the hash. It is not possible to set the default to a
 *  <code>Proc</code> that will be executed on each key lookup.
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h.default = "Go fish"
 *     h["a"]     #=> 100
 *     h["z"]     #=> "Go fish"
 *     # This doesn't do what you might hope...
 *     h.default = proc do |hash, key|
 *       hash[key] = key + key
 *     end
 *     h[2]       #=> #<Proc:0x401b3948@-:6>
 *     h["cat"]   #=> #<Proc:0x401b3948@-:6>
 */

static mrb_value
mrb_hash_set_default(mrb_state *mrb, mrb_value hash)
{
  mrb_value ifnone = mrb_get_arg1(mrb);

  mrb_hash_modify(mrb, hash);
  mrb_iv_set(mrb, hash, mrb_intern_lit(mrb, "ifnone"), ifnone);
  RHASH(hash)->flags &= ~MRB_HASH_PROC_DEFAULT;
  if (!mrb_nil_p(ifnone)) {
    RHASH(hash)->flags |= MRB_HASH_DEFAULT;
  }
  else {
    RHASH(hash)->flags &= ~MRB_HASH_DEFAULT;
  }
  return ifnone;
}

/* 15.2.13.4.7  */
/*
 *  call-seq:
 *     hsh.default_proc -> anObject
 *
 *  If <code>Hash::new</code> was invoked with a block, return that
 *  block, otherwise return <code>nil</code>.
 *
 *     h = Hash.new {|h,k| h[k] = k*k }   #=> {}
 *     p = h.default_proc                 #=> #<Proc:0x401b3d08@-:1>
 *     a = []                             #=> []
 *     p.call(a, 2)
 *     a                                  #=> [nil, nil, 4]
 */


static mrb_value
mrb_hash_default_proc(mrb_state *mrb, mrb_value hash)
{
  if (MRB_RHASH_PROCDEFAULT_P(hash)) {
    return RHASH_PROCDEFAULT(hash);
  }
  return mrb_nil_value();
}

/*
 *  call-seq:
 *     hsh.default_proc = proc_obj     -> proc_obj
 *
 *  Sets the default proc to be executed on each key lookup.
 *
 *     h.default_proc = proc do |hash, key|
 *       hash[key] = key + key
 *     end
 *     h[2]       #=> 4
 *     h["cat"]   #=> "catcat"
 */

static mrb_value
mrb_hash_set_default_proc(mrb_state *mrb, mrb_value hash)
{
  mrb_value ifnone = mrb_get_arg1(mrb);

  mrb_hash_modify(mrb, hash);
  mrb_iv_set(mrb, hash, mrb_intern_lit(mrb, "ifnone"), ifnone);
  if (!mrb_nil_p(ifnone)) {
    RHASH(hash)->flags |= MRB_HASH_PROC_DEFAULT;
    RHASH(hash)->flags |= MRB_HASH_DEFAULT;
  }
  else {
    RHASH(hash)->flags &= ~MRB_HASH_DEFAULT;
    RHASH(hash)->flags &= ~MRB_HASH_PROC_DEFAULT;
  }

  return ifnone;
}

MRB_API mrb_value
mrb_hash_delete_key(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  htable *t = RHASH_TBL(hash);
  mrb_value del_val;

  if (ht_del(mrb, t, key, &del_val)) {
    return del_val;
  }

  /* not found */
  return mrb_nil_value();
}

static mrb_value
mrb_hash_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value key = mrb_get_arg1(mrb);

  mrb_hash_modify(mrb, self);
  return mrb_hash_delete_key(mrb, self, key);
}

/* find first element in the hash table, and remove it. */
static void
ht_shift(mrb_state *mrb, htable *t, mrb_value *kp, mrb_value *vp)
{
  segment *seg = t->rootseg;
  mrb_int i;

  while (seg) {
    for (i=0; i<seg->size; i++) {
      mrb_value key;

      if (!seg->next && i >= t->last_len) {
        return;
      }
      key = seg->e[i].key;
      if (mrb_undef_p(key)) continue;
      *kp = key;
      *vp = seg->e[i].val;
      /* delete element */
      seg->e[i].key = mrb_undef_value();
      t->size--;
      return;
    }
    seg = seg->next;
  }
}

/* 15.2.13.4.24 */
/*
 *  call-seq:
 *     hsh.shift -> anArray or obj
 *
 *  Removes a key-value pair from <i>hsh</i> and returns it as the
 *  two-item array <code>[</code> <i>key, value</i> <code>]</code>, or
 *  the hash's default value if the hash is empty.
 *
 *      h = { 1 => "a", 2 => "b", 3 => "c" }
 *      h.shift   #=> [1, "a"]
 *      h         #=> {2=>"b", 3=>"c"}
 */

static mrb_value
mrb_hash_shift(mrb_state *mrb, mrb_value hash)
{
  htable *t = RHASH_TBL(hash);

  mrb_hash_modify(mrb, hash);
  if (t && t->size > 0) {
    mrb_value del_key, del_val;

    ht_shift(mrb, t, &del_key, &del_val);
    mrb_gc_protect(mrb, del_key);
    mrb_gc_protect(mrb, del_val);
    return mrb_assoc_new(mrb, del_key, del_val);
  }

  if (MRB_RHASH_DEFAULT_P(hash)) {
    if (MRB_RHASH_PROCDEFAULT_P(hash)) {
      return mrb_funcall(mrb, RHASH_PROCDEFAULT(hash), "call", 2, hash, mrb_nil_value());
    }
    else {
      return RHASH_IFNONE(hash);
    }
  }
  return mrb_nil_value();
}

/* 15.2.13.4.4  */
/*
 *  call-seq:
 *     hsh.clear -> hsh
 *
 *  Removes all key-value pairs from `hsh`.
 *
 *      h = { "a" => 100, "b" => 200 }   #=> {"a"=>100, "b"=>200}
 *      h.clear                          #=> {}
 *
 */

MRB_API mrb_value
mrb_hash_clear(mrb_state *mrb, mrb_value hash)
{
  htable *t = RHASH_TBL(hash);

  mrb_hash_modify(mrb, hash);
  if (t) {
    ht_free(mrb, t);
    RHASH_TBL(hash) = NULL;
  }
  return hash;
}

/* 15.2.13.4.3  */
/* 15.2.13.4.26 */
/*
 *  call-seq:
 *     hsh[key] = value        -> value
 *     hsh.store(key, value)   -> value
 *
 *  Element Assignment---Associates the value given by
 *  <i>value</i> with the key given by <i>key</i>.
 *  <i>key</i> should not have its value changed while it is in
 *  use as a key (a <code>String</code> passed as a key will be
 *  duplicated and frozen).
 *
 *      h = { "a" => 100, "b" => 200 }
 *      h["a"] = 9
 *      h["c"] = 4
 *      h   #=> {"a"=>9, "b"=>200, "c"=>4}
 *
 */
static mrb_value
mrb_hash_aset(mrb_state *mrb, mrb_value self)
{
  mrb_value key, val;

  mrb_get_args(mrb, "oo", &key, &val);
  mrb_hash_set(mrb, self, key, val);
  return val;
}

MRB_API mrb_int
mrb_hash_size(mrb_state *mrb, mrb_value hash)
{
  htable *t = RHASH_TBL(hash);

  if (!t) return 0;
  return t->size;
}

/* 15.2.13.4.20 */
/* 15.2.13.4.25 */
/*
 *  call-seq:
 *     hsh.length    ->  fixnum
 *     hsh.size      ->  fixnum
 *
 *  Returns the number of key-value pairs in the hash.
 *
 *     h = { "d" => 100, "a" => 200, "v" => 300, "e" => 400 }
 *     h.length        #=> 4
 *     h.delete("a")   #=> 200
 *     h.length        #=> 3
 */
static mrb_value
mrb_hash_size_m(mrb_state *mrb, mrb_value self)
{
  mrb_int size = mrb_hash_size(mrb, self);
  return mrb_fixnum_value(size);
}

MRB_API mrb_bool
mrb_hash_empty_p(mrb_state *mrb, mrb_value self)
{
  htable *t = RHASH_TBL(self);

  if (!t) return TRUE;
  return t->size == 0;
}

/* 15.2.13.4.12 */
/*
 *  call-seq:
 *     hsh.empty?    -> true or false
 *
 *  Returns <code>true</code> if <i>hsh</i> contains no key-value pairs.
 *
 *     {}.empty?   #=> true
 *
 */
static mrb_value
mrb_hash_empty_m(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(mrb_hash_empty_p(mrb, self));
}

static int
hash_keys_i(mrb_state *mrb, mrb_value key, mrb_value val, void *p)
{
  mrb_ary_push(mrb, *(mrb_value*)p, key);
  return 0;
}

/* 15.2.13.4.19 */
/*
 *  call-seq:
 *     hsh.keys    -> array
 *
 *  Returns a new array populated with the keys from this hash. See also
 *  <code>Hash#values</code>.
 *
 *     h = { "a" => 100, "b" => 200, "c" => 300, "d" => 400 }
 *     h.keys   #=> ["a", "b", "c", "d"]
 *
 */

MRB_API mrb_value
mrb_hash_keys(mrb_state *mrb, mrb_value hash)
{
  htable *t = RHASH_TBL(hash);
  mrb_int size;
  mrb_value ary;

  if (!t || (size = t->size) == 0)
    return mrb_ary_new(mrb);
  ary = mrb_ary_new_capa(mrb, size);
  ht_foreach(mrb, t, hash_keys_i, (void*)&ary);
  return ary;
}

static int
hash_vals_i(mrb_state *mrb, mrb_value key, mrb_value val, void *p)
{
  mrb_ary_push(mrb, *(mrb_value*)p, val);
  return 0;
}

/* 15.2.13.4.28 */
/*
 *  call-seq:
 *     hsh.values    -> array
 *
 *  Returns a new array populated with the values from <i>hsh</i>. See
 *  also <code>Hash#keys</code>.
 *
 *     h = { "a" => 100, "b" => 200, "c" => 300 }
 *     h.values   #=> [100, 200, 300]
 *
 */

MRB_API mrb_value
mrb_hash_values(mrb_state *mrb, mrb_value hash)
{
  htable *t = RHASH_TBL(hash);
  mrb_int size;
  mrb_value ary;

  if (!t || (size = t->size) == 0)
    return mrb_ary_new(mrb);
  ary = mrb_ary_new_capa(mrb, size);
  ht_foreach(mrb, t, hash_vals_i, (void*)&ary);
  return ary;
}

/* 15.2.13.4.13 */
/* 15.2.13.4.15 */
/* 15.2.13.4.18 */
/* 15.2.13.4.21 */
/*
 *  call-seq:
 *     hsh.has_key?(key)    -> true or false
 *     hsh.include?(key)    -> true or false
 *     hsh.key?(key)        -> true or false
 *     hsh.member?(key)     -> true or false
 *
 *  Returns <code>true</code> if the given key is present in <i>hsh</i>.
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h.has_key?("a")   #=> true
 *     h.has_key?("z")   #=> false
 *
 */

MRB_API mrb_bool
mrb_hash_key_p(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  htable *t;

  t = RHASH_TBL(hash);
  if (ht_get(mrb, t, key, NULL)) {
    return TRUE;
  }
  return FALSE;
}

static mrb_value
mrb_hash_has_key(mrb_state *mrb, mrb_value hash)
{
  mrb_value key = mrb_get_arg1(mrb);
  mrb_bool key_p;

  key_p = mrb_hash_key_p(mrb, hash, key);
  return mrb_bool_value(key_p);
}

struct has_v_arg {
  mrb_bool found;
  mrb_value val;
};

static int
hash_has_value_i(mrb_state *mrb, mrb_value key, mrb_value val, void *p)
{
  struct has_v_arg *arg = (struct has_v_arg*)p;
  
  if (mrb_equal(mrb, arg->val, val)) {
    arg->found = TRUE;
    return 1;
  }
  return 0;
}

/* 15.2.13.4.14 */
/* 15.2.13.4.27 */
/*
 *  call-seq:
 *     hsh.has_value?(value)    -> true or false
 *     hsh.value?(value)        -> true or false
 *
 *  Returns <code>true</code> if the given value is present for some key
 *  in <i>hsh</i>.
 *
 *     h = { "a" => 100, "b" => 200 }
 *     h.has_value?(100)   #=> true
 *     h.has_value?(999)   #=> false
 */

static mrb_value
mrb_hash_has_value(mrb_state *mrb, mrb_value hash)
{
  mrb_value val = mrb_get_arg1(mrb);
  struct has_v_arg arg;
  
  arg.found = FALSE;
  arg.val = val;
  ht_foreach(mrb, RHASH_TBL(hash), hash_has_value_i, &arg);
  return mrb_bool_value(arg.found);
}

static int
merge_i(mrb_state *mrb, mrb_value key, mrb_value val, void *data)
{
  htable *h1 = (htable*)data;

  ht_put(mrb, h1, key, val);
  return 0;
}

MRB_API void
mrb_hash_merge(mrb_state *mrb, mrb_value hash1, mrb_value hash2)
{
  htable *h1, *h2;

  mrb_hash_modify(mrb, hash1);
  hash2 = mrb_ensure_hash_type(mrb, hash2);
  h1 = RHASH_TBL(hash1);
  h2 = RHASH_TBL(hash2);

  if (!h2) return;
  if (!h1) {
    RHASH_TBL(hash1) = ht_copy(mrb, h2);
    return;
  }
  ht_foreach(mrb, h2, merge_i, h1);
  mrb_write_barrier(mrb, (struct RBasic*)RHASH(hash1));
  return;
}

/*
 *  call-seq:
 *    hsh.rehash -> hsh
 *
 *  Rebuilds the hash based on the current hash values for each key. If
 *  values of key objects have changed since they were inserted, this
 *  method will reindex <i>hsh</i>.
 *
 *     keys = (1..17).map{|n| [n]}
 *     k = keys[0]
 *     h = {}
 *     keys.each{|key| h[key] = key[0]}
 *     h     #=> { [1]=> 1, [2]=> 2, [3]=> 3, [4]=> 4, [5]=> 5, [6]=> 6, [7]=> 7,
 *                 [8]=> 8, [9]=> 9,[10]=>10,[11]=>11,[12]=>12,[13]=>13,[14]=>14,
 *                [15]=>15,[16]=>16,[17]=>17}
 *     h[k]  #=> 1
 *     k[0] = keys.size + 1
 *     h     #=> {[18]=> 1, [2]=> 2, [3]=> 3, [4]=> 4, [5]=> 5, [6]=> 6, [7]=> 7,
 *                 [8]=> 8, [9]=> 9,[10]=>10,[11]=>11,[12]=>12,[13]=>13,[14]=>14,
 *                [15]=>15,[16]=>16,[17]=>17}
 *     h[k]  #=> nil
 *     h.rehash
 *     h[k]  #=> 1
 */
static mrb_value
mrb_hash_rehash(mrb_state *mrb, mrb_value self)
{
  ht_compact(mrb, RHASH_TBL(self));
  return self;
}

void
mrb_init_hash(mrb_state *mrb)
{
  struct RClass *h;

  mrb->hash_class = h = mrb_define_class(mrb, "Hash", mrb->object_class);              /* 15.2.13 */
  MRB_SET_INSTANCE_TT(h, MRB_TT_HASH);

  mrb_define_method(mrb, h, "initialize_copy", mrb_hash_init_copy,   MRB_ARGS_REQ(1));
  mrb_define_method(mrb, h, "[]",              mrb_hash_aget,        MRB_ARGS_REQ(1)); /* 15.2.13.4.2  */
  mrb_define_method(mrb, h, "[]=",             mrb_hash_aset,        MRB_ARGS_REQ(2)); /* 15.2.13.4.3  */
  mrb_define_method(mrb, h, "clear",           mrb_hash_clear,       MRB_ARGS_NONE()); /* 15.2.13.4.4  */
  mrb_define_method(mrb, h, "default",         mrb_hash_default,     MRB_ARGS_OPT(1));  /* 15.2.13.4.5  */
  mrb_define_method(mrb, h, "default=",        mrb_hash_set_default, MRB_ARGS_REQ(1)); /* 15.2.13.4.6  */
  mrb_define_method(mrb, h, "default_proc",    mrb_hash_default_proc,MRB_ARGS_NONE()); /* 15.2.13.4.7  */
  mrb_define_method(mrb, h, "default_proc=",   mrb_hash_set_default_proc,MRB_ARGS_REQ(1)); /* 15.2.13.4.7  */
  mrb_define_method(mrb, h, "__delete",        mrb_hash_delete,      MRB_ARGS_REQ(1)); /* core of 15.2.13.4.8  */
  mrb_define_method(mrb, h, "empty?",          mrb_hash_empty_m,     MRB_ARGS_NONE()); /* 15.2.13.4.12 */
  mrb_define_method(mrb, h, "has_key?",        mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.13 */
  mrb_define_method(mrb, h, "has_value?",      mrb_hash_has_value,   MRB_ARGS_REQ(1)); /* 15.2.13.4.14 */
  mrb_define_method(mrb, h, "include?",        mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.15 */
  mrb_define_method(mrb, h, "initialize",      mrb_hash_init,        MRB_ARGS_OPT(1)|MRB_ARGS_BLOCK()); /* 15.2.13.4.16 */
  mrb_define_method(mrb, h, "key?",            mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.18 */
  mrb_define_method(mrb, h, "keys",            mrb_hash_keys,        MRB_ARGS_NONE()); /* 15.2.13.4.19 */
  mrb_define_method(mrb, h, "length",          mrb_hash_size_m,      MRB_ARGS_NONE()); /* 15.2.13.4.20 */
  mrb_define_method(mrb, h, "member?",         mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.21 */
  mrb_define_method(mrb, h, "shift",           mrb_hash_shift,       MRB_ARGS_NONE()); /* 15.2.13.4.24 */
  mrb_define_method(mrb, h, "size",            mrb_hash_size_m,      MRB_ARGS_NONE()); /* 15.2.13.4.25 */
  mrb_define_method(mrb, h, "store",           mrb_hash_aset,        MRB_ARGS_REQ(2)); /* 15.2.13.4.26 */
  mrb_define_method(mrb, h, "value?",          mrb_hash_has_value,   MRB_ARGS_REQ(1)); /* 15.2.13.4.27 */
  mrb_define_method(mrb, h, "values",          mrb_hash_values,      MRB_ARGS_NONE()); /* 15.2.13.4.28 */
  mrb_define_method(mrb, h, "rehash",          mrb_hash_rehash,      MRB_ARGS_NONE());
}
