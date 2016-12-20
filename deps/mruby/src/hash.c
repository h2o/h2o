/*
** hash.c - Hash class
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/khash.h>
#include <mruby/string.h>
#include <mruby/variable.h>

/* a function to get hash value of a float number */
mrb_int mrb_float_id(mrb_float f);

static inline khint_t
mrb_hash_ht_hash_func(mrb_state *mrb, mrb_value key)
{
  enum mrb_vtype t = mrb_type(key);
  mrb_value hv;
  const char *p;
  mrb_int i, len;
  khint_t h;

  switch (t) {
  case MRB_TT_STRING:
    p = RSTRING_PTR(key);
    len = RSTRING_LEN(key);
    h = 0;
    for (i=0; i<len; i++) {
      h = (h << 5) - h + *p++;
    }
    return h;

  case MRB_TT_SYMBOL:
    h = (khint_t)mrb_symbol(key);
    return kh_int_hash_func(mrb, h);

  case MRB_TT_FIXNUM:
    h = (khint_t)mrb_float_id((mrb_float)mrb_fixnum(key));
    return kh_int_hash_func(mrb, h);

  case MRB_TT_FLOAT:
    h = (khint_t)mrb_float_id(mrb_float(key));
    return kh_int_hash_func(mrb, h);

  default:
    hv = mrb_funcall(mrb, key, "hash", 0);
    h = (khint_t)t ^ mrb_fixnum(hv);
    return kh_int_hash_func(mrb, h);
  }
}

static inline khint_t
mrb_hash_ht_hash_equal(mrb_state *mrb, mrb_value a, mrb_value b)
{
  enum mrb_vtype t = mrb_type(a);

  switch (t) {
  case MRB_TT_STRING:
    return mrb_str_equal(mrb, a, b);

  case MRB_TT_SYMBOL:
    if (mrb_type(b) != MRB_TT_SYMBOL) return FALSE;
    return mrb_symbol(a) == mrb_symbol(b);

  case MRB_TT_FIXNUM:
    switch (mrb_type(b)) {
    case MRB_TT_FIXNUM:
      return mrb_fixnum(a) == mrb_fixnum(b);
    case MRB_TT_FLOAT:
      return (mrb_float)mrb_fixnum(a) == mrb_float(b);
    default:
      return FALSE;
    }

  case MRB_TT_FLOAT:
    switch (mrb_type(b)) {
    case MRB_TT_FIXNUM:
      return mrb_float(a) == (mrb_float)mrb_fixnum(b);
    case MRB_TT_FLOAT:
      return mrb_float(a) == mrb_float(b);
    default:
      return FALSE;
    }

  default:
    return mrb_eql(mrb, a, b);
  }
}

KHASH_DEFINE (ht, mrb_value, mrb_hash_value, TRUE, mrb_hash_ht_hash_func, mrb_hash_ht_hash_equal)

static void mrb_hash_modify(mrb_state *mrb, mrb_value hash);

static inline mrb_value
mrb_hash_ht_key(mrb_state *mrb, mrb_value key)
{
  if (mrb_string_p(key) && !MRB_FROZEN_P(mrb_str_ptr(key))) {
    key = mrb_str_dup(mrb, key);
    MRB_SET_FROZEN_FLAG(mrb_str_ptr(key));
  }
  return key;
}

#define KEY(key) mrb_hash_ht_key(mrb, key)

void
mrb_gc_mark_hash(mrb_state *mrb, struct RHash *hash)
{
  khiter_t k;
  khash_t(ht) *h = hash->ht;

  if (!h) return;
  for (k = kh_begin(h); k != kh_end(h); k++) {
    if (kh_exist(h, k)) {
      mrb_value key = kh_key(h, k);
      mrb_value val = kh_value(h, k).v;

      mrb_gc_mark_value(mrb, key);
      mrb_gc_mark_value(mrb, val);
    }
  }
}

size_t
mrb_gc_mark_hash_size(mrb_state *mrb, struct RHash *hash)
{
  if (!hash->ht) return 0;
  return kh_size(hash->ht)*2;
}

void
mrb_gc_free_hash(mrb_state *mrb, struct RHash *hash)
{
  if (hash->ht) kh_destroy(ht, mrb, hash->ht);
}


MRB_API mrb_value
mrb_hash_new_capa(mrb_state *mrb, int capa)
{
  struct RHash *h;

  h = (struct RHash*)mrb_obj_alloc(mrb, MRB_TT_HASH, mrb->hash_class);
  h->ht = kh_init(ht, mrb);
  if (capa > 0) {
    kh_resize(ht, mrb, h->ht, capa);
  }
  h->iv = 0;
  return mrb_obj_value(h);
}

MRB_API mrb_value
mrb_hash_new(mrb_state *mrb)
{
  return mrb_hash_new_capa(mrb, 0);
}

MRB_API mrb_value
mrb_hash_get(mrb_state *mrb, mrb_value hash, mrb_value key)
{
  khash_t(ht) *h = RHASH_TBL(hash);
  khiter_t k;

  if (h) {
    k = kh_get(ht, mrb, h, key);
    if (k != kh_end(h))
      return kh_value(h, k).v;
  }

  /* not found */
  /* xxx mrb_funcall_tailcall(mrb, hash, "default", 1, key); */
  return mrb_funcall(mrb, hash, "default", 1, key);
}

MRB_API mrb_value
mrb_hash_fetch(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value def)
{
  khash_t(ht) *h = RHASH_TBL(hash);
  khiter_t k;

  if (h) {
    k = kh_get(ht, mrb, h, key);
    if (k != kh_end(h))
      return kh_value(h, k).v;
  }

  /* not found */
  return def;
}

MRB_API void
mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val)
{
  khash_t(ht) *h;
  khiter_t k;
  int r;

  mrb_hash_modify(mrb, hash);
  h = RHASH_TBL(hash);

  if (!h) h = RHASH_TBL(hash) = kh_init(ht, mrb);
  k = kh_put2(ht, mrb, h, key, &r);
  kh_value(h, k).v = val;

  if (r != 0) {
    /* expand */
    int ai = mrb_gc_arena_save(mrb);
    key = kh_key(h, k) = KEY(key);
    mrb_gc_arena_restore(mrb, ai);
    kh_value(h, k).n = kh_size(h)-1;
  }

  mrb_field_write_barrier_value(mrb, (struct RBasic*)RHASH(hash), key);
  mrb_field_write_barrier_value(mrb, (struct RBasic*)RHASH(hash), val);
  return;
}

static mrb_value
mrb_hash_dup(mrb_state *mrb, mrb_value hash)
{
  struct RHash* ret;
  khash_t(ht) *h, *ret_h;
  khiter_t k, ret_k;
  mrb_value ifnone, vret;

  h = RHASH_TBL(hash);
  ret = (struct RHash*)mrb_obj_alloc(mrb, MRB_TT_HASH, mrb->hash_class);
  ret->ht = kh_init(ht, mrb);

  if (kh_size(h) > 0) {
    ret_h = ret->ht;

    for (k = kh_begin(h); k != kh_end(h); k++) {
      if (kh_exist(h, k)) {
        int ai = mrb_gc_arena_save(mrb);
        ret_k = kh_put(ht, mrb, ret_h, KEY(kh_key(h, k)));
        mrb_gc_arena_restore(mrb, ai);
        kh_val(ret_h, ret_k) = kh_val(h, k);
      }
    }
  }

  if (MRB_RHASH_DEFAULT_P(hash)) {
    ret->flags |= MRB_HASH_DEFAULT;
  }
  if (MRB_RHASH_PROCDEFAULT_P(hash)) {
    ret->flags |= MRB_HASH_PROC_DEFAULT;
  }
  vret = mrb_obj_value(ret);
  ifnone = RHASH_IFNONE(hash);
  if (!mrb_nil_p(ifnone)) {
      mrb_iv_set(mrb, vret, mrb_intern_lit(mrb, "ifnone"), ifnone);
  }
  return vret;
}

MRB_API mrb_value
mrb_check_hash_type(mrb_state *mrb, mrb_value hash)
{
  return mrb_check_convert_type(mrb, hash, MRB_TT_HASH, "Hash", "to_hash");
}

MRB_API khash_t(ht)*
mrb_hash_tbl(mrb_state *mrb, mrb_value hash)
{
  khash_t(ht) *h = RHASH_TBL(hash);

  if (!h) {
    return RHASH_TBL(hash) = kh_init(ht, mrb);
  }
  return h;
}

static void
mrb_hash_modify(mrb_state *mrb, mrb_value hash)
{
  if (MRB_FROZEN_P(mrb_hash_ptr(hash))) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't modify frozen hash");
  }
  mrb_hash_tbl(mrb, hash);
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
      mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong number of arguments");
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
  mrb_value key;

  mrb_get_args(mrb, "o", &key);
  return mrb_hash_get(mrb, self, key);
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
  mrb_value ifnone;

  mrb_get_args(mrb, "o", &ifnone);
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
  mrb_value ifnone;

  mrb_get_args(mrb, "o", &ifnone);
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
  khash_t(ht) *h = RHASH_TBL(hash);
  khiter_t k;
  mrb_value delVal;
  mrb_int n;

  if (h) {
    k = kh_get(ht, mrb, h, key);
    if (k != kh_end(h)) {
      delVal = kh_value(h, k).v;
      n = kh_value(h, k).n;
      kh_del(ht, mrb, h, k);
      for (k = kh_begin(h); k != kh_end(h); k++) {
        if (!kh_exist(h, k)) continue;
        if (kh_value(h, k).n > n) kh_value(h, k).n--;
      }
      return delVal;
    }
  }

  /* not found */
  return mrb_nil_value();
}

/* 15.2.13.4.8  */
/*
 *  call-seq:
 *     hsh.delete(key)                   -> value
 *     hsh.delete(key) {| key | block }  -> value
 *
 *  Deletes and returns a key-value pair from <i>hsh</i> whose key is
 *  equal to <i>key</i>. If the key is not found, returns the
 *  <em>default value</em>. If the optional code block is given and the
 *  key is not found, pass in the key and return the result of
 *  <i>block</i>.
 *
 *      h = { "a" => 100, "b" => 200 }
 *      h.delete("a")                              #=> 100
 *      h.delete("z")                              #=> nil
 *      h.delete("z") { |el| "#{el} not found" }   #=> "z not found"
 *
 */
static mrb_value
mrb_hash_delete(mrb_state *mrb, mrb_value self)
{
  mrb_value key;

  mrb_get_args(mrb, "o", &key);
  return mrb_hash_delete_key(mrb, self, key);
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
  khash_t(ht) *h = RHASH_TBL(hash);
  khiter_t k;
  mrb_value delKey, delVal;

  mrb_hash_modify(mrb, hash);
  if (h && kh_size(h) > 0) {
    for (k = kh_begin(h); k != kh_end(h); k++) {
      if (!kh_exist(h, k)) continue;

      delKey = kh_key(h, k);
      mrb_gc_protect(mrb, delKey);
      delVal = mrb_hash_delete_key(mrb, hash, delKey);
      mrb_gc_protect(mrb, delVal);

      return mrb_assoc_new(mrb, delKey, delVal);
    }
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
  khash_t(ht) *h = RHASH_TBL(hash);

  if (h) kh_clear(ht, mrb, h);
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
  khash_t(ht) *h = RHASH_TBL(self);

  if (!h) return mrb_fixnum_value(0);
  return mrb_fixnum_value(kh_size(h));
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
MRB_API mrb_value
mrb_hash_empty_p(mrb_state *mrb, mrb_value self)
{
  khash_t(ht) *h = RHASH_TBL(self);

  if (h) return mrb_bool_value(kh_size(h) == 0);
  return mrb_true_value();
}

/* 15.2.13.4.29 (x)*/
/*
 * call-seq:
 *    hsh.to_hash   => hsh
 *
 * Returns +self+.
 */

static mrb_value
mrb_hash_to_hash(mrb_state *mrb, mrb_value hash)
{
  return hash;
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
  khash_t(ht) *h = RHASH_TBL(hash);
  khiter_t k;
  mrb_value ary;
  mrb_value *p;

  if (!h || kh_size(h) == 0) return mrb_ary_new(mrb);
  ary = mrb_ary_new_capa(mrb, kh_size(h));
  mrb_ary_set(mrb, ary, kh_size(h)-1, mrb_nil_value());
  p = mrb_ary_ptr(ary)->ptr;
  for (k = kh_begin(h); k != kh_end(h); k++) {
    if (kh_exist(h, k)) {
      mrb_value kv = kh_key(h, k);
      mrb_hash_value hv = kh_value(h, k);

      p[hv.n] = kv;
    }
  }
  return ary;
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
  khash_t(ht) *h = RHASH_TBL(hash);
  khiter_t k;
  mrb_value ary;

  if (!h) return mrb_ary_new(mrb);
  ary = mrb_ary_new_capa(mrb, kh_size(h));
  for (k = kh_begin(h); k != kh_end(h); k++) {
    if (kh_exist(h, k)) {
      mrb_hash_value hv = kh_value(h, k);

      mrb_ary_set(mrb, ary, hv.n, hv.v);
    }
  }
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

static mrb_value
mrb_hash_has_key(mrb_state *mrb, mrb_value hash)
{
  mrb_value key;
  khash_t(ht) *h;
  khiter_t k;

  mrb_get_args(mrb, "o", &key);

  h = RHASH_TBL(hash);
  if (h) {
    k = kh_get(ht, mrb, h, key);
    return mrb_bool_value(k != kh_end(h));
  }
  return mrb_false_value();
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
  mrb_value val;
  khash_t(ht) *h;
  khiter_t k;

  mrb_get_args(mrb, "o", &val);
  h = RHASH_TBL(hash);

  if (h) {
    for (k = kh_begin(h); k != kh_end(h); k++) {
      if (!kh_exist(h, k)) continue;

      if (mrb_equal(mrb, kh_value(h, k).v, val)) {
        return mrb_true_value();
      }
    }
  }
  return mrb_false_value();
}

void
mrb_init_hash(mrb_state *mrb)
{
  struct RClass *h;

  mrb->hash_class = h = mrb_define_class(mrb, "Hash", mrb->object_class);              /* 15.2.13 */
  MRB_SET_INSTANCE_TT(h, MRB_TT_HASH);

  mrb_define_method(mrb, h, "[]",              mrb_hash_aget,        MRB_ARGS_REQ(1)); /* 15.2.13.4.2  */
  mrb_define_method(mrb, h, "[]=",             mrb_hash_aset,        MRB_ARGS_REQ(2)); /* 15.2.13.4.3  */
  mrb_define_method(mrb, h, "clear",           mrb_hash_clear,       MRB_ARGS_NONE()); /* 15.2.13.4.4  */
  mrb_define_method(mrb, h, "default",         mrb_hash_default,     MRB_ARGS_ANY());  /* 15.2.13.4.5  */
  mrb_define_method(mrb, h, "default=",        mrb_hash_set_default, MRB_ARGS_REQ(1)); /* 15.2.13.4.6  */
  mrb_define_method(mrb, h, "default_proc",    mrb_hash_default_proc,MRB_ARGS_NONE()); /* 15.2.13.4.7  */
  mrb_define_method(mrb, h, "default_proc=",   mrb_hash_set_default_proc,MRB_ARGS_REQ(1)); /* 15.2.13.4.7  */
  mrb_define_method(mrb, h, "__delete",        mrb_hash_delete,      MRB_ARGS_REQ(1)); /* core of 15.2.13.4.8  */
  mrb_define_method(mrb, h, "empty?",          mrb_hash_empty_p,     MRB_ARGS_NONE()); /* 15.2.13.4.12 */
  mrb_define_method(mrb, h, "has_key?",        mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.13 */
  mrb_define_method(mrb, h, "has_value?",      mrb_hash_has_value,   MRB_ARGS_REQ(1)); /* 15.2.13.4.14 */
  mrb_define_method(mrb, h, "include?",        mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.15 */
  mrb_define_method(mrb, h, "initialize",      mrb_hash_init,        MRB_ARGS_OPT(1)); /* 15.2.13.4.16 */
  mrb_define_method(mrb, h, "key?",            mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.18 */
  mrb_define_method(mrb, h, "keys",            mrb_hash_keys,        MRB_ARGS_NONE()); /* 15.2.13.4.19 */
  mrb_define_method(mrb, h, "length",          mrb_hash_size_m,      MRB_ARGS_NONE()); /* 15.2.13.4.20 */
  mrb_define_method(mrb, h, "member?",         mrb_hash_has_key,     MRB_ARGS_REQ(1)); /* 15.2.13.4.21 */
  mrb_define_method(mrb, h, "shift",           mrb_hash_shift,       MRB_ARGS_NONE()); /* 15.2.13.4.24 */
  mrb_define_method(mrb, h, "dup",             mrb_hash_dup,         MRB_ARGS_NONE());
  mrb_define_method(mrb, h, "size",            mrb_hash_size_m,      MRB_ARGS_NONE()); /* 15.2.13.4.25 */
  mrb_define_method(mrb, h, "store",           mrb_hash_aset,        MRB_ARGS_REQ(2)); /* 15.2.13.4.26 */
  mrb_define_method(mrb, h, "value?",          mrb_hash_has_value,   MRB_ARGS_REQ(1)); /* 15.2.13.4.27 */
  mrb_define_method(mrb, h, "values",          mrb_hash_values,      MRB_ARGS_NONE()); /* 15.2.13.4.28 */

  mrb_define_method(mrb, h, "to_hash",         mrb_hash_to_hash,     MRB_ARGS_NONE()); /* 15.2.13.4.29 (x)*/
}
