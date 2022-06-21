/**
** @file mruby/hash.h - Hash class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_HASH_H
#define MRUBY_HASH_H

#include "common.h"

/**
 * Hash class
 */
MRB_BEGIN_DECL

/* offset of `iv` must be 3 words */
struct RHash {
  MRB_OBJECT_HEADER;
#ifdef MRB_64BIT
  uint32_t size;
  struct iv_tbl *iv;
  uint32_t ea_capa;
  uint32_t ea_n_used;
#else
  struct iv_tbl *iv;
  uint32_t size;
#endif
  union {
    struct hash_entry *ea;
    struct hash_table *ht;
  } hsh;
};

#define mrb_hash_ptr(v)    ((struct RHash*)(mrb_ptr(v)))
#define mrb_hash_value(p)  mrb_obj_value((void*)(p))

size_t mrb_hash_memsize(mrb_value obj);
MRB_API mrb_value mrb_hash_new_capa(mrb_state *mrb, mrb_int capa);

/*
 * Initializes a new hash.
 *
 * Equivalent to:
 *
 *      Hash.new
 *
 * @param mrb The mruby state reference.
 * @return The initialized hash.
 */
MRB_API mrb_value mrb_hash_new(mrb_state *mrb);

/*
 * Sets a keys and values to hashes.
 *
 * Equivalent to:
 *
 *      hash[key] = val
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to set.
 * @param val The value to set.
 * @return The value.
 */
MRB_API void mrb_hash_set(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value val);

/*
 * Gets a value from a key. If the key is not found, the default of the
 * hash is used.
 *
 * Equivalent to:
 *
 *     hash[key]
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to get.
 * @return The found value.
 */
MRB_API mrb_value mrb_hash_get(mrb_state *mrb, mrb_value hash, mrb_value key);

/*
 * Gets a value from a key. If the key is not found, the default parameter is
 * used.
 *
 * Equivalent to:
 *
 *     hash.key?(key) ? hash[key] : def
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to get.
 * @param def The default value.
 * @return The found value.
 */
MRB_API mrb_value mrb_hash_fetch(mrb_state *mrb, mrb_value hash, mrb_value key, mrb_value def);

/*
 * Deletes hash key and value pair.
 *
 * Equivalent to:
 *
 *     hash.delete(key)
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to delete.
 * @return The deleted value. This value is not protected from GC. Use `mrb_gc_protect()` if necessary.
 */
MRB_API mrb_value mrb_hash_delete_key(mrb_state *mrb, mrb_value hash, mrb_value key);

/*
 * Gets an array of keys.
 *
 * Equivalent to:
 *
 *     hash.keys
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return An array with the keys of the hash.
 */
MRB_API mrb_value mrb_hash_keys(mrb_state *mrb, mrb_value hash);
/*
 * Check if the hash has the key.
 *
 * Equivalent to:
 *
 *     hash.key?(key)
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @param key The key to check existence.
 * @return True if the hash has the key
 */
MRB_API mrb_bool mrb_hash_key_p(mrb_state *mrb, mrb_value hash, mrb_value key);

/*
 * Check if the hash is empty
 *
 * Equivalent to:
 *
 *     hash.empty?
 *
 * @param mrb The mruby state reference.
 * @param self The target hash.
 * @return True if the hash is empty, false otherwise.
 */
MRB_API mrb_bool mrb_hash_empty_p(mrb_state *mrb, mrb_value self);

/*
 * Gets an array of values.
 *
 * Equivalent to:
 *
 *     hash.values
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return An array with the values of the hash.
 */
MRB_API mrb_value mrb_hash_values(mrb_state *mrb, mrb_value hash);

/*
 * Clears the hash.
 *
 * Equivalent to:
 *
 *     hash.clear
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return The hash
 */
MRB_API mrb_value mrb_hash_clear(mrb_state *mrb, mrb_value hash);

/*
 * Get hash size.
 *
 * Equivalent to:
 *
 *      hash.size
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return The hash size.
 */
MRB_API mrb_int mrb_hash_size(mrb_state *mrb, mrb_value hash);

/*
 * Copies the hash. This function does NOT copy the instance variables
 * (except for the default value). Use mrb_obj_dup() to copy the instance
 * variables as well.
 *
 * @param mrb The mruby state reference.
 * @param hash The target hash.
 * @return The copy of the hash
 */
MRB_API mrb_value mrb_hash_dup(mrb_state *mrb, mrb_value hash);

/*
 * Merges two hashes. The first hash will be modified by the
 * second hash.
 *
 * @param mrb The mruby state reference.
 * @param hash1 The target hash.
 * @param hash2 Updating hash
 */
MRB_API void mrb_hash_merge(mrb_state *mrb, mrb_value hash1, mrb_value hash2);

#define RHASH(hash) ((struct RHash*)(mrb_ptr(hash)))

#define MRB_HASH_IB_BIT_BIT         5
#define MRB_HASH_AR_EA_CAPA_BIT     5
#define MRB_HASH_IB_BIT_SHIFT       0
#define MRB_HASH_AR_EA_CAPA_SHIFT   0
#define MRB_HASH_AR_EA_N_USED_SHIFT MRB_HASH_AR_EA_CAPA_BIT
#define MRB_HASH_SIZE_FLAGS_SHIFT   (MRB_HASH_AR_EA_CAPA_BIT * 2)
#define MRB_HASH_IB_BIT_MASK        ((1 << MRB_HASH_IB_BIT_BIT) - 1)
#define MRB_HASH_AR_EA_CAPA_MASK    ((1 << MRB_HASH_AR_EA_CAPA_BIT) - 1)
#define MRB_HASH_AR_EA_N_USED_MASK  (MRB_HASH_AR_EA_CAPA_MASK << MRB_HASH_AR_EA_N_USED_SHIFT)
#define MRB_HASH_DEFAULT            (1 << (MRB_HASH_SIZE_FLAGS_SHIFT + 0))
#define MRB_HASH_PROC_DEFAULT       (1 << (MRB_HASH_SIZE_FLAGS_SHIFT + 1))
#define MRB_HASH_HT                 (1 << (MRB_HASH_SIZE_FLAGS_SHIFT + 2))
#define MRB_RHASH_DEFAULT_P(hash) (RHASH(hash)->flags & MRB_HASH_DEFAULT)
#define MRB_RHASH_PROCDEFAULT_P(hash) (RHASH(hash)->flags & MRB_HASH_PROC_DEFAULT)

/* GC functions */
void mrb_gc_mark_hash(mrb_state*, struct RHash*);
size_t mrb_gc_mark_hash_size(mrb_state*, struct RHash*);
void mrb_gc_free_hash(mrb_state*, struct RHash*);

/* return non zero to break the loop */
typedef int (mrb_hash_foreach_func)(mrb_state *mrb, mrb_value key, mrb_value val, void *data);
MRB_API void mrb_hash_foreach(mrb_state *mrb, struct RHash *hash, mrb_hash_foreach_func *func, void *p);

MRB_END_DECL

#endif  /* MRUBY_HASH_H */
