/**
** @file mruby/string.h - String class
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_STRING_H
#define MRUBY_STRING_H

#include "common.h"

/**
 * String class
 */
MRB_BEGIN_DECL

extern const char mrb_digitmap[];

#define RSTRING_EMBED_LEN_MAX \
  ((mrb_int)(sizeof(void*) * 3 + sizeof(void*) - 32 / CHAR_BIT - 1))

struct RString {
  MRB_OBJECT_HEADER;
  union {
    struct {
      mrb_ssize len;
      union {
        mrb_ssize capa;
        struct mrb_shared_string *shared;
        struct RString *fshared;
      } aux;
      char *ptr;
    } heap;
  } as;
};
struct RStringEmbed {
  MRB_OBJECT_HEADER;
  char ary[];
};

#define RSTR_SET_TYPE_FLAG(s, type) (RSTR_UNSET_TYPE_FLAG(s), (s)->flags |= MRB_STR_##type)
#define RSTR_UNSET_TYPE_FLAG(s) ((s)->flags &= ~(MRB_STR_TYPE_MASK|MRB_STR_EMBED_LEN_MASK))

#define RSTR_EMBED_P(s) ((s)->flags & MRB_STR_EMBED)
#define RSTR_SET_EMBED_FLAG(s) ((s)->flags |= MRB_STR_EMBED)
#define RSTR_UNSET_EMBED_FLAG(s) ((s)->flags &= ~(MRB_STR_EMBED|MRB_STR_EMBED_LEN_MASK))
#define RSTR_SET_EMBED_LEN(s, n) do {\
  size_t tmp_n = (n);\
  (s)->flags &= ~MRB_STR_EMBED_LEN_MASK;\
  (s)->flags |= (tmp_n) << MRB_STR_EMBED_LEN_SHIFT;\
} while (0)
#define RSTR_SET_LEN(s, n) do {\
  if (RSTR_EMBED_P(s)) {\
    RSTR_SET_EMBED_LEN((s),(n));\
  }\
  else {\
    (s)->as.heap.len = (mrb_ssize)(n);\
  }\
} while (0)
#define RSTR_EMBED_PTR(s) (((struct RStringEmbed*)(s))->ary)
#define RSTR_EMBED_LEN(s)\
  (mrb_int)(((s)->flags & MRB_STR_EMBED_LEN_MASK) >> MRB_STR_EMBED_LEN_SHIFT)
#define RSTR_EMBEDDABLE_P(len) ((len) <= RSTRING_EMBED_LEN_MAX)

#define RSTR_PTR(s) ((RSTR_EMBED_P(s)) ? RSTR_EMBED_PTR(s) : (s)->as.heap.ptr)
#define RSTR_LEN(s) ((RSTR_EMBED_P(s)) ? RSTR_EMBED_LEN(s) : (s)->as.heap.len)
#define RSTR_CAPA(s) (RSTR_EMBED_P(s) ? RSTRING_EMBED_LEN_MAX : (s)->as.heap.aux.capa)

#define RSTR_SHARED_P(s) ((s)->flags & MRB_STR_SHARED)
#define RSTR_SET_SHARED_FLAG(s) ((s)->flags |= MRB_STR_SHARED)
#define RSTR_UNSET_SHARED_FLAG(s) ((s)->flags &= ~MRB_STR_SHARED)

#define RSTR_FSHARED_P(s) ((s)->flags & MRB_STR_FSHARED)
#define RSTR_SET_FSHARED_FLAG(s) ((s)->flags |= MRB_STR_FSHARED)
#define RSTR_UNSET_FSHARED_FLAG(s) ((s)->flags &= ~MRB_STR_FSHARED)

#define RSTR_NOFREE_P(s) ((s)->flags & MRB_STR_NOFREE)
#define RSTR_SET_NOFREE_FLAG(s) ((s)->flags |= MRB_STR_NOFREE)
#define RSTR_UNSET_NOFREE_FLAG(s) ((s)->flags &= ~MRB_STR_NOFREE)

#ifdef MRB_UTF8_STRING
# define RSTR_ASCII_P(s) ((s)->flags & MRB_STR_ASCII)
# define RSTR_SET_ASCII_FLAG(s) ((s)->flags |= MRB_STR_ASCII)
# define RSTR_UNSET_ASCII_FLAG(s) ((s)->flags &= ~MRB_STR_ASCII)
# define RSTR_WRITE_ASCII_FLAG(s, v) (RSTR_UNSET_ASCII_FLAG(s), (s)->flags |= v)
# define RSTR_COPY_ASCII_FLAG(dst, src) RSTR_WRITE_ASCII_FLAG(dst, RSTR_ASCII_P(src))
#else
# define RSTR_ASCII_P(s) (void)0
# define RSTR_SET_ASCII_FLAG(s) (void)0
# define RSTR_UNSET_ASCII_FLAG(s) (void)0
# define RSTR_WRITE_ASCII_FLAG(s, v) (void)0
# define RSTR_COPY_ASCII_FLAG(dst, src) (void)0
#endif

#define RSTR_POOL_P(s) ((s)->flags & MRB_STR_POOL)
#define RSTR_SET_POOL_FLAG(s) ((s)->flags |= MRB_STR_POOL)

/**
 * Returns a pointer from a Ruby string
 */
#define mrb_str_ptr(s)       ((struct RString*)(mrb_ptr(s)))
#define RSTRING(s)           mrb_str_ptr(s)
#define RSTRING_PTR(s)       RSTR_PTR(RSTRING(s))
#define RSTRING_EMBED_LEN(s) RSTR_EMBED_LEN(RSTRING(s))
#define RSTRING_LEN(s)       RSTR_LEN(RSTRING(s))
#define RSTRING_CAPA(s)      RSTR_CAPA(RSTRING(s))
#define RSTRING_END(s)       (RSTRING_PTR(s) + RSTRING_LEN(s))
MRB_API mrb_int mrb_str_strlen(mrb_state*, struct RString*);
#define RSTRING_CSTR(mrb,s)  mrb_string_cstr(mrb, s)

#define MRB_STR_SHARED    1
#define MRB_STR_FSHARED   2
#define MRB_STR_NOFREE    4
#define MRB_STR_EMBED     8  /* type flags up to here */
#define MRB_STR_POOL     16  /* status flags from here */
#define MRB_STR_ASCII    32
#define MRB_STR_EMBED_LEN_SHIFT 6
#define MRB_STR_EMBED_LEN_BIT 5
#define MRB_STR_EMBED_LEN_MASK (((1 << MRB_STR_EMBED_LEN_BIT) - 1) << MRB_STR_EMBED_LEN_SHIFT)
#define MRB_STR_TYPE_MASK (MRB_STR_POOL - 1)


void mrb_gc_free_str(mrb_state*, struct RString*);

MRB_API void mrb_str_modify(mrb_state *mrb, struct RString *s);
/* mrb_str_modify() with keeping ASCII flag if set */
MRB_API void mrb_str_modify_keep_ascii(mrb_state *mrb, struct RString *s);

/**
 * Finds the index of a substring in a string
 */
MRB_API mrb_int mrb_str_index(mrb_state *mrb, mrb_value str, const char *p, mrb_int len, mrb_int offset);
#define mrb_str_index_lit(mrb, str, lit, off) mrb_str_index(mrb, str, lit, mrb_strlen_lit(lit), off);

/**
 * Appends self to other. Returns self as a concatenated string.
 *
 *
 * Example:
 *
 *     int
 *     main(int argc,
 *          char **argv)
 *     {
 *       // Variable declarations.
 *       mrb_value str1;
 *       mrb_value str2;
 *
 *       mrb_state *mrb = mrb_open();
 *       if (!mrb)
 *       {
 *          // handle error
 *       }
 *
 *       // Creates new Ruby strings.
 *       str1 = mrb_str_new_lit(mrb, "abc");
 *       str2 = mrb_str_new_lit(mrb, "def");
 *
 *       // Concatenates str2 to str1.
 *       mrb_str_concat(mrb, str1, str2);
 *
 *       // Prints new Concatenated Ruby string.
 *       mrb_p(mrb, str1);
 *
 *       mrb_close(mrb);
 *       return 0;
 *     } 
 *
 * Result:
 *
 *     => "abcdef"
 *
 * @param mrb The current mruby state.
 * @param self String to concatenate.
 * @param other String to append to self.
 * @return [mrb_value] Returns a new String appending other to self.
 */
MRB_API void mrb_str_concat(mrb_state *mrb, mrb_value self, mrb_value other);

/**
 * Adds two strings together.
 *
 *
 * Example:
 *
 *     int
 *     main(int argc,
 *          char **argv)
 *     {
 *       // Variable declarations.
 *       mrb_value a;
 *       mrb_value b;
 *       mrb_value c;
 *
 *       mrb_state *mrb = mrb_open();
 *       if (!mrb)
 *       {
 *          // handle error
 *       }
 *
 *       // Creates two Ruby strings from the passed in C strings.
 *       a = mrb_str_new_lit(mrb, "abc");
 *       b = mrb_str_new_lit(mrb, "def");
 *
 *       // Prints both C strings.
 *       mrb_p(mrb, a);
 *       mrb_p(mrb, b);
 *
 *       // Concatenates both Ruby strings.
 *       c = mrb_str_plus(mrb, a, b);
 *
 *       // Prints new Concatenated Ruby string.
 *       mrb_p(mrb, c);
 *
 *       mrb_close(mrb);
 *       return 0;
 *     }
 *
 *
 * Result:
 *
 *     => "abc"  # First string
 *     => "def"  # Second string
 *     => "abcdef" # First & Second concatenated.
 *
 * @param mrb The current mruby state.
 * @param a First string to concatenate.
 * @param b Second string to concatenate.
 * @return [mrb_value] Returns a new String containing a concatenated to b.
 */
MRB_API mrb_value mrb_str_plus(mrb_state *mrb, mrb_value a, mrb_value b);

/**
 * Converts pointer into a Ruby string.
 *
 * @param mrb The current mruby state.
 * @param p The pointer to convert to Ruby string.
 * @return [mrb_value] Returns a new Ruby String.
 */
MRB_API mrb_value mrb_ptr_to_str(mrb_state *mrb, void *p);

/**
 * Returns an object as a Ruby string.
 *
 * @param mrb The current mruby state.
 * @param obj An object to return as a Ruby string.
 * @return [mrb_value] An object as a Ruby string.
 */
MRB_API mrb_value mrb_obj_as_string(mrb_state *mrb, mrb_value obj);

/**
 * Resizes the string's length. Returns the amount of characters
 * in the specified by len.
 *
 * Example:
 *
 *     int
 *     main(int argc,
 *          char **argv)
 *     {
 *         // Variable declaration.
 *         mrb_value str;
 *
 *         mrb_state *mrb = mrb_open();
 *         if (!mrb)
 *         {
 *            // handle error
 *         }
 *         // Creates a new string.
 *         str = mrb_str_new_lit(mrb, "Hello, world!");
 *         // Returns 5 characters of
 *         mrb_str_resize(mrb, str, 5);
 *         mrb_p(mrb, str);
 *
 *         mrb_close(mrb);
 *         return 0;
 *      }
 *
 * Result:
 *
 *      => "Hello"
 *
 * @param mrb The current mruby state.
 * @param str The Ruby string to resize.
 * @param len The length.
 * @return [mrb_value] An object as a Ruby string.
 */
MRB_API mrb_value mrb_str_resize(mrb_state *mrb, mrb_value str, mrb_int len);

/**
 * Returns a sub string.
 *
 * Example:
 *
 *     int
 *     main(int argc,
 *     char const **argv)
 *     {
 *       // Variable declarations.
 *       mrb_value str1;
 *       mrb_value str2;
 *
 *       mrb_state *mrb = mrb_open();
 *       if (!mrb)
 *       {
 *         // handle error
 *       }
 *       // Creates new string.
 *       str1 = mrb_str_new_lit(mrb, "Hello, world!");
 *       // Returns a sub-string within the range of 0..2
 *       str2 = mrb_str_substr(mrb, str1, 0, 2);
 *
 *       // Prints sub-string.
 *       mrb_p(mrb, str2);
 *
 *       mrb_close(mrb);
 *       return 0;
 *     }
 *
 * Result:
 *
 *     => "He"
 *
 * @param mrb The current mruby state.
 * @param str Ruby string.
 * @param beg The beginning point of the sub-string.
 * @param len The end point of the sub-string.
 * @return [mrb_value] An object as a Ruby sub-string.
 */
MRB_API mrb_value mrb_str_substr(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len);

/**
 * Returns a Ruby string type.
 *
 *
 * @param mrb The current mruby state.
 * @param str Ruby string.
 * @return [mrb_value] A Ruby string.
 */
MRB_API mrb_value mrb_ensure_string_type(mrb_state *mrb, mrb_value str);
MRB_API mrb_value mrb_check_string_type(mrb_state *mrb, mrb_value str);
/* obsolete: use mrb_ensure_string_type() instead */
MRB_API mrb_value mrb_string_type(mrb_state *mrb, mrb_value str);


MRB_API mrb_value mrb_str_new_capa(mrb_state *mrb, size_t capa);
MRB_API mrb_value mrb_str_buf_new(mrb_state *mrb, size_t capa);

/* NULL terminated C string from mrb_value */
MRB_API const char *mrb_string_cstr(mrb_state *mrb, mrb_value str);
/* NULL terminated C string from mrb_value; `str` will be updated */
MRB_API const char *mrb_string_value_cstr(mrb_state *mrb, mrb_value *str);
/* obslete: use RSTRING_PTR() */
MRB_API const char *mrb_string_value_ptr(mrb_state *mrb, mrb_value str);
/* obslete: use RSTRING_LEN() */
MRB_API mrb_int mrb_string_value_len(mrb_state *mrb, mrb_value str);

/**
 * Duplicates a string object.
 *
 *
 * @param mrb The current mruby state.
 * @param str Ruby string.
 * @return [mrb_value] Duplicated Ruby string.
 */
MRB_API mrb_value mrb_str_dup(mrb_state *mrb, mrb_value str);

/**
 * Returns a symbol from a passed in Ruby string.
 *
 * @param mrb The current mruby state.
 * @param self Ruby string.
 * @return [mrb_value] A symbol.
 */
MRB_API mrb_value mrb_str_intern(mrb_state *mrb, mrb_value self);

MRB_API mrb_value mrb_str_to_inum(mrb_state *mrb, mrb_value str, mrb_int base, mrb_bool badcheck);
MRB_API mrb_value mrb_cstr_to_inum(mrb_state *mrb, const char *s, mrb_int base, mrb_bool badcheck);
MRB_API double mrb_str_to_dbl(mrb_state *mrb, mrb_value str, mrb_bool badcheck);
MRB_API double mrb_cstr_to_dbl(mrb_state *mrb, const char *s, mrb_bool badcheck);

/**
 * Returns a converted string type.
 * For type checking, non converting `mrb_to_str` is recommended.
 */
MRB_API mrb_value mrb_str_to_str(mrb_state *mrb, mrb_value str);

/**
 * Returns true if the strings match and false if the strings don't match.
 *
 * @param mrb The current mruby state.
 * @param str1 Ruby string to compare.
 * @param str2 Ruby string to compare.
 * @return [mrb_value] boolean value.
 */
MRB_API mrb_bool mrb_str_equal(mrb_state *mrb, mrb_value str1, mrb_value str2);

/**
 * Returns a concatenated string comprised of a Ruby string and a C string.
 *
 * @param mrb The current mruby state.
 * @param str Ruby string.
 * @param ptr A C string.
 * @param len length of C string.
 * @return [mrb_value] A Ruby string.
 * @see mrb_str_cat_cstr
 */
MRB_API mrb_value mrb_str_cat(mrb_state *mrb, mrb_value str, const char *ptr, size_t len);

/**
 * Returns a concatenated string comprised of a Ruby string and a C string.
 *
 * @param mrb The current mruby state.
 * @param str Ruby string.
 * @param ptr A C string.
 * @return [mrb_value] A Ruby string.
 * @see mrb_str_cat
 */
MRB_API mrb_value mrb_str_cat_cstr(mrb_state *mrb, mrb_value str, const char *ptr);
MRB_API mrb_value mrb_str_cat_str(mrb_state *mrb, mrb_value str, mrb_value str2);
#define mrb_str_cat_lit(mrb, str, lit) mrb_str_cat(mrb, str, lit, mrb_strlen_lit(lit))

/**
 * Adds str2 to the end of str1.
 */
MRB_API mrb_value mrb_str_append(mrb_state *mrb, mrb_value str, mrb_value str2);

/**
 * Returns 0 if both Ruby strings are equal. Returns a value < 0 if Ruby str1 is less than Ruby str2. Returns a value > 0 if Ruby str2 is greater than Ruby str1.
 */
MRB_API int mrb_str_cmp(mrb_state *mrb, mrb_value str1, mrb_value str2);

/**
 * Returns a newly allocated C string from a Ruby string.
 * This is an utility function to pass a Ruby string to C library functions.
 *
 * - Returned string does not contain any NUL characters (but terminator).
 * - It raises an ArgumentError exception if Ruby string contains
 *   NUL characters.
 * - Retured string will be freed automatically on next GC.
 * - Caller can modify returned string without affecting Ruby string
 *   (e.g. it can be used for mkstemp(3)).
 *
 * @param mrb The current mruby state.
 * @param str Ruby string. Must be an instance of String.
 * @return [char *] A newly allocated C string.
 */
MRB_API char *mrb_str_to_cstr(mrb_state *mrb, mrb_value str);

mrb_value mrb_str_pool(mrb_state *mrb, const char *s, mrb_int len, mrb_bool nofree);
uint32_t mrb_str_hash(mrb_state *mrb, mrb_value str);
mrb_value mrb_str_dump(mrb_state *mrb, mrb_value str);

/**
 * Returns a printable version of str, surrounded by quote marks, with special characters escaped.
 */
mrb_value mrb_str_inspect(mrb_state *mrb, mrb_value str);

/* For backward compatibility */
#define mrb_str_cat2(mrb, str, ptr) mrb_str_cat_cstr(mrb, str, ptr)
#define mrb_str_buf_cat(mrb, str, ptr, len) mrb_str_cat(mrb, str, ptr, len)
#define mrb_str_buf_append(mrb, str, str2) mrb_str_cat_str(mrb, str, str2)

mrb_bool mrb_str_beg_len(mrb_int str_len, mrb_int *begp, mrb_int *lenp);
mrb_value mrb_str_byte_subseq(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len);

#ifdef MRB_UTF8_STRING
mrb_int mrb_utf8len(const char *str, const char *end);
mrb_int mrb_utf8_strlen(const char *str, mrb_int byte_len);
#endif

MRB_END_DECL

#endif  /* MRUBY_STRING_H */
