/*
** mruby/string.h - String class
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

#define RSTRING_EMBED_LEN_MAX ((mrb_int)(sizeof(void*) * 3 - 1))

struct RString {
  MRB_OBJECT_HEADER;
  union {
    struct {
      mrb_int len;
      union {
        mrb_int capa;
        struct mrb_shared_string *shared;
      } aux;
      char *ptr;
    } heap;
    char ary[RSTRING_EMBED_LEN_MAX + 1];
  } as;
};

#define RSTR_EMBED_P(s) ((s)->flags & MRB_STR_EMBED)
#define RSTR_SET_EMBED_FLAG(s) ((s)->flags |= MRB_STR_EMBED)
#define RSTR_UNSET_EMBED_FLAG(s) ((s)->flags &= ~(MRB_STR_EMBED|MRB_STR_EMBED_LEN_MASK))
#define RSTR_SET_EMBED_LEN(s, n) do {\
  size_t tmp_n = (n);\
  s->flags &= ~MRB_STR_EMBED_LEN_MASK;\
  s->flags |= (tmp_n) << MRB_STR_EMBED_LEN_SHIFT;\
} while (0)
#define RSTR_SET_LEN(s, n) do {\
  if (RSTR_EMBED_P(s)) {\
    RSTR_SET_EMBED_LEN((s),(n));\
  } else {\
    s->as.heap.len = (mrb_int)(n);\
  }\
} while (0)
#define RSTR_EMBED_LEN(s)\
  (mrb_int)(((s)->flags & MRB_STR_EMBED_LEN_MASK) >> MRB_STR_EMBED_LEN_SHIFT)
#define RSTR_PTR(s) ((RSTR_EMBED_P(s)) ? (s)->as.ary : (s)->as.heap.ptr)
#define RSTR_LEN(s) ((RSTR_EMBED_P(s)) ? RSTR_EMBED_LEN(s) : (s)->as.heap.len)
#define RSTR_CAPA(s) (RSTR_EMBED_P(s) ? RSTRING_EMBED_LEN_MAX : (s)->as.heap.aux.capa)

#define RSTR_SHARED_P(s) ((s)->flags & MRB_STR_SHARED)
#define RSTR_SET_SHARED_FLAG(s) ((s)->flags |= MRB_STR_SHARED)
#define RSTR_UNSET_SHARED_FLAG(s) ((s)->flags &= ~MRB_STR_SHARED)

#define RSTR_NOFREE_P(s) ((s)->flags & MRB_STR_NOFREE)
#define RSTR_SET_NOFREE_FLAG(s) ((s)->flags |= MRB_STR_NOFREE)
#define RSTR_UNSET_NOFREE_FLAG(s) ((s)->flags &= ~MRB_STR_NOFREE)

/*
 * Returns a pointer from a Ruby string
 */
#define mrb_str_ptr(s)       ((struct RString*)(mrb_ptr(s)))
#define RSTRING(s)           mrb_str_ptr(s)
#define RSTRING_PTR(s)       RSTR_PTR(RSTRING(s))
#define RSTRING_EMBED_LEN(s) RSTR_ENBED_LEN(RSTRING(s))
#define RSTRING_LEN(s)       RSTR_LEN(RSTRING(s))
#define RSTRING_CAPA(s)      RSTR_CAPA(RSTRING(s))
#define RSTRING_END(s)       (RSTRING_PTR(s) + RSTRING_LEN(s))
MRB_API mrb_int mrb_str_strlen(mrb_state*, struct RString*);

#define MRB_STR_SHARED    1
#define MRB_STR_NOFREE    2
#define MRB_STR_NO_UTF    8
#define MRB_STR_EMBED    16
#define MRB_STR_EMBED_LEN_MASK 0x3e0
#define MRB_STR_EMBED_LEN_SHIFT 5

void mrb_gc_free_str(mrb_state*, struct RString*);
MRB_API void mrb_str_modify(mrb_state*, struct RString*);
/*
 * Appends self to other. Returns self as a concatnated string.
 *
 *
 *  Example:
 *
 *     !!!c
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
 *       // Concatnates str2 to str1.
 *       mrb_str_concat(mrb, str1, str2);
 *
 *      // Prints new Concatnated Ruby string.
 *      mrb_p(mrb, str1);
 *
 *      mrb_close(mrb);
 *      return 0;
 *    }
 *
 *
 *  Result:
 *
 *     => "abcdef"
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] self String to concatenate.
 * @param [mrb_value] other String to append to self.
 * @return [mrb_value] Returns a new String appending other to self.
 */
MRB_API void mrb_str_concat(mrb_state*, mrb_value, mrb_value);

/*
 * Adds two strings together.
 *
 *
 *  Example:
 *
 *     !!!c
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
 *       // Concatnates both Ruby strings.
 *       c = mrb_str_plus(mrb, a, b);
 *
 *      // Prints new Concatnated Ruby string.
 *      mrb_p(mrb, c);
 *
 *      mrb_close(mrb);
 *      return 0;
 *    }
 *
 *
 *  Result:
 *
 *     => "abc"  # First string
 *     => "def"  # Second string
 *     => "abcdef" # First & Second concatnated.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] a First string to concatenate.
 * @param [mrb_value] b Second string to concatenate.
 * @return [mrb_value] Returns a new String containing a concatenated to b.
 */
MRB_API mrb_value mrb_str_plus(mrb_state*, mrb_value, mrb_value);

/*
 * Converts pointer into a Ruby string.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [void*] p The pointer to convert to Ruby string.
 * @return [mrb_value] Returns a new Ruby String.
 */
MRB_API mrb_value mrb_ptr_to_str(mrb_state *, void*);

/*
 * Returns an object as a Ruby string.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] obj An object to return as a Ruby string.
 * @return [mrb_value] An object as a Ruby string.
 */
MRB_API mrb_value mrb_obj_as_string(mrb_state *mrb, mrb_value obj);

/*
 * Resizes the string's length. Returns the amount of characters
 * in the specified by len.
 *
 * Example:
 *
 *     !!!c
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
 *     => "Hello"
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str The Ruby string to resize.
 * @param [mrb_value] len The length.
 * @return [mrb_value] An object as a Ruby string.
 */
MRB_API mrb_value mrb_str_resize(mrb_state *mrb, mrb_value str, mrb_int len);

/*
 * Returns a sub string.
 *
 *  Example:
 *
 *     !!!c
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
 *  Result:
 *
 *     => "He"
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str Ruby string.
 * @param [mrb_int] beg The beginning point of the sub-string.
 * @param [mrb_int] len The end point of the sub-string.
 * @return [mrb_value] An object as a Ruby sub-string.
 */
MRB_API mrb_value mrb_str_substr(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len);

/*
 * Returns a Ruby string type.
 *
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str Ruby string.
 * @return [mrb_value] A Ruby string.
 */
MRB_API mrb_value mrb_string_type(mrb_state *mrb, mrb_value str);

MRB_API mrb_value mrb_check_string_type(mrb_state *mrb, mrb_value str);
MRB_API mrb_value mrb_str_buf_new(mrb_state *mrb, size_t capa);

MRB_API const char *mrb_string_value_cstr(mrb_state *mrb, mrb_value *ptr);
MRB_API const char *mrb_string_value_ptr(mrb_state *mrb, mrb_value str);
/*
 * Returns the length of the Ruby string.
 *
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str Ruby string.
 * @return [mrb_int] The length of the passed in Ruby string.
 */
MRB_API mrb_int mrb_string_value_len(mrb_state *mrb, mrb_value str);

/*
 * Duplicates a string object.
 *
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str Ruby string.
 * @return [mrb_value] Duplicated Ruby string.
 */
MRB_API mrb_value mrb_str_dup(mrb_state *mrb, mrb_value str);

/*
 * Returns a symbol from a passed in Ruby string.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] self Ruby string.
 * @return [mrb_value] A symbol.
 */
MRB_API mrb_value mrb_str_intern(mrb_state *mrb, mrb_value self);

MRB_API mrb_value mrb_str_to_inum(mrb_state *mrb, mrb_value str, mrb_int base, mrb_bool badcheck);
MRB_API double mrb_str_to_dbl(mrb_state *mrb, mrb_value str, mrb_bool badcheck);

/*
 * Returns a converted string type.
 */
MRB_API mrb_value mrb_str_to_str(mrb_state *mrb, mrb_value str);

/*
 * Returns true if the strings match and false if the strings don't match.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str1 Ruby string to compare.
 * @param [mrb_value] str2 Ruby string to compare.
 * @return [mrb_value] boolean value.
 */
MRB_API mrb_bool mrb_str_equal(mrb_state *mrb, mrb_value str1, mrb_value str2);

/*
 * Returns a concated string comprised of a Ruby string and a C string.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str Ruby string.
 * @param [const char *] ptr A C string.
 * @param [size_t] len length of C string.
 * @return [mrb_value] A Ruby string.
 * @see mrb_str_cat_cstr
 */
MRB_API mrb_value mrb_str_cat(mrb_state *mrb, mrb_value str, const char *ptr, size_t len);

/*
 * Returns a concated string comprised of a Ruby string and a C string.
 *
 * @param [mrb_state] mrb The current mruby state.
 * @param [mrb_value] str Ruby string.
 * @param [const char *] ptr A C string.
 * @return [mrb_value] A Ruby string.
 * @see mrb_str_cat
 */
MRB_API mrb_value mrb_str_cat_cstr(mrb_state *mrb, mrb_value str, const char *ptr);
MRB_API mrb_value mrb_str_cat_str(mrb_state *mrb, mrb_value str, mrb_value str2);
#define mrb_str_cat_lit(mrb, str, lit) mrb_str_cat(mrb, str, lit, mrb_strlen_lit(lit))

/*
 * Adds str2 to the end of str1.
 */
MRB_API mrb_value mrb_str_append(mrb_state *mrb, mrb_value str, mrb_value str2);

/*
 * Returns 0 if both Ruby strings are equal. Returns a value < 0 if Ruby str1 is less than Ruby str2. Returns a value > 0 if Ruby str2 is greater than Ruby str1.
 */
MRB_API int mrb_str_cmp(mrb_state *mrb, mrb_value str1, mrb_value str2);

/*
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
 * @param [mrb_state *] mrb The current mruby state.
 * @param [mrb_value] str Ruby string. Must be an instance of String.
 * @return [char *] A newly allocated C string.
 */
MRB_API char *mrb_str_to_cstr(mrb_state *mrb, mrb_value str);

mrb_value mrb_str_pool(mrb_state *mrb, mrb_value str);
mrb_int mrb_str_hash(mrb_state *mrb, mrb_value str);
mrb_value mrb_str_dump(mrb_state *mrb, mrb_value str);

/*
 * Returns a printable version of str, surrounded by quote marks, with special characters escaped.
 */
mrb_value mrb_str_inspect(mrb_state *mrb, mrb_value str);

void mrb_noregexp(mrb_state *mrb, mrb_value self);
void mrb_regexp_check(mrb_state *mrb, mrb_value obj);

/* For backward compatibility */
#define mrb_str_cat2(mrb, str, ptr) mrb_str_cat_cstr(mrb, str, ptr)
#define mrb_str_buf_cat(mrb, str, ptr, len) mrb_str_cat(mrb, str, ptr, len)
#define mrb_str_buf_append(mrb, str, str2) mrb_str_cat_str(mrb, str, str2)

MRB_END_DECL

#endif  /* MRUBY_STRING_H */
