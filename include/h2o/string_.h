/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef h2o__string_h
#define h2o__string_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "h2o/memory.h"

#define H2O_STRLIT(s) (s), sizeof(s) - 1

#define H2O_INT16_LONGEST_STR "-32768"
#define H2O_UINT16_LONGEST_STR "65535"
#define H2O_INT32_LONGEST_STR "-2147483648"
#define H2O_UINT32_LONGEST_STR "4294967295"
#define H2O_INT64_LONGEST_STR "-9223372036854775808"
#define H2O_UINT64_LONGEST_STR "18446744073709551615"

/**
 * duplicates given string
 * @param pool memory pool (or NULL to use malloc)
 * @param s source string
 * @param len length of the source string (the result of strlen(s) used in case len is SIZE_MAX)
 * @return buffer pointing to the duplicated string (buf is NUL-terminated but the length does not include the NUL char)
 */
h2o_iovec_t h2o_strdup(h2o_mem_pool_t *pool, const char *s, size_t len);
/**
 * variant of h2o_strdup that calls h2o_mem_alloc_shared
 */
h2o_iovec_t h2o_strdup_shared(h2o_mem_pool_t *pool, const char *s, size_t len);
/**
 * duplicates given string appending '/' to the tail if not found
 */
h2o_iovec_t h2o_strdup_slashed(h2o_mem_pool_t *pool, const char *s, size_t len);
/**
 * tr/A-Z/a-z/
 */
static int h2o_tolower(int ch);
/**
 * tr/A-Z/a-z/
 */
static void h2o_strtolower(char *s, size_t len);
/**
 * tr/a-z/A-Z/
 */
static int h2o_toupper(int ch);
/**
 * tr/a-z/A-Z/
 */
static void h2o_strtoupper(char *s, size_t len);
/**
 * tests if target string (target_len bytes long) is equal to test string (test_len bytes long) after being converted to lower-case
 */
static int h2o_lcstris(const char *target, size_t target_len, const char *test, size_t test_len);
/**
 * turns the length of a string into the length of the same string encoded in base64
 */
static size_t h2o_base64_encode_capacity(size_t len);
/**
 * parses a positive number of return SIZE_MAX if failed
 */
size_t h2o_strtosize(const char *s, size_t len);
/**
 * parses first positive number contained in *s or return SIZE_MAX if failed.
 * *s will set to right after the number in string or right after the end of string.
 */
size_t h2o_strtosizefwd(char **s, size_t len);
/**
 * base64 url decoder
 */
h2o_iovec_t h2o_decode_base64url(h2o_mem_pool_t *pool, const char *src, size_t len);
/**
 * base64 encoder (note: the function emits trailing '\0')
 */
size_t h2o_base64_encode(char *dst, const void *src, size_t len, int url_encoded);
/**
 * decodes hexadecimal string
 */
int h2o_hex_decode(void *dst, const char *src, size_t src_len);
/**
 * encodes binary into a hexadecimal string (with '\0' appended at last)
 */
void h2o_hex_encode(char *dst, const void *src, size_t src_len);
/**
 * URI-ecsapes given string (as defined in RFC 3986)
 */
h2o_iovec_t h2o_uri_escape(h2o_mem_pool_t *pool, const char *s, size_t l, const char *preserve_chars);
/**
 * returns the extension portion of path
 */
h2o_iovec_t h2o_get_filext(const char *path, size_t len);
/**
 * returns a vector with surrounding WS stripped
 */
h2o_iovec_t h2o_str_stripws(const char *s, size_t len);
/**
 * returns the offset of given substring or SIZE_MAX if not found
 */
size_t h2o_strstr(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len);
/**
 *
 */
const char *h2o_next_token(h2o_iovec_t *iter, int separator, size_t *element_len, h2o_iovec_t *value);
/**
 * tests if string needle exists within a separator-separated string (for handling "#rule" of RFC 2616)
 */
int h2o_contains_token(const char *haysack, size_t haysack_len, const char *needle, size_t needle_len, int separator);
/**
 * HTML-escapes a string
 * @param pool memory pool
 * @param src source string
 * @param len source length
 * @return the escaped string, or the source itself if escape was not necessary
 */
h2o_iovec_t h2o_htmlescape(h2o_mem_pool_t *pool, const char *src, size_t len);
/**
 * concatenates a list of iovecs (with NUL termination)
 */
#define h2o_concat(pool, ...)                                                                                                      \
    h2o_concat_list(pool, (h2o_iovec_t[]){__VA_ARGS__}, sizeof((h2o_iovec_t[]){__VA_ARGS__}) / sizeof(h2o_iovec_t))
h2o_iovec_t h2o_concat_list(h2o_mem_pool_t *pool, h2o_iovec_t *list, size_t count);
/**
 * emits a two-line string to buf that graphically points to given location within the source string
 * @return 0 if successful
 */
int h2o_str_at_position(char *buf, const char *src, size_t src_len, int lineno, int column);

int h2o__lcstris_core(const char *target, const char *test, size_t test_len);

/* inline defs */

inline int h2o_tolower(int ch)
{
    return 'A' <= ch && ch <= 'Z' ? ch + 0x20 : ch;
}

inline void h2o_strtolower(char *s, size_t len)
{
    for (; len != 0; ++s, --len)
        *s = h2o_tolower(*s);
}

inline int h2o_toupper(int ch)
{
    return 'a' <= ch && ch <= 'z' ? ch - 0x20 : ch;
}

inline void h2o_strtoupper(char *s, size_t len)
{
    for (; len != 0; ++s, --len)
        *s = h2o_toupper(*s);
}

inline int h2o_lcstris(const char *target, size_t target_len, const char *test, size_t test_len)
{
    if (target_len != test_len)
        return 0;
    return h2o__lcstris_core(target, test, test_len);
}

inline size_t h2o_base64_encode_capacity(size_t len)
{
    return (((len) + 2) / 3 * 4 + 1);
}

#ifdef __cplusplus
}
#endif

#endif
