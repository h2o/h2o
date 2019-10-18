/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the &quot;Software&quot;), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED &quot;AS IS&quot;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef h2o__token_h
#define h2o__token_h

#include "h2o/string_.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_h2o_token_flags_t {
    char http2_static_table_name_index; /* non-zero if any */
    unsigned char proxy_should_drop_for_req : 1;
    unsigned char proxy_should_drop_for_res : 1;
    unsigned char is_init_header_special : 1;
    unsigned char http2_should_reject : 1;
    unsigned char copy_for_push_request : 1;
    unsigned char dont_compress : 1; /* consult `h2o_header_t:dont_compress` as well */
    unsigned char likely_to_repeat : 1;
} h2o_token_flags_t;

/**
 * a predefined, read-only, fast variant of h2o_iovec_t, defined in h2o/token.h
 */
typedef struct st_h2o_token_t {
    h2o_iovec_t buf;
    h2o_token_flags_t flags;
} h2o_token_t;

/**
 * hpack static table entries
 */
typedef struct st_h2o_hpack_static_table_entry_t {
    const h2o_token_t *name;
    const h2o_iovec_t value;
} h2o_hpack_static_table_entry_t;

/**
 * qpack static tables entries
 */
typedef struct st_h2o_qpack_static_table_entry_t {
    const h2o_token_t *name;
    const h2o_iovec_t value;
} h2o_qpack_static_table_entry_t;

#ifndef H2O_MAX_TOKENS
#define H2O_MAX_TOKENS 100
#endif

extern h2o_token_t h2o__tokens[H2O_MAX_TOKENS];
extern size_t h2o__num_tokens;

/**
 * returns a token (an optimized subclass of h2o_iovec_t) containing given string, or NULL if no such thing is available
 */
const h2o_token_t *h2o_lookup_token(const char *name, size_t len);
/**
 * returns an boolean value if given buffer is a h2o_token_t.
 */
int h2o_iovec_is_token(const h2o_iovec_t *buf);

#include "h2o/token_table.h"

#ifdef __cplusplus
}
#endif

#endif
