/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <stdlib.h>
#include <pcre.h>
#include "h2o/memory.h"
#include "h2o/regexp.h"

struct st_h2o_regexp_t {
    pcre *re;
    pcre_extra *extra;
};

h2o_regexp_t *h2o_regexp_compile(h2o_iovec_t pattern, int flags, const char **err, size_t *err_offset)
{
    pcre *re;
    pcre_extra *extra;
    int erroff;
    h2o_regexp_t *ret;

    /* compile */
    if ((re = pcre_compile(pattern.base, (int)pattern.len, err, &erroff, NULL)) == NULL)
        return NULL;
    if ((extra = pcre_study(re, PCRE_STUDY_EXTRA_NEEDED | PCRE_STUDY_JIT_COMPILE, err)) == NULL) {
        *err_offset = 0;
        pcre_free(re);
        return NULL;
    }
    /* return */
    ret = h2o_malloc(sizeof(*ret));
    ret->re = re;
    ret->extra = extra;
    return ret;
}

void h2o_regexp_destroy(h2o_regexp_t *re)
{
    pcre_free_study(re->extra);
    pcre_free(re->re);
    free(re);
}

ssize_t h2o_regexp_exec(h2o_regexp_t *re, h2o_iovec_t str, h2o_iovec_t *matches, size_t match_size)
{
    int *ovector = alloca(sizeof(int) * 3 * match_size), rc;
    size_t i, nmatch;

    /* apply the regexp */
    if ((rc = pcre_exec(re->re, re->extra, str.base, (int)str.len, 0, 0, ovector, (int)(3 * match_size))) < 0) {
        /* error */
        switch (rc) {
        case PCRE_ERROR_NOMATCH:
        case PCRE_ERROR_BADUTF8:
            break; /* no need to log error */
        default:
            fprintf(stderr, "pcre_exec returned unexpected error %d\n", rc);
            break;
        }
        return -1;
    }

    /* save the results */
    nmatch = rc != 0 ? (size_t)rc : match_size;
    for (i = 0; i != nmatch; ++i) {
        matches[i].base = str.base + ovector[i * 2];
        matches[i].len = ovector[i * 2 + 1] - ovector[i * 2];
    }
    return (ssize_t)nmatch;
}
