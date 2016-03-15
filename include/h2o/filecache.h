/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__filecache_h
#define h2o__filecache_h

#include <stddef.h>
#include <sys/stat.h>
#include <time.h>
#include "h2o/linklist.h"
#include "h2o/memory.h"
#include "h2o/time_.h"

#define H2O_FILECACHE_ETAG_MAXLEN (sizeof("\"deadbeef-deadbeefdeadbeef\"") - 1)

typedef struct st_h2o_filecache_ref_t {
    int fd;
    size_t _refcnt;
    h2o_linklist_t _lru;
    union {
        struct {
            /* used if fd != -1 */
            struct stat st;
            struct {
                struct tm gm;
                char str[H2O_TIMESTR_RFC1123_LEN + 1];
            } _last_modified;
            struct {
                char buf[H2O_FILECACHE_ETAG_MAXLEN + 1];
                size_t len;
            } _etag;
        };
        /* used if fd != -1 */
        int open_err;
    };
    char _path[1];
} h2o_filecache_ref_t;

typedef struct st_h2o_filecache_t h2o_filecache_t;

h2o_filecache_t *h2o_filecache_create(size_t capacity);
void h2o_filecache_destroy(h2o_filecache_t *cache);
void h2o_filecache_clear(h2o_filecache_t *cache);

h2o_filecache_ref_t *h2o_filecache_open_file(h2o_filecache_t *cache, const char *path, int oflag);
void h2o_filecache_close_file(h2o_filecache_ref_t *ref);
struct tm *h2o_filecache_get_last_modified(h2o_filecache_ref_t *ref, char *outbuf);
size_t h2o_filecache_get_etag(h2o_filecache_ref_t *ref, char *outbuf);

#endif
