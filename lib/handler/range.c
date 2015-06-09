#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "h2o.h"


#define CHECK_EOF()                             \
    if (buf == buf_end) {                       \
        *ret = -2;                              \
        return NULL;                            \
    }

#define EXPECT_CHAR(ch)                         \
    CHECK_EOF();                                \
    if (*buf++ != ch) {                         \
        *ret = -1;                              \
        return NULL;                            \
    }

#define CHECK_OVERFLOW(range)                   \
    if (range == SIZE_MAX) {                    \
        *ret = -1;                              \
        return NULL;                            \
    }

size_t *process_range(h2o_mem_pool_t *pool, h2o_iovec_t *range_value, size_t file_size, size_t* ret)
{
    size_t range_start = -1, range_count = 0;
    char *buf = range_value->base, *buf_end = buf + range_value->len;
    int good_range = 1, ows_skipped = 0;
    H2O_VECTOR(size_t) ranges = {};
    
    if (range_value->len < 6 || memcmp(buf, "bytes=", 6) != 0) {
        *ret = -1;
        return NULL;
    }

    buf += 6;
    
    /* most range requests contain only one range */
    do {
        while (1) {
            if (*buf != ',') {
                if (ows_skipped) {
                    *ret = -1;
                    return NULL;
                }
                break;
            }
            ows_skipped = 0;
            buf ++;
            while (H2O_UNLIKELY(*buf == ' ') || H2O_UNLIKELY(*buf == '\t')) {
                buf ++;
                CHECK_EOF();
            }
        }
        if (H2O_UNLIKELY(buf == buf_end)) break;
        range_start = -1; range_count = 0;
        if (H2O_LIKELY(*buf >= '0') && H2O_LIKELY(*buf <= '9')) {
            range_start = h2o_strtosizefwd(&buf, buf_end - buf);
            CHECK_OVERFLOW(range_start);
            EXPECT_CHAR('-');
	    if (H2O_UNLIKELY(range_start >= file_size)) {
                good_range=0;
	    }
            if (H2O_UNLIKELY(buf == buf_end)) {
                range_count = file_size - range_start;
                goto GotOneRange;
            }
            if (H2O_UNLIKELY(*buf < '0') || H2O_UNLIKELY(*buf > '9')) {
                range_count = file_size - range_start;
                goto GotOneRange;
            }
            range_count = h2o_strtosizefwd(&buf, buf_end - buf);
            CHECK_OVERFLOW(range_count);
            if (H2O_UNLIKELY(range_count > file_size - 1))
                range_count = file_size - 1;
            if (H2O_UNLIKELY(range_start > range_count)) {
                good_range = 0;
            }
            range_count -= range_start - 1;
            if (H2O_UNLIKELY(*buf == '-')) {
                *ret = -1;
                return NULL;
            }
        } else if (H2O_LIKELY(*buf++ == '-')) {
            CHECK_EOF();
            if (H2O_UNLIKELY(*buf < '0') || H2O_UNLIKELY(*buf > '9')) {
                *ret = -1;
                return NULL;
            }
            range_count = h2o_strtosizefwd(&buf, buf_end - buf);
            CHECK_OVERFLOW(range_count);
            if (H2O_UNLIKELY(range_count == 0))
                good_range = 0;
	    if (H2O_UNLIKELY(range_count > file_size))
                range_count = file_size;
            range_start = file_size - range_count;
            if (H2O_UNLIKELY(*buf == '-')) {
                *ret = -1;
                return NULL;
            }
        } else {
            *ret = -1;
            return NULL;
        }
    GotOneRange:
        if (H2O_LIKELY(good_range)) {
            h2o_vector_reserve(pool, (void*)&ranges, sizeof(ranges.entries[0]), ranges.size + 2);
            ranges.entries[ranges.size++] = range_start;
            ranges.entries[ranges.size++] = range_count;
        }
        good_range=1;
        if (buf != buf_end)
            while (H2O_UNLIKELY(*buf == ' ') || H2O_UNLIKELY(*buf == '\t')) {
                buf ++;
                CHECK_EOF();
                ows_skipped = 1;
            }
    } while (H2O_UNLIKELY(buf < buf_end));
    *ret = ranges.size / 2;
    return ranges.entries;
}
