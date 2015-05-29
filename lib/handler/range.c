#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "h2o.h"

#if __GNUC__ >= 3
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

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

const size_t *process_range(h2o_mem_pool_t *pool, h2o_iovec_t *range_value, size_t file_size, size_t* ret)
{
    size_t range_start = -1, range_count = 0;
    char *buf = range_value->base, *buf_end = buf + range_value->len;
    int good_range=1;
    H2O_VECTOR(size_t) ranges = {};
    
    EXPECT_CHAR('b');
    EXPECT_CHAR('y');
    EXPECT_CHAR('t');
    EXPECT_CHAR('e');
    EXPECT_CHAR('s');
    EXPECT_CHAR('=');
    /* most range requests contain only one range */
    do {
        range_start = -1; range_count = 0;
        if (likely(*buf >= '0') && likely(*buf <= '9')) {
            range_start = 0;
            while (likely(*buf >= '0') && likely(*buf <= '9')) {
                range_start *= 10;
                range_start += *buf++ - '0';
                CHECK_EOF();
            }
            EXPECT_CHAR('-');
	    if (unlikely(range_start >= file_size)) {
                good_range=0;
	    }
            if (unlikely(buf == buf_end)) {
                range_count = file_size - range_start;
                goto GotOneRange;
            } else if (unlikely(*buf == ',')) {
                buf++;
                CHECK_EOF();
                range_count = file_size - range_start;
                goto GotOneRange;
            }
            if (unlikely(*buf < '0') || unlikely(*buf > '9')) {
                *ret = -1;
                return NULL;
            }
            while (likely(*buf >= '0') && likely(*buf <= '9')) {
                CHECK_EOF();
                range_count *= 10;
                range_count += *buf++ - '0';
            }
            if (unlikely(range_count > file_size - 1))
                range_count = file_size - 1;
            range_count -= range_start - 1;
            if (unlikely(range_count <= 0)) {
                good_range=0;
            }
            if (unlikely(buf < buf_end) && unlikely(*buf++ == ','))
                CHECK_EOF();
        } else if (likely(*buf++ == '-')) {
            CHECK_EOF();
            if (unlikely(*buf < '0') || unlikely(*buf > '9')) {
                *ret = -1;
                return NULL;
            }
            while (likely(*buf >= '0') && likely(*buf <= '9')) {
                CHECK_EOF();
                range_count *= 10;
                range_count += *buf++ - '0';
            }
	    if (unlikely(range_count > file_size))
                range_count = file_size;
            range_start = file_size - range_count;
            if (unlikely(buf < buf_end) && unlikely(*buf++ == ','))
                CHECK_EOF();
        } else {
            *ret = -1;
            return NULL;
        }
    GotOneRange:
        if (likely(good_range)) {
            h2o_vector_reserve(pool, (void*)&ranges, sizeof(ranges.entries[0]), ranges.size + 2);
            ranges.entries[ranges.size++] = range_start;
            ranges.entries[ranges.size++] = range_count;
        }
        good_range=1;
    } while (unlikely(buf < buf_end));
    *ret = ranges.size / 2;
    return ranges.entries;
}
