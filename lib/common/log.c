#include "./../h2o_log.h"

int h2o_log_fd = 2;

int h2o_log__do_pushv(ptls_buffer_t *buf, const void *p, size_t l)
{
    if (ptls_buffer_reserve(buf, l) != 0)
        return 0;

    memcpy(buf->base + buf->off, p, l);
    buf->off += l;
    return 1;
}

int h2o_log__do_push_hex(ptls_buffer_t *buf, uint64_t v)
{
    /* TODO optimize */
    char s[sizeof(v) * 2 + 3];
    sprintf(s, "0x%" PRIx64, v);

    return h2o_log__do_pushv(buf, s, strlen(s));
}

int h2o_log__do_push_signed(ptls_buffer_t *buf, int64_t v)
{
    /* TODO optimize */
    char s[32];
    sprintf(s, "%" PRId64, v);

    return h2o_log__do_pushv(buf, s, strlen(s));
}
