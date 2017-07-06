#ifndef HPACK_H__
#define HPACK_H__

#include "h2get.h"

struct h2get_decoded_header {
    struct h2get_buf key;
    struct h2get_buf value;
    struct list node;
};
#define list_to_dh(ln) (container_of((ln), struct h2get_decoded_header, node))

void h2get_hpack_ctx_init(struct h2get_hpack_ctx *hhc, size_t dyn_size);
void h2get_hpack_ctx_empty(struct h2get_hpack_ctx *hhc);
void h2get_hpack_ctx_resize(struct h2get_hpack_ctx *hhc, size_t dyn_size);
uint8_t *decode_string(uint8_t *buf, uint8_t *end, struct h2get_buf *ret);
struct list;
int h2get_hpack_decode(struct h2get_hpack_ctx *hhc, char *payload, size_t plen, struct list *headers);
void h2get_decoded_header_free(struct h2get_decoded_header *h);

static inline char *h2get_hpack_add_header(struct h2get_buf *key, struct h2get_buf *value, char *payload)
{
    *payload++ = 0x00; /* no encoding */
    *payload++ = key->len;
    memcpy(payload, key->buf, key->len);
    payload += key->len;
    *payload++ = value->len;
    memcpy(payload, value->buf, value->len);
    payload += value->len;
    return payload;
}

#endif /* HPACK_H__ */
/* vim: set expandtab ts=4 sw=4: */
