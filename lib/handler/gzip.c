#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include "h2o.h"

#define GZIP_ENCODING 16
#define DEFAULT_WBITS 15
#define DEFAULT_MEMLEVEL 8
#define BUF_SIZE 8192

typedef struct st_gzip_encoder_t {
    h2o_ostream_t super;
    z_stream zstream;
    int started;
    H2O_VECTOR(h2o_iovec_t) bufs;
} gzip_encoder_t;

static void *gzip_encoder_alloc(void *opaque, unsigned int items, unsigned int size)
{
    return h2o_mem_alloc(items * size);
}

static void gzip_encoder_free(void *opaque, void *address)
{
    free(address);
}

static void send_gzip(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    gzip_encoder_t *self = (void *)_self;
    
    size_t in_total, i, outbuf_count = 1;
    
    /* calc in data total size */
    in_total = 0;
    for (i = 0; i != inbufcnt; ++i)
        in_total += inbufs[i].len;

    if (self->started == 0) {
        /* Initialization */
        int ret = deflateInit2(&self->zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                               DEFAULT_WBITS + GZIP_ENCODING, DEFAULT_MEMLEVEL, Z_DEFAULT_STRATEGY);

        assert(ret == Z_OK);

        h2o_vector_reserve(&req->pool, (h2o_vector_t*)&self->bufs, sizeof(h2o_iovec_t),
                           self->bufs.capacity + 1);
        self->bufs.entries[0].base = h2o_mem_alloc_pool(&req->pool, BUF_SIZE);
        self->bufs.entries[0].len = BUF_SIZE;
        self->bufs.size = 1;

        self->started = 1;
    }

    // At most (in_total / BUF_SIZE + 1) + 1 buffers for next level
    h2o_iovec_t *outbufs = alloca(in_total / BUF_SIZE + 2);

    /* set first out buffer for output data from zlib */
    self->zstream.next_out = (unsigned char *) self->bufs.entries[0].base;
    self->zstream.avail_out = self->bufs.entries[0].len;
    outbufs[0] = self->bufs.entries[0];

    for (i = 0; i != inbufcnt; ++i) {
        int ret, flush;

        self->zstream.next_in = (unsigned char*) inbufs[i].base;
        self->zstream.avail_in = inbufs[i].len;
        
        if (i == inbufcnt - 1) {
            flush = is_final ? Z_FINISH : Z_SYNC_FLUSH;
        } else {
            flush = Z_NO_FLUSH;
        }

        while (1) {
            ret = deflate(&self->zstream, flush);
            assert(ret == Z_OK || ret == Z_STREAM_END);
            if (ret == Z_OK && self->zstream.avail_out == 0) {
                if (self->bufs.size == outbuf_count) {
                    if (self->bufs.size == self->bufs.capacity) {
                        h2o_vector_reserve(&req->pool, (h2o_vector_t*)&self->bufs, sizeof(h2o_iovec_t),
                                           self->bufs.capacity + 1);
                    }
                    self->bufs.entries[self->bufs.size].base = h2o_mem_alloc_pool(&req->pool, BUF_SIZE);
                    self->bufs.entries[self->bufs.size].len = BUF_SIZE;
                    self->bufs.size++;
                }
                outbufs[outbuf_count - 1].len = BUF_SIZE;
                outbufs[outbuf_count] = self->bufs.entries[outbuf_count];
                self->zstream.next_out = (unsigned char *)outbufs[outbuf_count].base;
                self->zstream.avail_out = outbufs[outbuf_count].len;
                outbuf_count++;
            } else
                break;
        }

    }
    outbufs[outbuf_count - 1].len = BUF_SIZE - self->zstream.avail_out;
    h2o_ostream_send_next(&self->super, req, outbufs, outbuf_count, is_final);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    gzip_encoder_t *encoder;
    size_t header_index;

    /* do nothing if HTTP version is lower than 1.1 */
    if (req->version < 0x101)
        goto Next;
    /* do nothing if response has prohibited gzip compression */
    if (req->gzip_is_prohibited)
        goto Next;
    /* RFC 2616 4.4 states that the following status codes (and response to a HEAD method) should not include message body */
    if ((100 <= req->res.status && req->res.status <= 199) || req->res.status == 204 || req->res.status == 304)
        goto Next;
    else if (h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")))
        goto Next;
    /* we cannot handle certain responses (like 101 switching protocols) */
    if (req->res.status != 200) {
        req->http1_is_persistent = 0;
        goto Next;
    }
    /* skip if no accept-encoding is set */
    if ((header_index = h2o_find_header(&req->headers, H2O_TOKEN_ACCEPT_ENCODING, -1)) == -1)
        goto Next;
    if (!h2o_contains_token(req->headers.entries[header_index].value.base,
                            req->headers.entries[header_index].value.len, H2O_STRLIT("gzip"), ','))
        goto Next;
    /* skip if content-encoding header is being set */
    if (h2o_find_header(&req->res.headers, H2O_TOKEN_CONTENT_ENCODING, -1) != -1)
        goto Next;

    /* 
     * NOTE: I think there should be some test on MIME type, since we have no need to enable gzip on
     *       those multimedia files or something like that. Maybe we can have a conf for this.
     */
    header_index = h2o_find_header(&req->res.headers, H2O_TOKEN_CONTENT_TYPE, -1);
    assert(header_index != -1);
    if (h2o_contains_token(req->res.headers.entries[header_index].value.base,
                           req->res.headers.entries[header_index].value.len, H2O_STRLIT("audio"), '/'))
        goto Next;
    if (h2o_contains_token(req->res.headers.entries[header_index].value.base,
                           req->res.headers.entries[header_index].value.len, H2O_STRLIT("image"), '/'))
        goto Next;
    if (h2o_contains_token(req->res.headers.entries[header_index].value.base,
                           req->res.headers.entries[header_index].value.len, H2O_STRLIT("video"), '/'))
        goto Next;
    if (h2o_contains_token(req->res.headers.entries[header_index].value.base,
                           req->res.headers.entries[header_index].value.len, H2O_STRLIT("gzip"), '/'))
        goto Next;
    if (h2o_contains_token(req->res.headers.entries[header_index].value.base,
                           req->res.headers.entries[header_index].value.len, H2O_STRLIT("zip"), '/'))
        goto Next;
    if (h2o_contains_token(req->res.headers.entries[header_index].value.base,
                           req->res.headers.entries[header_index].value.len, H2O_STRLIT("zlib"), '/'))
        goto Next;

    /* set content-encoding header */
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, H2O_STRLIT("gzip"));

    req->res.content_length = SIZE_MAX;

    /* setup filter */
    encoder = (void *)h2o_add_ostream(req, sizeof(gzip_encoder_t), slot);
    encoder->super.do_send = send_gzip;
    slot = &encoder->super.next;

    encoder->bufs.capacity = 0;
    encoder->bufs.size = 0;
    encoder->zstream.zalloc = gzip_encoder_alloc;
    encoder->zstream.zfree = gzip_encoder_free;
    encoder->zstream.opaque = encoder;
    encoder->started = 0;

Next:
    h2o_setup_next_ostream(self, req, slot);
}

void h2o_gzip_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
