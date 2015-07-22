#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include "h2o.h"

#define Z_GZIP_ENCODING 16
#define MAX_BUF_SIZE 65000

typedef struct st_gzip_encoder_t {
    h2o_ostream_t super;
    int wbits;
    int memlevel;
    z_stream zstream;
    h2o_mem_pool_t *mempool;
    H2O_VECTOR(h2o_iovec_t) outbufs;
} gzip_encoder_t;

static void *gzip_encoder_alloc(void *opaque, unsigned int items, unsigned int size)
{
    gzip_encoder_t *self = opaque;

    /*
     * I referenced from ngx_http_gzip_filter_module.c and write the code below (alloc len guard).
     * Maybe this will help for memory alignment? IMHO The guard can be removed though.
     */
    unsigned int alloc = items * size;

    if (alloc % 512 != 0 && alloc < 8192) {
        alloc = 8192;
    }

    return h2o_mem_alloc_pool(self->mempool, alloc);
}

static void gzip_encoder_free(void *opaque, void *address)
{
    /* we use mempool here, so no need of free */
}

static void send_gzip(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, int is_final)
{
    gzip_encoder_t *self = (void *)_self;
    
    /*
     * Well... The code below looks strange... I first tried to do gzip deflate in this way:
     * Each time this function called, a buffer for output is allocated for all the input passed.
     * If this call is not the final one, I just wait for the next call and do not pass the output
     * to the next filter since I need to change Content-Length when the whole response has been
     * deflated. So I don't need chunked filter anymore. Then the problem comes that I cannot get
     * the next call since I don't pass the output to the next filter, the callback for sending
     * next part of the response cannout be called...
     *
     * So I need to use chunked filter and the code becomes what it now looks like. Though chunked
     * filter may cause kind of traffic inefficiency but it brings one benifit: lower pressure
     * on memory since I do not need to store all the compress data in the memory. If this is okay
     * I shall remove the "legacy" code.
     *
     * And a small question, how is chunked data processed on HTTP/2? split them into several DATA
     * frames?
     */
    if (self->outbufs.size == self->outbufs.capacity) {
        h2o_vector_reserve(&req->pool, (h2o_vector_t*)&self->outbufs, sizeof(h2o_iovec_t), self->outbufs.capacity + 1);
    }
    
    size_t out_size, i, outbuf_index;

    /* calc gzip out buffer size for this time the same as in buffer total size */
    out_size = 0;
    for (i = 0; i != inbufcnt; ++i)
        out_size += inbufs[i].len;

    outbuf_index = self->outbufs.size++;
    self->outbufs.entries[outbuf_index].base = h2o_mem_alloc_pool(&req->pool, out_size);
    /* set out buffer for output data from zlib */
    self->zstream.next_out = (unsigned char *) self->outbufs.entries[outbuf_index].base;
    self->zstream.avail_out = out_size;

    for (i = 0; i != inbufcnt; ++i) {
        int ret, flush;

        self->zstream.next_in = (unsigned char*) inbufs[i].base;
        self->zstream.avail_in = inbufs[i].len;
        
        if (i == inbufcnt - 1) {
            flush = is_final ? Z_FINISH : Z_SYNC_FLUSH;
        } else {
            flush = Z_NO_FLUSH;
        }
        ret = deflate(&self->zstream, flush);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            /* Should log and a proper way */
            assert(0);
        }

    }
    self->outbufs.entries[outbuf_index].len = out_size - self->zstream.avail_out;
    h2o_ostream_send_next(&self->super, req, &self->outbufs.entries[outbuf_index], 1, is_final);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    gzip_encoder_t *encoder;

    /* do nothing if content-length is unknown */
    if (req->res.content_length == SIZE_MAX)
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
    /* skip if transfer-encoding header is being set (for now) */
    if (h2o_find_header(&req->res.headers, H2O_TOKEN_TRANSFER_ENCODING, -1) != -1)
        goto Next;
    /* skip if content-encoding header is being set */
    if (h2o_find_header(&req->res.headers, H2O_TOKEN_CONTENT_ENCODING, -1) != -1)
        goto Next;
    /* 
     * NOTE: I think there should be some test on MIME type, since we have no need to enable gzip on
     *       those multimedia files or something like that.
     */

    /* set content-encoding header */
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, H2O_STRLIT("gzip"));
    /* 
     * For now, I need to change content_length to SIZE_MAX so I can enable chunked filter.
     * I need chunked filter because I cannot know exactly how many times the "send_gzip()"
     * function above will called at this point.
     */
    req->res.content_length = SIZE_MAX;

    /* setup filter */
    encoder = (void *)h2o_add_ostream(req, sizeof(gzip_encoder_t), slot);
    encoder->super.do_send = send_gzip;
    slot = &encoder->super.next;
    
    /*
     * TBH, I don't know exactly what windowbits & memlevel do in zlib deflate/inflate procedure.
     * I just made a reference from ngx_http_gzip_filter_module.c
     */
    int wbits = 15, memlevel = 8;
    
    while (memlevel > 0 && req->res.content_length < ((1 << (wbits - 1)) - 262)) {
        wbits--;
        memlevel--;
    }
    
    if (memlevel < 1) {
        memlevel = 1;
    }
    
    encoder->wbits = wbits | Z_GZIP_ENCODING;
    encoder->memlevel = memlevel;
    encoder->outbufs.capacity = 0;
    encoder->outbufs.size = 0;
    encoder->zstream.zalloc = gzip_encoder_alloc;
    encoder->zstream.zfree = gzip_encoder_free;
    encoder->zstream.opaque = encoder;
    encoder->mempool = &req->pool;
    
    /* I think there could be some configuration options on the compression strategy? */
    int ret = deflateInit2(&encoder->zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                           encoder->wbits, encoder->memlevel, Z_DEFAULT_STRATEGY);
    
    if (ret != Z_OK) {
        /* Should log and handle in a proper way */
        assert(0);
    }

Next:
    h2o_setup_next_ostream(self, req, slot);
}

void h2o_gzip_register(h2o_pathconf_t *pathconf)
{
    h2o_filter_t *self = h2o_create_filter(pathconf, sizeof(*self));
    self->on_setup_ostream = on_setup_ostream;
}
