#include "h2get.h"

#include "hpack.h"
#include "huffman_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct h2get_header {
    struct h2get_buf *key;
    struct h2get_buf *value;
};

static struct h2get_buf h2get_header_authority = { H2GET_BUFLIT_ELMS(":authority") };
static struct h2get_buf h2get_header_method = { H2GET_BUFLIT_ELMS(":method") };
static struct h2get_buf h2get_header_method_get = { H2GET_BUFLIT_ELMS("get") };
static struct h2get_buf h2get_header_method_post = { H2GET_BUFLIT_ELMS("post") };
static struct h2get_buf h2get_header_path = { H2GET_BUFLIT_ELMS(":path") };
static struct h2get_buf h2get_header_path_slash = { H2GET_BUFLIT_ELMS("/") };
static struct h2get_buf h2get_header_path_index_html = { H2GET_BUFLIT_ELMS("/index.html") };
static struct h2get_buf h2get_header_scheme = { H2GET_BUFLIT_ELMS(":scheme") };
static struct h2get_buf h2get_header_scheme_http = { H2GET_BUFLIT_ELMS("http") };
static struct h2get_buf h2get_header_scheme_https = { H2GET_BUFLIT_ELMS("https") };
static struct h2get_buf h2get_header_status = { H2GET_BUFLIT_ELMS(":status") };
static struct h2get_buf h2get_header_status_200 = { H2GET_BUFLIT_ELMS("200") };
static struct h2get_buf h2get_header_status_204 = { H2GET_BUFLIT_ELMS("204") };
static struct h2get_buf h2get_header_status_206 = { H2GET_BUFLIT_ELMS("206") };
static struct h2get_buf h2get_header_status_304 = { H2GET_BUFLIT_ELMS("304") };
static struct h2get_buf h2get_header_status_400 = { H2GET_BUFLIT_ELMS("400") };
static struct h2get_buf h2get_header_status_404 = { H2GET_BUFLIT_ELMS("404") };
static struct h2get_buf h2get_header_status_500 = { H2GET_BUFLIT_ELMS("500") };
static struct h2get_buf h2get_header_accept_charset = { H2GET_BUFLIT_ELMS("accept-charset") };
static struct h2get_buf h2get_header_accept_encoding = { H2GET_BUFLIT_ELMS("accept-encoding") };
static struct h2get_buf h2get_header_accept_encoding_gzip_deflate = { H2GET_BUFLIT_ELMS("accept-encoding-gzip-deflate") };
static struct h2get_buf h2get_header_accept_language = { H2GET_BUFLIT_ELMS("accept-language") };
static struct h2get_buf h2get_header_accept_ranges = { H2GET_BUFLIT_ELMS("accept-ranges") };
static struct h2get_buf h2get_header_accept = { H2GET_BUFLIT_ELMS("accept") };
static struct h2get_buf h2get_header_access_control_allow_origin = { H2GET_BUFLIT_ELMS("access-control-allow-origin") };
static struct h2get_buf h2get_header_age = { H2GET_BUFLIT_ELMS("age") };
static struct h2get_buf h2get_header_allow = { H2GET_BUFLIT_ELMS("allow") };
static struct h2get_buf h2get_header_authorization = { H2GET_BUFLIT_ELMS("authorization") };
static struct h2get_buf h2get_header_cache_control = { H2GET_BUFLIT_ELMS("cache-control") };
static struct h2get_buf h2get_header_content_disposition = { H2GET_BUFLIT_ELMS("content-disposition") };
static struct h2get_buf h2get_header_content_encoding = { H2GET_BUFLIT_ELMS("content-encoding") };
static struct h2get_buf h2get_header_content_language = { H2GET_BUFLIT_ELMS("content-language") };
static struct h2get_buf h2get_header_content_length = { H2GET_BUFLIT_ELMS("content-length") };
static struct h2get_buf h2get_header_content_location = { H2GET_BUFLIT_ELMS("content-location") };
static struct h2get_buf h2get_header_content_range = { H2GET_BUFLIT_ELMS("content-range") };
static struct h2get_buf h2get_header_content_type = { H2GET_BUFLIT_ELMS("content-type") };
static struct h2get_buf h2get_header_cookie = { H2GET_BUFLIT_ELMS("cookie") };
static struct h2get_buf h2get_header_date = { H2GET_BUFLIT_ELMS("date") };
static struct h2get_buf h2get_header_etag = { H2GET_BUFLIT_ELMS("etag") };
static struct h2get_buf h2get_header_expect = { H2GET_BUFLIT_ELMS("expect") };
static struct h2get_buf h2get_header_expires = { H2GET_BUFLIT_ELMS("expires") };
static struct h2get_buf h2get_header_from = { H2GET_BUFLIT_ELMS("from") };
static struct h2get_buf h2get_header_host = { H2GET_BUFLIT_ELMS("host") };
static struct h2get_buf h2get_header_if_match = { H2GET_BUFLIT_ELMS("if-match") };
static struct h2get_buf h2get_header_if_modified_since = { H2GET_BUFLIT_ELMS("if-modified-since") };
static struct h2get_buf h2get_header_if_none_match = { H2GET_BUFLIT_ELMS("if-none-match") };
static struct h2get_buf h2get_header_if_range = { H2GET_BUFLIT_ELMS("if-range") };
static struct h2get_buf h2get_header_if_unmodified_since = { H2GET_BUFLIT_ELMS("if-unmodified-since") };
static struct h2get_buf h2get_header_last_modified = { H2GET_BUFLIT_ELMS("last-modified") };
static struct h2get_buf h2get_header_link = { H2GET_BUFLIT_ELMS("link") };
static struct h2get_buf h2get_header_location = { H2GET_BUFLIT_ELMS("location") };
static struct h2get_buf h2get_header_max_forwards = { H2GET_BUFLIT_ELMS("max-forwards") };
static struct h2get_buf h2get_header_proxy_authenticate = { H2GET_BUFLIT_ELMS("proxy-authenticate") };
static struct h2get_buf h2get_header_proxy_authorization = { H2GET_BUFLIT_ELMS("proxy-authorization") };
static struct h2get_buf h2get_header_range = { H2GET_BUFLIT_ELMS("range") };
static struct h2get_buf h2get_header_referer = { H2GET_BUFLIT_ELMS("referer") };
static struct h2get_buf h2get_header_refresh = { H2GET_BUFLIT_ELMS("refresh") };
static struct h2get_buf h2get_header_retry_after = { H2GET_BUFLIT_ELMS("retry-after") };
static struct h2get_buf h2get_header_server = { H2GET_BUFLIT_ELMS("server") };
static struct h2get_buf h2get_header_set_cookie = { H2GET_BUFLIT_ELMS("set-cookie") };
static struct h2get_buf h2get_header_strict_transport_security = { H2GET_BUFLIT_ELMS("strict-transport-security") };
static struct h2get_buf h2get_header_transfer_encoding = { H2GET_BUFLIT_ELMS("transfer-encoding") };
static struct h2get_buf h2get_header_user_agent = { H2GET_BUFLIT_ELMS("user-agent") };
static struct h2get_buf h2get_header_vary = { H2GET_BUFLIT_ELMS("vary") };
static struct h2get_buf h2get_header_via = { H2GET_BUFLIT_ELMS("via") };
static struct h2get_buf h2get_header_www_authenticate = { H2GET_BUFLIT_ELMS("www-authenticate") };

static struct h2get_header static_header_table[] = {
    {},
    {
        &h2get_header_authority,
    },
    {&h2get_header_method, &h2get_header_method_get},
    {&h2get_header_method, &h2get_header_method_post},
    {&h2get_header_path, &h2get_header_path_slash},
    {&h2get_header_path, &h2get_header_path_index_html},
    {&h2get_header_scheme, &h2get_header_scheme_http},
    {&h2get_header_scheme, &h2get_header_scheme_https},
    {&h2get_header_status, &h2get_header_status_200},
    {&h2get_header_status, &h2get_header_status_204},
    {&h2get_header_status, &h2get_header_status_206},
    {&h2get_header_status, &h2get_header_status_304},
    {&h2get_header_status, &h2get_header_status_400},
    {&h2get_header_status, &h2get_header_status_404},
    {&h2get_header_status, &h2get_header_status_500},
    {
        &h2get_header_accept_charset,
    },
    {&h2get_header_accept_encoding, &h2get_header_accept_encoding_gzip_deflate},
    {
        &h2get_header_accept_language,
    },
    {
        &h2get_header_accept_ranges,
    },
    {
        &h2get_header_accept,
    },
    {
        &h2get_header_access_control_allow_origin,
    },
    {
        &h2get_header_age,
    },
    {
        &h2get_header_allow,
    },
    {
        &h2get_header_authorization,
    },
    {
        &h2get_header_cache_control,
    },
    {
        &h2get_header_content_disposition,
    },
    {
        &h2get_header_content_encoding,
    },
    {
        &h2get_header_content_language,
    },
    {
        &h2get_header_content_length,
    },
    {
        &h2get_header_content_location,
    },
    {
        &h2get_header_content_range,
    },
    {
        &h2get_header_content_type,
    },
    {
        &h2get_header_cookie,
    },
    {
        &h2get_header_date,
    },
    {
        &h2get_header_etag,
    },
    {
        &h2get_header_expect,
    },
    {
        &h2get_header_expires,
    },
    {
        &h2get_header_from,
    },
    {
        &h2get_header_host,
    },
    {
        &h2get_header_if_match,
    },
    {
        &h2get_header_if_modified_since,
    },
    {
        &h2get_header_if_none_match,
    },
    {
        &h2get_header_if_range,
    },
    {
        &h2get_header_if_unmodified_since,
    },
    {
        &h2get_header_last_modified,
    },
    {
        &h2get_header_link,
    },
    {
        &h2get_header_location,
    },
    {
        &h2get_header_max_forwards,
    },
    {
        &h2get_header_proxy_authenticate,
    },
    {
        &h2get_header_proxy_authorization,
    },
    {
        &h2get_header_range,
    },
    {
        &h2get_header_referer,
    },
    {
        &h2get_header_refresh,
    },
    {
        &h2get_header_retry_after,
    },
    {
        &h2get_header_server,
    },
    {
        &h2get_header_set_cookie,
    },
    {
        &h2get_header_strict_transport_security,
    },
    {
        &h2get_header_transfer_encoding,
    },
    {
        &h2get_header_user_agent,
    },
    {
        &h2get_header_vary,
    },
    {
        &h2get_header_via,
    },
    {
        &h2get_header_www_authenticate,
    },
};
__attribute__((unused)) static uint8_t *encode_int(uint8_t *out, unsigned long i, size_t prefix)
{
    /*
     *  Pseudocode to represent an integer I is as follows:
     *
     *  if I < 2^N - 1, encode I on N bits
     *  else
     *      encode (2^N - 1) on N bits
     *      I = I - (2^N - 1)
     *      while I >= 128
     *           encode (I % 128 + 128) on 8 bits
     *           I = I / 128
     *      encode I on 8 bits
     */
    if (i < (1UL << prefix)) {
        *out++ = i;
        return out;
    }
    *out++ = ((1UL << prefix) - 1UL);
    i = i - ((1UL << prefix) - 1UL);
    while (i >= 128UL) {
        *out++ = (i % 128UL) + 128UL;
        i = i / 128UL;
    }
    *out++ = i;
    return out;
}

static uint8_t *decode_int(uint8_t *buf, uint8_t *end, size_t prefix, unsigned long *i)
{
    unsigned long next_i = 0;
    unsigned long m = 0;
    uint8_t b;

    if (buf >= end) {
        return NULL;
    }

    /*
     * decode I from the next N bits
     *   if I < 2^N - 1, return I
     *   else
     *       M = 0
     *       repeat
     *           B = next octet
     *           I = I + (B & 127) * 2^M
     *           M = M + 7
     *       while B & 128 == 128
     *       return I
     */

    *i = (*buf) & ((1UL << prefix) - 1UL);
    buf++;

    if (*i < ((1UL << prefix) - 1UL)) {
        return buf;
    }
    m = 0;
    do {
        if (buf >= end) {
            return NULL;
        }
        b = *buf++;
        next_i = *i + (b & 127) * (1UL << m);
        if (*i > next_i) {
            return NULL;
        }
        *i = next_i;
        m = m + 7;
    } while ((b & 128) == 128);
    return buf;
}

uint8_t *decode_string(uint8_t *buf, uint8_t *end, struct h2get_buf *ret)
{
    uint8_t b;
    bool huffman;
    uint8_t *new_buf;
    unsigned long enc_len;
    int i;

    if (buf >= end) {
        return NULL;
    }
    b = *buf;
    huffman = b & 0x80 ? true : false;

    new_buf = decode_int(buf, end, 7, &enc_len);
    if (!buf) {
        return NULL;
    }
    if (new_buf >= end) {
        return NULL;
    }

    buf = new_buf;

    if (!huffman) {
        if (buf + enc_len > end) {
            return NULL;
        }
        ret->buf = malloc(enc_len);
        if (!ret->buf) {
            return NULL;
        }
        memcpy(ret->buf, buf, enc_len);
        ret->len = enc_len;
        return &buf[enc_len];
    }

    /* huffman encoded */
    uint8_t prev_nr_bits_read, nr_bits_read = 0;
    /* allocate for worst case */
    char *tmpbuf = alloca((enc_len * 30 / 8) + 1);
    memset(tmpbuf, 0, (enc_len * 30 / 8) + 1);
    i = 0;
    uint8_t *huff_end = buf + enc_len;
    while (buf < huff_end) {
        int j;
        uint32_t b32 = 0;
        int found = 0;

        for (j = 0; j < ARRAY_SIZE(htable); j++) {
            prev_nr_bits_read = nr_bits_read;
            if ((((htable[j].shift + nr_bits_read - 1) / 8) + buf) >= huff_end) {
                /* reading `shift` + `nr_bits_read` bits would make us over read the buffer, exit */
                goto out;
            }
            new_buf = read_bits(buf, htable[j].shift, &b32, &nr_bits_read);
            if (!new_buf) {
                return NULL;
            }
            if (b32 >= htable[j].min && b32 <= htable[j].max) {
                tmpbuf[i] = htable[j].chars[b32 - htable[j].min];
                // fprintf(stderr, "read:%x-%d, adding: '%c'\n", b32 & ((1U << htable[j].shift) - 1U),htable[j].shift,
                // tmpbuf[i]);
                i++;
                buf = new_buf;
                found = 1;
                nr_bits_read = 8 - nr_bits_read;
                if (nr_bits_read == 8) {
                    nr_bits_read = 0;
                    buf++;
                }
                break;
            } else {
                nr_bits_read = prev_nr_bits_read;
            }
        }
        if (!found) {
            return NULL;
        }
    }
out:
    ret->buf = malloc(i);
    if (!ret->buf) {
        return NULL;
    }
    memcpy(ret->buf, tmpbuf, i);
    ret->len = i;

    return huff_end;
}

static size_t rfc7541_header_size(struct h2get_decoded_header *h)
{
    /* The size of an entry is the sum of its name's length in octets (as defined in Section 5.2), its value's length in
     * octets, and 32. */
    return 32 + h->key.len + h->value.len;
}

static void evict_dyn_header(struct h2get_hpack_ctx *hhc)
{
    struct h2get_decoded_header *h;
    struct list *tail;

    if (list_empty(&hhc->dyn_table)) {
        return;
    }

    tail = list_tail(&hhc->dyn_table);
    h = list_to_dh(tail);
    hhc->dyn_size -= rfc7541_header_size(h);
    list_del(tail);
    h2get_decoded_header_free(h);
}

void h2get_hpack_ctx_init(struct h2get_hpack_ctx *hhc, size_t dyn_size)
{
    memset(hhc, 0, sizeof(*hhc));
    hhc->dyn_size = 0;
    hhc->max_dyn_size = dyn_size;
    list_init(&hhc->dyn_table);
}

void h2get_hpack_ctx_empty(struct h2get_hpack_ctx *hhc)
{
    while (!list_empty(&hhc->dyn_table)) {
        evict_dyn_header(hhc);
    }
}

static struct h2get_decoded_header *get_dyn_header(struct h2get_hpack_ctx *hhc, unsigned index)
{
    struct list *cur;

    for (cur = hhc->dyn_table.next; cur != &hhc->dyn_table; cur = cur->next) {
        if (!index) {
            break;
        }
        index--;
    }
    if (cur == &hhc->dyn_table) {
        return NULL;
    }
    return list_to_dh(cur);
}

static int init_via_index(struct h2get_hpack_ctx *hhc, struct h2get_decoded_header *newh, int index)
{
    struct h2get_header *h;
    if (index < ARRAY_SIZE(static_header_table)) {
        h = &static_header_table[index];
    } else {
        /* dynamic table */
        struct h2get_decoded_header *dynh;
        index -= ARRAY_SIZE(static_header_table);
        assert(index >= 0);
        dynh = get_dyn_header(hhc, index);
        if (!dynh)
            return -1;
        *newh = *dynh;
        newh->key.buf = memdup(dynh->key.buf, dynh->key.len);
        newh->value.buf = memdup(dynh->value.buf, dynh->value.len);
        list_init(&newh->node);
        return 0;
    }
    newh->key.len = h->key->len;
    newh->key.buf = memdup(h->key->buf, h->key->len);
    if (h->value) {
        newh->value.len = h->value->len;
        newh->value.buf = memdup(h->value->buf, h->value->len);
    }
    return 0;
}

static struct h2get_decoded_header *decoded_header_dup(struct h2get_decoded_header *h)
{
    struct h2get_decoded_header *newh;

    newh = malloc(sizeof(*newh));
    *newh = *h;
    newh->key.buf = memdup(h->key.buf, h->key.len);
    newh->value.buf = memdup(h->value.buf, h->value.len);
    list_init(&newh->node);

    return newh;
}

void h2get_decoded_header_free(struct h2get_decoded_header *h)
{
    free(h->key.buf);
    free(h->value.buf);
    free(h);
}

static void insert_dyn_header(struct h2get_hpack_ctx *hhc, struct h2get_decoded_header *h)
{
    struct h2get_decoded_header *newh;
    size_t hsize;

    hsize = rfc7541_header_size(h);

    while (!list_empty(&hhc->dyn_table) && hhc->dyn_size + hsize > hhc->max_dyn_size) {
        evict_dyn_header(hhc);
    }

    /* it's not an error, it just results in an empty list */
    if (hhc->dyn_size + hsize > hhc->max_dyn_size) {
        return;
    }

    newh = decoded_header_dup(h);
    list_add(&hhc->dyn_table, &newh->node);
    hhc->dyn_size += hsize;

    return;
}

static struct h2get_decoded_header *add_one_header(struct h2get_hpack_ctx *hhc, int index, struct list *headers,
                                                   int *nr_headers, uint8_t **buf, uint8_t *end, int only_index)
{
    struct h2get_decoded_header *newh = calloc(1, sizeof(*newh));
    uint8_t *new_buf;
    struct h2get_buf hbuf;

    if (index) {
        if (init_via_index(hhc, newh, index) < 0)
            goto err;
    } else {
        *buf += 1;
        new_buf = decode_string(*buf, end, &hbuf);
        if (!new_buf) {
            goto err;
        }
        *buf = new_buf;
        newh->key = hbuf;
    }
    if (!only_index) {
        new_buf = decode_string(*buf, end, &hbuf);
        if (!new_buf) {
            goto err;
        }
        *buf = new_buf;
        if (newh->value.buf) {
            free(newh->value.buf);
        }
        newh->value = hbuf;
    }

    *nr_headers += 1;
    list_add_tail(headers, &newh->node);
    return newh;

err:
    free(newh->key.buf);
    free(newh->value.buf);
    free(newh);
    return NULL;
}

int h2get_hpack_decode(struct h2get_hpack_ctx *hhc, char *payload, size_t plen, struct list *headers)
{
    uint8_t *new_buf, *buf = (uint8_t *)payload;
    uint8_t *end = (uint8_t *)(payload + plen);
    unsigned long i;
    int nr_headers = 0;

    while (buf < end) {
        int prefix = -1;
        int needs_indexing = 0;
        struct h2get_decoded_header *dh;

        if (*buf & 0x80) {
            /* 6.1.  Indexed Header Field Representation */
            new_buf = decode_int(buf, end, 7, &i);
            if (!new_buf || !i) {
                return -1;
            }
            buf = new_buf;
            if (!add_one_header(hhc, i, headers, &nr_headers, &buf, end, 1)) {
                return -1;
            }
            continue;
        } else if (*buf & 0x40) {
            needs_indexing = 1;
            /* 6.2.1.  Literal Header Field with Incremental Indexing */
            if (*buf & ~0x40)
                prefix = 6;
            else
                prefix = 0;
        } else if (!(*buf & 0xf0)) {
            /* 6.2.2.  Literal Header Field without Indexing */
            if (*buf & 0x0f)
                prefix = 4;
            else
                prefix = 0;
        } else if (*buf & 0x10) {
            /* 6.2.3.  Literal Header Field Never Indexed */
            if (*buf & 0x0f)
                prefix = 4;
            else
                prefix = 0;

        } else if (*buf & 0x20) {
            /* 6.3.  Dynamic Table Size Update */
            new_buf = decode_int(buf, end, 5, &i);
            if (!new_buf) {
                return 0;
            }
            buf = new_buf;
            /* FIXME: take `i` into account */
            continue;
        }

        switch (prefix) {
        case -1:
            return 0;
        case 0:
            dh = add_one_header(hhc, 0, headers, &nr_headers, &buf, end, 0);
            if (!dh) {
                return -1;
            }
            break;
        default:
            new_buf = decode_int(buf, end, prefix, &i);
            if (!new_buf || !i) {
                return -1;
            }
            buf = new_buf;
            dh = add_one_header(hhc, i, headers, &nr_headers, &buf, end, 0);
            if (!dh) {
                return -1;
            }
        }
        if (needs_indexing && dh) {
            insert_dyn_header(hhc, dh);
        }
    }

    return nr_headers;
#undef ADD_ONE
#undef ADD_ONE_KEY_INDEX
}

void h2get_hpack_ctx_resize(struct h2get_hpack_ctx *hhc, size_t dyn_size) { return; }

#ifdef TEST
#include <assert.h>
#include <time.h>

int test_decode_int(void);
int test_decode_int(void)
{
    int i;
    int j;
    int seed;

    uint8_t *new_buf;
    struct {
        uint8_t buf[3];
        int buf_size;
        int prefix;
        unsigned long res;
    } rfc_tests[] = {
        {
            {10}, 1, 5, 10,
        },
        {
            {31, 154, 10}, 3, 5, 1337,
        },
        {
            {42}, 1, 8, 42,
        },
    };

    for (i = 0; i < ARRAY_SIZE(rfc_tests); i++) {
        unsigned long n;
#define EOB(b) (&(b).buf[(b).buf_size])
        new_buf = decode_int(rfc_tests[i].buf, EOB(rfc_tests[i]), rfc_tests[i].prefix, &n);
        assert(n == rfc_tests[i].res);
#undef EOB
        assert(new_buf);
    }

    for (i = 0; i < ARRAY_SIZE(rfc_tests); i++) {
        uint8_t out[10];
        uint8_t *res;
        res = encode_int(out, rfc_tests[i].res, rfc_tests[i].prefix);
        assert(res <= &out[9]);
        assert(!memcmp(out, rfc_tests[i].buf, rfc_tests[i].buf_size));
    }

    seed = (int)time(NULL);
    printf("seed: %d\n", seed);
    srand(seed);

    for (i = 0; i < 10 * 1000; i++) {
        char *buf;
        unsigned long res;
        size_t len = rand() % 4096;
        int prefix;
        uint8_t out[10];
        uint8_t *ret;
        unsigned long enc;

        buf = malloc(len);
        for (j = 0; j < len; j++) {
            buf[j] = rand();
        }
        prefix = (rand() % 7) + 1;
        new_buf = decode_int((uint8_t *)buf, (void *)&buf[len], prefix, &res);
        if (!(i % (100 * 1000))) {
            fprintf(stderr, "prefix: %d, res is %lu, err: %s\n", prefix, res, !new_buf ? "true" : "false");
            if (new_buf && false) {
                dump_zone(buf, len);
            }
        }
        enc = rand();
        ret = encode_int(out, enc, prefix);
        assert(ret <= &out[9]);
        new_buf = decode_int(out, &out[sizeof(out)], prefix, &res);
        assert(new_buf);
        assert(res == enc);

        free(buf);
    }
    return 0;
}

int test_decode_string(void);
int test_decode_string(void)
{
    static char *in[] = {
        "\x85\xae\xc3\x77\x1a\x4b", "\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0"
                                    "\x84\xa6\x2d\x1b\xff",
        "\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", "\x86\xa8\xeb\x10\x64\x9c\xbf",
        "\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f", "\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf",
        "\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff",
        "\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3",
    };
    static char *res[] = {
        "private",      "Mon, 21 Oct 2013 20:13:22 GMT", "www.example.com",         "no-cache", "custom-key",
        "custom-value", "Mon, 21 Oct 2013 20:13:21 GMT", "https://www.example.com",
    };

    int i;
    for (i = 0; i < ARRAY_SIZE(in); i++) {
        int loops = 0;
        uint8_t *idx, *end;
        idx = (uint8_t *)in[i];
        end = (uint8_t *)(in[i] + strlen(in[i]));

        while (idx < end) {
            loops++;
            struct h2get_buf ret = {};
            idx = decode_string(idx, end, &ret);
            if (memcmp(ret.buf, res[i], ret.len)) {
                fprintf(stderr, "decoded buffer doesn't match: seen:[%.*s], expected [%s]\n", (int)ret.len, ret.buf,
                        res[i]);
                assert(0);
            }
            free(ret.buf);
        }
        assert(loops == 1);
    }

    return 0;
}

int test_decode_header_frame(void);
int test_decode_header_frame(void)
{

    char test[] = {
        0x88, 0x61, 0x96, 0xdf, 0x69, 0x7e, 0x94, 0x0b, 0xca, 0x6a, 0x22, 0x54, 0x10, 0x02, 0xe2, 0x80, 0x6a, 0xe0,
        0x01, 0x70, 0x0f, 0xa9, 0x8b, 0x46, 0xff, 0x64, 0x02, 0x2d, 0x31, 0x58, 0x8d, 0xae, 0xc3, 0x77, 0x1a, 0x4b,
        0xf4, 0xa5, 0x23, 0xf2, 0xb0, 0xe6, 0x2c, 0x00, 0x5f, 0x96, 0x49, 0x7c, 0xa5, 0x89, 0xd3, 0x4d, 0x1f, 0x6a,
        0x12, 0x71, 0xd8, 0x82, 0xa6, 0x0c, 0x9b, 0xb5, 0x2c, 0xf3, 0xcd, 0xbe, 0xb0, 0x7f, 0x40, 0x03, 0x70, 0x33,
        0x70, 0xd1, 0xbd, 0xae, 0x0f, 0xe7, 0x7c, 0xe6, 0x42, 0x86, 0x42, 0x95, 0x1d, 0x2a, 0x0d, 0x4d, 0x6c, 0xeb,
        0x52, 0xb3, 0xd0, 0x62, 0x7a, 0xfe, 0x14, 0xdc, 0x52, 0xa9, 0x3a, 0x53, 0x5a, 0x2e, 0x30, 0xc7, 0x8f, 0x1e,
        0x17, 0x98, 0xe7, 0x9a, 0x82, 0xae, 0x43, 0xd2, 0xc2, 0x2d, 0xae, 0xb3, 0xd8, 0x96, 0x06, 0x42, 0x1e, 0xda,
        0x92, 0x86, 0x07, 0x52, 0x3c, 0x16, 0xc6, 0x02, 0xd8, 0x5c, 0x6d, 0xdf, 0xf2, 0x7a, 0x20, 0x2d, 0x4a, 0x4a,
        0x7b, 0x14, 0xa4, 0xf6, 0x15, 0x43, 0x55, 0x29, 0xd7, 0xfe, 0x7f, 0x5a, 0x83, 0x9b, 0xd9, 0xab, 0x76, 0x03,
        0x67, 0x77, 0x73, 0x5c, 0x83, 0x69, 0x97, 0x9f, 0x40, 0x8c, 0xf2, 0xb7, 0x94, 0x21, 0x6a, 0xec, 0x3a, 0x4a,
        0x44, 0x98, 0xf5, 0x7f, 0x8a, 0x0f, 0xda, 0x94, 0x9e, 0x42, 0xc1, 0x1d, 0x07, 0x27, 0x5f, 0x40, 0x8b, 0xf2,
        0xb4, 0xb6, 0x0e, 0x92, 0xac, 0x7a, 0xd2, 0x63, 0xd4, 0x8f, 0x89, 0xdd, 0x0e, 0x8c, 0x1a, 0xb6, 0xe4, 0xc5,
        0x93, 0x4f, 0x77, 0xff, 0x32, 0xd3, 0x92, 0xfc, 0x0f, 0x3d, 0x06, 0xae, 0x17, 0x99, 0xeb, 0xd7, 0x48, 0xd9,
        0xc5, 0xd3, 0x26, 0xf2, 0x65, 0xdf, 0x5f, 0x8f, 0x0e, 0x9a, 0xf5, 0x3a, 0x3d, 0x79, 0xd5, 0xcd, 0xeb, 0xb6,
        0xba, 0x5a, 0xbc, 0x3c, 0x3f, 0x08, 0xf5, 0xe8, 0x1d, 0x68, 0xf3, 0x83, 0x08, 0x74, 0xad, 0x4f, 0xee, 0xc1,
        0x51, 0x93, 0x84, 0xad, 0x77, 0x9f, 0xdc, 0x31, 0xfe, 0xe9, 0x91, 0x10, 0xde, 0xec, 0xb1, 0x00, 0xff, 0xeb,
        0x3e, 0x59, 0xc1, 0x66, 0xe0, 0x79, 0xc7, 0x5e, 0xa9, 0xe1, 0xeb, 0x0d, 0x09, 0xb2, 0xef, 0xec, 0xd9, 0x9f,
        0xb3, 0x01, 0x32, 0x92, 0x1a, 0x78, 0xe0, 0xba, 0xe6, 0x4f, 0x1c, 0x4e, 0x9d, 0x5a, 0xa9, 0x27, 0x48, 0x72,
        0xe2, 0xe0, 0x4c, 0xd4, 0x4f, 0x77, 0x45, 0xbc, 0xaf, 0x6a, 0x9e, 0x85, 0xb9, 0xec, 0x97, 0x7c, 0xdf, 0x6a,
        0x17, 0xcd, 0x66, 0xb0, 0xa8, 0x83, 0x91, 0x64, 0xfa, 0x50, 0x2f, 0xad, 0x0d, 0x76, 0x2c, 0x20, 0x05, 0xd5,
        0x00, 0xd5, 0xc0, 0x02, 0xe0, 0x1f, 0x53, 0x16, 0x8d, 0xff, 0x6a, 0x56, 0x34, 0xcf, 0x03, 0x1f, 0x6a, 0x48,
        0x7a, 0x46, 0x6a, 0xa0, 0x5e, 0x63, 0x9e, 0x6a, 0x0a, 0xb9, 0x0f, 0x4f, 0xda, 0x98, 0xd2, 0x9a, 0xf5, 0x55,
        0x47, 0xaf, 0x40, 0x85, 0x1d, 0x09, 0x59, 0x1d, 0xc9, 0xa3, 0xed, 0x69, 0x89, 0x07, 0xf3, 0x71, 0xa6, 0x99,
        0xfe, 0x7e, 0xd4, 0xa4, 0x70, 0x09, 0xb7, 0xc4, 0x00, 0x03, 0xed, 0x4e, 0xf0, 0x7f, 0x2c, 0xb9, 0xf4, 0xcb,
        0x7f, 0x4c, 0xb5, 0xf4, 0xcb, 0x3f, 0x4c, 0x8b, 0xf9,
    };
    char *expected[][2] = {
        {
            ":status", "200",
        },
        {
            "date", "Tue, 18 Oct 2016 04:00:09 GMT",
        },
        {
            "expires", "-1",
        },
        {
            "cache-control", "private, max-age=0",
        },
        {
            "content-type", "text/html; charset=ISO-8859-1",
        },
        {
            "p3p", "CP=\"This is not a P3P policy! See https://www.google.com/support/accounts/answer/151657?hl=en for "
                   "more info.\"",
        },
        {
            "content-encoding", "gzip",
        },
        {
            "server", "gws",
        },
        {
            "content-length", "4389",
        },
        {
            "x-xss-protection", "1; mode=block",
        },
        {
            "x-frame-options", "SAMEORIGIN",
        },
        {
            "set-cookie", "NID=88=OUC3kkNa3GjITcJTpww7iCmMyxOY8Bu7enw8awsyy0klxEF1N-mZQ2lIUf4vhzAbZNdsACq-"
                          "c09Z3x3ErS0xHpOhAkAltrBZgK9rEcJcAmVEB6IwVotOOmcjAJGUcKlhBMuWCOhl-YQfTg; expires=Wed, "
                          "19-Apr-2017 04:00:09 GMT; path=/; domain=.google.com; HttpOnly",
        },
        {
            "alt-svc", "quic=\":443\"; ma=2592000; v=\"36,35,34,33,32\"",
        },

    };
    struct h2get_hpack_ctx hhc;
    struct list headers, *cur, *next;
    int ret;
    h2get_hpack_ctx_init(&hhc, 10);
    list_init(&headers);
    ret = h2get_hpack_decode(&hhc, test, sizeof(test), &headers);
    assert(ret > 0);

    int i = 0;
    for (cur = headers.next; cur != &headers; cur = next) {
        struct h2get_decoded_header *hdh = list_to_dh(cur);

        next = cur->next;
        list_del(&hdh->node);

        assert(i < ARRAY_SIZE(expected));
        assert(strlen(expected[i][0]) == hdh->key.len);
        assert(strlen(expected[i][1]) == hdh->value.len);
        assert(!memcmp(expected[i][0], hdh->key.buf, hdh->key.len));
        assert(!memcmp(expected[i][1], hdh->value.buf, hdh->value.len));
        free(hdh->key.buf);
        free(hdh->value.buf);
        free(hdh);
        i++;
    }
    assert(i == ARRAY_SIZE(expected));
    return 0;
}

/* replays the examples in rfc 7541: C.6.  Response Examples with Huffman Coding */
int test_decode_header_successive_frames(void);
int test_decode_header_successive_frames(void)
{
    char *responses[] = {
        "\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b"
        "\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3",
        "\x48\x83\x64\x0e\xff\xc1\xc0\xbf",
        "\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0"
        "\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08"
        "\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07"};
    char *expected_1[] = {
        ":status",       "302",
        "cache-control", "private",
        "date",          "Mon, 21 Oct 2013 20:13:21 GMT",
        "location",      "https://www.example.com",
    };
    char *expected_2[] = {
        ":status",       "307",
        "cache-control", "private",
        "date",          "Mon, 21 Oct 2013 20:13:21 GMT",
        "location",      "https://www.example.com",
    };
    char *expected_3[] = {
        ":status",
        "200",
        "cache-control",
        "private",
        "date",
        "Mon, 21 Oct 2013 20:13:22 GMT",
        "location",
        "https://www.example.com",
        "content-encoding",
        "gzip",
        "set-cookie",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    };
    struct {
        char **expected;
        size_t len;
        size_t expected_dyn_size;
        size_t expected_dyn_elems;
        struct h2get_buf dyn_table_contents[8];
    } decoded[] = {
        {
            expected_1,
            ARRAY_SIZE(expected_1),
            222,
            4,
            {
                H2GET_BUFLIT("location"), H2GET_BUFLIT("https://www.example.com"), H2GET_BUFLIT("date"),
                H2GET_BUFLIT("Mon, 21 Oct 2013 20:13:21 GMT"), H2GET_BUFLIT("cache-control"), H2GET_BUFLIT("private"),
                H2GET_BUFLIT(":status"), H2GET_BUFLIT("302"),
            },
        },
        {
            expected_2,
            ARRAY_SIZE(expected_2),
            222,
            4,
            {
                H2GET_BUFLIT(":status"), H2GET_BUFLIT("307"), H2GET_BUFLIT("location"),
                H2GET_BUFLIT("https://www.example.com"), H2GET_BUFLIT("date"),
                H2GET_BUFLIT("Mon, 21 Oct 2013 20:13:21 GMT"), H2GET_BUFLIT("cache-control"), H2GET_BUFLIT("private"),
            },
        },
        {
            expected_3,
            ARRAY_SIZE(expected_3),
            215,
            3,
            {
                H2GET_BUFLIT("set-cookie"), H2GET_BUFLIT("foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
                H2GET_BUFLIT("content-encoding"), H2GET_BUFLIT("gzip"), H2GET_BUFLIT("date"),
                H2GET_BUFLIT("Mon, 21 Oct 2013 20:13:22 GMT"),
            },
        },
    };

    struct h2get_hpack_ctx hhc;
    struct list headers, *cur, *next;
    int ret;
    h2get_hpack_ctx_init(&hhc, 256);

    list_init(&headers);

    int n;
    for (n = 0; n < ARRAY_SIZE(decoded); n++) {
        int i = 0;
        char **expected = decoded[n].expected;

        ret = h2get_hpack_decode(&hhc, responses[n], strlen(responses[n]), &headers);
        assert(ret > 0);
        for (cur = headers.next; cur != &headers; cur = next) {
            struct h2get_decoded_header *hdh = list_to_dh(cur);

            next = cur->next;
            list_del(&hdh->node);

            assert(i < decoded[n].len);
            assert(strlen(expected[i]) == hdh->key.len);
            assert(strlen(expected[i + 1]) == hdh->value.len);
            assert(!memcmp(expected[i], hdh->key.buf, hdh->key.len));
            assert(!memcmp(expected[i + 1], hdh->value.buf, hdh->value.len));
            h2get_decoded_header_free(hdh);
            i += 2;
        }
        assert(i == decoded[n].len);
        assert(hhc.dyn_size == decoded[n].expected_dyn_size);
        for (i = 0, cur = hhc.dyn_table.next; cur != &hhc.dyn_table; cur = cur->next, i++) {
            struct h2get_decoded_header *hdh = list_to_dh(cur);

            assert(i < decoded[n].expected_dyn_elems);
            assert((decoded[n].dyn_table_contents[2 * i].len + decoded[n].dyn_table_contents[2 * i + 1].len + 32) ==
                   rfc7541_header_size(hdh));
            assert(decoded[n].dyn_table_contents[2 * i].len == hdh->key.len);
            assert(decoded[n].dyn_table_contents[2 * i + 1].len == hdh->value.len);
            assert(!memcmp(decoded[n].dyn_table_contents[2 * i].buf, hdh->key.buf, hdh->key.len));
            assert(!memcmp(decoded[n].dyn_table_contents[2 * i + 1].buf, hdh->value.buf, hdh->value.len));
        }
        assert(i == decoded[n].expected_dyn_elems);
    }
    h2get_hpack_ctx_empty(&hhc);
    return 0;
}
#endif
/* vim: set expandtab ts=4 sw=4: */
