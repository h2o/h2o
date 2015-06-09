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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/handler/fastcgi.c"

static h2o_context_t ctx;

static void test_build_request(void)
{
    h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);
    iovec_vector_t vecs;

    conn->req.method = h2o_iovec_init(H2O_STRLIT("GET"));
    conn->req.scheme = &H2O_URL_SCHEME_HTTP;
    conn->req.authority = h2o_iovec_init(H2O_STRLIT("localhost"));
    conn->req.path = h2o_iovec_init(H2O_STRLIT("/"));
    conn->req.query_at = SIZE_MAX;
    conn->req.version = 0x101;
    conn->req.pathconf = (*ctx.globalconf->hosts)->paths.entries;
    h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_COOKIE, H2O_STRLIT("foo=bar"));
    h2o_add_header(&conn->req.pool, &conn->req.headers, H2O_TOKEN_USER_AGENT,
                   H2O_STRLIT("Mozilla/5.0 (X11; Linux) KHTML/4.9.1 (like Gecko) Konqueror/4.9"));

    /* build with max_record_size=65535 */
    build_request(&conn->req, &vecs, 0x1234, 65535, 0);
    ok(vecs.size == 5);
    ok(h2o_memis(vecs.entries[0].base, vecs.entries[0].len, H2O_STRLIT("\x01\x01\x12\x34\x00\x08\x00\x00"
                                                                       "\x00\x01\0\0\0\0\0\0")));
    ok(h2o_memis(vecs.entries[1].base, vecs.entries[1].len, H2O_STRLIT("\x01\x04\x12\x34\x01\x00\x00\x00")));
    ok(h2o_memis(vecs.entries[2].base, vecs.entries[2].len,
                 H2O_STRLIT("\x0c\x00QUERY_STRING"                    /* */
                            "\x0e\x03REQUEST_METHODGET"               /* */
                            "\x0b\x01REQUEST_URI/"                    /* */
                            "\x0b\x07SERVER_NAMEdefault"              /* */
                            "\x0b\x05SERVER_PORT65535"                /* */
                            "\x0f\x08SERVER_PROTOCOLHTTP/1.1"         /* */
                            "\x0f\x10SERVER_SOFTWAREh2o/1.2.1-alpha1" /* */
                            "\x0b\x00SCRIPT_NAME"                     /* */
                            "\x0b\x07HTTP_COOKIEfoo=bar"              /* */
                            "\x0f\x3fHTTP_USER_AGENTMozilla/5.0 (X11; Linux) KHTML/4.9.1 (like Gecko) Konqueror/4.9" /* */)));
    ok(h2o_memis(vecs.entries[3].base, vecs.entries[3].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x00\x00\x00")));
    ok(h2o_memis(vecs.entries[4].base, vecs.entries[4].len, H2O_STRLIT("\x01\x05\x12\x34\x00\x00\x00\x00")));

    /* build with max_record_size=64, and content */
    conn->req.entity = h2o_iovec_init(H2O_STRLIT("The above copyright notice and this permission notice shall be included in all "
                                                 "copies or substantial portions of the Software."));
    build_request(&conn->req, &vecs, 0x1234, 64, 0);
    ok(vecs.size == 17);
    ok(h2o_memis(vecs.entries[0].base, vecs.entries[0].len, H2O_STRLIT("\x01\x01\x12\x34\x00\x08\x00\x00"
                                                                       "\x00\x01\0\0\0\0\0\0")));
    ok(h2o_memis(vecs.entries[1].base, vecs.entries[1].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x40\x00\x00")));
    ok(h2o_memis(vecs.entries[2].base, vecs.entries[2].len, H2O_STRLIT("\x0e\x03"
                                                                       "CONTENT_LENGTH126"         /* */
                                                                       "\x0c\x00QUERY_STRING"      /* */
                                                                       "\x0e\x03REQUEST_METHODGET" /* */
                                                                       "\x0b\x01REQUEST_UR")));
    ok(h2o_memis(vecs.entries[3].base, vecs.entries[3].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x40\x00\x00")));
    ok(h2o_memis(vecs.entries[4].base, vecs.entries[4].len, H2O_STRLIT("I/"                         /* */
                                                                       "\x0b\x07SERVER_NAMEdefault" /* */
                                                                       "\x0b\x05SERVER_PORT65535"   /* */
                                                                       "\x0f\x08SERVER_PROTOCOLHTTP/1.")));
    ok(h2o_memis(vecs.entries[5].base, vecs.entries[5].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x40\x00\x00")));
    ok(h2o_memis(vecs.entries[6].base, vecs.entries[6].len, H2O_STRLIT("1"                                       /* */
                                                                       "\x0f\x10SERVER_SOFTWAREh2o/1.2.1-alpha1" /* */
                                                                       "\x0b\x00SCRIPT_NAME"                     /* */
                                                                       "\x0b\x07HTTP_COOKIEfoo=")));
    ok(h2o_memis(vecs.entries[7].base, vecs.entries[7].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x40\x00\x00")));
    ok(h2o_memis(vecs.entries[8].base, vecs.entries[8].len,
                 H2O_STRLIT("bar" /* */
                            "\x0f\x3fHTTP_USER_AGENTMozilla/5.0 (X11; Linux) KHTML/4.9.1 (like G")));
    ok(h2o_memis(vecs.entries[9].base, vecs.entries[9].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x13\x00\x00")));
    ok(h2o_memis(vecs.entries[10].base, vecs.entries[10].len, H2O_STRLIT("ecko) Konqueror/4.9")));
    ok(h2o_memis(vecs.entries[11].base, vecs.entries[11].len, H2O_STRLIT("\x01\x04\x12\x34\x00\x00\x00\x00")));
    ok(h2o_memis(vecs.entries[12].base, vecs.entries[12].len, H2O_STRLIT("\x01\x05\x12\x34\x00\x40\x00\x00")));
    ok(h2o_memis(vecs.entries[13].base, vecs.entries[13].len,
                 H2O_STRLIT("The above copyright notice and this permission notice shall be i")));
    ok(h2o_memis(vecs.entries[14].base, vecs.entries[14].len, H2O_STRLIT("\x01\x05\x12\x34\x00\x3e\x00\x00")));
    ok(h2o_memis(vecs.entries[15].base, vecs.entries[15].len,
                 H2O_STRLIT("ncluded in all copies or substantial portions of the Software.")));
    ok(h2o_memis(vecs.entries[16].base, vecs.entries[16].len, H2O_STRLIT("\x01\x05\x12\x34\x00\x00\x00\x00")));

    h2o_loopback_destroy(conn);
}

void test_lib__handler__fastcgi_c()
{
    h2o_globalconf_t globalconf;
    h2o_hostconf_t *hostconf;
    h2o_pathconf_t *pathconf;

    h2o_config_init(&globalconf);
    globalconf.server_name = h2o_iovec_init(H2O_STRLIT("h2o/1.2.1-alpha1"));
    hostconf = h2o_config_register_host(&globalconf, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    pathconf = h2o_config_register_path(hostconf, "/");

    h2o_context_init(&ctx, test_loop, &globalconf);

    subtest("build-request", test_build_request);

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
