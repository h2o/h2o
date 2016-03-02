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
#include <inttypes.h>
#include <stdio.h>
#include "../test.h"

static h2o_context_t ctx;

static void register_authority(h2o_globalconf_t *globalconf, h2o_iovec_t host, uint16_t port)
{
    static h2o_iovec_t x_authority = {H2O_STRLIT("x-authority")};

    h2o_hostconf_t *hostconf = h2o_config_register_host(globalconf, host, port);
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, "/", 0);
    h2o_file_register(pathconf, "t/00unit/assets", NULL, NULL, 0);

    char *authority = h2o_mem_alloc(host.len + sizeof(":" H2O_UINT16_LONGEST_STR));
    sprintf(authority, "%.*s:%" PRIu16, (int)host.len, host.base, port);
    h2o_headers_command_t *cmds = h2o_mem_alloc(sizeof(*cmds) * 2);
    cmds[0] = (h2o_headers_command_t){H2O_HEADERS_CMD_ADD, &x_authority, {authority, strlen(authority)}};
    cmds[1] = (h2o_headers_command_t){H2O_HEADERS_CMD_NULL};
    h2o_headers_register(pathconf, cmds);
}

static void check(const h2o_url_scheme_t *scheme, const char *host, const char *expected)
{
    h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx, ctx.globalconf->hosts);

    conn->req.input.method = h2o_iovec_init(H2O_STRLIT("GET"));
    conn->req.input.scheme = scheme;
    conn->req.input.authority = h2o_iovec_init(host, strlen(host));
    conn->req.input.path = h2o_iovec_init(H2O_STRLIT("/"));
    h2o_loopback_run_loop(conn);
    ok(conn->req.res.status == 200);

    size_t index = h2o_find_header_by_str(&conn->req.res.headers, H2O_STRLIT("x-authority"), SIZE_MAX);
    ok(index != SIZE_MAX);

    if (index != SIZE_MAX) {
        ok(h2o_memis(conn->req.res.headers.entries[index].value.base, conn->req.res.headers.entries[index].value.len, expected,
                     strlen(expected)));
    }

    h2o_loopback_destroy(conn);
}

void test_issues293()
{
    h2o_globalconf_t globalconf;

    h2o_config_init(&globalconf);

    /* register two hosts, using 80 and 443 */
    register_authority(&globalconf, h2o_iovec_init(H2O_STRLIT("default")), 65535);
    register_authority(&globalconf, h2o_iovec_init(H2O_STRLIT("host1")), 80);
    register_authority(&globalconf, h2o_iovec_init(H2O_STRLIT("host1")), 443);
    register_authority(&globalconf, h2o_iovec_init(H2O_STRLIT("host2")), 80);
    register_authority(&globalconf, h2o_iovec_init(H2O_STRLIT("host2")), 443);
    register_authority(&globalconf, h2o_iovec_init(H2O_STRLIT("host3")), 65535);

    h2o_context_init(&ctx, test_loop, &globalconf);

    /* run the tests */
    check(&H2O_URL_SCHEME_HTTP, "host1", "host1:80");
    check(&H2O_URL_SCHEME_HTTPS, "host1", "host1:443");
    check(&H2O_URL_SCHEME_HTTP, "host2", "host2:80");
    check(&H2O_URL_SCHEME_HTTPS, "host2", "host2:443");

    /* supplied port number in the Host header must be preferred */
    check(&H2O_URL_SCHEME_HTTP, "host1:80", "host1:80");
    check(&H2O_URL_SCHEME_HTTP, "host1:443", "host1:443");
    check(&H2O_URL_SCHEME_HTTPS, "host1:80", "host1:80");
    check(&H2O_URL_SCHEME_HTTPS, "host1:443", "host1:443");
    check(&H2O_URL_SCHEME_HTTP, "host2:80", "host2:80");
    check(&H2O_URL_SCHEME_HTTP, "host2:443", "host2:443");
    check(&H2O_URL_SCHEME_HTTPS, "host2:80", "host2:80");
    check(&H2O_URL_SCHEME_HTTPS, "host2:443", "host2:443");

    /* host-level conf without default port */
    check(&H2O_URL_SCHEME_HTTP, "host3", "host3:65535");
    check(&H2O_URL_SCHEME_HTTPS, "host3", "host3:65535");
    check(&H2O_URL_SCHEME_HTTP, "host3", "host3:65535");
    check(&H2O_URL_SCHEME_HTTPS, "host3", "host3:65535");
    check(&H2O_URL_SCHEME_HTTP, "host3:80", "host3:65535");
    check(&H2O_URL_SCHEME_HTTPS, "host3:80", "default:65535");
    check(&H2O_URL_SCHEME_HTTP, "host3:443", "default:65535");
    check(&H2O_URL_SCHEME_HTTPS, "host3:443", "host3:65535");

    /* upper-case */
    check(&H2O_URL_SCHEME_HTTP, "HoST1", "host1:80");
    check(&H2O_URL_SCHEME_HTTP, "HoST1:80", "host1:80");
    check(&H2O_URL_SCHEME_HTTPS, "HoST1", "host1:443");
    check(&H2O_URL_SCHEME_HTTPS, "HoST1:443", "host1:443");

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}
