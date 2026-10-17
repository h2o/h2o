/*
 * Copyright (c) 2024 Fastly, Inc.
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
#include <string.h>
#include "../../test.h"
#include "../../../../lib/core/logconf.c"

/* %{error}x emits the accumulated per-request error log. The bytes are attacker-influenced (upstream fastcgi stderr, proxy error
 * strings, repeated per-error prefixes carrying the request authority and path) and can exceed the caller's line buffer. Confirm
 * the emitted element reserves space for the fully-escaped output rather than writing past the buffer. */
static void test_error_escape_reserves(void)
{
    static const size_t payload_len = 8192;
    char errbuf[256];
    h2o_logconf_t *conf = h2o_logconf_compile("%{error}x", H2O_LOGCONF_ESCAPE_JSON, errbuf);
    ok(conf != NULL);
    if (conf == NULL)
        return;

    h2o_req_t req = {NULL};
    h2o_mem_init_pool(&req.pool);

    /* fill the error log with bytes that each expand to the 6-byte "\uXXXX" form under JSON escaping */
    h2o_buffer_init(&req.error_logs, &h2o_socket_buffer_prototype);
    char *payload = h2o_mem_alloc(payload_len);
    memset(payload, 0x01, payload_len);
    h2o_buffer_append(&req.error_logs, payload, payload_len);

    /* pass a small stack buffer; h2o_log_request must grow it on demand instead of overrunning */
    char buf[128];
    size_t len = sizeof(buf);
    char *line = h2o_log_request(conf, &req, &len, buf);

    ok(len == payload_len * 6 + 1); /* 6 bytes per escaped byte, plus the trailing '\n' suffix */
    int all_escaped = 1;
    for (size_t i = 0; i < payload_len; ++i) {
        if (memcmp(line + i * 6, "\\u0001", 6) != 0) {
            all_escaped = 0;
            break;
        }
    }
    ok(all_escaped);

    if (line != buf)
        free(line);
    free(payload);
    h2o_buffer_dispose(&req.error_logs);
    h2o_mem_clear_pool(&req.pool);
    h2o_logconf_dispose(conf);
}

void test_lib__core__logconf_c(void)
{
    subtest("error-escape-reserves", test_error_escape_reserves);
}
