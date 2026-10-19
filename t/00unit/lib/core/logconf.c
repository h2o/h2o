/*
 * Copyright (c) 2026 the h2o authors
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include "../../test.h"
#include "../../../../lib/core/logconf.c"

/* the size of the error log that is used for testing; it is intentionally larger than the size of the buffer that is
 * passed to `h2o_log_request` by the access log handler */
#define TEST_ERROR_LOG_SIZE 10000

static void test_log_request_error_element(void)
{
    h2o_logconf_t *logconf;
    char errbuf[256];
    h2o_req_t req;
    h2o_buffer_t *error_logs = NULL;
    char buf[4096];
    size_t len = sizeof(buf);
    char *line;
    char *error_text;
    size_t i;

    /* compile a log configuration that emits the error log */
    logconf = h2o_logconf_compile("%{error}x", H2O_LOGCONF_ESCAPE_APACHE, errbuf);
    ok(logconf != NULL);
    if (logconf == NULL)
        return;

    /* prepare an error log that does not fit into the buffer used for logging */
    error_text = h2o_mem_alloc(TEST_ERROR_LOG_SIZE);
    for (i = 0; i < TEST_ERROR_LOG_SIZE; ++i)
        error_text[i] = (char)('a' + (i % 26));
    h2o_buffer_init(&error_logs, &h2o_socket_buffer_prototype);
    h2o_buffer_append(&error_logs, error_text, TEST_ERROR_LOG_SIZE);

    /* the element being tested accesses nothing but `error_logs` */
    memset(&req, 0, sizeof(req));
    req.error_logs = error_logs;

    /* generate the log line; the buffer is too small to hold the error log, therefore the line buffer is expected to be
     * expanded (and, prior to the fix, the error log was written out of the bounds of the buffer) */
    line = h2o_log_request(logconf, &req, &len, buf);
    ok(line != buf);
    ok(len == TEST_ERROR_LOG_SIZE + 1); /* the error log and the terminating newline */
    ok(memcmp(line, error_text, TEST_ERROR_LOG_SIZE) == 0);
    ok(line[TEST_ERROR_LOG_SIZE] == '\n');

    if (line != buf)
        free(line);
    h2o_buffer_dispose(&error_logs);
    free(error_text);
    h2o_logconf_dispose(logconf);
}

static void test_log_request_error_element_with_escaping(void)
{
    h2o_logconf_t *logconf;
    char errbuf[256];
    h2o_req_t req;
    h2o_buffer_t *error_logs = NULL;
    char buf[4096];
    size_t len = sizeof(buf);
    char *line;
    static const char error_text[] = "a\tb\"c";

    logconf = h2o_logconf_compile("%{error}x", H2O_LOGCONF_ESCAPE_APACHE, errbuf);
    ok(logconf != NULL);
    if (logconf == NULL)
        return;

    h2o_buffer_init(&error_logs, &h2o_socket_buffer_prototype);
    h2o_buffer_append(&error_logs, error_text, sizeof(error_text) - 1);

    memset(&req, 0, sizeof(req));
    req.error_logs = error_logs;

    line = h2o_log_request(logconf, &req, &len, buf);
    /* "a" and "b" are emitted as-is, while "\t" and '"' are escaped as `\x09` and `\x22`; the line is terminated by a
     * newline */
    ok(len == 12);
    ok(memcmp(line, "a\\x09b\\x22c\n", 12) == 0);

    if (line != buf)
        free(line);
    h2o_buffer_dispose(&error_logs);
    h2o_logconf_dispose(logconf);
}

void test_lib__core__logconf_c(void)
{
    subtest("log_request_error_element", test_log_request_error_element);
    subtest("log_request_error_element_with_escaping", test_log_request_error_element_with_escaping);
}
