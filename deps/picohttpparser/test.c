/* use `make test` to run the test */
/*
 * Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
 *                         Shigeo Mitsunari
 *
 * The software is licensed under either the MIT License (below) or the Perl
 * license.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picotest/picotest.h"
#include "picohttpparser.h"

static int bufis(const char *s, size_t l, const char *t)
{
    return strlen(t) == l && memcmp(s, t, l) == 0;
}

static void test_request(void)
{
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    int minor_version;
    struct phr_header headers[4];
    size_t num_headers;

#define PARSE(s, last_len, exp, comment)                                                                                           \
    do {                                                                                                                           \
        note(comment);                                                                                                             \
        num_headers = sizeof(headers) / sizeof(headers[0]);                                                                        \
        ok(phr_parse_request(s, sizeof(s) - 1, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers,      \
                             last_len) == (exp == 0 ? strlen(s) : exp));                                                           \
    } while (0)

    PARSE("GET / HTTP/1.0\r\n\r\n", 0, 0, "simple");
    ok(num_headers == 0);
    ok(bufis(method, method_len, "GET"));
    ok(bufis(path, path_len, "/"));
    ok(minor_version == 0);

    PARSE("GET / HTTP/1.0\r\n\r", 0, -2, "partial");

    PARSE("GET /hoge HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n", 0, 0, "parse headers");
    ok(num_headers == 2);
    ok(bufis(method, method_len, "GET"));
    ok(bufis(path, path_len, "/hoge"));
    ok(minor_version == 1);
    ok(bufis(headers[0].name, headers[0].name_len, "Host"));
    ok(bufis(headers[0].value, headers[0].value_len, "example.com"));
    ok(bufis(headers[1].name, headers[1].name_len, "Cookie"));
    ok(bufis(headers[1].value, headers[1].value_len, ""));

    PARSE("GET /hoge HTTP/1.1\r\nHost: example.com\r\nUser-Agent: \343\201\262\343/1.0\r\n\r\n", 0, 0, "multibyte included");
    ok(num_headers == 2);
    ok(bufis(method, method_len, "GET"));
    ok(bufis(path, path_len, "/hoge"));
    ok(minor_version == 1);
    ok(bufis(headers[0].name, headers[0].name_len, "Host"));
    ok(bufis(headers[0].value, headers[0].value_len, "example.com"));
    ok(bufis(headers[1].name, headers[1].name_len, "User-Agent"));
    ok(bufis(headers[1].value, headers[1].value_len, "\343\201\262\343/1.0"));

    PARSE("GET / HTTP/1.0\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n", 0, 0, "parse multiline");
    ok(num_headers == 3);
    ok(bufis(method, method_len, "GET"));
    ok(bufis(path, path_len, "/"));
    ok(minor_version == 0);
    ok(bufis(headers[0].name, headers[0].name_len, "foo"));
    ok(bufis(headers[0].value, headers[0].value_len, ""));
    ok(bufis(headers[1].name, headers[1].name_len, "foo"));
    ok(bufis(headers[1].value, headers[1].value_len, "b"));
    ok(headers[2].name == NULL);
    ok(bufis(headers[2].value, headers[2].value_len, "  \tc"));

    PARSE("GET / HTTP/1.0\r\nfoo : ab\r\n\r\n", 0, -1, "parse header name with trailing space");

    PARSE("GET", 0, -2, "incomplete 1");
    ok(method == NULL);
    PARSE("GET ", 0, -2, "incomplete 2");
    ok(bufis(method, method_len, "GET"));
    PARSE("GET /", 0, -2, "incomplete 3");
    ok(path == NULL);
    PARSE("GET / ", 0, -2, "incomplete 4");
    ok(bufis(path, path_len, "/"));
    PARSE("GET / H", 0, -2, "incomplete 5");
    PARSE("GET / HTTP/1.", 0, -2, "incomplete 6");
    PARSE("GET / HTTP/1.0", 0, -2, "incomplete 7");
    ok(minor_version == -1);
    PARSE("GET / HTTP/1.0\r", 0, -2, "incomplete 8");
    ok(minor_version == 0);

    PARSE("GET /hoge HTTP/1.0\r\n\r", strlen("GET /hoge HTTP/1.0\r\n\r") - 1, -2, "slowloris (incomplete)");
    PARSE("GET /hoge HTTP/1.0\r\n\r\n", strlen("GET /hoge HTTP/1.0\r\n\r\n") - 1, 0, "slowloris (complete)");

    PARSE("GET / HTTP/1.0\r\n:a\r\n\r\n", 0, -1, "empty header name");
    PARSE("GET / HTTP/1.0\r\n :a\r\n\r\n", 0, -1, "header name (space only)");

    PARSE("G\0T / HTTP/1.0\r\n\r\n", 0, -1, "NUL in method");
    PARSE("G\tT / HTTP/1.0\r\n\r\n", 0, -1, "tab in method");
    PARSE("GET /\x7fhello HTTP/1.0\r\n\r\n", 0, -1, "DEL in uri-path");
    PARSE("GET / HTTP/1.0\r\na\0b: c\r\n\r\n", 0, -1, "NUL in header name");
    PARSE("GET / HTTP/1.0\r\nab: c\0d\r\n\r\n", 0, -1, "NUL in header value");
    PARSE("GET / HTTP/1.0\r\na\033b: c\r\n\r\n", 0, -1, "CTL in header name");
    PARSE("GET / HTTP/1.0\r\nab: c\033\r\n\r\n", 0, -1, "CTL in header value");
    PARSE("GET / HTTP/1.0\r\n/: 1\r\n\r\n", 0, -1, "invalid char in header value");
    PARSE("GET /\xa0 HTTP/1.0\r\nh: c\xa2y\r\n\r\n", 0, 0, "accept MSB chars");
    ok(num_headers == 1);
    ok(bufis(method, method_len, "GET"));
    ok(bufis(path, path_len, "/\xa0"));
    ok(minor_version == 0);
    ok(bufis(headers[0].name, headers[0].name_len, "h"));
    ok(bufis(headers[0].value, headers[0].value_len, "c\xa2y"));

    PARSE("GET / HTTP/1.0\r\n\x7c\x7e: 1\r\n\r\n", 0, 0, "accept |~ (though forbidden by SSE)");
    ok(num_headers == 1);
    ok(bufis(headers[0].name, headers[0].name_len, "\x7c\x7e"));
    ok(bufis(headers[0].value, headers[0].value_len, "1"));

    PARSE("GET / HTTP/1.0\r\n\x7b: 1\r\n\r\n", 0, -1, "disallow {");

#undef PARSE
}

static void test_response(void)
{
    int minor_version;
    int status;
    const char *msg;
    size_t msg_len;
    struct phr_header headers[4];
    size_t num_headers;

#define PARSE(s, last_len, exp, comment)                                                                                           \
    do {                                                                                                                           \
        note(comment);                                                                                                             \
        num_headers = sizeof(headers) / sizeof(headers[0]);                                                                        \
        ok(phr_parse_response(s, strlen(s), &minor_version, &status, &msg, &msg_len, headers, &num_headers, last_len) ==           \
           (exp == 0 ? strlen(s) : exp));                                                                                          \
    } while (0)

    PARSE("HTTP/1.0 200 OK\r\n\r\n", 0, 0, "simple");
    ok(num_headers == 0);
    ok(status == 200);
    ok(minor_version = 1);
    ok(bufis(msg, msg_len, "OK"));

    PARSE("HTTP/1.0 200 OK\r\n\r", 0, -2, "partial");

    PARSE("HTTP/1.1 200 OK\r\nHost: example.com\r\nCookie: \r\n\r\n", 0, 0, "parse headers");
    ok(num_headers == 2);
    ok(minor_version == 1);
    ok(status == 200);
    ok(bufis(msg, msg_len, "OK"));
    ok(bufis(headers[0].name, headers[0].name_len, "Host"));
    ok(bufis(headers[0].value, headers[0].value_len, "example.com"));
    ok(bufis(headers[1].name, headers[1].name_len, "Cookie"));
    ok(bufis(headers[1].value, headers[1].value_len, ""));

    PARSE("HTTP/1.0 200 OK\r\nfoo: \r\nfoo: b\r\n  \tc\r\n\r\n", 0, 0, "parse multiline");
    ok(num_headers == 3);
    ok(minor_version == 0);
    ok(status == 200);
    ok(bufis(msg, msg_len, "OK"));
    ok(bufis(headers[0].name, headers[0].name_len, "foo"));
    ok(bufis(headers[0].value, headers[0].value_len, ""));
    ok(bufis(headers[1].name, headers[1].name_len, "foo"));
    ok(bufis(headers[1].value, headers[1].value_len, "b"));
    ok(headers[2].name == NULL);
    ok(bufis(headers[2].value, headers[2].value_len, "  \tc"));

    PARSE("HTTP/1.0 500 Internal Server Error\r\n\r\n", 0, 0, "internal server error");
    ok(num_headers == 0);
    ok(minor_version == 0);
    ok(status == 500);
    ok(bufis(msg, msg_len, "Internal Server Error"));
    ok(msg_len == sizeof("Internal Server Error") - 1);

    PARSE("H", 0, -2, "incomplete 1");
    PARSE("HTTP/1.", 0, -2, "incomplete 2");
    PARSE("HTTP/1.1", 0, -2, "incomplete 3");
    ok(minor_version == -1);
    PARSE("HTTP/1.1 ", 0, -2, "incomplete 4");
    ok(minor_version == 1);
    PARSE("HTTP/1.1 2", 0, -2, "incomplete 5");
    PARSE("HTTP/1.1 200", 0, -2, "incomplete 6");
    ok(status == 0);
    PARSE("HTTP/1.1 200 ", 0, -2, "incomplete 7");
    ok(status == 200);
    PARSE("HTTP/1.1 200 O", 0, -2, "incomplete 8");
    PARSE("HTTP/1.1 200 OK\r", 0, -2, "incomplete 9");
    ok(msg == NULL);
    PARSE("HTTP/1.1 200 OK\r\n", 0, -2, "incomplete 10");
    ok(bufis(msg, msg_len, "OK"));
    PARSE("HTTP/1.1 200 OK\n", 0, -2, "incomplete 11");
    ok(bufis(msg, msg_len, "OK"));

    PARSE("HTTP/1.1 200 OK\r\nA: 1\r", 0, -2, "incomplete 11");
    ok(num_headers == 0);
    PARSE("HTTP/1.1 200 OK\r\nA: 1\r\n", 0, -2, "incomplete 12");
    ok(num_headers == 1);
    ok(bufis(headers[0].name, headers[0].name_len, "A"));
    ok(bufis(headers[0].value, headers[0].value_len, "1"));

    PARSE("HTTP/1.0 200 OK\r\n\r", strlen("HTTP/1.0 200 OK\r\n\r") - 1, -2, "slowloris (incomplete)");
    PARSE("HTTP/1.0 200 OK\r\n\r\n", strlen("HTTP/1.0 200 OK\r\n\r\n") - 1, 0, "slowloris (complete)");

    PARSE("HTTP/1. 200 OK\r\n\r\n", 0, -1, "invalid http version");
    PARSE("HTTP/1.2z 200 OK\r\n\r\n", 0, -1, "invalid http version 2");
    PARSE("HTTP/1.1  OK\r\n\r\n", 0, -1, "no status code");

#undef PARSE
}

static void test_headers(void)
{
    /* only test the interface; the core parser is tested by the tests above */

    struct phr_header headers[4];
    size_t num_headers;

#define PARSE(s, last_len, exp, comment)                                                                                           \
    do {                                                                                                                           \
        note(comment);                                                                                                             \
        num_headers = sizeof(headers) / sizeof(headers[0]);                                                                        \
        ok(phr_parse_headers(s, strlen(s), headers, &num_headers, last_len) == (exp == 0 ? strlen(s) : exp));                      \
    } while (0)

    PARSE("Host: example.com\r\nCookie: \r\n\r\n", 0, 0, "simple");
    ok(num_headers == 2);
    ok(bufis(headers[0].name, headers[0].name_len, "Host"));
    ok(bufis(headers[0].value, headers[0].value_len, "example.com"));
    ok(bufis(headers[1].name, headers[1].name_len, "Cookie"));
    ok(bufis(headers[1].value, headers[1].value_len, ""));

    PARSE("Host: example.com\r\nCookie: \r\n\r\n", 1, 0, "slowloris");
    ok(num_headers == 2);
    ok(bufis(headers[0].name, headers[0].name_len, "Host"));
    ok(bufis(headers[0].value, headers[0].value_len, "example.com"));
    ok(bufis(headers[1].name, headers[1].name_len, "Cookie"));
    ok(bufis(headers[1].value, headers[1].value_len, ""));

    PARSE("Host: example.com\r\nCookie: \r\n\r", 0, -2, "partial");

    PARSE("Host: e\7fample.com\r\nCookie: \r\n\r", 0, -1, "error");

#undef PARSE
}

static void test_chunked_at_once(int line, int consume_trailer, const char *encoded, const char *decoded, ssize_t expected)
{
    struct phr_chunked_decoder dec = {0};
    char *buf;
    size_t bufsz;
    ssize_t ret;

    dec.consume_trailer = consume_trailer;

    note("testing at-once, source at line %d", line);

    buf = strdup(encoded);
    bufsz = strlen(buf);

    ret = phr_decode_chunked(&dec, buf, &bufsz);

    ok(ret == expected);
    ok(bufsz == strlen(decoded));
    ok(bufis(buf, bufsz, decoded));
    if (expected >= 0) {
        if (ret == expected)
            ok(bufis(buf + bufsz, ret, encoded + strlen(encoded) - ret));
        else
            ok(0);
    }

    free(buf);
}

static void test_chunked_per_byte(int line, int consume_trailer, const char *encoded, const char *decoded, ssize_t expected)
{
    struct phr_chunked_decoder dec = {0};
    char *buf = malloc(strlen(encoded) + 1);
    size_t bytes_to_consume = strlen(encoded) - (expected >= 0 ? expected : 0), bytes_ready = 0, bufsz, i;
    ssize_t ret;

    dec.consume_trailer = consume_trailer;

    note("testing per-byte, source at line %d", line);

    for (i = 0; i < bytes_to_consume - 1; ++i) {
        buf[bytes_ready] = encoded[i];
        bufsz = 1;
        ret = phr_decode_chunked(&dec, buf + bytes_ready, &bufsz);
        if (ret != -2) {
            ok(0);
            return;
        }
        bytes_ready += bufsz;
    }
    strcpy(buf + bytes_ready, encoded + bytes_to_consume - 1);
    bufsz = strlen(buf + bytes_ready);
    ret = phr_decode_chunked(&dec, buf + bytes_ready, &bufsz);
    ok(ret == expected);
    bytes_ready += bufsz;
    ok(bytes_ready == strlen(decoded));
    ok(bufis(buf, bytes_ready, decoded));
    if (expected >= 0) {
        if (ret == expected)
            ok(bufis(buf + bytes_ready, expected, encoded + bytes_to_consume));
        else
            ok(0);
    }

    free(buf);
}

static void test_chunked_failure(int line, const char *encoded, ssize_t expected)
{
    struct phr_chunked_decoder dec = {0};
    char *buf = strdup(encoded);
    size_t bufsz, i;
    ssize_t ret;

    note("testing failure at-once, source at line %d", line);
    bufsz = strlen(buf);
    ret = phr_decode_chunked(&dec, buf, &bufsz);
    ok(ret == expected);

    note("testing failure per-byte, source at line %d", line);
    memset(&dec, 0, sizeof(dec));
    for (i = 0; encoded[i] != '\0'; ++i) {
        buf[0] = encoded[i];
        bufsz = 1;
        ret = phr_decode_chunked(&dec, buf, &bufsz);
        if (ret == -1) {
            ok(ret == expected);
            return;
        } else if (ret == -2) {
            /* continue */
        } else {
            ok(0);
            return;
        }
    }
    ok(ret == expected);

    free(buf);
}

static void (*chunked_test_runners[])(int, int, const char *, const char *, ssize_t) = {test_chunked_at_once, test_chunked_per_byte,
                                                                                        NULL};

static void test_chunked(void)
{
    size_t i;

    for (i = 0; chunked_test_runners[i] != NULL; ++i) {
        chunked_test_runners[i](__LINE__, 0, "b\r\nhello world\r\n0\r\n", "hello world", 0);
        chunked_test_runners[i](__LINE__, 0, "6\r\nhello \r\n5\r\nworld\r\n0\r\n", "hello world", 0);
        chunked_test_runners[i](__LINE__, 0, "6;comment=hi\r\nhello \r\n5\r\nworld\r\n0\r\n", "hello world", 0);
        chunked_test_runners[i](__LINE__, 0, "6\r\nhello \r\n5\r\nworld\r\n0\r\na: b\r\nc: d\r\n\r\n", "hello world",
                                sizeof("a: b\r\nc: d\r\n\r\n") - 1);
        chunked_test_runners[i](__LINE__, 0, "b\r\nhello world\r\n0\r\n", "hello world", 0);
    }

    note("failures");
    test_chunked_failure(__LINE__, "z\r\nabcdefg", -1);
    if (sizeof(size_t) == 8) {
        test_chunked_failure(__LINE__, "6\r\nhello \r\nffffffffffffffff\r\nabcdefg", -2);
        test_chunked_failure(__LINE__, "6\r\nhello \r\nfffffffffffffffff\r\nabcdefg", -1);
    }
}

static void test_chunked_consume_trailer(void)
{
    size_t i;

    for (i = 0; chunked_test_runners[i] != NULL; ++i) {
        chunked_test_runners[i](__LINE__, 1, "b\r\nhello world\r\n0\r\n", "hello world", -2);
        chunked_test_runners[i](__LINE__, 1, "6\r\nhello \r\n5\r\nworld\r\n0\r\n", "hello world", -2);
        chunked_test_runners[i](__LINE__, 1, "6;comment=hi\r\nhello \r\n5\r\nworld\r\n0\r\n", "hello world", -2);
        chunked_test_runners[i](__LINE__, 1, "b\r\nhello world\r\n0\r\n\r\n", "hello world", 0);
        chunked_test_runners[i](__LINE__, 1, "b\nhello world\n0\n\n", "hello world", 0);
        chunked_test_runners[i](__LINE__, 1, "6\r\nhello \r\n5\r\nworld\r\n0\r\na: b\r\nc: d\r\n\r\n", "hello world", 0);
    }
}

int main(int argc, char **argv)
{
    subtest("request", test_request);
    subtest("response", test_response);
    subtest("headers", test_headers);
    subtest("chunked", test_chunked);
    subtest("chunked-consume-trailer", test_chunked_consume_trailer);
    return done_testing();
}
