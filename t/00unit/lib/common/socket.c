/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include "../../../../lib/common/socket.c"

static void test_on_alpn_select(void)
{
    static const h2o_iovec_t protocols[] = {{H2O_STRLIT("h2")}, {H2O_STRLIT("h2-16")}, {H2O_STRLIT("h2-14")}, {}};
    const unsigned char *out;
    unsigned char outlen;
    int ret;

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\3foo"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_NOACK);

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\2h2"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_OK);
    ok(h2o_memis(out, outlen, H2O_STRLIT("h2")));

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\5h2-14\5h2-16\2h2"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_OK);
    ok(h2o_memis(out, outlen, H2O_STRLIT("h2")));

    ret = on_alpn_select(NULL, &out, &outlen, (const unsigned char *)H2O_STRLIT("\5h2-14\5h2-16"), (void *)protocols);
    ok(ret == SSL_TLSEXT_ERR_OK);
    ok(h2o_memis(out, outlen, H2O_STRLIT("h2-16")));
}

static void test_sliding_counter(void)
{
    h2o_sliding_counter_t counter = {};
    size_t i;

    h2o_sliding_counter_start(&counter, 100);
    h2o_sliding_counter_stop(&counter, 80 + 100);
    ok(counter.average == 10);

    for (i = 0; i != 7; ++i) {
        h2o_sliding_counter_start(&counter, 1);
        h2o_sliding_counter_stop(&counter, 81);
    }
    ok(counter.average == 80);

    h2o_sliding_counter_start(&counter, 1000);
    h2o_sliding_counter_stop(&counter, 1000 + 1000 * 8 - 80 * 7);
    ok(counter.average == 1000);

    for (i = 0; i != 8; ++i) {
        h2o_sliding_counter_start(&counter, 1);
        h2o_sliding_counter_stop(&counter, 11);
    }
    ok(counter.average == 10);
}

static struct {
    struct {
        int ret;
        struct st_h2o_socket_tcp_info_t tcp_info;
    } fetch_tcp_info;
    struct {
        int ret;
        size_t call_cnt;
    } minimize_notsent_lowat;
    struct {
        unsigned long ret;
    } get_cipher;
} cb_ret_vars;

static int test_fetch_tcp_info(h2o_socket_t *sock, struct st_h2o_socket_tcp_info_t *info)
{
    memcpy(info, &cb_ret_vars.fetch_tcp_info.tcp_info, sizeof(*info));
    return cb_ret_vars.fetch_tcp_info.ret;
}

static int test_minimize_notsent_lowat(h2o_socket_t *sock)
{
    ++cb_ret_vars.minimize_notsent_lowat.call_cnt;
    return cb_ret_vars.minimize_notsent_lowat.ret;
}

static unsigned long test_get_cipher(h2o_socket_t *sock)
{
    return cb_ret_vars.get_cipher.ret;
}

static void test_prepare_for_latency_optimization(void)
{
    h2o_socket_t sock = {};
    h2o_socket_latency_optimization_conditions_t cond = {UINT_MAX, 65535};

    /* feature unabled */
    memset(&sock, 0, sizeof(sock));
    memset(&cb_ret_vars, 0, sizeof(cb_ret_vars));
    cb_ret_vars.fetch_tcp_info.ret = -1;
    cb_ret_vars.minimize_notsent_lowat.ret = -1;
    prepare_for_latency_optimized_write(&sock, &cond, test_fetch_tcp_info, test_minimize_notsent_lowat, test_get_cipher);
    ok(cb_ret_vars.minimize_notsent_lowat.call_cnt == 0);
    ok(sock._latency_optimization.mode == H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_DISABLED);
    ok(sock._latency_optimization.suggested_write_size == SIZE_MAX);

    /* option disabled, or if rtt is too small */
    memset(&sock, 0, sizeof(sock));
    memset(&cb_ret_vars, 0, sizeof(cb_ret_vars));
    cb_ret_vars.fetch_tcp_info.ret = 0;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_rtt = 50000; /* 50 ms */
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_snd_mss = 1400;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_snd_cwnd = 10;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_unacked = 5;
    cb_ret_vars.get_cipher.ret = TLS1_CK_RSA_WITH_AES_128_GCM_SHA256;
    prepare_for_latency_optimized_write(&sock, &cond, test_fetch_tcp_info, test_minimize_notsent_lowat, test_get_cipher);
    ok(sock._latency_optimization.mode == H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_DISABLED);
    ok(sock._latency_optimization.suggested_write_size == SIZE_MAX);
    ok(sock._latency_optimization.tls_overhead == 5 + 8 + 16);
    ok(cb_ret_vars.minimize_notsent_lowat.call_cnt == 0);

    /* trigger optimiziation */
    memset(&sock, 0, sizeof(sock));
    cond.min_rtt = 25; /* 25 ms */
    prepare_for_latency_optimized_write(&sock, &cond, test_fetch_tcp_info, test_minimize_notsent_lowat, test_get_cipher);
    ok(sock._latency_optimization.mode == H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_USE_TINY_TLS_RECORDS);
    ok(sock._latency_optimization.suggested_write_size == (1400 - (5 + 8 + 16)) * (10 - 5 + 1));
    ok(sock._latency_optimization.tls_overhead = 5 + 8 + 16);
    ok(cb_ret_vars.minimize_notsent_lowat.call_cnt == 1);

    /* recalculate with an updated cwnd,unacked */
    sock._latency_optimization.mode = H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_NEEDS_UPDATE;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_snd_cwnd = 14;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_unacked = 3;
    prepare_for_latency_optimized_write(&sock, &cond, test_fetch_tcp_info, test_minimize_notsent_lowat, test_get_cipher);
    ok(sock._latency_optimization.mode == H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_USE_TINY_TLS_RECORDS);
    ok(sock._latency_optimization.suggested_write_size == (1400 - (5 + 8 + 16)) * (14 - 3 + 1));
    ok(sock._latency_optimization.tls_overhead == 5 + 8 + 16);
    ok(cb_ret_vars.minimize_notsent_lowat.call_cnt == 1);

    /* switches to B/W optimization when CWND becomes greater */
    sock._latency_optimization.mode = H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_NEEDS_UPDATE;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_snd_cwnd = (65535 / 1400) + 1;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_unacked = 3;
    prepare_for_latency_optimized_write(&sock, &cond, test_fetch_tcp_info, test_minimize_notsent_lowat, test_get_cipher);
    ok(sock._latency_optimization.mode == H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_USE_LARGE_TLS_RECORDS);
    ok(sock._latency_optimization.suggested_write_size == SIZE_MAX);
    ok(sock._latency_optimization.tls_overhead == 5 + 8 + 16);
    ok(cb_ret_vars.minimize_notsent_lowat.call_cnt == 1);

    /* switches back to latency optimization when CWND becomes small */
    sock._latency_optimization.mode = H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_NEEDS_UPDATE;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_snd_cwnd = 8;
    cb_ret_vars.fetch_tcp_info.tcp_info.tcpi_unacked = 3;
    prepare_for_latency_optimized_write(&sock, &cond, test_fetch_tcp_info, test_minimize_notsent_lowat, test_get_cipher);
    ok(sock._latency_optimization.mode == H2O_SOCKET_LATENCY_OPTIMIZATION_MODE_USE_TINY_TLS_RECORDS);
    ok(sock._latency_optimization.suggested_write_size == (1400 - (5 + 8 + 16)) * (8 - 3 + 1));
    ok(sock._latency_optimization.tls_overhead == 5 + 8 + 16);
    ok(cb_ret_vars.minimize_notsent_lowat.call_cnt == 1);
}

void test_lib__common__socket_c(void)
{
    subtest("on_alpn_select", test_on_alpn_select);
    subtest("sliding_counter", test_sliding_counter);
    subtest("prepare_for_latency_optimization", test_prepare_for_latency_optimization);
}
