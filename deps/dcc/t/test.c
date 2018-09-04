/*-
 * Copyright (c) 2017,2018 Fastly
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <string.h>
#include "picotest.h"
#include "cc.h"

struct cc_algo *cur_algo = NULL;
static int cur_step;

static void test_ss_core(void)
{
    struct cc_var ccv;
    int i;

    cc_ticks = 0;
    cc_init(&ccv, cur_algo, 1280 * 8, 1280);
    cc_ticks += 10;

    for (i = 1; i <= 8; i += cur_step) {
        cc_ack_received(&ccv, CC_ACK, cc_get_cwnd(&ccv), cur_step, cur_step * cc_get_maxseg(&ccv), 10, 0);
    }
    ok(cc_get_cwnd(&ccv) == 16 * cc_get_maxseg(&ccv));

    cc_destroy(&ccv);
}

static void test_rto(void)
{
    struct cc_var ccv;
    uint32_t bytes_in_pipe;

    cc_ticks = 0;

    cc_init(&ccv, cur_algo, 1280 * 4, 1280);

    /* send four, get three acked (but not the second one) */
    bytes_in_pipe = cc_get_cwnd(&ccv);
    cc_ticks += 10;
    cc_ack_received(&ccv, CC_ACK, bytes_in_pipe, 3, 3 * cc_get_maxseg(&ccv), 10, 0);
    ok(cc_get_cwnd(&ccv) == 7 * cc_get_maxseg(&ccv));

    /* retransmit */
    cc_ticks += 10;
    cc_cong_signal(&ccv, CC_RTO, cc_get_cwnd(&ccv));
    ok(ccv.ccvc.ccv.snd_ssthresh == 3 * cc_get_maxseg(&ccv));
    ok(cc_get_cwnd(&ccv) == cc_get_maxseg(&ccv));

    /* get acks for all */
    cc_ticks += 10;
    cc_ack_received(&ccv, CC_ACK, bytes_in_pipe, 1, cc_get_maxseg(&ccv), 10, 1);
    ok(cc_get_cwnd(&ccv) <= 2 * cc_get_maxseg(&ccv));

    cc_destroy(&ccv);
}

static void test_dupack(void)
{
    struct cc_var ccv;

    cc_ticks = 0;

    cc_init(&ccv, cur_algo, 1280 * 4, 1280);

    /* send 4 packets, got 3 dupacks */
    cc_ticks += 10;
    cc_ack_received(&ccv, CC_DUPACK, 1280 * 4, 0, 0, 10, 0);
    cc_ticks += 10;
    cc_ack_received(&ccv, CC_DUPACK, 1280 * 4, 0, 0, 10, 0);
    cc_ticks += 10;
    cc_cong_signal(&ccv, CC_NDUPACK, 1280 * 4);
    cc_ack_received(&ccv, CC_DUPACK, 1280 * 4, 0, 0, 10, 0);

    ok(CC_IN_RECOVERY(ccv.ccvc.ccv.t_flags));
    ok(cc_get_cwnd(&ccv) <= 1280 * 4);
    ok(ccv.ccvc.ccv.snd_ssthresh < 1280 * 4);

    /* got ack for 4 packets */
    cc_ticks += 10;
    cc_ack_received(&ccv, CC_ACK, 1280 * 4, 4, 1280 * 4, 10, 1);
    ok(cc_get_cwnd(&ccv) <= 1280 * 4);

    cc_destroy(&ccv);
}

static void test_algo(void)
{
    cur_step = 1;
    subtest("ss;step=1", test_ss_core);
    cur_step = 2;
    subtest("ss;step=2", test_ss_core);
    cur_step = 8;
    subtest("ss;step=8", test_ss_core);

    subtest("rto", test_rto);

    subtest("dupack", test_dupack);
}

int main(int argc, char **argv)
{
    extern struct cc_algo cubic_cc_algo;

    cur_algo = &newreno_cc_algo;
    subtest("newreno", test_algo);
    cur_algo = &cubic_cc_algo;
    subtest("cubic", test_algo);

    return done_testing();
}
