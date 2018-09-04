/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *      The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2007-2008,2010
 *      Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
 * Copyright (c) 2017,2018 Fastly
 * All rights reserved.
 *
 * Portions of this software were developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart,
 * James Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Portions of this software were developed by Robert N. M. Watson under
 * contract to Juniper Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tcp_input.c 8.12 (Berkeley) 5/24/95
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cc.h"

/* Enable RFC 3390 (Increasing TCP's Initial Congestion Window) */
int cc_tcp_do_rfc3390 = 1;

/* Enable RFC 3465 (Appropriate Byte Counting) */
int cc_tcp_do_rfc3465 = 1;

/* Cap the max cwnd increment during slow-start to this number of segments */
int cc_tcp_abc_l_var = 2;

int cc_hz = 100;
volatile int cc_ticks;

void *cc_malloc(size_t sz, const char *lbl)
{
    return malloc(sz);
}

void cc_free(void *p, const char *lbl)
{
    free(p);
}

#include "cc_int.h"

int cc_init(struct cc_var *ccv, struct cc_algo *algo, uint32_t cwnd, unsigned maxseg)
{
    int ret = 0;

    memset(ccv, 0, sizeof(*ccv));
    CCV(ccv, cc_algo) = algo;

    if (CCV(ccv, cc_algo)->cb_init != NULL && (ret = CCV(ccv, cc_algo)->cb_init(ccv)) != 0)
        return ret;

    CCV(ccv, snd_cwnd) = cwnd;
    CCV(ccv, t_maxseg) = maxseg;
    CCV(ccv, snd_ssthresh) = 65535 << 14;

    if (CCV(ccv, cc_algo)->conn_init != NULL)
        CCV(ccv, cc_algo)->conn_init(ccv);

    return ret;
}

void cc_destroy(struct cc_var *ccv)
{
    if (CCV(ccv, cc_algo)->cb_destroy != NULL)
        CCV(ccv, cc_algo)->cb_destroy(ccv);
}

void cc_ack_received(struct cc_var *ccv, uint16_t type, uint32_t bytes_in_pipe, uint16_t segs_acked, uint32_t bytes_acked, int srtt,
                     int exit_recovery)
{
    CCV(ccv, snd_pipe) = bytes_in_pipe;

    if (exit_recovery) {
        CCV(ccv, t_flags) &= ~CC_TF_RETRANSMIT;
        if (CC_ALGO(ccv)->post_recovery != NULL)
            CC_ALGO(ccv)->post_recovery(ccv);
        CCV(ccv, t_bytes_acked) = 0;
    }

    ccv->nsegs = segs_acked;
    ccv->bytes_this_ack = bytes_acked;
    if (CCV(ccv, snd_cwnd) <= CCV(ccv, snd_pipe))
        ccv->flags |= CCF_CWND_LIMITED;
    else
        ccv->flags &= ~CCF_CWND_LIMITED;

    if (type == CC_ACK) {
        if (CCV(ccv, snd_cwnd) > CCV(ccv, snd_ssthresh)) {
            CCV(ccv, t_bytes_acked) += min(bytes_acked, segs_acked * V_tcp_abc_l_var * CCV(ccv, t_maxseg));
            if (CCV(ccv, t_bytes_acked) >= CCV(ccv, snd_cwnd)) {
                CCV(ccv, t_bytes_acked) -= CCV(ccv, snd_cwnd);
                ccv->flags |= CCF_ABC_SENTAWND;
            }
        } else {
            ccv->flags &= ~CCF_ABC_SENTAWND;
            CCV(ccv, t_bytes_acked) = 0;
        }
        CCV(ccv, t_srtt) = srtt;
        CCV(ccv, t_rttupdated) = CCV(ccv, t_rttupdated) + 1;
    }

    if (CC_ALGO(ccv)->ack_received != NULL) {
        /* XXXLAS: Find a way to live without this */
        CC_ALGO(ccv)->ack_received(ccv, type);
    }

    if (exit_recovery)
        EXIT_RECOVERY(CCV(ccv, t_flags));
}

void cc_cong_signal(struct cc_var *ccv, uint32_t type, uint32_t bytes_in_pipe)
{
    unsigned maxseg;

    CCV(ccv, snd_pipe) = bytes_in_pipe;

    switch(type) {
    case CC_NDUPACK:
    case CC_ECN:
        break;
    case CC_FIRST_RTO:
        CCV(ccv, snd_cwnd_prev) = CCV(ccv, snd_cwnd);
        CCV(ccv, snd_ssthresh_prev) = CCV(ccv, snd_ssthresh);
        if (IN_FASTRECOVERY(CCV(ccv, t_flags))) {
            CCV(ccv, t_flags) |= CC_TF_WASFRECOVERY;
        } else {
            CCV(ccv, t_flags) &= ~CC_TF_WASFRECOVERY;
        }
        if (IN_CONGRECOVERY(CCV(ccv, t_flags))) {
            CCV(ccv, t_flags) |= CC_TF_WASCRECOVERY;
        } else {
            CCV(ccv, t_flags) &= ~CC_TF_WASCRECOVERY;
        }
        CCV(ccv, t_flags) |= CC_TF_PREVVALID;
        CCV(ccv, t_badrxtwin) = ticks + (CCV(ccv, t_srtt) >> (TCP_RTT_SHIFT + 1));
        /* fallthru */
    case CC_RTO:
        maxseg = CCV(ccv, t_maxseg);
        CCV(ccv, t_bytes_acked) = 0;
        EXIT_RECOVERY(CCV(ccv, t_flags));
        CCV(ccv, snd_ssthresh) = max(2, min(bytes_in_pipe, CCV(ccv, snd_cwnd)) / 2 / maxseg) * maxseg;
        CCV(ccv, snd_cwnd) = maxseg; /* KAZUHO FreeBSD does this; but is it correct? */
        CCV(ccv, t_flags) |= CC_TF_RETRANSMIT;
        break;
    case CC_RTO_ERR:
        CCV(ccv, snd_cwnd) = CCV(ccv, snd_cwnd_prev);
        CCV(ccv, snd_ssthresh) = CCV(ccv, snd_ssthresh_prev);
        if (CCV(ccv, t_flags) & CC_TF_WASFRECOVERY)
            ENTER_FASTRECOVERY(CCV(ccv, t_flags));
        if (CCV(ccv, t_flags) & CC_TF_WASCRECOVERY)
            ENTER_CONGRECOVERY(CCV(ccv, t_flags));
        CCV(ccv, t_flags) &= ~CC_TF_PREVVALID;
        CCV(ccv, t_badrxtwin) = 0;
        break;
    default:
        assert(!"FIXME");
        break;
    }

    if (CC_ALGO(ccv)->cong_signal != NULL) {
        CC_ALGO(ccv)->cong_signal(ccv, type);
    }
}
