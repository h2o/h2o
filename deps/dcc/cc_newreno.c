/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2007-2008,2010
 *	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart, James
 * Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
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

/*
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include "cc_int.h"

static void	newreno_ack_received(struct cc_var *ccv, uint16_t type);
static void	newreno_after_idle(struct cc_var *ccv);
static void	newreno_cong_signal(struct cc_var *ccv, uint32_t type);
static void	newreno_post_recovery(struct cc_var *ccv);

struct cc_algo newreno_cc_algo = {
	.name = "newreno",
	.ack_received = newreno_ack_received,
	.after_idle = newreno_after_idle,
	.cong_signal = newreno_cong_signal,
	.post_recovery = newreno_post_recovery,
};

static void
newreno_ack_received(struct cc_var *ccv, uint16_t type)
{
	if (type == CC_ACK && !IN_RECOVERY(CCV(ccv, t_flags)) &&
	    (ccv->flags & CCF_CWND_LIMITED)) {
		unsigned cw = CCV(ccv, snd_cwnd);
		unsigned incr = CCV(ccv, t_maxseg);

		/*
		 * Regular in-order ACK, open the congestion window.
		 * Method depends on which congestion control state we're
		 * in (slow start or cong avoid) and if ABC (RFC 3465) is
		 * enabled.
		 *
		 * slow start: cwnd <= ssthresh
		 * cong avoid: cwnd > ssthresh
		 *
		 * slow start and ABC (RFC 3465):
		 *   Grow cwnd exponentially by the amount of data
		 *   ACKed capping the max increment per ACK to
		 *   (abc_l_var * maxseg) bytes.
		 *
		 * slow start without ABC (RFC 5681):
		 *   Grow cwnd exponentially by maxseg per ACK.
		 *
		 * cong avoid and ABC (RFC 3465):
		 *   Grow cwnd linearly by maxseg per RTT for each
		 *   cwnd worth of ACKed data.
		 *
		 * cong avoid without ABC (RFC 5681):
		 *   Grow cwnd linearly by approximately maxseg per RTT using
		 *   maxseg^2 / cwnd per ACK as the increment.
		 *   If cwnd > maxseg^2, fix the cwnd increment at 1 byte to
		 *   avoid capping cwnd.
		 */
		if (cw > CCV(ccv, snd_ssthresh)) {
			if (V_tcp_do_rfc3465) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else
				incr = max((incr * incr / cw), 1);
		} else if (V_tcp_do_rfc3465) {
			/*
			 * In slow-start with ABC enabled and no RTO in sight?
			 * (Must not use abc_l_var > 1 if slow starting after
			 * an RTO. On RTO, snd_nxt = snd_una, so the
			 * snd_nxt == snd_max check is sufficient to
			 * handle this).
			 *
			 * XXXLAS: Find a way to signal SS after RTO that
			 * doesn't rely on tcpcb vars.
			 */
			if (!(CCV(ccv, t_flags) & CC_TF_RETRANSMIT))
				incr = min(ccv->bytes_this_ack,
				    ccv->nsegs * V_tcp_abc_l_var *
				    CCV(ccv, t_maxseg));
			else
				incr = min(ccv->bytes_this_ack, CCV(ccv, t_maxseg));
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0)
			CCV(ccv, snd_cwnd) = min(cw + incr,
			    TCP_MAXWIN << CCV(ccv, snd_scale));
	}
}

static void
newreno_after_idle(struct cc_var *ccv)
{
	int rw;

	/*
	 * If we've been idle for more than one retransmit timeout the old
	 * congestion window is no longer current and we have to reduce it to
	 * the restart window before we can transmit again.
	 *
	 * The restart window is the initial window or the last CWND, whichever
	 * is smaller.
	 *
	 * This is done to prevent us from flooding the path with a full CWND at
	 * wirespeed, overloading router and switch buffers along the way.
	 *
	 * See RFC5681 Section 4.1. "Restarting Idle Connections".
	 */
	if (V_tcp_do_rfc3390)
		rw = min(4 * CCV(ccv, t_maxseg),
		    max(2 * CCV(ccv, t_maxseg), 4380));
	else
		rw = CCV(ccv, t_maxseg) * 2;

	CCV(ccv, snd_cwnd) = min(rw, CCV(ccv, snd_cwnd));
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
newreno_cong_signal(struct cc_var *ccv, uint32_t type)
{
	unsigned win;

	/* Catch algos which mistakenly leak private signal types. */
	KASSERT((type & CC_SIGPRIVMASK) == 0,
	    ("%s: congestion signal type 0x%08x is private\n", __func__, type));

	win = max(CCV(ccv, snd_cwnd) / 2 / CCV(ccv, t_maxseg), 2) *
	    CCV(ccv, t_maxseg);

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(CCV(ccv, t_flags))) {
			if (!IN_CONGRECOVERY(CCV(ccv, t_flags)))
				CCV(ccv, snd_ssthresh) = win;
			ENTER_RECOVERY(CCV(ccv, t_flags));
		}
		break;
	case CC_ECN:
		if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
			CCV(ccv, snd_ssthresh) = win;
			CCV(ccv, snd_cwnd) = win;
			ENTER_CONGRECOVERY(CCV(ccv, t_flags));
		}
		break;
	}
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
static void
newreno_post_recovery(struct cc_var *ccv)
{
	int pipe;
	pipe = 0;

	if (IN_FASTRECOVERY(CCV(ccv, t_flags))) {
		/*
		 * Fast recovery will conclude after returning from this
		 * function. Window inflation should have left us with
		 * approximately snd_ssthresh outstanding data. But in case we
		 * would be inclined to send a burst, better to do it via the
		 * slow start mechanism.
		 *
		 * XXXLAS: Find a way to do this without needing curack
		 */
		pipe = CCV(ccv, snd_pipe);

		if (pipe < CCV(ccv, snd_ssthresh))
			CCV(ccv, snd_cwnd) = pipe + CCV(ccv, t_maxseg);
		else
			CCV(ccv, snd_cwnd) = CCV(ccv, snd_ssthresh);
	}
}


DECLARE_CC_MODULE(newreno, &newreno_cc_algo);
