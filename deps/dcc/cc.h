/*-
 * Copyright (c) 2007-2008
 * 	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * Copyright (c) 2017,2018 Fastly
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart and
 * James Healy, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
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
 *
 * $FreeBSD$
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

#ifndef _NETINET_CC_CC_H_
#define _NETINET_CC_CC_H_

extern int cc_tcp_do_rfc3390;
extern int cc_tcp_do_rfc3465;
extern int cc_tcp_abc_l_var;
extern int cc_hz;
extern volatile int cc_ticks;

#define CC_TF_RETRANSMIT 0x1
#define CC_TF_PREVVALID 0x2
#define CC_TF_FASTRECOVERY 0x10 /* in NewReno Fast Recovery */
#define CC_TF_CONGRECOVERY 0x20 /* congestion recovery mode */
#define CC_TF_WASFRECOVERY 0x100        /* in NewReno Fast Recovery */
#define CC_TF_WASCRECOVERY 0x200        /* was in NewReno Fast Recovery */

#define CC_IN_RECOVERY(t_flags) (t_flags & (CC_TF_CONGRECOVERY | CC_TF_FASTRECOVERY))
#define CC_ENTER_RECOVERY(t_flags) t_flags |= (CC_TF_CONGRECOVERY | CC_TF_FASTRECOVERY)
#define CC_EXIT_RECOVERY(t_flags) t_flags &= ~(CC_TF_CONGRECOVERY | CC_TF_FASTRECOVERY)

#define CC_IN_FASTRECOVERY(t_flags)        (t_flags & CC_TF_FASTRECOVERY)
#define CC_ENTER_FASTRECOVERY(t_flags)     t_flags |= CC_TF_FASTRECOVERY
#define CC_EXIT_FASTRECOVERY(t_flags)      t_flags &= ~CC_TF_FASTRECOVERY

#define CC_IN_CONGRECOVERY(t_flags)        (t_flags & CC_TF_CONGRECOVERY)
#define CC_ENTER_CONGRECOVERY(t_flags)     t_flags |= CC_TF_CONGRECOVERY
#define CC_EXIT_CONGRECOVERY(t_flags)      t_flags &= ~CC_TF_CONGRECOVERY

void *cc_malloc(size_t sz, const char *lbl);
void cc_free(void *p, const char *lbl);

/* Global CC vars. */
extern struct cc_algo newreno_cc_algo;

/* control block (mostly taken from sys/netinet/tcp_var.h) */
struct cc_ccv {
    unsigned t_flags;
    uint32_t snd_pipe;
    uint32_t snd_cwnd;             /* congestion-controlled window */
    uint32_t  snd_ssthresh;         /* snd_cwnd size threshold for
                                     * for slow start exponential to
                                     * linear switch
                                     */
    uint8_t  snd_scale;              /* window scaling for send window */
    int        t_bytes_acked;          /* # bytes acked during current RTT */
    unsigned   t_maxseg;               /* maximum segment size */
    unsigned long  t_rttupdated;           /* number of times rtt sampled */
    int     t_srtt;                 /* smoothed round-trip time */
    struct cc_algo  *cc_algo;

    unsigned t_badrxtwin;            /* window for retransmit recovery */
    uint32_t snd_cwnd_prev;
    uint32_t  snd_ssthresh_prev;
};

/*
 * Wrapper around transport structs that contain same-named congestion
 * control variables. Allows algos to be shared amongst multiple CC aware
 * transprots.
 */
struct cc_var {
	void		*cc_data; /* Per-connection private CC algorithm data. */
	int		bytes_this_ack; /* # bytes acked by the current ACK. */
	uint32_t	flags; /* Flags for cc_var (see below) */
	int		type; /* Indicates which ptr is valid in ccvc. */
	union ccv_container {
		struct cc_ccv ccv;
	} ccvc;
	uint16_t	nsegs; /* # segments coalesced into current chain. */
};

/* cc_var flags. */
#define	CCF_ABC_SENTAWND	0x0001	/* ABC counted cwnd worth of bytes? */
#define	CCF_CWND_LIMITED	0x0002	/* Are we currently cwnd limited? */
#define	CCF_DELACK		0x0004	/* Is this ack delayed? */
#define	CCF_ACKNOW		0x0008	/* Will this ack be sent now? */
#define	CCF_IPHDR_CE		0x0010	/* Does this packet set CE bit? */
#define	CCF_TCPHDR_CWR		0x0020	/* Does this packet set CWR bit? */

/* ACK types passed to the ack_received() hook. */
#define	CC_ACK		0x0001	/* Regular in sequence ACK. */
#define	CC_DUPACK	0x0002	/* Duplicate ACK. */
#define	CC_PARTIALACK	0x0004	/* Not yet. */
#define	CC_SACK		0x0008	/* Not yet. */

/*
 * Congestion signal types passed to the cong_signal() hook. The highest order 8
 * bits (0x01000000 - 0x80000000) are reserved for CC algos to declare their own
 * congestion signal types.
 */
#define	CC_ECN		0x00000001	/* ECN marked packet received. */
#define	CC_RTO		0x00000002	/* RTO fired. */
#define	CC_RTO_ERR	0x00000004	/* RTO fired in error. */
#define	CC_NDUPACK	0x00000008	/* Threshold of dupack's reached. */
#define CC_FIRST_RTO 0x00000010 /* first RTO */

#define	CC_SIGPRIVMASK	0xFF000000	/* Mask to check if sig is private. */

/*
 * Structure to hold data and function pointers that together represent a
 * congestion control algorithm.
 */
struct cc_algo {
	char	name[16];

	/* Init global module state on kldload. */
	int	(*mod_init)(void);

	/* Cleanup global module state on kldunload. */
	int	(*mod_destroy)(void);

	/* Init CC state for a new control block. */
	int	(*cb_init)(struct cc_var *ccv);

	/* Cleanup CC state for a terminating control block. */
	void	(*cb_destroy)(struct cc_var *ccv);

	/* Init variables for a newly established connection. */
	void	(*conn_init)(struct cc_var *ccv);

	/* Called on receipt of an ack. */
	void	(*ack_received)(struct cc_var *ccv, uint16_t type);

	/* Called on detection of a congestion signal. */
	void	(*cong_signal)(struct cc_var *ccv, uint32_t type);

	/* Called after exiting congestion recovery. */
	void	(*post_recovery)(struct cc_var *ccv);

	/* Called when data transfer resumes after an idle period. */
	void	(*after_idle)(struct cc_var *ccv);

	/* Called for an additional ECN processing apart from RFC3168. */
	void	(*ecnpkt_handler)(struct cc_var *ccv);
};

/* Macro to obtain the CC algo's struct ptr. */
#define	CC_ALGO(tp)	((tp)->ccvc.ccv.cc_algo)

/* Macro to obtain the CC algo's data ptr. */
#define	CC_DATA(tp)	((tp)->ccv->cc_data)

int cc_init(struct cc_var *ccv, struct cc_algo *algo, uint32_t cwnd, unsigned maxseg);
void cc_destroy(struct cc_var *ccv);
void cc_ack_received(struct cc_var *ccv, uint16_t type, uint32_t bytes_in_pipe, uint16_t segs_acked, uint32_t bytes_acked, int srtt,
                     int exit_recovery);
void cc_cong_signal(struct cc_var *ccv, uint32_t type, uint32_t bytes_in_pipe);
static uint32_t cc_get_cwnd(struct cc_var *ccv);
static unsigned cc_get_maxseg(struct cc_var *ccv);
static void cc_set_maxseg(struct cc_var *ccv, unsigned maxseg);

inline uint32_t cc_get_cwnd(struct cc_var *ccv)
{
    return ccv->ccvc.ccv.snd_cwnd;
}

inline unsigned cc_get_maxseg(struct cc_var *ccv)
{
    return ccv->ccvc.ccv.t_maxseg;
}

inline void cc_set_maxseg(struct cc_var *ccv, unsigned maxseg)
{
    ccv->ccvc.ccv.t_maxseg = maxseg;
}

#endif /* _NETINET_CC_CC_H_ */
