/*-
 * Copyright (c) 2007-2008
 *     Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
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

#ifndef cc_int_h
#define cc_int_h

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <math.h>
#include "cc.h"

#define _KERNEL

#ifndef min
#define min(x, y) ((x) <= (y) ? (x) : (y))
#define max(x, y) ((x) >= (y) ? (x) : (y))
#endif

#define VNET_DECLARE(...)
#define VNET(v) cc_##v
#define SYSCTL_DECL(...)
#define SYSCTL_PROC(...)
#define TCP_CA_NAME_MAX 16

#define IN_RECOVERY CC_IN_RECOVERY
#define ENTER_RECOVERY CC_ENTER_RECOVERY
#define EXIT_RECOVERY CC_EXIT_RECOVERY

#define IN_FASTRECOVERY CC_IN_FASTRECOVERY
#define ENTER_FASTRECOVERY CC_ENTER_FASTRECOVERY
#define EXIT_FASTRECOVERY CC_EXIT_FASTRECOVERY

#define IN_CONGRECOVERY CC_IN_CONGRECOVERY
#define ENTER_CONGRECOVERY CC_ENTER_CONGRECOVERY
#define EXIT_CONGRECOVERY CC_EXIT_CONGRECOVERY

#define MALLOC_DEFINE(sym, lbl, desc) const char *sym = lbl
#define malloc(sz, lbl, flags) cc_malloc((sz), (lbl))
#define free(p, lbl) cc_free((p), (lbl))

#define V_tcp_do_rfc3390        VNET(tcp_do_rfc3390)
#define V_tcp_do_rfc3465        VNET(tcp_do_rfc3465)
#define V_tcp_do_rfc6675_pipe   0
#define V_tcp_abc_l_var         VNET(tcp_abc_l_var)

#define TCP_MAXWIN	65535
#define TCPTV_SRTTBASE  0                       /* base roundtrip time;
                                                   if 0, no idea yet */

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define TCP_RTT_SCALE           32      /* multiplier for srtt; 3 bits frac. */
#define TCP_RTT_SHIFT           5       /* shift for srtt; 3 bits frac. */
#define TCP_RTTVAR_SCALE        16      /* multiplier for rttvar; 2 bits */
#define TCP_RTTVAR_SHIFT        4       /* shift for rttvar; 2 bits */

#define hz cc_hz
#define ticks cc_ticks

#define	CCV(ccv, what) (ccv)->ccvc.ccv.what
#define	DECLARE_CC_MODULE(...)
#define KASSERT(cond, ...) assert(cond) /* FIXME */

#include "cc.h"

#endif
