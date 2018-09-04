/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include "quicly/loss.h"

quicly_loss_conf_t quicly_loss_default_conf = {
    QUICLY_LOSS_DEFAULT_MAX_TLPS,                   /* max_tlps */
    QUICLY_LOSS_DEFAULT_TIME_REORDERING_PERCENTILE, /* time_reordering_percentile */
    QUICLY_LOSS_DEFAULT_MIN_TLP_TIMEOUT,            /* min_tlp_timeout */
    QUICLY_LOSS_DEFAULT_MIN_RTO_TIMEOUT,            /* min_rto_timeout */
    QUICLY_LOSS_DEFAULT_INITIAL_RTT                 /* initial_rtt */
};
