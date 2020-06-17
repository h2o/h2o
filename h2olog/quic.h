/*
 * Copyright (c) 2019-2020 Fastly, Inc., Toru Maesaka, Goro Fuji
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

#ifndef H2OLOG_QUIC_H
#define H2OLOG_QUIC_H

/*
 * These structs mirror H2O's internal structs. As the name suggests, dummy
 * fields are paddings that are ignored.
 */
struct st_quicly_stream_t {
    uint64_t dummy;
    int64_t stream_id;
};

struct st_quicly_conn_t {
    uint32_t dummy[4];
    uint32_t master_id;
};

struct quicly_rtt_t {
    uint32_t minimum;
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
};

struct st_quicly_address_token_plaintext_t {
    int dummy;
};

struct st_h2o_conn_t {
    int dummy;
};

#endif
