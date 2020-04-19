/*
 * Copyright (c) 2019-2020 Fastly, Inc., Toru Maesaka
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

#ifndef h2olog_h
#define h2olog_h

#include <cinttypes>
#include <vector>
#include <bcc/BPF.h>

struct st_h2o_tracer_t;
typedef struct st_h2o_tracer_t h2o_tracer_t;

struct st_h2o_tracer_t {
    /*
     * Where to output the results. Defaults to `stdout`.
     */
    FILE *out;

    /*
     * The number of events emitted in `handle_event`.
     */
    uint64_t count;

    /*
     * The number of lost events. It is reset periodically.
     */
    uint64_t lost_count;

    /*
     * Handles an incoming BPF event.
     */
    void (*handle_event)(h2o_tracer_t *tracer, const void *data, int len);

    /*
     * Handles an event data lost.
     */
    void (*handle_lost)(h2o_tracer_t *tracer, uint64_t lost);

    /*
     * Returns a vector of relevant USDT probes.
     */
    std::vector<ebpf::USDT> (*init_usdt_probes)(pid_t h2o_pid);

    /*
     * Returns the code to be compiled into BPF bytecode.
     */
    const char *(*bpf_text)(void);
};

/*
 * Initialize an HTTP tracer.
 */
void init_http_tracer(h2o_tracer_t *);

/*
 * Initialize a QUIC tracer.
 */
void init_quic_tracer(h2o_tracer_t *);

#endif
