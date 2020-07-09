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
#include <cstdio>
#include <vector>
#include <string>
extern "C" {
#include <time.h>
}
#include <bcc/BPF.h>

struct h2o_tracer {
    /**
     * Where to output the results. Defaults to `stdout`.
     */
    FILE *out;
    /**
     * The sequence number of the event.
     */
    uint64_t seq;
    /**
     * Counters for generating stats. They are reset periodically.
     */
    struct {
        uint64_t num_events;
        uint64_t num_lost;
    } stats;

    h2o_tracer() : out(NULL), seq(0)
    {
        stats.num_events = 0;
        stats.num_lost = 0;
    }
    /*
     * Handles an incoming BPF event.
     */
    virtual void handle_event(const void *data, int len) = 0;
    /**
     * Handles an event data lost.
     */
    void handle_lost(uint64_t lost);
    /**
     * Returns a vector of relevant USDT probes.
     */
    virtual const std::vector<ebpf::USDT> &init_usdt_probes(pid_t h2o_pid) = 0;
    /**
     * Returns the code to be compiled into BPF bytecode.
     */
    virtual std::string bpf_text() = 0;
    /**
     * Returns current time in milliseconds.
     */
    uint64_t time_milliseconds();
    /**
     *
     */
    void show_event_per_sec(time_t *t0);
};

/**
 * Initialize an HTTP tracer.
 */
h2o_tracer *create_http_tracer();
/**
 * Initializes a QUIC tracer.
 */
h2o_tracer *create_quic_tracer();

#endif
