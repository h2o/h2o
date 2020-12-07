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
#include <sys/socket.h>
#include <netinet/in.h>
}

union h2olog_address_t {
    sockaddr sa;
    sockaddr_in sin;
    sockaddr_in6 sin6;
};

class h2o_tracer
{
  public:
    class usdt
    {
      public:
        std::string provider;
        std::string name;
        std::string probe_func;
        usdt(const std::string &provider, const std::string &name, const std::string &probe_func)
            : provider(provider), name(name), probe_func(probe_func)
        {
        }

        std::string fully_qualified_name() const
        {
            return provider + ":" + name;
        }
    };

  protected:
    /**
     * Where to output the results. Defaults to `stdout`.
     */
    FILE *out_;
    /**
     * The sequence number of the event.
     */
    uint64_t seq_;
    /**
     * Counters for generating stats. They are reset periodically.
     */
    struct {
        uint64_t num_events;
        uint64_t num_lost;
    } stats_;
    /**
     * The stub function for handling an event.
     */
    virtual void do_handle_event(const void *data, int len) = 0;
    /**
     * The stub function for handling a loss event.
     */
    virtual void do_handle_lost(uint64_t lost) = 0;

  public:
    /**
     * Constructor.
     */
    h2o_tracer() : out_(NULL), seq_(0)
    {
        stats_.num_events = 0;
        stats_.num_lost = 0;
    }

    virtual ~h2o_tracer()
    {
    }

    /**
     * Performs post-construction initialization common to all the tracers.
     */
    void init(FILE *fp)
    {
        out_ = fp;
    }

    /**
     * Handles an incoming BPF event.
     */
    void handle_event(const void *data, int len)
    {
        ++seq_;
        ++stats_.num_events;
        do_handle_event(data, len);
    }
    /**
     * Handles an event data lost.
     */
    void handle_lost(uint64_t lost)
    {
        stats_.num_lost += lost;
        do_handle_lost(lost);
    }

    /**
     * Select a tracepoint with pattern, e.g. "quicly:*".
     * It affects what `usdt_probes()` returns;
     *
     * @return an error message for failure, an empty string for success
     */
    virtual std::string select_usdts(const char *pattern) = 0;
    /**
     * Returns a vector of relevant USDT probes.
     */
    virtual const std::vector<usdt> &usdt_probes() = 0;
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
    /**
     *
     */
    void flush()
    {
        fflush(out_);
    }
};

/**
 * Initialize an HTTP tracer.
 */
h2o_tracer *create_http_tracer();
/**
 * Initializes a QUIC tracer.
 */
h2o_tracer *create_raw_tracer();

#endif
