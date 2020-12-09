/*
 * Copyright (c) 2019-2020 Fastly, Inc., Goro Fuji
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

#ifndef h2olog_raw_tracer_h
#define h2olog_raw_tracer_h

#include <cinttypes>
#include <cstdio>
#include <vector>
#include "h2olog.h"

extern "C" {
#include <fnmatch.h>
}

#define STR_LEN 64
#define STR_LIT(s) s, strlen(s)

class h2o_raw_tracer : public h2o_tracer
{
    std::vector<h2o_tracer::usdt> selected_usdts;
    std::vector<h2o_tracer::usdt> available_usdts;

    void initialize();

  protected:
    void do_handle_event(const void *data, int len) override;
    void do_handle_lost(std::uint64_t lost) override;

  public:
    h2o_raw_tracer(): h2o_tracer() {
      initialize();
    }

    std::string select_usdts(const char *pattern) override;
    const std::vector<h2o_tracer::usdt> &usdt_probes() override
    {
        return selected_usdts.empty() ? available_usdts : selected_usdts;
    }
    std::string bpf_text() override;
};

void h2o_raw_tracer::do_handle_lost(std::uint64_t lost)
{
    std::fprintf(out_,
                 "{"
                 "\"type\":\"h2olog-event-lost\","
                 "\"seq\":%" PRIu64 ","
                 "\"time\":%" PRIu64 ","
                 "\"lost\":%" PRIu64 "}\n",
                 seq_, time_milliseconds(), lost);
}

std::string h2o_raw_tracer::select_usdts(const char *pattern)
{
    size_t added = 0;
    for (const auto &usdt : available_usdts) {
        if (fnmatch(pattern, usdt.fully_qualified_name().c_str(), 0) == 0) {
            selected_usdts.push_back(usdt);
            added++;
        }
    }

    if (added > 0) {
        return std::string();
    } else {
        return std::string("No such tracepoint: ") + pattern;
    }
}

h2o_tracer *create_raw_tracer()
{
    return new h2o_raw_tracer;
}

#endif
