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

#include "h2olog.h"

static void handle_event(void *context, void *data, int len)
{
    printf("unimplemented\n");
}

static std::vector<ebpf::USDT> init_usdt_probes(pid_t h2o_pid)
{
    // Unimplemented
    std::vector<ebpf::USDT> vec;
    return vec;
}

static const char *bpf_text(void)
{
    return "unimplemented";
}

h2o_tracer_t *create_http_tracer(void)
{
    h2o_tracer_t *tracer = (h2o_tracer_t *)malloc(sizeof(tracer));
    tracer->handle_event = handle_event;
    tracer->init_usdt_probes = init_usdt_probes;
    tracer->bpf_text = bpf_text;
    return tracer;
}
