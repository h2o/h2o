/*
 * Copyright (c) 2016 Fastly, Inc.
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

/*
 * This file implements a test harness for using h2o with LibFuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info.
 */
#define H2O_USE_EPOLL 1

#include "h2o.h"
#include "h2o/url.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    h2o_url_t url;
    int ret;
    ret = h2o_url_parse((const char *)Data, Size, &url);
    if (ret != -1) {
        size_t total = 0, i;
        assert(url.scheme != NULL);
        for (i = 0; i < url.authority.len; i++)
            if (url.authority.base[i])
                total++;
        for (i = 0; i < url.host.len; i++)
            if (url.host.base[i])
                total++;
        for (i = 0; i < url.path.len; i++)
            if (url.path.base[i])
                total++;
        assert(total <= Size * 2);
    }
    return 0;
}
