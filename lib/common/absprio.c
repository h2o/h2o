/*
 * Copyright (c) 2019 Fastly
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

#include <ctype.h>
#include "h2o.h"
#include "h2o/absprio.h"

h2o_absprio_t h2o_absprio_default = {H2O_ABSPRIO_URGENCY_DEFAULT, 0};

void h2o_absprio_parse_priority(const char *s, size_t len, h2o_absprio_t *prio)
{
    h2o_iovec_t iter = h2o_iovec_init(s, len), value;
    const char *token;
    size_t token_len;

    while ((token = h2o_next_token(&iter, ',', ',', &token_len, &value)) != NULL) {
        if (token_len != 1) {
            /* Currently only "u=" and "i=" are supported. Thus token_len should always be 1.
             * Ignore unknown keys. */
            continue;
        }

        if (token[0] == 'u') {
            H2O_BUILD_ASSERT(H2O_ABSPRIO_URGENCY_MAX < 10);
            if (value.base != NULL && value.len == 1 && '0' <= value.base[0] &&
                value.base[0] <= '0' + H2O_ABSPRIO_URGENCY_BACKGROUND)
                prio->urgency = value.base[0] - '0';
        } else if (token[0] == 'i') {
            if (value.base != NULL) {
                if (value.len == 2 && value.base[0] == '?') {
                    /* value should contain '?0' or '?1' */
                    if (value.base[1] == '0')
                        prio->incremental = 0;
                    else if (value.base[1] == '1')
                        prio->incremental = 1;

                    /* All other cases mean invalid format. Just ignore. */
                }
            } else {
                /* value omitted, meaning that i is true */
                prio->incremental = 1;
            }
        }
    }
}
