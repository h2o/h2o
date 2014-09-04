/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <alloca.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "picotest.h"

#define _STR(...) #__VA_ARGS__
#define STR(...) _STR(__VA_ARGS__)

static int numtests_in_subtest, subtest_success;
static int all_success = 1;

__attribute__((format (printf, 1, 2)))
void note(const char *fmt, ...)
{
    char *escaped_fmt = alloca(strlen(fmt) + sizeof("    # \n"));
    va_list arg;

    strcpy(escaped_fmt, "    # ");
    strcat(escaped_fmt, fmt);
    strcat(escaped_fmt, "\n");

    va_start(arg, fmt);
    vprintf(escaped_fmt, arg);
    va_end(arg);
}

void _ok(int cond, const char *file, int line)
{
    if (! cond) {
        subtest_success = 0;
        all_success = 0;
    }
    printf("    %s %d - %s %d\n", cond ? "ok" : "not ok", ++numtests_in_subtest, file, line);
}

int main(int argc, char **argv)
{
    picotest_cb_t **test, *tests[] = { PICOTEST_FUNCS, NULL };
    const char *test_name = STR(PICOTEST_FUNCS);
    int cnt = 0;

    for (test = tests; *test != NULL; ++test, test_name = strchr(test_name, ',')) {
        const char *colon_in_test_name = strchr(test_name, ',');
        int test_name_len = (int)(colon_in_test_name != NULL ? colon_in_test_name - test_name : strlen(test_name));
        numtests_in_subtest = 0;
        subtest_success = 1;
        printf("    # Subtest: %.*s\n", test_name_len, test_name);
        (**test)();
        printf("    1..%d\n", numtests_in_subtest);
        printf("%s %d - %.*s\n", subtest_success ? "ok" : "not ok", ++cnt, test_name_len, test_name);
    }

    printf("1..%d\n", cnt);

    return all_success ? 0 : 1;
}
