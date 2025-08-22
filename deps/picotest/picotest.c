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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "picotest.h"

int test_index[32] = {1};
static int test_fail[32];
static int test_level = 0;

static void indent(void)
{
    int i;
    for (i = 0; i != test_level; ++i)
        printf("    ");
}

__attribute__((format (printf, 1, 2)))
void note(const char *fmt, ...)
{
    va_list arg;

    indent();
    printf("# ");

    va_start(arg, fmt);
    vprintf(fmt, arg);
    va_end(arg);

    printf("\n");
    fflush(stdout);
}

__attribute__((format (printf, 2, 3)))
void _ok(int cond, const char *fmt, ...)
{
    va_list arg;

    if (! cond)
        test_fail[test_level] = 1;
    indent();

    printf("%s %d - ", cond ? "ok" : "not ok", test_index[test_level]++);
    va_start(arg, fmt);
    vprintf(fmt, arg);
    va_end(arg);

    printf("\n");
    fflush(stdout);
}

int done_testing(void)
{
    indent();
    printf("1..%d\n", test_index[test_level] - 1);
    fflush(stdout);
    return test_fail[test_level];
}

void enter_subtest(const char *name)
{
    ++test_level;

    test_index[test_level] = 1;
    test_fail[test_level] = 0;

    note("Subtest: %s", name);
}

void exit_subtest(const char *name)
{
    done_testing();

    --test_level;
    _ok(! test_fail[test_level + 1], "%s", name);
    test_index[test_level + 1] = 0;
    test_fail[test_level + 1] = 0;
}

int test_is_at(int index, ...)
{
    va_list arg;
    va_start(arg, index);
    size_t level;

    for (level = 0; index == test_index[level] && index != 0; ++level)
        index = va_arg(arg, int);

    va_end(arg);
    return index == test_index[level] && index == 0;
}
