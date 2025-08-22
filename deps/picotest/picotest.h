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
#ifndef picotest_h
#define picotest_h

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#ifndef __attribute__
#define __attribute__(X)
#endif
#endif

extern int test_index[32];

void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void _ok(int cond, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define ok(cond) _ok(cond, "%s %d", __FILE__, __LINE__)
int done_testing(void);
#define subtest(name, cb, ...)                                                                                                     \
    do {                                                                                                                           \
        const char *_name = (name);                                                                                                \
        enter_subtest(_name);                                                                                                      \
        (cb)(__VA_ARGS__);                                                                                                         \
        exit_subtest(_name);                                                                                                       \
    } while (0)
void enter_subtest(const char *name);
void exit_subtest(const char *name);
/**
 * Returns if the test is at the expected position.  For example, `test_is_at(3, 2, 0)` returns true if it is running the 3rd test at
 * the top level, which is a subtest in which the next test to be run is the second one.  The last `0` is the terminator.
 */
int test_is_at(int index, ...);

#ifdef __cplusplus
}
#endif

#endif
