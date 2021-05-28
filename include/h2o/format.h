/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#ifndef h2o__format_h
#define h2o__format_h

#ifdef __GNUC__
#define H2O_ATTRIBUTE_FORMAT_PRINTF(x,y) __attribute__((format(gnu_printf, x, y)))
#define H2O_ATTRIBUTE_FORMAT_SCANF(x,y)  __attribute__((format(gnu_scanf, x, y)))
#else
#define H2O_ATTRIBUTE_FORMAT_PRINTF(x,y) __attribute__((format(printf, x, y)))
#define H2O_ATTRIBUTE_FORMAT_SCANF(x,y)  __attribute__((format(scanf, x, y)))
#endif

#endif
