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
#ifndef h2o__internal_h
#define h2o__internal_h

static uint16_t decode16u(const uint8_t *src);
static uint32_t decode24u(const uint8_t *src);
static uint32_t decode32u(const uint8_t *src);
static uint8_t *encode24u(uint8_t *dst, uint32_t value);
static uint8_t *encode32u(uint8_t *dst, uint32_t value);

static size_t sz_min(size_t x, size_t y);

inline uint16_t decode16u(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

inline uint32_t decode24u(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

inline uint32_t decode32u(const uint8_t *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | src[3];
}

inline uint8_t *encode24u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline uint8_t *encode32u(uint8_t *dst, uint32_t value)
{
    *dst++ = value >> 24;
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst++ = value;
    return dst;
}

inline size_t sz_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

#endif
