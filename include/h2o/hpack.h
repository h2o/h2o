/*
 * Copyright (c) 2014-2018 DeNA Co., Ltd., Kazuho Oku, Fastly
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
#ifndef h2o__hpack_h
#define h2o__hpack_h

#include <stddef.h>
#include <stdint.h>

extern const char *h2o_hpack_err_found_upper_case_in_header_name;
extern const char *h2o_hpack_soft_err_found_invalid_char_in_header_name;
extern const char *h2o_hpack_soft_err_found_invalid_char_in_header_value;

/**
 * encodes a huffman string and returns its length, or returns SIZE_MAX if the resulting string would be longer than the input
 */
size_t h2o_hpack_encode_huffman(uint8_t *dst, const uint8_t *src, size_t len);
/**
 * decodes a huffman string and returns its length, or SIZE_MAX if fails. The destination buffer must be at least double the size
 * of the input.
 */
size_t h2o_hpack_decode_huffman(char *dst, const uint8_t *src, size_t len, int is_name, const char **err_desc);
/**
 * validates header name and returns a boolean. Result will be true and *err_desc will be set to non-NULL if a soft error is
 * detected.
 */
int h2o_hpack_validate_header_name(const char *s, size_t len, const char **err_desc);
/**
 * see h2o_http2_validate_header_name. The function only returns soft errors hence declared void.
 */
void h2o_hpack_validate_header_value(const char *s, size_t len, const char **err_desc);

#endif
