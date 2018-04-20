/*
* Copyright (c) 2017 Christian Huitema <huitema@huitema.net>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef PTLS_PEMBASE64_H
#define PTLS_PEMBASE64_H

/*
* Base64 functions used in encoding and decoding of PEM files
*/

#define PTLS_BASE64_DECODE_DONE 0
#define PTLS_BASE64_DECODE_IN_PROGRESS 1
#define PTLS_BASE64_DECODE_FAILED -1

typedef struct st_ptls_base64_decode_state_t {
    int nbc;
    int nbo;
    int status;
    uint32_t v;
} ptls_base64_decode_state_t;

int ptls_base64_encode(const uint8_t *data, size_t data_len, char *base64_text);

size_t ptls_base64_howlong(size_t data_length);

void ptls_base64_decode_init(ptls_base64_decode_state_t *state);
int ptls_base64_decode(const char *base64_text, ptls_base64_decode_state_t *state, ptls_buffer_t *buf);

int ptls_load_pem_objects(char const *pem_fname, const char *label, ptls_iovec_t *list, size_t list_max, size_t *nb_objects);

#endif /* PTLS_PEMBASE64_H */
