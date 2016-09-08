/*
 * Copyright (c) 2015 Kazuho Oku
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
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "golombset.h"

int main(int argc, char **argv)
{
    uint64_t keys[] = {151, 192,  208,  269,  461,  512,  526,  591,  662,  806,  831,  866,  890,
                       997, 1005, 1017, 1134, 1207, 1231, 1327, 1378, 1393, 1418, 1525, 1627, 1630};
    const size_t num_keys = sizeof(keys) / sizeof(keys[0]);
    unsigned char buf[1024];
    size_t bufsize = sizeof(buf);

    if (golombset_encode(6, keys, num_keys, buf, &bufsize) != 0) {
        fprintf(stderr, "golombset_encode failed\n");
        return 111;
    }
    printf("encoded %zu entries into %zu bytes\n", num_keys, bufsize);
    
    uint64_t decoded_keys[num_keys];
    size_t num_decoded_keys = num_keys;
    if (golombset_decode(6, buf, bufsize, decoded_keys, &num_decoded_keys) != 0) {
        fprintf(stderr, "golombset_decode failed\n");
        return 111;
    }

    if (num_decoded_keys != num_keys) {
        fprintf(stderr, "unexpected number of outputs\n");
        return 111;
    }
    if (memcmp(keys, decoded_keys, sizeof(keys[0]) * num_keys) != 0) {
        fprintf(stderr, "output mismatch\n");
        return 111;
    }

    return 0;
}
