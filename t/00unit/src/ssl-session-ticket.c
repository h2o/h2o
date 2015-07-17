/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include "../test.h"
#include "../../../src/ssl-session-ticket.c"

void test_src__ssl_session_ticket_c(void)
{
    int ret = load_file("t/assets/session_tickets.yaml");
    ok(ret == 0);
    if (ret != 0)
        return;

    pthread_rwlock_rdlock(&session_tickets.rwlock);
    ok(session_tickets.tickets.size == 2);
    if (session_tickets.tickets.size == 2) {
        /* first entry should be the newer one */
        struct st_session_ticket_t *ticket = session_tickets.tickets.entries[0];
        ok(memcmp(ticket->name, H2O_STRLIT("\xe7\xe3\xc6\x98\x0b\x18\x32\xbd\x5d\x23\x91\x75\x72\xe8\x44\x8f")) == 0);
        ok(ticket->cipher.cipher == EVP_aes_256_cbc());
        ok(memcmp(ticket->cipher.key, H2O_STRLIT("\xf6\xe0\x71\xd9\x93\xb0\x5f\x77\xce\x51\xcb\x0f\xe2\xe0\xe1\x8c\x72\x00\xc2\xa7"
                                                 "\x87\x3a\x66\x00\x8c\x8e\x1d\x75\xae\x7b\x8e\x2a")) == 0);
        ok(ticket->hmac.md == EVP_sha256());
        ok(memcmp(ticket->hmac.key,
                  H2O_STRLIT("\xf4\xfc\xb8\x6f\xdf\x03\xa7\xf3\x35\x63\x2e\x66\x8a\x8f\xe9\x56\xc5\xbf\xe7\x7a\x41\x41\x2d\x26\x99"
                             "\x79\x63\x47\x68\x99\x9a\xdd\x6a\x84\xca\xfe\xa4\x1b\x6b\x2c\x47\xaa\xf1\xa5\x14\xca\x9d\x2a\x84\xf4"
                             "\x8d\x1f\x5f\x70\x18\xff\x17\x40\xcf\x9b\x94\x4b\x8f\xcf")) == 0);
        ok(ticket->not_before == 1437093330);
        ok(ticket->not_after == 1437096929);
        /* second is the older one */
        ticket = session_tickets.tickets.entries[1];
        ok(memcmp(ticket->name, H2O_STRLIT("\xa3\x97\xb6\xb7\xfa\xb9\x29\x36\x62\x03\xf1\x6f\xc8\x1f\xfb\xed")) == 0);
        ok(ticket->cipher.cipher == EVP_aes_128_cbc());
        ok(memcmp(ticket->cipher.key, H2O_STRLIT("\xf1\xed\x89\xcd\xe6\x87\x63\x63\x0e\x80\xd2\xbe\x82\x7c\xfb\x98")) == 0);
        ok(ticket->hmac.md == EVP_sha1());
        ok(memcmp(ticket->hmac.key,
                  H2O_STRLIT("\xe3\xfe\x72\x64\x4f\x64\x31\x5a\x4a\x8a\xd6\x37\x69\xa3\x57\x7c\xce\xc4\xdd\x13\xb2\x0e\xaf\x8c\x00\x88\x86\xe5\x45\x8d\xb1\x0e\x65\x8c\xf2\xa8\x3f\x04\x40\x3a\xc4\xe9\x80\x35\xd2\x42\x2a\x75\x80\x67\x30\xeb\x4f\x2f\xee\x12\xfa\xff\x95\x48\x95\xbc\x65\xd1")) == 0);
        ok(ticket->not_before == 1437092430);
        ok(ticket->not_after == 1437096029);
    }
    pthread_rwlock_unlock(&session_tickets.rwlock);
}
