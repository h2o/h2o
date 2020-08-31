/*
 * Copyright (c) 2020 Chul-Woong Yang
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
#ifndef h2o__util_h
#define h2o__util_h
#ifdef __cplusplus
//extern "C" {
#endif
#include <arpa/inet.h>

static inline void h2o_addr_to_str(struct sockaddr *srcaddr, char *buf, int buflen)
{
    uint16_t port = 0;
    char name[64];

    switch (srcaddr->sa_family) {
    case AF_UNIX: {
        struct sockaddr_un *sun = (struct sockaddr_un *) srcaddr;
        snprintf(buf, buflen, "unix:%s", sun->sun_path);
        return;
    }
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *) srcaddr;
        inet_ntop(AF_INET, &sin->sin_addr.s_addr, name, INET_ADDRSTRLEN);
        port = sin->sin_port;
        snprintf(buf, buflen, "%s:%d", name, ntohs(port));
        return;
    }
    default: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) srcaddr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, name, INET6_ADDRSTRLEN);    /* len = 46 */
        port = sin6->sin6_port;
        break;
    }
    }
    snprintf(buf, buflen, "[%s]:%d", name, ntohs(port));
}

/* used for development session */
#define h2o_pinfo(fmt, args...) do {                             \
        fprintf(stderr, "%-18.18s| " fmt, __func__, ##args); \
        fprintf(stderr, "\n");                               \
    } while (0)

#ifdef __cplusplus
//}
#endif
#endif
