/*
 * NAME: injectaddr.so
 *
 * SYSOPSIS:
 *   % gcc -shared -fPIC injectaddr.c -ldl -o injectaddr.so
 *
 *     -- inject 1s delay, then connect to 127.0.0.1:8888
 *   % LD_PRELOAD=injectaddr.so \
 *     curl http://d1000.p8888.4127-0-0-1.inject.example.com/
 *
 *
 * This preload library overrides getaddrinfo (3), letting applications specify
 * returned IP addresses, ports, and delay. The intended use-case is to
 * simulate behavior of complex DNS responses / for testing load balancing
 * implementations.
 *
 * When suffix of the hostname is `.inject.example.com`, the prefix is
 * interpreted as commands being passed to the preload library split by dots.
 * Accepted commands are:
 *
 *   d<msec>  inject delay (specified by milliseconds)
 *   p<port>  return specified port number for the addresses that follow
 *   4<addr>  return specified IPv4 address
 *   6<addr>  return specified IPv6 address
 *
 * IPv4 and v6 addresses use `-` as the separator instead of `.` or `:`.
 */
/*
 * Copyright (c) 2021 Kazuho Oku
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

#include <arpa/inet.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define die(msg) dief("injectaddr: " msg "\n")

static void dief(const char *msg)
{
    write(2, msg, strlen(msg));
    abort();
}

int getaddrinfo(const char *host, const char *serv, const struct addrinfo *hints, struct addrinfo **res)
{
    static const char inject_suffix[] = ".inject.example.com";

    size_t host_len;

    if (host == NULL || (host_len = strlen(host)) < sizeof(inject_suffix) - 1 ||
        strcasecmp(host + host_len - (sizeof(inject_suffix) - 1), inject_suffix) != 0) {
        int (*orig)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = dlsym(RTLD_NEXT, "getaddrinfo");
        if (orig == NULL)
            die("failed to locate original getaddrinfo");
        return orig(host, serv, hints, res);
    }

    int ret = EAI_NONAME;
    int sleep_msec = 0;
    uint16_t port;

    if (sscanf(serv, "%" SCNu16, &port) != 1)
        die("invalid serv");

    size_t off = 0;
    while (off < host_len - (sizeof(inject_suffix) - 1)) {
        int cmd = host[off++];
        switch (cmd) {
        case 'd': /* set delay */
            for (; '0' <= host[off] && host[off] <= '9'; ++off)
                sleep_msec = sleep_msec * 10 + host[off] - '0';
            break;
        case 'p': /* override port number */
            port = 0;
            for (; '0' <= host[off] && host[off] <= '9'; ++off)
                port = port * 10 + host[off] - '0';
            break;
        case '4': /* IPv4 address */
        case '6': /* IPv6 address */ {
            char addrbuf[5 * 8], *p = addrbuf; /* TODO fix overrun of addrbuf */
            for (; host[off] != '.'; ++off)
                *p++ = host[off] == '-' ? cmd == '4' ? '.' : ':' : host[off];
            *p = '\0';
            if (hints->ai_family == AF_UNSPEC || hints->ai_family == (cmd == '4' ? AF_INET : AF_INET6)) {
                if (sleep_msec != 0)
                    usleep(sleep_msec * 1000);
                *res = malloc(sizeof(**res));
                **res = (struct addrinfo){
                    .ai_flags = 0,
                    .ai_family = cmd == '4' ? AF_INET : AF_INET6,
                    .ai_socktype = hints->ai_socktype,
                };
                if (cmd == '4') {
                    struct sockaddr_in *sin = malloc(sizeof(*sin));
                    memset(sin, 0, sizeof(*sin));
                    sin->sin_family = AF_INET;
                    if (inet_pton(AF_INET, addrbuf, &sin->sin_addr) != 1)
                        die("invalid v4 address");
                    sin->sin_port = htons(port);
                    (*res)->ai_addr = (struct sockaddr *)sin;
                    (*res)->ai_addrlen = sizeof(*sin);
                } else {
                    struct sockaddr_in6 *sin6 = malloc(sizeof(*sin6));
                    memset(sin6, 0, sizeof(*sin6));
                    sin6->sin6_family = AF_INET6;
                    if (inet_pton(AF_INET6, addrbuf, &sin6->sin6_addr) != 1)
                        die("invalid v6 address");
                    sin6->sin6_port = htons(port);
                    (*res)->ai_addr = (struct sockaddr *)sin6;
                    (*res)->ai_addrlen = sizeof(*sin6);
                }
                res = &(*res)->ai_next;
                ret = 0;
            }
            sleep_msec = 0;
        } break;
        case '.': /* skip . */
            break;
        default:
            die("unexpected command");
            break;
        }
    }

    return ret;
}

void freeaddrinfo(struct addrinfo *res)
{
    /* TODO implement. Note that Wrapped `getaddrinfo` should convert the original format to our internal, as we have to build
     * `addrinfo` ourselves when injecting, without knoweledge of how libc builds the structure. */
}
