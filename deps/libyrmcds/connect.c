// (C) 2013, 2016 Cybozu.

#include "yrmcds.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// workaround for a known-bug in NetBSD, from https://lists.gnu.org/archive/html/bug-gnulib/2010-02/msg00071.html
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif

static yrmcds_error connect_to_server(const char* node, uint16_t port, int* server_fd) {
    if( node == NULL )
        return YRMCDS_BAD_ARGUMENT;

    long fl;
    char sport[8];
    snprintf(sport, sizeof(sport), "%u", (unsigned int)port);

    struct addrinfo hint, *res;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;  // prefer IPv4
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_NUMERICSERV|AI_ADDRCONFIG;
    int e = getaddrinfo(node, sport, &hint, &res);
    if( e == EAI_FAMILY || e == EAI_NONAME
#ifdef EAI_ADDRFAMILY
        || e == EAI_ADDRFAMILY
#endif
#ifdef EAI_NODATA
        || e == EAI_NODATA
#endif
        ) {
        hint.ai_family = AF_INET6;
        // intentionally drop AI_ADDRCONFIG to support IPv6 link-local address.
        // see https://github.com/cybozu/yrmcds/issues/40
        hint.ai_flags = AI_NUMERICSERV|AI_V4MAPPED;
        e = getaddrinfo(node, sport, &hint, &res);
    }
    if( e == EAI_SYSTEM ) {
        return YRMCDS_SYSTEM_ERROR;
    } else if( e != 0 ) {
        return YRMCDS_NOT_RESOLVED;
    }

    int s = socket(res->ai_family,
                   res->ai_socktype
#ifdef __linux__
                   | SOCK_NONBLOCK | SOCK_CLOEXEC
#endif
                   , res->ai_protocol);
    if( s == -1 ) {
        e = errno;
        freeaddrinfo(res);
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#ifndef __linux__
    fl = fcntl(s, F_GETFD, 0);
    fcntl(s, F_SETFD, fl | FD_CLOEXEC);
    fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
    e = connect(s, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if( e == -1 && errno != EINPROGRESS ) {
        e = errno;
        close(s);
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }

    if( e != 0 ) {
        struct pollfd fds;
        fds.fd = s;
        fds.events = POLLOUT;
        int n = poll(&fds, 1, 5000);
        if( n == 0 ) { // timeout
            close(s);
            return YRMCDS_TIMEOUT;
        }
        if( n == -1 ) {
            e = errno;
            close(s);
            errno = e;
            return YRMCDS_SYSTEM_ERROR;
        }

        if( fds.revents & (POLLERR|POLLHUP|POLLNVAL) ) {
            close(s);
            return YRMCDS_DISCONNECTED;
        }
        socklen_t l = sizeof(e);
        if( getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &l) == -1 ) {
            close(s);
            return YRMCDS_SYSTEM_ERROR;
        }
        if( e != 0 ) {
            close(s);
            errno = e;
            return YRMCDS_SYSTEM_ERROR;
        }
    }
    fl = fcntl(s, F_GETFL, 0);
    if( fcntl(s, F_SETFL, fl & ~O_NONBLOCK) == -1 ) {
        e = errno;
        close(s);
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
    int ok = 1;
    if( setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &ok, sizeof(ok)) == -1 ) {
        e = errno;
        close(s);
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
    *server_fd = s;
    return YRMCDS_OK;
}

yrmcds_error yrmcds_connect(yrmcds* c, const char* node, uint16_t port) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    int e = pthread_mutex_init(&(c->lock), NULL);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#endif // ! LIBYRMCDS_NO_INTERNAL_LOCK
    int server_fd;
    yrmcds_error err = connect_to_server(node, port, &server_fd);
    if( err != YRMCDS_OK )
        return err;
    c->sock = server_fd;
    c->serial = 0;
    c->compress_size = 0;
    c->recvbuf = (char*)malloc(1 << 20);
    if( c->recvbuf == NULL ) {
        close(server_fd);
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
        pthread_mutex_destroy(&(c->lock));
#endif
        return YRMCDS_OUT_OF_MEMORY;
    }
    c->capacity = 1 << 20;
    c->used = 0;
    c->last_size = 0;
    c->decompressed = NULL;
    c->invalid = 0;
    c->text_mode = 0;
    c->rserial = 0;
    return YRMCDS_OK;
}

yrmcds_error yrmcds_cnt_connect(yrmcds_cnt* c, const char* node, uint16_t port) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    int e = pthread_mutex_init(&(c->lock), NULL);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#endif // ! LIBYRMCDS_NO_INTERNAL_LOCK
    int server_fd;
    yrmcds_error err = connect_to_server(node, port, &server_fd);
    if( err != YRMCDS_OK )
        return err;
    c->sock = server_fd;
    c->serial = 0;
    c->recvbuf = (char*)malloc(4096);
    if( c->recvbuf == NULL ) {
        close(server_fd);
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
        pthread_mutex_destroy(&(c->lock));
#endif
        return YRMCDS_OUT_OF_MEMORY;
    }
    c->capacity = 4096;
    c->used = 0;
    c->last_size = 0;
    c->invalid = 0;
    c->stats.count = c->stats.capacity = 0;
    c->stats.records = NULL;
    return YRMCDS_OK;
}
