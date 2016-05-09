// (C) 2013-2015 Cybozu et al.

#include "yrmcds.h"
#include "yrmcds_portability.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

static const size_t HEADER_SIZE = 12;
static const size_t RECV_SIZE = 4096;
static const size_t INITIAL_STATS_CAPACITY = 16;

static inline void hton32(uint32_t i, char* p) {
    uint32_t n = htobe32(i);
    memcpy(p, &n, sizeof(n));
}

static inline void hton16(uint16_t i, char* p) {
    uint16_t n = htobe16(i);
    memcpy(p, &n, sizeof(n));
}

static inline uint32_t ntoh32(const char* p) {
    uint32_t n;
    memcpy(&n, p, sizeof(n));
    return be32toh(n);
}

static inline uint16_t ntoh16(const char* p) {
    uint16_t n;
    memcpy(&n, p, sizeof(n));
    return be16toh(n);
}

yrmcds_error
yrmcds_cnt_set_timeout(yrmcds_cnt* c, int timeout) {
    if( c == NULL || timeout < 0 )
        return YRMCDS_BAD_ARGUMENT;

    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    if( setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1 )
        return YRMCDS_SYSTEM_ERROR;
    if( setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1 )
        return YRMCDS_SYSTEM_ERROR;
    return YRMCDS_OK;
}

yrmcds_error
yrmcds_cnt_close(yrmcds_cnt* c) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
    if( c->sock == -1 )
        return YRMCDS_OK;

    close(c->sock);
    c->sock = -1;
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    pthread_mutex_destroy(&(c->lock));
#endif
    free(c->recvbuf);
    c->recvbuf = NULL;
    free(c->stats.records);
    c->stats.records = NULL;
    return YRMCDS_OK;
}

yrmcds_error
yrmcds_cnt_shutdown(yrmcds_cnt* c) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
    if( shutdown(c->sock, SHUT_RD) == -1 )
        return YRMCDS_SYSTEM_ERROR;
    return YRMCDS_OK;
}

int
yrmcds_cnt_fileno(yrmcds_cnt* c) {
    return c->sock;
}

static yrmcds_error
recv_data(yrmcds_cnt* c) {
    if( (c->capacity - c->used) < RECV_SIZE ) {
        size_t new_capacity = c->capacity * 2;
        char* new_buffer = (char*)realloc(c->recvbuf, new_capacity);
        if( new_buffer == NULL )
            return YRMCDS_OUT_OF_MEMORY;
        c->recvbuf = new_buffer;
        c->capacity = new_capacity;
    }

    ssize_t n;
  AGAIN:
    n = recv(c->sock, c->recvbuf + c->used, RECV_SIZE, 0);
    if( n == -1 ) {
        if( errno == EINTR ) goto AGAIN;
        return YRMCDS_SYSTEM_ERROR;
    }
    if( n == 0 )
        return YRMCDS_DISCONNECTED;
    c->used += (size_t)n;
    return YRMCDS_OK;
}

static yrmcds_error
append_stat(yrmcds_cnt_statistics* s,
            uint16_t name_len, uint16_t value_len,
            const char* name, const char* value) {
    if( s->count == s->capacity ) {
        size_t new_capacity = s->capacity * 2;
        if( new_capacity < INITIAL_STATS_CAPACITY )
            new_capacity = INITIAL_STATS_CAPACITY;
        yrmcds_cnt_stat* new_records =
            realloc(s->records, sizeof(yrmcds_cnt_stat) * new_capacity);
        if( new_records == NULL )
            return YRMCDS_OUT_OF_MEMORY;
        s->capacity = new_capacity;
        s->records = new_records;
    }

    s->records[s->count].name_length = name_len;
    s->records[s->count].value_length = value_len;
    s->records[s->count].name = name;
    s->records[s->count].value = value;
    s->count += 1;
    return YRMCDS_OK;
}

static yrmcds_error
parse_statistics(yrmcds_cnt* c, const yrmcds_cnt_response* r) {
    yrmcds_cnt_statistics* s = &c->stats;
    s->count = 0;

    const char* p = r->body;
    const char* end = r->body + r->body_length;
    while( p < end ) {
        if( p + 4 > end )
            return YRMCDS_PROTOCOL_ERROR;
        uint16_t name_len = ntoh16(p);
        uint16_t value_len = ntoh16(p + 2);
        if( p + 4 + name_len + value_len > end )
            return YRMCDS_PROTOCOL_ERROR;
        yrmcds_error err =
            append_stat(s, name_len, value_len, p + 4, p + 4 + name_len);
        if( err != YRMCDS_OK )
            return err;
        p += 4 + name_len + value_len;
    }
    return YRMCDS_OK;
}

static yrmcds_error
parse_dump_record(yrmcds_cnt* c, yrmcds_cnt_response* r) {
    if( r->body_length == 0 ) {
        // End of dump
        return YRMCDS_OK;
    }
    if( r->body_length < 10 ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }
    r->current_consumption = ntoh32(r->body);
    r->max_consumption = ntoh32(r->body + 4);
    r->name_length = ntoh16(r->body + 8);
    if( r->body_length < 10 + r->name_length ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }
    r->name = r->body + 10;
    return YRMCDS_OK;
}

yrmcds_error
yrmcds_cnt_recv(yrmcds_cnt* c, yrmcds_cnt_response* r) {
    if( c == NULL || r == NULL )
        return YRMCDS_BAD_ARGUMENT;
    if( c->invalid )
        return YRMCDS_PROTOCOL_ERROR;

    if( c->last_size > 0 ) {
        size_t remain = c->used - c->last_size;
        if( remain > 0 )
            memmove(c->recvbuf, c->recvbuf + c->last_size, remain);
        c->used = remain;
        c->last_size = 0;
    }

    while( c->used < HEADER_SIZE ) {
        yrmcds_error e = recv_data(c);
        if( e != YRMCDS_OK ) return e;
    }

    if( (uint8_t)c->recvbuf[0] != 0x91 ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }

    r->command = (yrmcds_cnt_command)c->recvbuf[1];
    r->status = (yrmcds_cnt_status)c->recvbuf[2];
    r->body_length = ntoh32(c->recvbuf + 4);
    memcpy(&r->serial, c->recvbuf + 8, sizeof(r->serial));
    r->body = NULL;
    r->resources = 0;
    r->current_consumption = 0;
    r->max_consumption = 0;
    r->name_length = 0;
    r->stats = NULL;

    if( r->body_length > 0 ) {
        while( c->used < HEADER_SIZE + r->body_length ) {
            yrmcds_error e = recv_data(c);
            if( e != YRMCDS_OK ) return e;
        }
        r->body = c->recvbuf + HEADER_SIZE;
    }
    c->last_size = HEADER_SIZE + r->body_length;

    if( r->status != YRMCDS_STATUS_OK )
        return YRMCDS_OK;

    yrmcds_error err;
    switch( r->command ) {
    case YRMCDS_CNT_CMD_GET:
        if( r->body_length < 4 ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->current_consumption = ntoh32(r->body);
        break;

    case YRMCDS_CNT_CMD_ACQUIRE:
        if( r->body_length < 4 ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->resources = ntoh32(r->body);
        break;

    case YRMCDS_CNT_CMD_STATS:
        err = parse_statistics(c, r);
        if( err != YRMCDS_OK ) {
            c->invalid = 1;
            return err;
        }
        r->stats = &c->stats;
        break;

    case YRMCDS_CNT_CMD_DUMP:
        err = parse_dump_record(c, r);
        if( err != YRMCDS_OK ) {
            c->invalid = 1;
            return err;
        }
        break;

    default:
        // No body
        break;
    }
    return YRMCDS_OK;
}

static yrmcds_error
send_command(yrmcds_cnt* c, yrmcds_cnt_command cmd, uint32_t* serial,
             size_t body1_len, const char* body1,
             size_t body2_len, const char* body2) {
    if( c == NULL ||
        body1_len > UINT32_MAX - body2_len ||
        (body1_len != 0 && body1 == NULL) ||
        (body2_len != 0 && body2 == NULL) )
        return YRMCDS_BAD_ARGUMENT;

#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    int e = pthread_mutex_lock(&c->lock);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#endif // ! LIBYRMCDS_NO_INTERNAL_LOCK

    c->serial += 1;
    if( serial != NULL )
        *serial = c->serial;

    char header[HEADER_SIZE];
    header[0] = '\x90';
    header[1] = (char)cmd;
    header[2] = 0;
    header[3] = 0;
    hton32((uint32_t)(body1_len + body2_len), header + 4);
    memcpy(header + 8, &c->serial, 4);

    yrmcds_error ret = YRMCDS_OK;

    struct iovec iov[3];
    size_t iovcnt = 1;

    iov[0].iov_base = header;
    iov[0].iov_len = HEADER_SIZE;

    if( body1_len != 0 ) {
        iov[iovcnt].iov_base = (void*)body1;
        iov[iovcnt].iov_len = body1_len;
        ++iovcnt;
    }
    if( body2_len != 0 ) {
        iov[iovcnt].iov_base = (void*)body2;
        iov[iovcnt].iov_len = body2_len;
        ++iovcnt;
    }

    size_t i;
    for( i = 0; i < iovcnt; ) {
        ssize_t n = writev(c->sock, iov + i, (int)(iovcnt - i));
        size_t n2 = (size_t)n;
        if( n == -1 ) {
            if( errno == EINTR ) continue;
            ret = YRMCDS_SYSTEM_ERROR;
            break;
        }
        while( n2 > 0 ) {
            if( n2 < iov[i].iov_len ) {
                iov[i].iov_base = (char*)iov[i].iov_base + n2;
                iov[i].iov_len -= n2;
                break;
            }
            n2 -= iov[i].iov_len;
            ++i;
        }
    }

#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    pthread_mutex_unlock(&c->lock);
#endif
    return ret;
}

yrmcds_error
yrmcds_cnt_noop(yrmcds_cnt* c, uint32_t* serial) {
    return send_command(c, YRMCDS_CNT_CMD_NOOP, serial,
                        0, NULL, 0, NULL);
}

yrmcds_error
yrmcds_cnt_get(yrmcds_cnt* c, const char* name, size_t name_len,
               uint32_t* serial) {
    if( name == NULL || name_len == 0 || name_len > UINT16_MAX )
        return YRMCDS_BAD_ARGUMENT;

    char body[2];
    hton16((uint16_t)name_len, body);
    return send_command(c, YRMCDS_CNT_CMD_GET, serial,
                        sizeof(body), body, name_len, name);
}

yrmcds_error
yrmcds_cnt_acquire(yrmcds_cnt* c, const char* name, size_t name_len,
                   uint32_t resources, uint32_t initial, uint32_t* serial) {
    if( name == NULL || name_len == 0 || name_len > UINT16_MAX ||
        resources == 0 || resources > initial )
        return YRMCDS_BAD_ARGUMENT;

    char body[10];
    hton32(resources, body);
    hton32(initial, body + 4);
    hton16((uint16_t)name_len, body + 8);
    return send_command(c, YRMCDS_CNT_CMD_ACQUIRE, serial,
                        sizeof(body), body, name_len, name);
}

yrmcds_error
yrmcds_cnt_release(yrmcds_cnt* c, const char* name, size_t name_len,
                   uint32_t resources, uint32_t* serial) {
    if( name == NULL || name_len == 0 || name_len > UINT16_MAX )
        return YRMCDS_BAD_ARGUMENT;

    char body[6];
    hton32(resources, body);
    hton16((uint16_t)name_len, body + 4);
    return send_command(c, YRMCDS_CNT_CMD_RELEASE, serial,
                        sizeof(body), body, name_len, name);
}

yrmcds_error
yrmcds_cnt_stats(yrmcds_cnt* c, uint32_t* serial) {
    return send_command(c, YRMCDS_CNT_CMD_STATS, serial,
                        0, NULL, 0, NULL);
}

yrmcds_error
yrmcds_cnt_dump(yrmcds_cnt* c, uint32_t* serial) {
    return send_command(c, YRMCDS_CNT_CMD_DUMP, serial,
                        0, NULL, 0, NULL);
}
