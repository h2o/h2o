// (C) 2013 Cybozu.

#include "yrmcds.h"

#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint16_t DEFAULT_PORT = 11211;
static const char DEFAULT_SERVER[] = "localhost";
static const size_t DEFAULT_COMPRESS = 16384;
static int debug = 0;
static int quiet = 0;

void version() {
    printf("yc with libyrmcds " LIBYRMCDS_VERSION "\n");
}

void usage() {
    printf("Usage: yc "
           "[-h] [-v] [-d] [-s SERVER] [-p PORT] [-c COMPRESS] COMMAND ...\n\n"
           "Options:\n"
           "  -h      print help and exit.\n"
           "  -v      print version information.\n"
           "  -d      turn on debug messages.\n"
           "  -q      Use quiet commands, if possible.\n"
           "  -s      connect to SERVER.      Default: localhost\n"
           "  -p      TCP port number.        Default: 11211\n"
           "  -c      compression threshold.  Default: 16384\n\n"
           "Commands:\n"
           "  noop\n"
           "          ping the server.\n"
           "  get KEY\n"
           "          get named objects.\n"
           "  set KEY FILE [EXPIRE [FLAGS [CAS]]]\n"
           "          store FILE data.  If FILE is \"-\", stdin is used.\n"
        );
}

void print_response(const yrmcds_response* r) {
    fprintf(stderr, "dump response:\n"
            "  serial:   %u\n"
            "  length:   %lu\n"
            "  status:   0x%04x\n"
            "  command:  0x%02x\n"
            "  cas:      %" PRIu64 "\n"
            "  flags:    0x%08x\n"
            "  value:    %" PRIu64 "\n",
            r->serial, r->length, r->status, r->command,
            r->cas_unique, r->flags, r->value);
    if( r->key_len )
        fprintf(stderr, "  key:      %.*s (%lu bytes)\n",
                (int)r->key_len, r->key, r->key_len);
    if( r->data_len )
        fprintf(stderr, "  data:     %.*s (%lu bytes)\n",
                (int)r->data_len, r->data, r->data_len);
}

#define CHECK_ERROR(e, s)                                               \
    if( e != 0 ) {                                                      \
        if( e == YRMCDS_SYSTEM_ERROR ) {                                \
            error(0, errno, "system error");                            \
        } else {                                                        \
            fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));  \
        }                                                               \
        if( s != NULL )                                                 \
            yrmcds_close(s);                                            \
        return 2;                                                       \
    }

int cmd_noop(int argc, char** argv,
             const char* server, uint16_t port, size_t comp) {
    yrmcds s[1];
    yrmcds_response r[1];
    int e = yrmcds_connect(s, server, port);
    CHECK_ERROR(e, NULL);
    e = yrmcds_set_compression(s, comp);
    CHECK_ERROR(e, s);
    uint32_t serial;
    e = yrmcds_noop(s, &serial);
    CHECK_ERROR(e, s);
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    e = yrmcds_recv(s, r);
    CHECK_ERROR(e, s);
    if( debug )
        print_response(r);
    yrmcds_close(s);
    printf("OK\n");
    return 0;
}

int main(int argc, char** argv) {
    const char* server = DEFAULT_SERVER;
    uint16_t port = DEFAULT_PORT;
    size_t compression = DEFAULT_COMPRESS;

    while( 1 ) {
        int n;
        int c = getopt(argc, argv, "s:p:c:dqvh");
        if( c == -1 ) break;
        switch( c ) {
        case 's':
            server = optarg;
            break;
        case 'p':
            n = atoi(optarg);
            if( n <= 0 || n > 65535 ) {
                fprintf(stderr, "Invalid TCP port.\n");
                return 1;
            }
            port = (uint16_t)n;
            break;
        case 'c':
            n = atoi(optarg);
            if( n <= 0 ) {
                fprintf(stderr, "Invalid compression thoreshold.\n");
                return 1;
            }
            compression = n;
            break;
        case 'd':
            debug = 1;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'v':
            version();
            return 0;
        case 'h':
            usage();
            return 0;
        default:
            return 1;
        }
    }

    if( optind == argc ) {
        usage();
        return 0;
    }

    const char* cmd = argv[optind];
    argc -= optind + 1;
    argv += optind + 1;

#define do_cmd(name) \
    if( strcmp(cmd, #name) == 0 )               \
        return cmd_##name(argc, argv, server, port, compression);

    do_cmd(noop);

    fprintf(stderr, "No such command: %s\n", cmd);
    return 1;
}
