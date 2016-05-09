#include "yrmcds.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char USAGE[] =
    "Usage: yc-cnt [-s SERVER] [-p PORT] [-h] SUBCOMMAND\n"
    "\n"
    "Subcommands:\n"
    "  noop\n"
    "  get NAME\n"
    "  acquire RESOURCES MAXIMUM\n"
    "  release RESOURCES\n"
    "  stats\n"
    "  dump\n";

static const char DEFAULT_SERVER[] = "localhost";
static const uint16_t DEFAULT_PORT = 11215;

static void recv_or_die(yrmcds_cnt* c, yrmcds_cnt_response* r, uint32_t serial) {
    yrmcds_error e;
    while( 1 ) {
        e = yrmcds_cnt_recv(c, r);
        if( e != YRMCDS_OK ) {
            fprintf(stderr, "yc-cnt: failed to recv: %s\n",
                    yrmcds_strerror(e));
            yrmcds_cnt_close(c);
            exit(1);
        }
        if( r->serial == serial )
            break;
    }
}

static void cmd_noop(yrmcds_cnt* c) {
    yrmcds_error e;
    uint32_t serial;

    e = yrmcds_cnt_noop(c, &serial);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to send noop: %s\n",
                yrmcds_strerror(e));
        yrmcds_cnt_close(c);
        exit(1);
    }

    yrmcds_cnt_response r;
    recv_or_die(c, &r, serial);

    if( r.status == YRMCDS_STATUS_OK ) {
        puts("OK");
    } else {
        printf("ERROR: %02x %.*s\n", r.status, (int)r.body_length, r.body);
        yrmcds_cnt_close(c);
        exit(2);
    }
}

static void cmd_get(yrmcds_cnt* c,
                    const char* name, size_t name_len) {
    yrmcds_error e;
    uint32_t serial;

    e = yrmcds_cnt_get(c, name, name_len, &serial);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to send get: %s\n",
                yrmcds_strerror(e));
        yrmcds_cnt_close(c);
        exit(1);
    }

    yrmcds_cnt_response r;
    recv_or_die(c, &r, serial);

    if( r.status == YRMCDS_STATUS_OK ) {
        printf("%" PRIu32 "\n", r.current_consumption);
    } else {
        printf("ERROR: %02x %.*s\n", r.status, (int)r.body_length, r.body);
        yrmcds_cnt_close(c);
        exit(2);
    }
}

static void cmd_acquire(yrmcds_cnt* c,
                        const char* name, size_t name_len,
                        uint32_t resouces, uint32_t initial) {
    yrmcds_error e;
    uint32_t serial;

    e = yrmcds_cnt_acquire(c, name, name_len, resouces, initial, &serial);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to send acquire: %s\n",
                yrmcds_strerror(e));
        yrmcds_cnt_close(c);
        exit(1);
    }

    yrmcds_cnt_response r;
    recv_or_die(c, &r, serial);

    if( r.status == YRMCDS_STATUS_OK ) {
        printf("%" PRIu32 "\n", r.resources);
    } else {
        printf("ERROR: %02x %.*s\n", r.status, (int)r.body_length, r.body);
        yrmcds_cnt_close(c);
        exit(2);
    }
}

static void cmd_release(yrmcds_cnt* c,
                        const char* name, size_t name_len,
                        uint32_t resouces) {
    yrmcds_error e;
    uint32_t serial;

    e = yrmcds_cnt_release(c, name, name_len, resouces, &serial);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to send release: %s\n",
                yrmcds_strerror(e));
        yrmcds_cnt_close(c);
        exit(1);
    }

    yrmcds_cnt_response r;
    recv_or_die(c, &r, serial);

    if( r.status == YRMCDS_STATUS_OK ) {
        puts("OK");
    } else {
        printf("ERROR: %02x %.*s\n", r.status, (int)r.body_length, r.body);
        yrmcds_cnt_close(c);
        exit(2);
    }
}

static void cmd_stats(yrmcds_cnt* c) {
    yrmcds_error e;
    uint32_t serial;

    e = yrmcds_cnt_stats(c, &serial);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to send stats: %s\n",
                yrmcds_strerror(e));
        yrmcds_cnt_close(c);
        exit(1);
    }

    yrmcds_cnt_response r;
    recv_or_die(c, &r, serial);

    if( r.status == YRMCDS_STATUS_OK ) {
        size_t i;
        for( i = 0; i < r.stats->count; ++i ) {
            yrmcds_cnt_stat* stat = &r.stats->records[i];
            printf("%.*s %.*s\n", (int)stat->name_length, stat->name,
                                  (int)stat->value_length, stat->value);
        }
    } else {
        printf("ERROR: %02x %.*s\n", r.status, (int)r.body_length, r.body);
        yrmcds_cnt_close(c);
        exit(2);
    }
}

static void cmd_dump(yrmcds_cnt* c) {
    yrmcds_error e;
    uint32_t serial;

    e = yrmcds_cnt_dump(c, &serial);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to send stats: %s\n",
                yrmcds_strerror(e));
        yrmcds_cnt_close(c);
        exit(1);
    }

    for(;;) {
        yrmcds_cnt_response r;
        recv_or_die(c, &r, serial);

        if( r.status != YRMCDS_STATUS_OK ) {
            printf("ERROR: %02x %.*s\n", r.status, (int)r.body_length, r.body);
            yrmcds_cnt_close(c);
            exit(2);
        }
        if( r.body_length == 0 )
            break;
        printf("%" PRIu32 " %" PRIu32 " %.*s\n",
               r.current_consumption, r.max_consumption,
               (int)r.name_length, r.name);
    }
}

void usage() {
    fprintf(stderr, "%s", USAGE);
    exit(1);
}

int main(int argc, char** argv) {
    const char* server = DEFAULT_SERVER;
    uint16_t port = DEFAULT_PORT;

    while( 1 ) {
        int n;
        int c = getopt(argc, argv, "s:p:h");
        if( c == -1 ) break;
        switch( c ) {
        case 's':
            server = optarg;
            break;
        case 'p':
            n = atoi(optarg);
            if( n <= 0 || n > 65535 ) {
                fprintf(stderr, "yc-cnt: invalid TCP port.\n");
                return 1;
            }
            port = (uint16_t)n;
            break;
        case 'h':
            usage();
        default:
            return 1;
        }
    }

    if( optind == argc )
        usage();

    argc -= optind;
    argv += optind;

    yrmcds_cnt c;
    yrmcds_error e = yrmcds_cnt_connect(&c, server, port);
    if( e != YRMCDS_OK ) {
        fprintf(stderr, "yc-cnt: failed to connect to '%s:%d': %s\n",
                server, port, yrmcds_strerror(e));
        exit(1);
    }
    yrmcds_cnt_set_timeout(&c, 1);

    if( strcmp(argv[0], "noop") == 0 ) {
        if( argc != 1 ) {
            fprintf(stderr, "yc-cnt: invalid number of arguments.\n");
            goto EXIT;
        }
        cmd_noop(&c);
    } else if( strcmp(argv[0], "get") == 0 ) {
        if( argc != 2 ) {
            fprintf(stderr, "yc-cnt: invalid number of arguments.\n");
            goto EXIT;
        }
        cmd_get(&c, argv[1], strlen(argv[1]));
    } else if( strcmp(argv[0], "acquire") == 0 ){
        if( argc != 4 ) {
            fprintf(stderr, "yc-cnt: invalid number of arguments.\n");
            goto EXIT;
        }
        uint32_t resources, initial;
        if( sscanf(argv[2], "%" PRIu32, &resources) != 1 ) {
            fprintf(stderr, "yc-cnt: RESOURCES must be a unsigned 4-byte integer.\n");
            goto EXIT;
        }
        if( sscanf(argv[3], "%" PRIu32, &initial) != 1 ) {
            fprintf(stderr, "yc-cnt: MAXIMUM must be a unsigned 4-byte integer.\n");
            goto EXIT;
        }
        cmd_acquire(&c, argv[1], strlen(argv[1]), resources, initial);
    } else if( strcmp(argv[0], "release") == 0 ){
        if( argc != 3 ) {
            fprintf(stderr, "yc-cnt: invalid number of arguments.\n");
            goto EXIT;
        }
        uint32_t resources;
        if( sscanf(argv[2], "%" PRIu32, &resources) != 1 ) {
            fprintf(stderr, "yc-cnt: RESOURCES must be a unsigned 4-byte integer.\n");
            goto EXIT;
        }
        cmd_release(&c, argv[1], strlen(argv[1]), resources);
    } else if( strcmp(argv[0], "stats") == 0 ) {
        if( argc != 1 ) {
            fprintf(stderr, "yc-cnt: invalid number of arguments.\n");
            goto EXIT;
        }
        cmd_stats(&c);
    } else if( strcmp(argv[0], "dump") == 0 ) {
        if( argc != 1 ) {
            fprintf(stderr, "yc-cnt: invalid number of arguments.\n");
            goto EXIT;
        }
        cmd_dump(&c);
    } else {
        fprintf(stderr, "yc-cnt: unknown command: %s\n", argv[0]);
        goto EXIT;
    }

    yrmcds_cnt_close(&c);
    return 0;

EXIT:
    yrmcds_cnt_close(&c);
    exit(1);
}
