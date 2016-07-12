// (C) 2013-2015 Cybozu.

#include "yrmcds.h"

#include <errno.h>
#include <fcntl.h>
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

static void version() {
    printf("yc with libyrmcds " LIBYRMCDS_VERSION "\n");
}

static void usage() {
    printf("Usage: yc "
           "[-h] [-v] [-d] [-t] [-s SERVER] [-p PORT] [-c COMPRESS] COMMAND ...\n\n"
           "Options:\n"
           "  -h      print help and exit.\n"
           "  -v      print version information.\n"
           "  -d      turn on debug messages.\n"
           "  -t      turn on text protocol mode.\n"
           "  -q      Use quiet commands, if possible.\n"
           "  -s      connect to SERVER.      Default: localhost\n"
           "  -p      TCP port number.        Default: 11211\n"
           "  -c      compression threshold.  Default: 16384\n\n"
           "Commands:\n"
           "  noop\n"
           "          ping the server.\n"
           "  get KEY\n"
           "          get an object.\n"
           "  getk KEY\n"
           "          get an object with key.\n"
           "  gat KEY EXPIRE\n"
           "          get and touch an object.\n"
           "  gatk KEY EXPIRE\n"
           "          get and touch an object with key.\n"
           "  lag KEY\n"
           "          lock and get an object.\n"
           "  lagk KEY\n"
           "          lock and get an object with key.\n"
           "  touch KEY EXPIRE\n"
           "          touch an object.\n"
           "  set KEY FILE [EXPIRE [FLAGS [CAS]]]\n"
           "          store FILE data.  If FILE is \"-\", stdin is used.\n"
           "  replace KEY FILE [EXPIRE [FLAGS [CAS]]]\n"
           "          update an existing object. FILE is the same as set.\n"
           "  add KEY FILE [EXPIRE [FLAGS [CAS]]]\n"
           "          create a new object. FILE is the same as set.\n"
           "  rau KEY FILE [EXPIRE [FLAGS]]\n"
           "          replace a locked object then unlock it.\n"
           "          Since this command always fails, do not use this.\n"
           "  incr KEY VALUE [INITIAL [EXPIRE]]\n"
           "          increments an exiting object's value by VALUE.\n"
           "          If INITIAL is given, new object is created when KEY\n"
           "          is not found.  EXPIRE is used only when an object is\n"
           "          created.\n"
           "  decr KEY VALUE [INITIAL [EXPIRE]]\n"
           "          decrements an exiting object's value by VALUE.\n"
           "          If INITIAL is given, new object is created when KEY\n"
           "          is not found.  EXPIRE is used only when an object is\n"
           "          created.\n"
           "  append KEY FILE\n"
           "          append FILE data  FILE is the same as set.\n"
           "  prepend KEY FILE\n"
           "          prepend FILE data  FILE is the same as set.\n"
           "  delete KEY\n"
           "          delete an object.\n"
           "  lock KEY\n"
           "          locks an object.\n"
           "  unlock KEY\n"
           "          this command always fails.  Do not use this.\n"
           "  unlockall\n"
           "          this command has no effect.\n"
           "  flush [DELAY]\n"
           "          flush all unlocked items immediately or after DELAY seconds.\n"
           "  stat [settings|items|sizes]\n"
           "          obtain general or specified statistics.\n"
           "  keys [PREFIX]\n"
           "          dump keys matching PREFIX.\n"
           "  version\n"
           "          shows the server version.\n"
           "  quit\n"
           "          just quits.  Not much interesting.\n"
        );
}

static void print_response(const yrmcds_response* r) {
    fprintf(stderr, "dump response:\n"
            "  serial:   %u\n"
            "  length:   %lu\n"
            "  status:   0x%04x\n"
            "  command:  0x%02x\n"
            "  cas:      %" PRIu64 "\n"
            "  flags:    0x%08x\n"
            "  value:    %" PRIu64 "\n",
            r->serial, (unsigned long)r->length, r->status, r->command,
            r->cas_unique, r->flags, r->value);
    if( r->key_len )
        fprintf(stderr, "  key:      %.*s (%lu bytes)\n",
                (int)r->key_len, r->key, (unsigned long)r->key_len);
    if( r->data_len )
        fprintf(stderr, "  data:     %.*s (%lu bytes)\n",
                (int)r->data_len, r->data, (unsigned long)r->data_len);
}

static void write_data(const yrmcds_response* r) {
    const char* p = r->data;
    size_t to_write = r->data_len;
    while( to_write > 0 ) {
        ssize_t n = write(STDOUT_FILENO, p, to_write);
        if( n == -1 ) return;
        p += n;
        to_write -= (size_t)n;
    }
    // writing a newline breaks data equality...
    //char nl = '\n';
    //write(STDOUT_FILENO, &nl, 1);
}

static size_t read_data(const char* filename, char** pdata) {
    int fd;
    if( strcmp(filename, "-") == 0 ) {
        fd = STDIN_FILENO;
    } else {
        fd = open(filename, O_RDONLY);
        if( fd == -1 ) return 0;
    }

    size_t data_len = 0;
    size_t capacity = 1 << 20;
    *pdata = (char*)malloc(capacity);
    if( *pdata == NULL ) return 0;
    while( 1 ) {
        if( (capacity - data_len) < (1 << 20) ) {
            char* new_data = (char*)realloc(*pdata, capacity * 2);
            if( new_data == NULL ) {
                free(*pdata);
                *pdata = NULL;
                return 0;
            }
            *pdata = new_data;
            capacity *= 2;
        }
        ssize_t n = read(fd, *pdata + data_len, 1 << 20);
        if( n == -1 ) {
            free(*pdata);
            *pdata = NULL;
            return 0;
        }
        if( n == 0 ) break;
        data_len += (size_t)n;
    }

    if( fd != STDIN_FILENO )
        close(fd);
    return data_len;
}


#define CHECK_ERROR(e)                                                  \
    if( e != 0 ) {                                                      \
        if( e == YRMCDS_SYSTEM_ERROR ) {                                \
            fprintf(stderr, "system error: %s\n", strerror(errno));     \
        } else {                                                        \
            fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));  \
        }                                                               \
        return 2;                                                       \
    }

#define CHECK_RESPONSE(r)                                   \
    if( r->status != YRMCDS_STATUS_OK ) {                   \
        fprintf(stderr, "Command failed: 0x%04x %.*s\n",    \
                r->status, (int)r->data_len, r->data);      \
        return 3;                                           \
    }

int cmd_noop(int argc, char** argv, yrmcds* s) {
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_noop(s, &serial);
    CHECK_ERROR(e);
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    e = yrmcds_recv(s, r);
    CHECK_ERROR(e);
    if( debug )
        print_response(r);
    CHECK_RESPONSE(r);
    printf("OK\n");
    return 0;
}

int cmd_get(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_get(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    return 0;
}

int cmd_getk(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_getk(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    return 0;
}

int cmd_gat(int argc, char** argv, yrmcds* s) {
    if( argc != 2 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    uint32_t expire = (uint32_t)strtoull(argv[1], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_get_touch(s, key, strlen(key), expire, quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    return 0;
}

int cmd_gatk(int argc, char** argv, yrmcds* s) {
    if( argc != 2 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    uint32_t expire = (uint32_t)strtoull(argv[1], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_getk_touch(s, key, strlen(key), expire, quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    return 0;
}

int cmd_lag(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_lock_get(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    fprintf(stderr, "Press enter to unlock.\n");
    getchar();
    return 0;
}

int cmd_lagk(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_lock_getk(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    fprintf(stderr, "Press enter to unlock.\n");
    getchar();
    return 0;
}

int cmd_touch(int argc, char** argv, yrmcds* s) {
    if( argc != 2 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    uint32_t expire = (uint32_t)strtoull(argv[1], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_touch(s, key, strlen(key), expire, quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_set(int argc, char** argv, yrmcds* s) {
    if( argc < 2 || 5 < argc ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    char* data = NULL;
    size_t data_len = read_data(argv[1], &data);
    if( data == NULL ) {
        fprintf(stderr, "Failed to read data.\n");
        return 2;
    }
    uint32_t expire = 0;
    uint32_t flags = 0;
    uint64_t cas = 0;

    if( argc > 2 )
        expire = (uint32_t)strtoull(argv[2], NULL, 0);
    if( argc > 3 )
        flags = (uint32_t)strtoull(argv[3], NULL, 0);
    if( argc > 4 )
        cas = (uint64_t)strtoull(argv[4], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_set(s, key, strlen(key), data, data_len,
                                flags, expire, cas, quiet, &serial);
    free(data);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_replace(int argc, char** argv, yrmcds* s) {
    if( argc < 2 || 5 < argc ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    char* data = NULL;
    size_t data_len = read_data(argv[1], &data);
    if( data == NULL ) {
        fprintf(stderr, "Failed to read data.\n");
        return 2;
    }
    uint32_t expire = 0;
    uint32_t flags = 0;
    uint64_t cas = 0;

    if( argc > 2 )
        expire = (uint32_t)strtoull(argv[2], NULL, 0);
    if( argc > 3 )
        flags = (uint32_t)strtoull(argv[3], NULL, 0);
    if( argc > 4 )
        cas = (uint64_t)strtoull(argv[4], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_replace(s, key, strlen(key), data, data_len,
                                    flags, expire, cas, quiet, &serial);
    free(data);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_add(int argc, char** argv, yrmcds* s) {
    if( argc < 2 || 5 < argc ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    char* data = NULL;
    size_t data_len = read_data(argv[1], &data);
    if( data == NULL ) {
        fprintf(stderr, "Failed to read data.\n");
        return 2;
    }
    uint32_t expire = 0;
    uint32_t flags = 0;
    uint64_t cas = 0;

    if( argc > 2 )
        expire = (uint32_t)strtoull(argv[2], NULL, 0);
    if( argc > 3 )
        flags = (uint32_t)strtoull(argv[3], NULL, 0);
    if( argc > 4 )
        cas = (uint64_t)strtoull(argv[4], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_add(s, key, strlen(key), data, data_len,
                                flags, expire, cas, quiet, &serial);
    free(data);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_rau(int argc, char** argv, yrmcds* s) {
    if( argc < 2 || 4 < argc ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    char* data = NULL;
    size_t data_len = read_data(argv[1], &data);
    if( data == NULL ) {
        fprintf(stderr, "Failed to read data.\n");
        return 2;
    }
    uint32_t expire = 0;
    uint32_t flags = 0;

    if( argc > 2 )
        expire = (uint32_t)strtoull(argv[2], NULL, 0);
    if( argc > 3 )
        flags = (uint32_t)strtoull(argv[3], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_replace_unlock(s, key, strlen(key), data, data_len,
                                           flags, expire, quiet, &serial);
    free(data);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_incr(int argc, char** argv, yrmcds* s) {
    if( argc < 2 || 4 < argc ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    uint64_t value = (uint64_t)strtoull(argv[1], NULL, 0);
    uint64_t initial = 0;
    uint32_t expire = ~(uint32_t)0;

    if( argc > 2 ) {
        initial = (uint64_t)strtoull(argv[2], NULL, 0);
        expire = 0;
    }
    if( argc > 3 )
        expire = (uint32_t)strtoull(argv[3], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e;
    if( argc == 2 ) {
        e = yrmcds_incr(s, key, strlen(key), value, quiet, &serial);
    } else {
        e = yrmcds_incr2(s, key, strlen(key), value, initial, expire,
                         quiet, &serial);
    }
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    printf("%" PRIu64 "\n", r->value);
    return 0;
}

int cmd_decr(int argc, char** argv, yrmcds* s) {
    if( argc < 2 || 4 < argc ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    uint64_t value = (uint64_t)strtoull(argv[1], NULL, 0);
    uint64_t initial = 0;
    uint32_t expire = ~(uint32_t)0;

    if( argc > 2 ) {
        initial = (uint64_t)strtoull(argv[2], NULL, 0);
        expire = 0;
    }
    if( argc > 3 )
        expire = (uint32_t)strtoull(argv[3], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e;
    if( argc == 2 ) {
        e = yrmcds_decr(s, key, strlen(key), value, quiet, &serial);
    } else {
        e = yrmcds_decr2(s, key, strlen(key), value, initial, expire,
                         quiet, &serial);
    }
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    printf("%" PRIu64 "\n", r->value);
    return 0;
}

int cmd_append(int argc, char** argv, yrmcds* s) {
    if( argc != 2 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    char* data = NULL;
    size_t data_len = read_data(argv[1], &data);
    if( data == NULL ) {
        fprintf(stderr, "Failed to read data.\n");
        return 2;
    }

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_append(s, key, strlen(key),
                                   data, data_len, quiet, &serial);
    free(data);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_prepend(int argc, char** argv, yrmcds* s) {
    if( argc != 2 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    const char* key = argv[0];
    char* data = NULL;
    size_t data_len = read_data(argv[1], &data);
    if( data == NULL ) {
        fprintf(stderr, "Failed to read data.\n");
        return 2;
    }

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_prepend(s, key, strlen(key),
                                    data, data_len, quiet, &serial);
    free(data);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_delete(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_remove(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    write_data(r);
    return 0;
}

int cmd_lock(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_lock(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    fprintf(stderr, "Press enter to unlock.\n");
    getchar();
    return 0;
}

int cmd_unlock(int argc, char** argv, yrmcds* s) {
    if( argc != 1 ) {
        fprintf(stderr, "Wrong number of arguments.\n");
        return 1;
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_unlock(s, argv[0], strlen(argv[0]), quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_unlockall(int argc, char** argv, yrmcds* s) {
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_unlockall(s, quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_flush(int argc, char** argv, yrmcds* s) {
    uint32_t delay = 0;
    if( argc == 1 )
        delay = (uint32_t)strtoull(argv[0], NULL, 0);

    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_flush(s, delay, quiet, &serial);
    CHECK_ERROR(e);
    if( quiet ) {
        e = yrmcds_noop(s, &serial);
        CHECK_ERROR(e);
    }
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial == serial )
            break;
    }
    return 0;
}

int cmd_stat(int argc, char** argv, yrmcds* s) {
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e;
    if( argc > 0 ) {
        if( strcmp(argv[0], "settings") == 0 ) {
            e = yrmcds_stat_settings(s, &serial);
        } else if( strcmp(argv[0], "items") == 0 ) {
            e = yrmcds_stat_items(s, &serial);
        } else if( strcmp(argv[0], "sizes") == 0 ) {
            e = yrmcds_stat_sizes(s, &serial);
        } else {
            fprintf(stderr, "No such statistics.\n");
            return 1;
        }
    } else {
        e = yrmcds_stat_general(s, &serial);
    }
    CHECK_ERROR(e);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->key_len == 0 )
            break;
        if( r->data_len == 0 )
            continue;
        printf("%.*s: %.*s\n", (int)r->key_len, r->key,
               (int)r->data_len, r->data);
    }
    return 0;
}

int cmd_keys(int argc, char** argv, yrmcds* s) {
    const char* prefix = NULL;
    size_t prefix_len = 0;
    if( argc == 1 ) {
        prefix = argv[0];
        prefix_len = strlen(prefix);
    }
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_keys(s, prefix, prefix_len, &serial);
    CHECK_ERROR(e);
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    while( 1 ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
        if( r->serial != serial )
            continue;
        if( r->key_len == 0 )
            break;
        printf("%.*s\n", (int)r->key_len, r->key);
    }
    return 0;
}

int cmd_version(int argc, char** argv, yrmcds* s) {
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_version(s, &serial);
    CHECK_ERROR(e);
    e = yrmcds_recv(s, r);
    CHECK_ERROR(e);
    if( debug )
        print_response(r);
    CHECK_RESPONSE(r);
    printf("%.*s\n", (int)r->data_len, r->data);
    return 0;
}

int cmd_quit(int argc, char** argv, yrmcds* s) {
    yrmcds_response r[1];
    uint32_t serial;
    yrmcds_error e = yrmcds_quit(s, quiet, &serial);
    CHECK_ERROR(e);
    if( debug )
        fprintf(stderr, "request serial = %u\n", serial);
    if( ! quiet ) {
        e = yrmcds_recv(s, r);
        CHECK_ERROR(e);
        if( debug )
            print_response(r);
        CHECK_RESPONSE(r);
    }
    return 0;
}

int main(int argc, char** argv) {
    const char* server = DEFAULT_SERVER;
    uint16_t port = DEFAULT_PORT;
    size_t compression = DEFAULT_COMPRESS;
    int text_mode = 0;

    while( 1 ) {
        int n;
        int c = getopt(argc, argv, "s:p:c:dtqvh");
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
            compression = (size_t)n;
            break;
        case 'd':
            debug = 1;
            break;
        case 't':
            text_mode = 1;
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

    yrmcds s[1];
    yrmcds_error e = yrmcds_connect(s, server, port);
    CHECK_ERROR(e);
    if( text_mode ) {
        e = yrmcds_text_mode(s);
        CHECK_ERROR(e);
    }
    e = yrmcds_set_compression(s, compression);
    if( e != 0 && e != YRMCDS_NOT_IMPLEMENTED ) {
        yrmcds_close(s);
        CHECK_ERROR(e);
    }

    int ret = 1;
#define do_cmd(name)                            \
    if( strcmp(cmd, #name) == 0 )  {            \
        ret = cmd_##name(argc, argv, s);        \
            goto OUT;                           \
    }

    do_cmd(noop);
    do_cmd(get);
    do_cmd(getk);
    do_cmd(gat);
    do_cmd(gatk);
    do_cmd(lag);
    do_cmd(lagk);
    do_cmd(touch);
    do_cmd(set);
    do_cmd(replace);
    do_cmd(add);
    do_cmd(rau);
    do_cmd(incr);
    do_cmd(decr);
    do_cmd(append);
    do_cmd(prepend);
    do_cmd(delete);
    do_cmd(lock);
    do_cmd(unlock);
    do_cmd(unlockall);
    do_cmd(flush);
    do_cmd(stat);
    do_cmd(keys);
    do_cmd(version);
    do_cmd(quit);

    fprintf(stderr, "No such command: %s\n", cmd);

  OUT:
    yrmcds_close(s);
    return ret;
}
