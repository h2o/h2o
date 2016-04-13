// test utilities

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <yrmcds.h>

static int n_failures = 0;

static void check_error(yrmcds_error e) {
    if( e == YRMCDS_OK )
        return;

    fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));
    exit(1);
}

static yrmcds* get_yrmcds(yrmcds* c) {
    const char* host = getenv("YRMCDS_HOST");
    if( host == NULL ) {
        return NULL;
    }
    uint16_t port = 11211;
    if( getenv("YRMCDS_PORT") ) {
        port = (uint16_t)atoi(getenv("YRMCDS_PORT"));
    }

    check_error( yrmcds_connect(c, host, port) );
    return c;
}

static void test_main(yrmcds* c);

#define TEST_MAIN() static void test_main(yrmcds* c)

int main(int argc, char** argv) {
    yrmcds c_;
    yrmcds* c = get_yrmcds(&c_);
    if( c == NULL ) {
        fprintf(stderr, "No YRMCDS_HOST.  Skipped.\n");
        return 0;
    }

    test_main(c);
    yrmcds_close(c);

    if( n_failures > 0 ) {
        fprintf(stderr, "%d tests failed.\n", n_failures);
        return 1;
    }
    fprintf(stderr, "Passed.\n");
    return 0;
}

#define DEF_TEST(name) void test_##name(yrmcds* c)

#define CALL_TEST(name)                                   \
    fprintf(stderr, "[%s]\n", #name);                     \
    test_##name(c);                                       \
    uint32_t serial_##name;                               \
    check_error( yrmcds_flush(c, 0, 0, &serial_##name) ); \
    while( 1 ) {                                          \
        yrmcds_response r;                                \
        check_error( yrmcds_recv(c, &r) );                \
        if( r.serial == serial_##name ) break;            \
    }                                                     \
    sleep(1)

#define ASSERT(expr, to_return)                                 \
    if( ! (expr) ) {                                            \
        fprintf(stderr, "assertion failure at line %d: %s\n",   \
                __LINE__, #expr);                               \
        n_failures++;                                           \
        if( to_return ) return;                                 \
    }
