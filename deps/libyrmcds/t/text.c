#include "t.h"
#include <string.h>
#include <yrmcds.h>

DEF_TEST(set) {
    // quiet cannot be used
    ASSERT( yrmcds_set(c, "a", 1, "a", 1, 0, 0, 0, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    uint32_t serial;
    check_error( yrmcds_set(c, "hoge", 4, "hoge", 4, 1, 0, 0, 0, &serial) );

    yrmcds_response r;
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_get(c, "hoge", 4, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.data_len == 4, 0 );
    ASSERT( memcmp(r.data, "hoge", 4) == 0, 0 );
    ASSERT( r.flags == 1, 0 );

    // CAS failure
    check_error( yrmcds_set(c, "hoge", 4, "fu", 2, 2, 0, r.cas_unique+1,
                            0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_EXISTS, 1 );

    check_error( yrmcds_getk(c, "hoge", 4, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.key_len == 4, 0 );
    ASSERT( memcmp(r.key, "hoge", 4) == 0, 0 );
    ASSERT( r.data_len == 4, 0 );
    ASSERT( memcmp(r.data, "hoge", 4) == 0, 0 );
    ASSERT( r.flags == 1, 0 );

    // CAS success
    check_error( yrmcds_set(c, "hoge", 4, "fu", 2, 4097, 0, r.cas_unique,
                            0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_getk(c, "hoge", 4, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.key_len == 4, 0 );
    ASSERT( memcmp(r.key, "hoge", 4) == 0, 0 );
    ASSERT( r.data_len == 2, 0 );
    ASSERT( memcmp(r.data, "fu", 2) == 0, 0 );
    ASSERT( r.flags == 4097, 0 );

    // set exptime
    check_error( yrmcds_set(c, "hoge", 4, "999", 3, 0, 1, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    sleep(2);

    check_error( yrmcds_getk(c, "hoge", 4, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTFOUND, 1 );
}

DEF_TEST(add) {
    // quiet cannot be used
    ASSERT( yrmcds_add(c, "a", 1, "a", 1, 0, 0, 0, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    uint32_t serial;
    check_error( yrmcds_add(c, "hoge", 4, "hoge", 4, 1, 0, 0, 0, &serial) );

    yrmcds_response r;
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_add(c, "hoge", 4, "fu", 2, 16, 0, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTSTORED, 1 );
}

DEF_TEST(replace) {
    // quiet cannot be used
    ASSERT( yrmcds_replace(c, "a", 1, "a", 1, 0, 0, 0, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    uint32_t serial;
    check_error( yrmcds_replace(c, "abc", 3, "hoge", 4, 1, 0, 0, 0, &serial) );

    yrmcds_response r;
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTSTORED, 1 );

    check_error( yrmcds_set(c, "abc", 3, "def", 3, 16, 0, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_replace(c, "abc", 3, "hoge", 4, 1, 0, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
}

DEF_TEST(append) {
    uint32_t serial;
    yrmcds_response r;

    // quiet cannot be used
    ASSERT( yrmcds_append(c, "a", 1, "a", 1, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    check_error( yrmcds_append(c, "012", 3, "345", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTSTORED, 1 );

    check_error( yrmcds_set(c, "012", 3, "345", 3, 1, 0, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_append(c, "012", 3, "6789", 4, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_getk(c, "012", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.data_len == 7, 1 );
    ASSERT( memcmp(r.data, "3456789", 7) == 0, 0 );
}

DEF_TEST(prepend) {
    uint32_t serial;
    yrmcds_response r;

    // quiet cannot be used
    ASSERT( yrmcds_prepend(c, "a", 1, "a", 1, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    check_error( yrmcds_prepend(c, "012", 3, "345", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTSTORED, 1 );

    check_error( yrmcds_set(c, "012", 3, "345", 3, 1, 0, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_prepend(c, "012", 3, "6789", 4, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_getk(c, "012", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.data_len == 7, 1 );
    ASSERT( memcmp(r.data, "6789345", 7) == 0, 0 );
}

DEF_TEST(touch) {
    uint32_t serial;
    yrmcds_response r;

    // quiet cannot be used
    ASSERT( yrmcds_touch(c, "a", 1, 0, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    check_error( yrmcds_set(c, "a", 1, "345", 3, 0, 1, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_touch(c, "a", 1, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    sleep(2);

    check_error( yrmcds_getk(c, "a", 1, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
}

DEF_TEST(incdec) {
    uint32_t serial;
    yrmcds_response r;

    // quiet cannot be used
    ASSERT( yrmcds_incr(c, "a", 1, 100, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );
    ASSERT( yrmcds_decr(c, "a", 1, 100, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    check_error( yrmcds_incr(c, "a", 1, 100, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTFOUND, 0 );

    check_error( yrmcds_decr(c, "a", 1, 100, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTFOUND, 0 );

    check_error( yrmcds_set(c, "a", 1, "345", 3, 0, 1, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_incr(c, "a", 1, 1000, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.value == 1345, 1 );

    check_error( yrmcds_decr(c, "a", 1, 1, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.value == 1344, 1 );

    check_error( yrmcds_getk(c, "a", 1, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.data_len == 4, 1 );
    ASSERT( memcmp(r.data, "1344", 4) == 0, 0 );
}

DEF_TEST(remove) {
    uint32_t serial;
    yrmcds_response r;

    // quiet cannot be used
    ASSERT( yrmcds_remove(c, "a", 1, 1, NULL) == YRMCDS_BAD_ARGUMENT, 0 );

    check_error( yrmcds_remove(c, "uuu", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTFOUND, 0 );

    check_error( yrmcds_set(c, "uuu", 3, "345", 3, 111, 0, 0, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_remove(c, "uuu", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );

    check_error( yrmcds_getk(c, "uuu", 3, 0, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_NOTFOUND, 1 );
}

DEF_TEST(version) {
    uint32_t serial;
    yrmcds_response r;

    check_error( yrmcds_version(c, &serial) );
    check_error( yrmcds_recv(c, &r) );
    ASSERT( r.serial == serial, 0 );
    ASSERT( r.status == YRMCDS_STATUS_OK, 1 );
    ASSERT( r.data_len > 0, 1 );
    fprintf(stderr, "version=%.*s\n", (int)r.data_len, r.data);
}

TEST_MAIN() {
    check_error( yrmcds_text_mode(c) );

    CALL_TEST(set);
    CALL_TEST(add);
    CALL_TEST(replace);
    CALL_TEST(append);
    CALL_TEST(prepend);
    CALL_TEST(touch);
    CALL_TEST(incdec);
    CALL_TEST(remove);
    CALL_TEST(version);
}
