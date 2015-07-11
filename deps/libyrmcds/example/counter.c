#include <yrmcds.h>

#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>

void check_error(yrmcds_error e) {
    if( e != YRMCDS_OK ) {
        if( e == YRMCDS_SYSTEM_ERROR ) {
            error(0, errno, "system error");
        } else {
            fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));
        }
        exit(2);
    }
}

void check_response(const yrmcds_cnt_response* r) {
    if( r->status != YRMCDS_STATUS_OK ) {
        fprintf(stderr, "Command failed: 0x%02x %.*s\n",
                r->status, (int)r->body_length, r->body);
        exit(3);
    }
}

int main(void) {
    yrmcds_cnt c;
    yrmcds_cnt_response r;

    check_error( yrmcds_cnt_connect(&c, "localhost", 11215) );
    check_error( yrmcds_cnt_noop(&c, NULL) );
    check_error( yrmcds_cnt_recv(&c, &r) );
    check_response(&r);
    check_error( yrmcds_cnt_close(&c) );

    return 0;
}
