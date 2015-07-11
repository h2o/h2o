#include <yrmcds.h>

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <stdio.h>

void check_error(yrmcds_error e) {
    if( e != 0 ) {
        if( e == YRMCDS_SYSTEM_ERROR ) {
            error(0, errno, "system error");
        } else {
            fprintf(stderr, "yrmcds error: %s\n", yrmcds_strerror(e));
        }
        exit(2);
    }
}

void check_response(const yrmcds_response* r) {
    if( r->status != YRMCDS_STATUS_OK ) {
        fprintf(stderr, "Command failed: 0x%04x %.*s\n",
                r->status, (int)r->data_len, r->data);
        exit(3);
    }
}

int main(int argc, char** argv) {
    yrmcds c;
    yrmcds_response r;

    check_error( yrmcds_connect(&c, "localhost", 11211) );
    check_error( yrmcds_noop(&c, NULL) );
    check_error( yrmcds_recv(&c, &r) );
    check_response(&r);
    check_error( yrmcds_close(&c) );

    return 0;
}
