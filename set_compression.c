// (C) 2013 Cybozu.

#include "yrmcds.h"

yrmcds_error yrmcds_set_compression(yrmcds* c, size_t threshold) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
    c->compress_size = threshold;
    return YRMCDS_OK;
}
