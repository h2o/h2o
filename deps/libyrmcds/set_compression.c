// (C) 2013-2015 Cybozu.

#include "yrmcds.h"

yrmcds_error yrmcds_set_compression(yrmcds* c, size_t threshold) {
#ifdef LIBYRMCDS_USE_LZ4
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
    c->compress_size = threshold;
    return YRMCDS_OK;
#else
    return YRMCDS_NOT_IMPLEMENTED;
#endif
}
