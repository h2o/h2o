// (C) 2013-2015 Cybozu.

#include "yrmcds.h"

const char* yrmcds_strerror(yrmcds_error e) {
    switch( e ) {
    case YRMCDS_OK:
        return "OK";
    case YRMCDS_SYSTEM_ERROR:
        return "Check errno for details";
    case YRMCDS_BAD_ARGUMENT:
        return "Bad argument";
    case YRMCDS_NOT_RESOLVED:
        return "Host not found";
    case YRMCDS_TIMEOUT:
        return "Timeout";
    case YRMCDS_DISCONNECTED:
        return "Connection was reset by peer";
    case YRMCDS_OUT_OF_MEMORY:
        return "Failed to allocate memory";
    case YRMCDS_COMPRESS_FAILED:
        return "Failed to compress data";
    case YRMCDS_PROTOCOL_ERROR:
        return "Received malformed packet";
    case YRMCDS_NOT_IMPLEMENTED:
        return "Not implemented";
    case YRMCDS_IN_BINARY:
        return "Connection is fixed for binary protocol";
    case YRMCDS_BAD_KEY:
        return "Bad key";
    default:
        return "Unknown error";
    };
}
