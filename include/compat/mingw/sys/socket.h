/*
 * NOTE: ws2tcpip.h does not provide struct msghdr, struct cmsghdr and related functions.
 * The Windows sockets implementation provides WSAMSG which does the same job as msghdr,
 * but is not source compatible. It may be possible to declare a struct msghdr that would
 * be guaranteed to have the same in-memory layout as WSAMSG, but since the current port
 * of h2o on MingW is libuv-only and h2o does not support QUIC with libuv, this work is left
 * for the future.
 */

#include <ws2tcpip.h>