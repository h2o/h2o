/*
 * Public domain
 * sys/socket.h compatibility shim
 */

#ifndef _WIN32
#include_next <sys/socket.h>
#else
#include <win32netcompat.h>
#endif
