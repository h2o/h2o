/*
 * Public domain
 * limits.h compatibility shim
 */

#ifdef _MSC_VER
#include <../include/limits.h>
#else
#include_next <limits.h>
#endif

#ifdef __hpux
#include <sys/param.h>
#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif
#endif
