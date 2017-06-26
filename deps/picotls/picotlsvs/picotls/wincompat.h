#ifndef WINCOMPAT_H
#define WINCOMPAT_H

#include <stdint.h>
#define ssize_t int
#include <Winsock2.h>

#ifndef gettimeofday
#define gettimeofday wintimeofday

#ifdef  __cplusplus
extern "C" {
#endif

    int wintimeofday(struct timeval* tv, struct timezone* tz);

#ifdef  __cplusplus
} /* extern "C" */
#endif




#endif


#endif /* WINCOMPAT_H */