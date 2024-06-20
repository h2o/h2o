#pragma once

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

#if defined(__linux__)
#include <sys/eventfd.h>
#define ASYNC_NB_USE_EVENTFD 1
#endif

#if defined(__linux) && defined(SO_REUSEPORT)
#define H2O_USE_REUSEPORT 1
#define H2O_SO_REUSEPORT SO_REUSEPORT
#elif defined(SO_REUSEPORT_LB) /* FreeBSD */
#define H2O_USE_REUSEPORT 1
#define H2O_SO_REUSEPORT SO_REUSEPORT_LB
#else
#define H2O_USE_REUSEPORT 0
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
#define H2O_HAS_PTHREAD_SETAFFINITY_NP 1
#endif
