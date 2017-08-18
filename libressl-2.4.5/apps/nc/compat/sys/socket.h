/*
 * Public domain
 * sys/socket.h compatibility shim
 */

#ifndef _WIN32
#include_next <sys/socket.h>

#if !defined(SOCK_NONBLOCK) || !defined(SOCK_CLOEXEC)
#define NEED_SOCKET_FLAGS
int _socket(int domain, int type, int protocol);
#ifndef SOCKET_FLAGS_PRIV
#define socket(d, t, p) _socket(d, t, p)
#endif
#endif

#ifndef SOCK_NONBLOCK
#define	SOCK_NONBLOCK		0x4000	/* set O_NONBLOCK */
#endif

#ifndef SOCK_CLOEXEC
#define	SOCK_CLOEXEC		0x8000	/* set FD_CLOEXEC */
#endif

#ifndef HAVE_ACCEPT4
int accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags);
#endif

#else
#include <win32netcompat.h>
#endif
