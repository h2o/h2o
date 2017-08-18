#include <sys/socket.h>
#include <fcntl.h>

int
accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rets = accept(s, addr, addrlen);
	if (rets == -1)
		return s;

	if (flags & SOCK_CLOEXEC) {
		flags = fcntl(s, F_GETFD);
		fcntl(rets, F_SETFD, flags | FD_CLOEXEC);
	}

	return rets;
}
