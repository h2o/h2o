/*
 * Copyright (c) 2020 Christian S.J. Peron
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>

static int rootfd = -1;

struct proc_map {
	int			proc_fd;
	pid_t			proc_pid;
	TAILQ_ENTRY(proc_map)	proc_glue;
};

static TAILQ_HEAD( , proc_map)	proc_map_head;
pthread_mutex_t map_mutex;
static int nprocs;

static int sandbox_get_root_fd(void)
{
	char *fd_string;

	if (rootfd > -1) {
		return (rootfd);
	}
	fd_string = getenv("H2O_SANDBOX_ROOT_FD");
	if (fd_string == NULL) {
		return (-1);
	}
	rootfd = atoi(fd_string);
	return (rootfd);
}

static pid_t
lookup_map_by_fd(int fd)
{
	struct proc_map *pm;

	pthread_mutex_lock(&map_mutex);
	TAILQ_FOREACH(pm, &proc_map_head, proc_glue) {
		if (pm->proc_fd == fd) {
			pthread_mutex_unlock(&map_mutex);
			return (pm->proc_pid);
		}
	}
	pthread_mutex_unlock(&map_mutex);
	return (-1);
}

static void
remove_map(pid_t pid)
{
	struct proc_map *pm, *pm_temp;

	pthread_mutex_lock(&map_mutex);
	TAILQ_FOREACH_SAFE(pm, &proc_map_head, proc_glue, pm_temp) {
		if (pm->proc_pid != pid) {
			continue;
		}
		nprocs--;
		TAILQ_REMOVE(&proc_map_head, pm, proc_glue);
		pthread_mutex_unlock(&map_mutex);
		free(pm);
		return;
        }
        pthread_mutex_unlock(&map_mutex);
}

static int
lookup_map_by_pid(pid_t pid)
{
	struct proc_map *pm;

	pthread_mutex_lock(&map_mutex);
	TAILQ_FOREACH(pm, &proc_map_head, proc_glue) {
		if (pm->proc_pid == pid) {
			pthread_mutex_unlock(&map_mutex);
			return (pm->proc_fd);
		}
	}
	pthread_mutex_unlock(&map_mutex);
	return (-1);
}

static pid_t
waitpid_all(pid_t pid, int *status, int options)
{
	struct kevent *kev, *kp;
	struct proc_map *pm;
	int kq, ret, k, ents;
	pid_t p;

	kq = kqueue();
	if (kq == -1) {
		return (-1);
	}
	ents = nprocs;
	kev = calloc(ents, sizeof(*kev));
	if (kev == NULL) {
		return (-1);
	}
	k = 0;
	pthread_mutex_lock(&map_mutex);
	TAILQ_FOREACH(pm, &proc_map_head, proc_glue) {
		kp = &kev[k++];
		EV_SET(kp, pm->proc_fd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT,
		    0, NULL);
		if (k == ents) {
			break;
		}
	}
	pthread_mutex_unlock(&map_mutex);
	ret = kevent(kq, kev, ents, NULL, 0, NULL);
	if (ret == -1) {
		return (-1);
	}
	while (1) {
		ret = kevent(kq, NULL, 0, kev, ents, NULL);
		if (ret == -1) {
			return (-1);
		}
		kp = &kev[0];
		p = lookup_map_by_fd(kp->ident);
		remove_map(p);
		*status = kev->data;
		break;
	}
	return (p);
}

pid_t
waitpid(pid_t pid, int *status, int options)
{
	struct kevent kev;
	int kq, ret, pidfd;

	if (pid == -1) {
		return (waitpid_all(pid, status, options));
	}
	kq = kqueue();
	if (kq == -1) {
		return (-1);
	}
	pidfd = lookup_map_by_pid(pid);
	if (pidfd == -1) {
		/*
		 * Do we need to return ESRCH here?
		 */
		errno = EINVAL;
		return (-1);
	}
	EV_SET(&kev, pidfd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
	ret = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (ret == -1) {
		return (-1);
	}
	while (1) {
		ret = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (ret == -1) {
			return (-1);
		}
		remove_map(pid);
		*status = kev.data;
		break;
	}
        return (pid);
}

pid_t
fork(void)
{
	struct proc_map *pm;
	pid_t pid;
	int fd;

	pm = calloc(1, sizeof(*pm));
	if (pm == NULL) {
		return (-1);
	}
	pid = pdfork(&fd, 0);
	if (pid == 0 || pid == -1) {
		free(pm);
		return (pid);
	}
	pm->proc_fd = fd;
	pm->proc_pid = pid;
	pthread_mutex_lock(&map_mutex);
	TAILQ_INSERT_HEAD(&proc_map_head, pm, proc_glue);
	nprocs++;
	pthread_mutex_unlock(&map_mutex);
	return (pid);
}

pid_t
vfork(void)
{

	return (fork());
}

int
kill(pid_t pid, int sig)
{
	int fd;

	fd = lookup_map_by_pid(pid);
	if (fd == -1) {
		errno = ESRCH;
		return (-1);
	}
	return (pdkill(fd, sig));
}

int
access(const char *path, int mode)
{
	int fd;

	if (*path == '/') {
		path++;
	}
	fd = sandbox_get_root_fd();
	if (fd == -1) {
		return (-1);
	}
	return (faccessat(fd, path, mode, 0));
}

int
eaccess(const char *path, int mode)
{
	int fd;

        if (*path == '/') {
                path++;
        }
	fd = sandbox_get_root_fd();
	if (fd == -1) {
		return (-1);
	}
	return (faccessat(fd, path, mode, 0));
}

int
stat(const char *path, struct stat *st)
{
	int fd;

        if (*path == '/') {
                path++;
        }
	fd = sandbox_get_root_fd();
	if (fd == -1) {
		return (-1);
	}
	return (fstatat(fd, path, st, AT_SYMLINK_NOFOLLOW));
}

int
lstat(const char *path, struct stat *st)
{
	int fd;

        if (*path == '/') {
                path++;
        }
	fd = sandbox_get_root_fd();
	if (fd == -1) {
		return (-1);
	}
	return (fstatat(fd, path, st, AT_SYMLINK_NOFOLLOW));
}

int
_open(const char *path, int flags, ...)
{
	va_list args;
	int fd, mode;

        if (*path == '/') {
                path++;
        }
	va_start(args, flags);
	mode = va_arg(args, int);
	fd = sandbox_get_root_fd();
	if (fd == -1) {
		return (-1);
	}
	return (openat(fd, path, flags, mode));
}

int
open(const char *path, int flags, ...)
{
	va_list args;
	int mode;

        if (*path == '/') {
                path++;
        }
	va_start(args, flags);
	mode = va_arg(args, int);
	return (_open(path, flags, mode));
}

pid_t
wait(int *status)
{

	return (waitpid(-1, status, 0));
}

pid_t
wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{

	return (waitpid(pid, status, options));
}
