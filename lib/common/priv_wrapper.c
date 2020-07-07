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
#include <sys/wait.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <err.h>

#include "h2o.h"
#include "h2o/privsep.h"

static int privsep_state = PRIVSEP_STATE_OFF;

int h2o_priv_active(void)
{

    return (privsep_state == PRIVSEP_STATE_ACTIVE);
}

FILE *h2o_priv_fopen(const char * restrict path, const char * restrict mode)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_fopen(path, mode));
        break;
    case PRIVSEP_STATE_OFF:
        return (fopen(path, mode));
        break;
    }
    return (NULL);
}

void h2o_priv_localtime_cleanup(struct tm *result)
{

    /* NB: storage for the timezone data */
}

void h2o_priv_gmtime_cleanup(struct tm *result)
{

    /* NB: storage for the timezone data */
}

struct tm *h2o_priv_localtime_r(const time_t *clock, struct tm *result)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_dotime_r(clock, result, PRIV_LOCALTIME));
        break;
    case PRIVSEP_STATE_OFF:
        return (localtime_r(clock, result));
        break;
    default:
        abort();
    }
    return (NULL);
}

struct tm *h2o_priv_gmtime_r(const time_t *clock, struct tm *result)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_dotime_r(clock, result, PRIV_GMTIME));
        break;
    case PRIVSEP_STATE_OFF:
        return (gmtime_r(clock, result));
        break;
    default:
        abort();
    }
    return (NULL);
}

char **h2o_priv_init_fastcgi(char *sock_dir, char *spawn_user,
    char *spawn_cmd)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_init_fastcgi(sock_dir, spawn_user, spawn_cmd));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_init_fastcgi(sock_dir, spawn_user, spawn_cmd));
        break;
    default:
        abort();
    }
    return (NULL);
}

char **h2o_priv_gen_env(void)
{
    extern char **environ;
    size_t num;

    /* calculate number of envvars, as well as looking for H2O_ROOT= */
    for (num = 0; environ[num] != NULL; ++num)
        if (strncmp(environ[num], "H2O_ROOT=", sizeof("H2O_ROOT=") - 1) == 0)
            return (NULL);
    /* not found */
    char **newenv = h2o_mem_alloc(sizeof(*newenv) * (num + 2) + sizeof("H2O_ROOT=" H2O_TO_STR(H2O_ROOT)));
    memcpy(newenv, environ, sizeof(*newenv) * num);
    newenv[num] = (char *)(newenv + num + 2);
    newenv[num + 1] = NULL;
    strcpy(newenv[num], "H2O_ROOT=" H2O_TO_STR(H2O_ROOT));
    return (newenv);
}

pid_t h2o_priv_waitpid(pid_t pid, int *stat_loc, int options)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_waitpid(pid, stat_loc, options));
        break;
    case PRIVSEP_STATE_OFF:
        return (waitpid(pid, stat_loc, options));
        break;
    default:
        abort();
    }
}

pid_t h2o_priv_exec(h2o_exec_context_t *ec, const char *cmd,
  char *const argv[], int policy)
{
    char **env;

    env = h2o_priv_gen_env();
    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_exec(ec, cmd, argv, env, policy));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_exec(ec, cmd, argv, env, policy));
        break;
    default:
        abort();
    }
    /* NB: need to know whether h2o_priv_gen_env allocated a new env */
}

void h2o_priv_cleanup_exec_context(h2o_exec_context_t *ec)
{

    assert(ec->fdmaps != NULL);
    free(ec->fdmaps);
}

void h2o_priv_bind_fd(h2o_exec_context_t *ec, int from, int to, int type)
{
    h2o_fd_mapping_t *map;

    if (ec->maps_alloc == 0) {
        ec->fdmaps = calloc(4, sizeof(h2o_fd_mapping_t));
        ec->maps_alloc = 4;
    } else if (ec->maps_used == ec->maps_alloc) {
        ec->maps_alloc += 2;
        ec->fdmaps = realloc(ec->fdmaps,
            ec->maps_alloc * sizeof(h2o_fd_mapping_t));
    }
    assert(ec != NULL);
    assert(from >= 0);
    assert(to >= 0);
    map = &ec->fdmaps[ec->maps_used++];
    map->from = from;
    map->to = to;
    map->type = type;
}

void h2o_priv_init_exec_context(h2o_exec_context_t *ec)
{

    assert(ec != NULL);
    ec->maps_alloc = 0;
    ec->maps_used = 0;
    ec->fdmaps = NULL;
}

/*
 * The privsep constructed addrinfo structures use a bit more heap storage than
 * the libc versions. As a result, the the privsep constructed addrinfo needs
 * it's own destuctor, as using freeaddrinfo(3) will miss the socket addr
 * storage.
 */
void h2o_priv_freeaddrinfo(struct addrinfo *ai)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        h2o_privsep_freeaddrinfo(ai);
        break;
    case PRIVSEP_STATE_OFF:
        freeaddrinfo(ai);
        break;
    default:
        abort();
    }
}

void h2o_priv_sandbox_hints(char *root)
{

    h2o_privsep_sandbox_hints(root);
}

/*
 * We are currently using sendmsg(2) to transmit H3 UDP packets. Because of the
 * arbitrary connectionless peer specification, it has been considered a
 * dangerous syscall. We need to implement a privilege for it.
 */
ssize_t h2o_priv_sendmsg(int sock, struct msghdr *msg, int flags)
{

    /*
     * NB: depending on the operating system, we may allow sendmsg() in
     * sandbox mode. We need a flag that is specified to control whether
     * or not we want to use the privsep version of this function.
     */
    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_sendmsg(sock, msg, flags));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_sendmsg(sock, msg, flags));
        break;
    default:
        abort();
    }
}

/*
 * We need to define a privilege to setup listeners. This is primarily for the
 * H2O_HTTP3_USE_REUSEPORT case in the run_loop when the sandbox has been bound
 * to the thread.
 */
int h2o_priv_open_listener(int domain, int type, int protocol,
  struct sockaddr_storage *addr, socklen_t addrlen, int reuseport)
{
    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_open_listener(domain, type, protocol, addr,
          addrlen, reuseport));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_open_listener(domain, type, protocol, addr,
          addrlen, reuseport));
        break;
    default:
        abort();
    }
}

int h2o_priv_init(h2o_globalconf_t *gcp)
{

    assert(privsep_state == PRIVSEP_STATE_OFF);
    if (gcp->privsep_dir == NULL) {
        privsep_state = PRIVSEP_STATE_OFF;
        h2o_allpriv_init(gcp);
        return (0);
    }
    privsep_state = PRIVSEP_STATE_ACTIVE;
    return (h2o_privsep_init(gcp));
}

void h2o_priv_bind_sandbox(int policy)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        h2o_privsep_bind_sandbox(policy);
        break;
    case PRIVSEP_STATE_OFF:
        h2o_allpriv_bind_sandbox(policy);
        break;
    default:
        abort();
    }
}

void h2o_priv_set_neverbleed_path(const char *path)
{
    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        h2o_privsep_set_neverbleed_path(path);
        break;
    case PRIVSEP_STATE_OFF:
        break;
    default:
        abort();
    }
}

int h2o_priv_get_neverbleed_sock(struct sockaddr_un *sun)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_get_neverbleed_sock());
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_get_neverbleed_sock(sun));
        break;
    default:
        abort();
    }
    /* NOTREACHED */
    return (-1);
}

int h2o_priv_open(const char *path, int flag, ...)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_open(path, flag, 0));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_open(path, flag, 0));
        break;
    default:
        abort();
    }
    /* NOTREACHED */
    return (-1);
}

int h2o_priv_getaddrinfo(const char *host, const char *servname,
  const struct addrinfo *hints, struct addrinfo **res)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_getaddrinfo(host, servname, hints, res));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_getaddrinfo(host, servname, hints, res));
        break;
    default:
        abort();
    }
    /* NOTREACHED */
    return (-1);

}

int h2o_priv_connect_sock_noblock(struct sockaddr_storage *sas,
  int *sock_ret, int *connect_ret)
{

    assert(privsep_state != 0);
    switch (privsep_state) {
    case PRIVSEP_STATE_ACTIVE:
        return (h2o_privsep_connect_sock_noblock(sas, sock_ret, connect_ret));
        break;
    case PRIVSEP_STATE_OFF:
        return (h2o_allpriv_connect_sock_noblock(sas, sock_ret, connect_ret));
        break;
    default:
        abort();
    }
    /* NOTREACHED */
    return (-1);
}
