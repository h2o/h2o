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
#ifndef PRIVSEP_DOT_H_
#define PRIVSEP_DOT_H_
#include <sys/types.h>
#include <pwd.h>

#include "h2o.h"

#define H2O_CMD_BUF 1024
#define H2O_TZ_BUF  32

struct h2o_privsep_waitpid {
    pid_t               pid;
    int                 options;
};
typedef struct h2o_privsep_waitpid h2o_privsep_waitpid_t;

struct h2o_fd_mapping {
    int     type;
#define H2O_FDMAP_WRITE_TO_PROC     1
#define H2O_FDMAP_READ_FROM_PROC    2
#define H2O_FDMAP_SEND_TO_PROC      3
#define H2O_FDMAP_BASIC             4
    int     from;
    int     to;
    int     pipefds[2];
};
typedef struct h2o_fd_mapping h2o_fd_mapping_t;

struct h2o_exec_context {
    struct h2o_fd_mapping   *fdmaps;
    int                      maps_alloc;
    int                      maps_used;
};
typedef struct h2o_exec_context h2o_exec_context_t;

struct h2o_privsep_sendmsg {
    size_t              msg_namelen;
    size_t              msg_iovlen;
    size_t              msg_controllen;
    int                 flags;
};
typedef struct h2o_privsep_sendmsg h2o_privsep_sendmsg_t;

struct h2o_privsep_open_listener {
    int                         domain;
    int                         type;
    int                         protocol;
    struct sockaddr_storage     sas;
    socklen_t                   addrlen;
    int                         reuseport;
};
typedef struct h2o_privsep_open_listener h2o_privsep_open_listener_t;

struct h2o_privsep_socket_worker {
    h2o_globalconf_t    *gcp;
    int                  sock;
};
typedef struct h2o_privsep_socket_worker h2o_privsep_socket_worker_t;

struct privsep_worker {
    pthread_t            thr;
    int                  sock;
    h2o_globalconf_t    *gcp;
};

typedef struct privsep_worker privsep_worker_t;

int     privsep_init(h2o_globalconf_t *);
int     privsep_set_neverbleed_path(const char *);
void    privsep_bind_sandbox(int);


struct h2o_privsep_neverbleed_path {
    char                    path[512];
};
typedef struct h2o_privsep_neverbleed_path h2o_privsep_neverbleed_path_t;

struct h2o_privsep_open {
    char                    path[512];
    int                     flags;
    mode_t                  mode;
};
typedef struct h2o_privsep_open h2o_privsep_open_t;

struct h2o_privsep_getaddrinfo {
    char                    hostname[256];
    char                    servname[256];
    struct addrinfo         hints;
};
typedef struct h2o_privsep_getaddrinfo h2o_privsep_getaddrinfo_t;

struct h2o_privsep_getaddrinfo_result {
    int                     ai_flags;
	int                     ai_family;
	int                     ai_socktype;
	int                     ai_protocol;
	socklen_t               ai_addrlen;
	struct sockaddr_storage sas;
	char                    ai_canonname[256];
};
typedef struct h2o_privsep_getaddrinfo_result h2o_privsep_getaddrinfo_result_t;

struct h2o_privsep {
    int     ps_sock;
};
typedef struct h2o_privsep h2o_privsep_t;

#define PRIVSEP_STATE_ACTIVE    1
#define PRIVSEP_STATE_OFF       2

/*
 * Define a set of privsep features. These flags will control OS specific
 * aspects of the sandboxing operations.
 */
#define SANDBOX_ALLOWS_SENDMSG  0x0000000000000001
#define PRIVSEP_PRIVILEGED      0x0000000000000002
#define PRIVSEP_NON_PRIVILEGED  0x0000000000000004

enum {
    SANDBOX_POLICY_NONE,
    SANDBOX_POLICY_NEVERBLEED,
    SANDBOX_POLICY_H2OMAIN
};

enum {
    PRIV_NONE,
    PRIV_OPEN,
    PRIV_PRIVSEP_SOCK,
    PRIV_NEVERBLEED_SOCK,
    PRIV_SET_NEVERBLEED_PATH,
    PRIV_GETADDRINFO,
    PRIV_CONNECT,
    PRIV_DROP_PRIVS,
    PRIV_OPEN_LISTENER,
    PRIV_SENDMSG,
    PRIV_FD_MAPPED_EXEC,
    PRIV_WAITPID,
    PRIV_GMTIME,
    PRIV_LOCALTIME
};

/*
 * Wrapper functions for privsep/regular mode.
 */
int              h2o_priv_active(void);
int              h2o_priv_init(h2o_globalconf_t *);
void             h2o_priv_bind_sandbox(int);
int              h2o_priv_get_neverbleed_sock(struct sockaddr_un *);
int              h2o_priv_open(const char *, int, ...);
int              h2o_priv_getaddrinfo(const char *, const char *,
                   const struct addrinfo *, struct addrinfo **);
int              h2o_priv_connect_sock_noblock(struct sockaddr_storage *, int *, int *);
void             h2o_priv_set_neverbleed_path(const char *);
int              h2o_priv_open_listener(int, int, int, struct sockaddr_storage *,
                   socklen_t, int);
ssize_t          h2o_priv_sendmsg(int, struct msghdr *, int);
void             h2o_priv_freeaddrinfo(struct addrinfo *);
void             h2o_priv_init_exec_context(h2o_exec_context_t *);
void             h2o_priv_cleanup_exec_context(h2o_exec_context_t *);
void             h2o_priv_bind_fd(h2o_exec_context_t *, int, int, int);
pid_t            h2o_priv_exec(h2o_exec_context_t *, const char *, char *const [], int);
pid_t            h2o_priv_waitpid(pid_t, int *, int);
void             h2o_priv_sandbox_hints(char *);
char **          h2o_priv_gen_env(void);
struct tm *      h2o_priv_gmtime_r(const time_t *, struct tm *);
void             h2o_priv_gmtime_cleanup(struct tm *);
struct tm *      h2o_priv_localtime_r(const time_t *, struct tm *);
void             h2o_priv_localtime_cleanup(struct tm *);
FILE *           h2o_priv_fopen(const char * restrict, const char * restrict);
/*
 * All privilege operation prototypes
 */
void             h2o_allpriv_bind_sandbox(int);
int              h2o_allpriv_get_neverbleed_sock(struct sockaddr_un *);
int              h2o_allpriv_open(const char *, int, ...);
int              h2o_allpriv_getaddrinfo(const char *, const char *,
                   const struct addrinfo *, struct addrinfo **);
int              h2o_allpriv_connect_sock_noblock(struct sockaddr_storage *, int *, int *);
int              h2o_allpriv_init(h2o_globalconf_t *);
int              h2o_allpriv_open_listener(int, int, int, struct sockaddr_storage *,
                  socklen_t, int);
ssize_t          h2o_allpriv_sendmsg(int, struct msghdr *, int);
pid_t            h2o_allpriv_exec(h2o_exec_context_t *, const char *, char *const [],
                   char **, int);
/*
 * Privsep operation prototypes
 */
FILE            *h2o_privsep_fopen(const char * restrict,
                   const char * restrict);
struct tm *      h2o_privsep_dotime_r(const time_t *, struct tm *, int);
pid_t            h2o_privsep_waitpid(pid_t, int *, int);
void             h2o_privsep_bind_sandbox(int);
int              h2o_privsep_init(h2o_globalconf_t *);
int              h2o_privsep_activate(void);
int              h2o_privsep_may_read(int, void *, size_t);
void             h2o_privsep_must_readv(int, const struct iovec *, int);
void             h2o_privsep_must_writev(int, const struct iovec *, int);
void             h2o_privsep_must_read(int, void *, size_t);
void             h2o_privsep_must_write(int, void *, size_t);
void             h2o_privsep_send_fd(int, int);
int              h2o_privsep_receive_fd(int);
h2o_privsep_t   *h2o_get_tsd(void);
int              h2o_privsep_set_global_sock(int);
int              h2o_privsep_open(const char *, int, ...);
int              h2o_privsep_get_neverbleed_sock(void);
void             h2o_privsep_set_neverbleed_path(const char *);
int              h2o_privsep_getaddrinfo(const char *, const char *,
                   const struct addrinfo *, struct addrinfo **);
int              h2o_privsep_connect_sock_noblock(struct sockaddr_storage *,
                   int *, int *);
int              h2o_privsep_drop_privs(void);
void             h2o_privsep_event_loop(h2o_globalconf_t *, int, int);
int              h2o_privsep_open_listener(int, int, int,
                   struct sockaddr_storage *, socklen_t, int);
ssize_t          h2o_privsep_sendmsg(int, struct msghdr *, int);
void             h2o_privsep_freeaddrinfo(struct addrinfo *);
pid_t            h2o_privsep_exec(h2o_exec_context_t *, const char *,
                   char *const [],
                   char **, int);
char            *h2o_privsep_marshal_vec(char *const [], size_t *);
char            **h2o_privsep_unmarshal_vec(char *, size_t);
void             h2o_privsep_sandbox_hints(char *);
FILE *           h2o_privsep_fopen(const char * restrict,
                   const char * restrict);

void             sandbox_bind_linux(int);
void             sandbox_bind_freebsd(int);
void             sandbox_emit_linux_hints(char *);
void             sandbox_emit_freebsd_hints(char *);

#endif /* PRIVSEP_DOT_H_ */
