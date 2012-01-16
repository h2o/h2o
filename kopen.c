#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#ifndef _WIN32
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#ifdef _WIN32
#define _KO_NO_NET
#endif

#ifndef _KO_NO_NET
static int socket_wait(int fd, int is_read)
{
	fd_set fds, *fdr = 0, *fdw = 0;
	struct timeval tv;
	int ret;
	tv.tv_sec = 5; tv.tv_usec = 0; // 5 seconds time out
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	if (is_read) fdr = &fds;
	else fdw = &fds;
	ret = select(fd+1, fdr, fdw, 0, &tv);
	if (ret == -1) perror("select");
	return ret;
}

static int socket_connect(const char *host, const char *port)
{
#define __err_connect(func) do { perror(func); freeaddrinfo(res); return -1; } while (0)

	int on = 1, fd;
	struct linger lng = { 0, 0 };
	struct addrinfo hints, *res = 0;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &res) != 0) __err_connect("getaddrinfo");
	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) __err_connect("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) __err_connect("setsockopt");
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lng, sizeof(lng)) == -1) __err_connect("setsockopt");
	if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) __err_connect("connect");
	freeaddrinfo(res);
	return fd;
#undef __err_connect
}

static int http_open(const char *fn)
{
	char *p, *proxy, *q, *http_host, *host, *port, *path, *buf;
	int fd, ret, l;

	/* parse URL; adapted from khttp_parse_url() in knetfile.c */
	if (strstr(fn, "http://") != fn) return 0;
	// set ->http_host
	for (p = (char*)fn + 7; *p && *p != '/'; ++p);
	l = p - fn - 7;
	http_host = calloc(l + 1, 1);
	strncpy(http_host, fn + 7, l);
	http_host[l] = 0;
	for (q = http_host; *q && *q != ':'; ++q);
	if (*q == ':') *q++ = 0;
	// get http_proxy
	proxy = getenv("http_proxy");
	// set host, port and path
	if (proxy == 0) {
		host = strdup(http_host); // when there is no proxy, server name is identical to http_host name.
		port = strdup(*q? q : "80");
		path = strdup(*p? p : "/");
	} else {
		host = (strstr(proxy, "http://") == proxy)? strdup(proxy + 7) : strdup(proxy);
		for (q = host; *q && *q != ':'; ++q);
		if (*q == ':') *q++ = 0; 
		port = strdup(*q? q : "80");
		path = strdup(fn);
	}

	/* connect; adapted from khttp_connect() in knetfile.c */
	l = 0;
	fd = socket_connect(host, port);
	buf = calloc(0x10000, 1); // FIXME: I am lazy... But in principle, 64KB should be large enough.
	l += sprintf(buf + l, "GET %s HTTP/1.0\r\nHost: %s\r\n", path, http_host);
	l += sprintf(buf + l, "\r\n");
	write(fd, buf, l);
	l = 0;
	while (read(fd, buf + l, 1)) { // read HTTP header; FIXME: bad efficiency
		if (buf[l] == '\n' && l >= 3)
			if (strncmp(buf + l - 3, "\r\n\r\n", 4) == 0) break;
		++l;
	}
	buf[l] = 0;
	if (l < 14) { // prematured header
		close(fd);
		fd = -1;
	}
	ret = strtol(buf + 8, &p, 0); // HTTP return code
	if (ret != 200) {
		close(fd);
		fd = -1;
	}
	free(buf); free(http_host); free(host); free(port); free(path);
	return fd;
}

typedef struct {
	int max_response, ctrl_fd;
	char *response;
} ftpaux_t;

static int kftp_get_response(ftpaux_t *aux)
{
	unsigned char c;
	int n = 0;
	char *p;
	if (socket_wait(aux->ctrl_fd, 1) <= 0) return 0;
	while (read(aux->ctrl_fd, &c, 1)) { // FIXME: this is *VERY BAD* for unbuffered I/O
		if (n >= aux->max_response) {
			aux->max_response = aux->max_response? aux->max_response<<1 : 256;
			aux->response = realloc(aux->response, aux->max_response);
		}
		aux->response[n++] = c;
		if (c == '\n') {
			if (n >= 4 && isdigit(aux->response[0]) && isdigit(aux->response[1]) && isdigit(aux->response[2])
				&& aux->response[3] != '-') break;
			n = 0;
			continue;
		}
	}
	if (n < 2) return -1;
	aux->response[n-2] = 0;
	return strtol(aux->response, &p, 0);
}

static int kftp_send_cmd(ftpaux_t *aux, const char *cmd, int is_get)
{
	if (socket_wait(aux->ctrl_fd, 0) <= 0) return -1; // socket is not ready for writing
	write(aux->ctrl_fd, cmd, strlen(cmd));
	return is_get? kftp_get_response(aux) : 0;
}

static int ftp_open(const char *fn)
{
	char *p, *host = 0, *port = 0, *retr = 0;
	char host2[80], port2[10];
	int v[6], l, fd = -1, ret, pasv_port, pasv_ip[4];
	ftpaux_t aux;
	
	/* parse URL */
	if (strstr(fn, "ftp://") != fn) return 0;
	for (p = (char*)fn + 6; *p && *p != '/'; ++p);
	if (*p != '/') return 0;
	l = p - fn - 6;
	port = strdup("21");
	host = calloc(l + 1, 1);
	strncpy(host, fn + 6, l);
	retr = calloc(strlen(p) + 8, 1);
	sprintf(retr, "RETR %s\r\n", p);
	
	/* connect to ctrl */
	memset(&aux, 0, sizeof(ftpaux_t));
	aux.ctrl_fd = socket_connect(host, port);
	if (aux.ctrl_fd == -1) goto ftp_open_end; /* fail to connect ctrl */

	/* connect to the data stream */
	kftp_get_response(&aux);
	kftp_send_cmd(&aux, "USER anonymous\r\n", 1);
	kftp_send_cmd(&aux, "PASS kopen@\r\n", 1);
	kftp_send_cmd(&aux, "TYPE I\r\n", 1);
	kftp_send_cmd(&aux, "PASV\r\n", 1);
	for (p = aux.response; *p && *p != '('; ++p);
	if (*p != '(') goto ftp_open_end;
	++p;
	sscanf(p, "%d,%d,%d,%d,%d,%d", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
	memcpy(pasv_ip, v, 4 * sizeof(int));
	pasv_port = (v[4]<<8&0xff00) + v[5];
	kftp_send_cmd(&aux, retr, 0);
	sprintf(host2, "%d.%d.%d.%d", pasv_ip[0], pasv_ip[1], pasv_ip[2], pasv_ip[3]);
	sprintf(port2, "%d", pasv_port);
	fd = socket_connect(host2, port2);
	if (fd == -1) goto ftp_open_end;
	ret = kftp_get_response(&aux);
	if (ret != 150) {
		close(fd);
		fd = -1;
	}
	close(aux.ctrl_fd);

ftp_open_end:
	free(host); free(port); free(retr); free(aux.response);
	return fd;
}
#endif /* !defined(_KO_NO_NET) */

static char **cmd2argv(const char *cmd)
{
	int i, beg, end, argc;
	char **argv, *p, *q, *str;
	end = strlen(cmd);
	for (i = end - 1; i >= 0; --i)
		if (!isspace(cmd[i])) break;
	end = i + 1;
	for (beg = 0; beg < end; ++beg)
		if (!isspace(cmd[beg])) break;
	if (beg == end) return 0;
	for (i = beg + 1, argc = 0; i < end; ++i)
		if (isspace(cmd[i]) && !isspace(cmd[i-1]))
			++argc;
	argv = (char**)calloc(argc + 2, sizeof(void*));
	argv[0] = str = (char*)calloc(end - beg + 1, 1);
	strncpy(argv[0], cmd + beg, end - beg);
	for (i = argc = 1, q = p = str; i < end - beg; ++i)
		if (isspace(str[i])) str[i] = 0;
		else if (str[i] && str[i-1] == 0) argv[argc++] = &str[i];
	return argv;
}

#define KO_STDIN    1
#define KO_FILE     2
#define KO_PIPE     3
#define KO_HTTP     4
#define KO_FTP      5

typedef struct {
	int type, fd;
	pid_t pid;
} koaux_t;

void *kopen(const char *fn, int *_fd)
{
	koaux_t *aux = 0;
	*_fd = -1;
	if (strstr(fn, "http://") == fn) {
		aux = calloc(1, sizeof(koaux_t));
		aux->type = KO_HTTP;
		aux->fd = http_open(fn);
	} else if (strstr(fn, "ftp://") == fn) {
		aux = calloc(1, sizeof(koaux_t));
		aux->type = KO_FTP;
		aux->fd = ftp_open(fn);
	} else if (strcmp(fn, "-") == 0) {
		aux = calloc(1, sizeof(koaux_t));
		aux->type = KO_STDIN;
		aux->fd = STDIN_FILENO;
	} else {
		const char *p;
		for (p = fn; *p; ++p)
			if (!isspace(*p)) break;
		if (*p == '<') { // pipe open
			int pfd[2];
			pid_t pid;
			pipe(pfd);
			pid = vfork();
			if (pid == -1) { /* vfork() error */
				close(pfd[0]); close(pfd[1]);
				return 0;
			}
			if (pid == 0) { /* the child process */
				char **argv; /* FIXME: I do not know if this will lead to a memory leak */
				close(pfd[0]);
				dup2(pfd[1], STDOUT_FILENO);
				close(pfd[1]);
				argv = cmd2argv(p + 1);
				execvp(argv[0], argv);
				free(argv[0]); free(argv);
				exit(1);
			} else { /* parent process */
				close(pfd[1]);
				aux = calloc(1, sizeof(koaux_t));
				aux->type = KO_PIPE;
				aux->fd = pfd[0];
				aux->pid = pid;
			}
		} else {
#ifdef _WIN32
			*_fd = open(fn, O_RDONLY | O_BINARY);
#else
			*_fd = open(fn, O_RDONLY);
#endif
			if (*_fd) {
				aux = calloc(1, sizeof(koaux_t));
				aux->type = KO_FILE;
				aux->fd = *_fd;
			}
		}
	}
	*_fd = aux->fd;
	return aux;
}

int kclose(void *a)
{
	koaux_t *aux = (koaux_t*)a;
	if (aux->type == KO_PIPE) {
		int status;
		pid_t pid;
		pid = waitpid(aux->pid, &status, WNOHANG);
		if (pid != aux->pid) kill(aux->pid, 15);
	}
	return 0;
}

#ifdef _KO_MAIN
#define BUF_SIZE 0x10000
int main(int argc, char *argv[])
{
	void *x;
	int l, fd;
	unsigned char buf[BUF_SIZE];
	FILE *fp;
	if (argc == 1) {
		fprintf(stderr, "Usage: kopen <file>\n");
		return 1;
	}
	x = kopen(argv[1], &fd);
	fp = fdopen(fd, "r");
	if (fp == 0) {
		fprintf(stderr, "ERROR: fail to open the input\n");
		return 1;
	}
	do {
		if ((l = fread(buf, 1, BUF_SIZE, fp)) != 0)
			fwrite(buf, 1, l, stdout);
	} while (l == BUF_SIZE);
	fclose(fp);
	kclose(x);
	return 0;
}
#endif
