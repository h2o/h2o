/* The MIT License

   Copyright (c) 2008 by Genome Research Ltd (GRL).
                 2010 by Attractive Chaos <attractor@live.co.uk>

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

/* Probably I will not do socket programming in the next few years and
   therefore I decide to heavily annotate this file, for Linux and
   Windows as well.  -ac */

#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef _WIN32
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include "knetfile.h"

/* In winsock.h, the type of a socket is SOCKET, which is: "typedef
 * u_int SOCKET". An invalid SOCKET is: "(SOCKET)(~0)", or signed
 * integer -1. In knetfile.c, I use "int" for socket type
 * throughout. This should be improved to avoid confusion.
 *
 * In Linux/Mac, recv() and read() do almost the same thing. You can see
 * in the header file that netread() is simply an alias of read(). In
 * Windows, however, they are different and using recv() is mandatory.
 */

/* This function tests if the file handler is ready for reading (or
 * writing if is_read==0). */
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
#ifndef _WIN32
	if (ret == -1) perror("select");
#else
	if (ret == 0)
		fprintf(stderr, "select time-out\n");
	else if (ret == SOCKET_ERROR)
		fprintf(stderr, "select: %d\n", WSAGetLastError());
#endif
	return ret;
}

#ifndef _WIN32
/* This function does not work with Windows due to the lack of
 * getaddrinfo() in winsock. It is addapted from an example in "Beej's
 * Guide to Network Programming" (http://beej.us/guide/bgnet/). */
static int socket_connect(const char *host, const char *port)
{
#define __err_connect(func) do { perror(func); freeaddrinfo(res); return -1; } while (0)

	int on = 1, fd;
	struct linger lng = { 0, 0 };
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	/* In Unix/Mac, getaddrinfo() is the most convenient way to get
	 * server information. */
	if (getaddrinfo(host, port, &hints, &res) != 0) __err_connect("getaddrinfo");
	if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) __err_connect("socket");
	/* The following two setsockopt() are used by ftplib
	 * (http://nbpfaus.net/~pfau/ftplib/). I am not sure if they
	 * necessary. */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) __err_connect("setsockopt");
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lng, sizeof(lng)) == -1) __err_connect("setsockopt");
	if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) __err_connect("connect");
	freeaddrinfo(res);
	return fd;
}
#else
/* MinGW's printf has problem with "%lld" */
char *int64tostr(char *buf, int64_t x)
{
	int cnt;
	int i = 0;
	do {
		buf[i++] = '0' + x % 10;
		x /= 10;
	} while (x);
	buf[i] = 0;
	for (cnt = i, i = 0; i < cnt/2; ++i) {
		int c = buf[i]; buf[i] = buf[cnt-i-1]; buf[cnt-i-1] = c;
	}
	return buf;
}

int64_t strtoint64(const char *buf)
{
	int64_t x;
	for (x = 0; *buf != '\0'; ++buf)
		x = x * 10 + ((int64_t) *buf - 48);
	return x;
}
/* In windows, the first thing is to establish the TCP connection. */
int knet_win32_init()
{
	WSADATA wsaData;
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
}
void knet_win32_destroy()
{
	WSACleanup();
}
/* A slightly modfied version of the following function also works on
 * Mac (and presummably Linux). However, this function is not stable on
 * my Mac. It sometimes works fine but sometimes does not. Therefore for
 * non-Windows OS, I do not use this one. */
static SOCKET socket_connect(const char *host, const char *port)
{
#define __err_connect(func)										\
	do {														\
		fprintf(stderr, "%s: %d\n", func, WSAGetLastError());	\
		return -1;												\
	} while (0)

	int on = 1;
	SOCKET fd;
	struct linger lng = { 0, 0 };
	struct sockaddr_in server;
	struct hostent *hp = 0;
	// open socket
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) __err_connect("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)) == -1) __err_connect("setsockopt");
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&lng, sizeof(lng)) == -1) __err_connect("setsockopt");
	// get host info
	if (isalpha(host[0])) hp = gethostbyname(host);
	else {
		struct in_addr addr;
		addr.s_addr = inet_addr(host);
		hp = gethostbyaddr((char*)&addr, 4, AF_INET);
	}
	if (hp == 0) __err_connect("gethost");
	// connect
	server.sin_addr.s_addr = *((unsigned long*)hp->h_addr);
	server.sin_family= AF_INET;
	server.sin_port = htons(atoi(port));
	if (connect(fd, (struct sockaddr*)&server, sizeof(server)) != 0) __err_connect("connect");
	// freehostent(hp); // strangely in MSDN, hp is NOT freed (memory leak?!)
	return fd;
}
#endif

static off_t my_netread(int fd, void *buf, off_t len)
{
	off_t rest = len, curr, l = 0;
	/* recv() and read() may not read the required length of data with
	 * one call. They have to be called repeatedly. */
	while (rest) {
		if (socket_wait(fd, 1) <= 0) break; // socket is not ready for reading
		curr = netread(fd, buf + l, rest);
		/* According to the glibc manual, section 13.2, a zero returned
		 * value indicates end-of-file (EOF), which should mean that
		 * read() will not return zero if EOF has not been met but data
		 * are not immediately available. */
		if (curr == 0) break;
		l += curr; rest -= curr;
	}
	return l;
}

/*************************
 * FTP specific routines *
 *************************/

static int kftp_get_response(knetFile *ftp)
{
#ifndef _WIN32
	unsigned char c;
#else
	char c;
#endif
	int n = 0;
	char *p;
	if (socket_wait(ftp->ctrl_fd, 1) <= 0) return 0;
	while (netread(ftp->ctrl_fd, &c, 1)) { // FIXME: this is *VERY BAD* for unbuffered I/O
		//fputc(c, stderr);
		if (n >= ftp->max_response) {
			ftp->max_response = ftp->max_response? ftp->max_response<<1 : 256;
			ftp->response = realloc(ftp->response, ftp->max_response);
		}
		ftp->response[n++] = c;
		if (c == '\n') {
			if (n >= 4 && isdigit(ftp->response[0]) && isdigit(ftp->response[1]) && isdigit(ftp->response[2])
				&& ftp->response[3] != '-') break;
			n = 0;
			continue;
		}
	}
	if (n < 2) return -1;
	ftp->response[n-2] = 0;
	return strtol(ftp->response, &p, 0);
}

static int kftp_send_cmd(knetFile *ftp, const char *cmd, int is_get)
{
	if (socket_wait(ftp->ctrl_fd, 0) <= 0) return -1; // socket is not ready for writing
	netwrite(ftp->ctrl_fd, cmd, strlen(cmd));
	return is_get? kftp_get_response(ftp) : 0;
}

static int kftp_pasv_prep(knetFile *ftp)
{
	char *p;
	int v[6];
	kftp_send_cmd(ftp, "PASV\r\n", 1);
	for (p = ftp->response; *p && *p != '('; ++p);
	if (*p != '(') return -1;
	++p;
	sscanf(p, "%d,%d,%d,%d,%d,%d", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
	memcpy(ftp->pasv_ip, v, 4 * sizeof(int));
	ftp->pasv_port = (v[4]<<8&0xff00) + v[5];
	return 0;
}


static int kftp_pasv_connect(knetFile *ftp)
{
	char host[80], port[10];
	if (ftp->pasv_port == 0) {
		fprintf(stderr, "[kftp_pasv_connect] kftp_pasv_prep() is not called before hand.\n");
		return -1;
	}
	sprintf(host, "%d.%d.%d.%d", ftp->pasv_ip[0], ftp->pasv_ip[1], ftp->pasv_ip[2], ftp->pasv_ip[3]);
	sprintf(port, "%d", ftp->pasv_port);
	ftp->fd = socket_connect(host, port);
	if (ftp->fd == -1) return -1;
	return 0;
}

int kftp_connect(knetFile *ftp)
{
	ftp->ctrl_fd = socket_connect(ftp->host, ftp->port);
	if (ftp->ctrl_fd == -1) return -1;
	kftp_get_response(ftp);
	kftp_send_cmd(ftp, "USER anonymous\r\n", 1);
	kftp_send_cmd(ftp, "PASS kftp@\r\n", 1);
	kftp_send_cmd(ftp, "TYPE I\r\n", 1);
	return 0;
}

int kftp_reconnect(knetFile *ftp)
{
	if (ftp->ctrl_fd != -1) {
		netclose(ftp->ctrl_fd);
		ftp->ctrl_fd = -1;
	}
	netclose(ftp->fd);
	ftp->fd = -1;
	return kftp_connect(ftp);
}

// initialize ->type, ->host, ->retr and ->size
knetFile *kftp_parse_url(const char *fn, const char *mode)
{
	knetFile *fp;
	char *p;
	int l;
	if (strstr(fn, "ftp://") != fn) return 0;
	for (p = (char*)fn + 6; *p && *p != '/'; ++p);
	if (*p != '/') return 0;
	l = p - fn - 6;
	fp = calloc(1, sizeof(knetFile));
	fp->type = KNF_TYPE_FTP;
	fp->fd = -1;
	/* the Linux/Mac version of socket_connect() also recognizes a port
	 * like "ftp", but the Windows version does not. */
	fp->port = strdup("21");
	fp->host = calloc(l + 1, 1);
	if (strchr(mode, 'c')) fp->no_reconnect = 1;
	strncpy(fp->host, fn + 6, l);
	fp->retr = calloc(strlen(p) + 8, 1);
	sprintf(fp->retr, "RETR %s\r\n", p);
    fp->size_cmd = calloc(strlen(p) + 8, 1);
    sprintf(fp->size_cmd, "SIZE %s\r\n", p);
	fp->seek_offset = 0;
	return fp;
}
// place ->fd at offset off
int kftp_connect_file(knetFile *fp)
{
	int ret;
	long long file_size;
	if (fp->fd != -1) {
		netclose(fp->fd);
		if (fp->no_reconnect) kftp_get_response(fp);
	}
	kftp_pasv_prep(fp);
    kftp_send_cmd(fp, fp->size_cmd, 1);
#ifndef _WIN32
    if ( sscanf(fp->response,"%*d %lld", &file_size) != 1 )
    {
        fprintf(stderr,"[kftp_connect_file] %s\n", fp->response);
        return -1;
    }
#else
	const char *p = fp->response;
	while (*p != ' ') ++p;
	while (*p < '0' || *p > '9') ++p;
	file_size = strtoint64(p);
#endif
	fp->file_size = file_size;
	if (fp->offset>=0) {
		char tmp[32];
#ifndef _WIN32
		sprintf(tmp, "REST %lld\r\n", (long long)fp->offset);
#else
		strcpy(tmp, "REST ");
		int64tostr(tmp + 5, fp->offset);
		strcat(tmp, "\r\n");
#endif
		kftp_send_cmd(fp, tmp, 1);
	}
	kftp_send_cmd(fp, fp->retr, 0);
	kftp_pasv_connect(fp);
	ret = kftp_get_response(fp);
	if (ret != 150) {
		fprintf(stderr, "[kftp_connect_file] %s\n", fp->response);
		netclose(fp->fd);
		fp->fd = -1;
		return -1;
	}
	fp->is_ready = 1;
	return 0;
}


/**************************
 * HTTP specific routines *
 **************************/

knetFile *khttp_parse_url(const char *fn, const char *mode)
{
	knetFile *fp;
	char *p, *proxy, *q;
	int l;
	if (strstr(fn, "http://") != fn) return 0;
	// set ->http_host
	for (p = (char*)fn + 7; *p && *p != '/'; ++p);
	l = p - fn - 7;
	fp = calloc(1, sizeof(knetFile));
	fp->http_host = calloc(l + 1, 1);
	strncpy(fp->http_host, fn + 7, l);
	fp->http_host[l] = 0;
	for (q = fp->http_host; *q && *q != ':'; ++q);
	if (*q == ':') *q++ = 0;
	// get http_proxy
	proxy = getenv("http_proxy");
	// set ->host, ->port and ->path
	if (proxy == 0) {
		fp->host = strdup(fp->http_host); // when there is no proxy, server name is identical to http_host name.
		fp->port = strdup(*q? q : "80");
		fp->path = strdup(*p? p : "/");
	} else {
		fp->host = (strstr(proxy, "http://") == proxy)? strdup(proxy + 7) : strdup(proxy);
		for (q = fp->host; *q && *q != ':'; ++q);
		if (*q == ':') *q++ = 0; 
		fp->port = strdup(*q? q : "80");
		fp->path = strdup(fn);
	}
	fp->type = KNF_TYPE_HTTP;
	fp->ctrl_fd = fp->fd = -1;
	fp->seek_offset = 0;
	return fp;
}

int khttp_connect_file(knetFile *fp)
{
	int ret, l = 0;
	char *buf, *p;
	if (fp->fd != -1) netclose(fp->fd);
	fp->fd = socket_connect(fp->host, fp->port);
	buf = calloc(0x10000, 1); // FIXME: I am lazy... But in principle, 64KB should be large enough.
	l += sprintf(buf + l, "GET %s HTTP/1.0\r\nHost: %s\r\n", fp->path, fp->http_host);
    l += sprintf(buf + l, "Range: bytes=%lld-\r\n", (long long)fp->offset);
	l += sprintf(buf + l, "\r\n");
	netwrite(fp->fd, buf, l);
	l = 0;
	while (netread(fp->fd, buf + l, 1)) { // read HTTP header; FIXME: bad efficiency
		if (buf[l] == '\n' && l >= 3)
			if (strncmp(buf + l - 3, "\r\n\r\n", 4) == 0) break;
		++l;
	}
	buf[l] = 0;
	if (l < 14) { // prematured header
		netclose(fp->fd);
		fp->fd = -1;
		return -1;
	}
	ret = strtol(buf + 8, &p, 0); // HTTP return code
	if (ret == 200 && fp->offset>0) { // 200 (complete result); then skip beginning of the file
		off_t rest = fp->offset;
		while (rest) {
			off_t l = rest < 0x10000? rest : 0x10000;
			rest -= my_netread(fp->fd, buf, l);
		}
	} else if (ret != 206 && ret != 200) {
		free(buf);
		fprintf(stderr, "[khttp_connect_file] fail to open file (HTTP code: %d).\n", ret);
		netclose(fp->fd);
		fp->fd = -1;
		return -1;
	}
	free(buf);
	fp->is_ready = 1;
	return 0;
}

/********************
 * Generic routines *
 ********************/

knetFile *knet_open(const char *fn, const char *mode)
{
	knetFile *fp = 0;
	if (mode[0] != 'r') {
		fprintf(stderr, "[kftp_open] only mode \"r\" is supported.\n");
		return 0;
	}
	if (strstr(fn, "ftp://") == fn) {
		fp = kftp_parse_url(fn, mode);
		if (fp == 0) return 0;
		if (kftp_connect(fp) == -1) {
			knet_close(fp);
			return 0;
		}
		kftp_connect_file(fp);
	} else if (strstr(fn, "http://") == fn) {
		fp = khttp_parse_url(fn, mode);
		if (fp == 0) return 0;
		khttp_connect_file(fp);
	} else { // local file
#ifdef _WIN32
		/* In windows, O_BINARY is necessary. In Linux/Mac, O_BINARY may
		 * be undefined on some systems, although it is defined on my
		 * Mac and the Linux I have tested on. */
		int fd = open(fn, O_RDONLY | O_BINARY);
#else		
		int fd = open(fn, O_RDONLY);
#endif
		if (fd == -1) {
			perror("open");
			return 0;
		}
		fp = (knetFile*)calloc(1, sizeof(knetFile));
		fp->type = KNF_TYPE_LOCAL;
		fp->fd = fd;
		fp->ctrl_fd = -1;
	}
	if (fp && fp->fd == -1) {
		knet_close(fp);
		return 0;
	}
	return fp;
}

knetFile *knet_dopen(int fd, const char *mode)
{
	knetFile *fp = (knetFile*)calloc(1, sizeof(knetFile));
	fp->type = KNF_TYPE_LOCAL;
	fp->fd = fd;
	return fp;
}

off_t knet_read(knetFile *fp, void *buf, off_t len)
{
	off_t l = 0;
	if (fp->fd == -1) return 0;
	if (fp->type == KNF_TYPE_FTP) {
		if (fp->is_ready == 0) {
			if (!fp->no_reconnect) kftp_reconnect(fp);
			kftp_connect_file(fp);
		}
	} else if (fp->type == KNF_TYPE_HTTP) {
		if (fp->is_ready == 0)
			khttp_connect_file(fp);
	}
	if (fp->type == KNF_TYPE_LOCAL) { // on Windows, the following block is necessary; not on UNIX
		off_t rest = len, curr;
		while (rest) {
			do {
				curr = read(fp->fd, buf + l, rest);
			} while (curr < 0 && EINTR == errno);
			if (curr < 0) return -1;
			if (curr == 0) break;
			l += curr; rest -= curr;
		}
	} else l = my_netread(fp->fd, buf, len);
	fp->offset += l;
	return l;
}

off_t knet_seek(knetFile *fp, int64_t off, int whence)
{
	if (whence == SEEK_SET && off == fp->offset) return 0;
	if (fp->type == KNF_TYPE_LOCAL) {
		/* Be aware that lseek() returns the offset after seeking,
		 * while fseek() returns zero on success. */
		off_t offset = lseek(fp->fd, off, whence);
		if (offset == -1) {
            // Be silent, it is OK for knet_seek to fail when the file is streamed
            // fprintf(stderr,"[knet_seek] %s\n", strerror(errno));
			return -1;
		}
		fp->offset = offset;
		return 0;
	}
    else if (fp->type == KNF_TYPE_FTP) 
    {
        if (whence==SEEK_CUR)
            fp->offset += off;
        else if (whence==SEEK_SET)
            fp->offset = off;
        else if ( whence==SEEK_END)
            fp->offset = fp->file_size+off;
		fp->is_ready = 0;
		return 0;
	} 
    else if (fp->type == KNF_TYPE_HTTP) 
    {
		if (whence == SEEK_END) { // FIXME: can we allow SEEK_END in future?
			fprintf(stderr, "[knet_seek] SEEK_END is not supported for HTTP. Offset is unchanged.\n");
			errno = ESPIPE;
			return -1;
		}
        if (whence==SEEK_CUR)
            fp->offset += off;
        else if (whence==SEEK_SET)
            fp->offset = off;
		fp->is_ready = 0;
		return 0;
	}
	errno = EINVAL;
    fprintf(stderr,"[knet_seek] %s\n", strerror(errno));
	return -1;
}

int knet_close(knetFile *fp)
{
	if (fp == 0) return 0;
	if (fp->ctrl_fd != -1) netclose(fp->ctrl_fd); // FTP specific
	if (fp->fd != -1) {
		/* On Linux/Mac, netclose() is an alias of close(), but on
		 * Windows, it is an alias of closesocket(). */
		if (fp->type == KNF_TYPE_LOCAL) close(fp->fd);
		else netclose(fp->fd);
	}
	free(fp->host); free(fp->port);
	free(fp->response); free(fp->retr); // FTP specific
	free(fp->path); free(fp->http_host); // HTTP specific
	free(fp);
	return 0;
}

#ifdef KNETFILE_MAIN
int main(void)
{
	char *buf;
	knetFile *fp;
	int type = 4, l;
#ifdef _WIN32
	knet_win32_init();
#endif
	buf = calloc(0x100000, 1);
	if (type == 0) {
		fp = knet_open("knetfile.c", "r");
		knet_seek(fp, 1000, SEEK_SET);
	} else if (type == 1) { // NCBI FTP, large file
		fp = knet_open("ftp://ftp.ncbi.nih.gov/1000genomes/ftp/data/NA12878/alignment/NA12878.chrom6.SLX.SRP000032.2009_06.bam", "r");
		knet_seek(fp, 2500000000ll, SEEK_SET);
		l = knet_read(fp, buf, 255);
	} else if (type == 2) {
		fp = knet_open("ftp://ftp.sanger.ac.uk/pub4/treefam/tmp/index.shtml", "r");
		knet_seek(fp, 1000, SEEK_SET);
	} else if (type == 3) {
		fp = knet_open("http://www.sanger.ac.uk/Users/lh3/index.shtml", "r");
		knet_seek(fp, 1000, SEEK_SET);
	} else if (type == 4) {
		fp = knet_open("http://www.sanger.ac.uk/Users/lh3/ex1.bam", "r");
		knet_read(fp, buf, 10000);
		knet_seek(fp, 20000, SEEK_SET);
		knet_seek(fp, 10000, SEEK_SET);
		l = knet_read(fp, buf+10000, 10000000) + 10000;
	}
	if (type != 4 && type != 1) {
		knet_read(fp, buf, 255);
		buf[255] = 0;
		printf("%s\n", buf);
	} else write(fileno(stdout), buf, l);
	knet_close(fp);
	free(buf);
	return 0;
}
#endif
