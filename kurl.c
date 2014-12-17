#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>
#include "kurl.h"

/**********************
 *** Core kurl APIs ***
 **********************/

#define KU_DEF_BUFLEN   0x8000
#define KU_MAX_SKIP     (KU_DEF_BUFLEN<<1) // if seek step is smaller than this, skip

#define kurl_isfile(u) ((u)->fd >= 0)

#ifndef kroundup32
#define kroundup32(x) (--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
#endif

struct kurl_t {
	CURLM *multi; // cURL multi handler
	CURL *curl;   // cURL easy handle
	uint8_t *buf; // buffer
	off_t off0;   // offset of the first byte in the buffer; the actual file offset equals off0 + p_buf
	int fd;       // file descriptor for a normal file; <0 for a remote file
	int m_buf;    // max buffer size; for a remote file, CURL_MAX_WRITE_SIZE*2 is recommended
	int l_buf;    // length of the buffer; l_buf == 0 iff the input read entirely; l_buf <= m_buf
	int p_buf;    // file position in the buffer; p_buf <= l_buf
	int done_reading; // true if we can read nothing from the file; buffer may not be empty even if done_reading is set
	int err;      // error code
	struct curl_slist *hdr;
};

typedef struct {
	char *url, *date, *auth;
} s3aux_t;

int kurl_init(void) // required for SSL and win32 socket; NOT thread safe
{
	return curl_global_init(CURL_GLOBAL_DEFAULT);
}

void kurl_destroy(void)
{
	curl_global_cleanup();
}

static int prepare(kurl_t *ku, int do_seek)
{
	if (kurl_isfile(ku)) {
		if (do_seek && lseek(ku->fd, ku->off0, SEEK_SET) != ku->off0)
			return -1;
	} else { // FIXME: for S3, we need to re-authorize
		int rc;
		rc = curl_multi_remove_handle(ku->multi, ku->curl);
		rc = curl_easy_setopt(ku->curl, CURLOPT_RESUME_FROM, ku->off0);
		rc = curl_multi_add_handle(ku->multi, ku->curl);
	}
	ku->p_buf = ku->l_buf = 0; // empty the buffer
	return 0;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *data) // callback required by cURL
{
	kurl_t *ku = (kurl_t*)data;
	ssize_t nbytes = size * nmemb;
	if (nbytes + ku->l_buf > ku->m_buf)
		return CURL_WRITEFUNC_PAUSE;
	memcpy(ku->buf + ku->l_buf, ptr, nbytes);
	ku->l_buf += nbytes;
	return nbytes;
}

static int fill_buffer(kurl_t *ku) // fill the buffer
{
	assert(ku->p_buf == ku->l_buf); // buffer is always used up when fill_buffer() is called; otherwise a bug
	ku->off0 += ku->l_buf;
	ku->p_buf = ku->l_buf = 0;
	if (ku->done_reading) return 0;
	if (kurl_isfile(ku)) {
		// The following block is equivalent to "ku->l_buf = read(ku->fd, ku->buf, ku->m_buf)" on Mac.
		// On Linux, the man page does not specify whether read() guarantees to read ku->m_buf bytes
		// even if ->fd references a normal file with sufficient remaining bytes.
		while (ku->l_buf < ku->m_buf) {
			int l;
			l = read(ku->fd, ku->buf + ku->l_buf, ku->m_buf - ku->l_buf);
			if (l == 0) break;
			ku->l_buf += l;
		}
		if (ku->l_buf < ku->m_buf) ku->done_reading = 1;
	} else {
		int n_running, rc;
		fd_set fdr, fdw, fde;
		do {
			int maxfd = -1;
			long curl_to = -1;
			struct timeval to;
			// the following is adaped from docs/examples/fopen.c 
			to.tv_sec = 10, to.tv_usec = 0; // 10 seconds
			curl_multi_timeout(ku->multi, &curl_to);
			if (curl_to >= 0) {
				to.tv_sec = curl_to / 1000;
				if (to.tv_sec > 1) to.tv_sec = 1;
				else to.tv_usec = (curl_to % 1000) * 1000;
			}
			FD_ZERO(&fdr); FD_ZERO(&fdw); FD_ZERO(&fde);
			curl_multi_fdset(ku->multi, &fdr, &fdw, &fde, &maxfd); // FIXME: check return code
			if (maxfd >= 0 && (rc = select(maxfd+1, &fdr, &fdw, &fde, &to)) < 0) break;
			if (maxfd < 0) { // check curl_multi_fdset.3 about why we wait for 100ms here
				struct timespec req, rem;
				req.tv_sec = 0; req.tv_nsec = 100000000; // this is 100ms
				nanosleep(&req, &rem);
			}
			curl_easy_pause(ku->curl, CURLPAUSE_CONT);
			rc = curl_multi_perform(ku->multi, &n_running); // FIXME: check return code
		} while (n_running && ku->l_buf < ku->m_buf - CURL_MAX_WRITE_SIZE);
		if (ku->l_buf < ku->m_buf - CURL_MAX_WRITE_SIZE) ku->done_reading = 1;
	}
	return ku->l_buf;
}

int kurl_close(kurl_t *ku)
{
	if (ku == 0) return 0;
	if (ku->fd < 0) {
		curl_multi_remove_handle(ku->multi, ku->curl);
		curl_easy_cleanup(ku->curl);
		curl_multi_cleanup(ku->multi);
		if (ku->hdr) curl_slist_free_all(ku->hdr);
	} else close(ku->fd);
	free(ku->buf);
	free(ku);
	return 0;
}

kurl_t *kurl_open(const char *url, kurl_opt_t *opt)
{
	extern s3aux_t s3_parse(const char *url, const char *_id, const char *_secret, const char *fn);
	const char *p, *q;
	kurl_t *ku;
	int fd = -1, is_file = 1, failed = 0;

	p = strstr(url, "://");
	if (p && *p) {
		for (q = url; q != p; ++q)
			if (!isalnum(*q)) break;
		if (q == p) is_file = 0;
	}
	if (is_file && (fd = open(url, O_RDONLY)) < 0) return 0;

	ku = (kurl_t*)calloc(1, sizeof(kurl_t));
	ku->fd = is_file? fd : -1;
	if (!kurl_isfile(ku)) {
		ku->multi = curl_multi_init();
		ku->curl  = curl_easy_init();
		if (strstr(url, "s3://") == url) {
			s3aux_t a;
			a = s3_parse(url, (opt? opt->s3keyid : 0), (opt? opt->s3secretkey : 0), (opt? opt->s3key_fn : 0));
			if (a.url == 0 || a.date == 0 || a.auth == 0) {
				kurl_close(ku);
				return 0;
			}
			ku->hdr = curl_slist_append(ku->hdr, a.date);
			ku->hdr = curl_slist_append(ku->hdr, a.auth);
			curl_easy_setopt(ku->curl, CURLOPT_URL, a.url);
			curl_easy_setopt(ku->curl, CURLOPT_HTTPHEADER, ku->hdr);
			free(a.date); free(a.auth); free(a.url);
		} else curl_easy_setopt(ku->curl, CURLOPT_URL, url);
		curl_easy_setopt(ku->curl, CURLOPT_WRITEDATA, ku);
		curl_easy_setopt(ku->curl, CURLOPT_VERBOSE, 0L);
		curl_easy_setopt(ku->curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(ku->curl, CURLOPT_WRITEFUNCTION, write_cb);
		curl_easy_setopt(ku->curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(ku->curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(ku->curl, CURLOPT_FOLLOWLOCATION, 1L);
	}
	ku->m_buf = KU_DEF_BUFLEN;
	if (!kurl_isfile(ku) && ku->m_buf < CURL_MAX_WRITE_SIZE * 2)
		ku->m_buf = CURL_MAX_WRITE_SIZE * 2; // for remote files, the buffer set to 2*CURL_MAX_WRITE_SIZE
	ku->buf = (uint8_t*)calloc(ku->m_buf, 1);
	if (kurl_isfile(ku)) failed = (fill_buffer(ku) <= 0);
	else failed = (prepare(ku, 0) < 0 || fill_buffer(ku) <= 0);
	if (failed) {
		kurl_close(ku);
		return 0;
	}
	return ku;
}

kurl_t *kurl_dopen(int fd)
{
	kurl_t *ku;
	ku = (kurl_t*)calloc(1, sizeof(kurl_t));
	ku->fd = fd;
	ku->m_buf = KU_DEF_BUFLEN;
	ku->buf = (uint8_t*)calloc(ku->m_buf, 1);
	if (prepare(ku, 0) < 0 || fill_buffer(ku) <= 0) {
		kurl_close(ku);
		return 0;
	}
	return ku;
}

int kurl_buflen(kurl_t *ku, int len)
{
	if (len <= 0 || len < ku->l_buf) return ku->m_buf;
	if (!kurl_isfile(ku) && len < CURL_MAX_WRITE_SIZE * 2) return ku->m_buf;
	ku->m_buf = len;
	kroundup32(ku->m_buf);
	ku->buf = (uint8_t*)realloc(ku->buf, ku->m_buf);
	return ku->m_buf;
}

ssize_t kurl_read(kurl_t *ku, void *buf, size_t nbytes)
{
	ssize_t rest = nbytes;
	if (ku->l_buf == 0) return 0; // end-of-file
	while (rest) {
		if (ku->l_buf - ku->p_buf >= rest) {
			if (buf) memcpy((uint8_t*)buf + (nbytes - rest), ku->buf + ku->p_buf, rest);
			ku->p_buf += rest;
			rest = 0;
		} else {
			int ret;
			if (buf && ku->l_buf > ku->p_buf)
				memcpy((uint8_t*)buf + (nbytes - rest), ku->buf + ku->p_buf, ku->l_buf - ku->p_buf);
			rest -= ku->l_buf - ku->p_buf;
			ku->p_buf = ku->l_buf;
			ret = fill_buffer(ku);
			if (ret <= 0) break;
		}
	}
	return nbytes - rest;
}

off_t kurl_seek(kurl_t *ku, off_t offset, int whence) // FIXME: sometimes when seek() fails, read() will fail as well.
{
	off_t new_off = -1, cur_off;
	int failed = 0, seek_end = 0;
	if (ku == 0) return -1;
	cur_off = ku->off0 + ku->p_buf;
	if (whence == SEEK_SET) new_off = offset;
	else if (whence == SEEK_CUR) new_off += cur_off + offset;
	else if (whence == SEEK_END && kurl_isfile(ku)) new_off = lseek(ku->fd, offset, SEEK_END), seek_end = 1;
	else { // not supported whence
		ku->err = KURL_INV_WHENCE;
		return -1;
	}
	if (new_off < 0) { // negtive absolute offset
		ku->err = KURL_SEEK_OUT;
		return -1;
	}
	if (!seek_end && new_off >= cur_off && new_off - cur_off + ku->p_buf < ku->l_buf) {
		ku->p_buf += new_off - cur_off;
		return ku->off0 + ku->p_buf;
	}
	if (seek_end || new_off < cur_off || new_off - cur_off > KU_MAX_SKIP) { // if jump is large, do actual seek
		ku->off0 = new_off;
		ku->done_reading = 0;
		if (prepare(ku, 1) < 0 || fill_buffer(ku) <= 0) failed = 1;
	} else { // if jump is small, read through
		off_t r;
		r = kurl_read(ku, 0, new_off - cur_off);
		if (r + cur_off != new_off) failed = 1; // out of range
	}
	if (failed) ku->err = KURL_SEEK_OUT, ku->l_buf = ku->p_buf = 0, new_off = -1;
	return new_off;
}

off_t kurl_tell(const kurl_t *ku)
{
	if (ku == 0) return -1;
	return ku->off0 + ku->p_buf;
}

int kurl_eof(const kurl_t *ku)
{
	if (ku == 0) return 1;
	return (ku->l_buf == 0); // unless file end, buffer should never be empty
}

int kurl_fileno(const kurl_t *ku)
{
	if (ku == 0) return -1;
	return ku->fd;
}

int kurl_error(const kurl_t *ku)
{
	if (ku == 0) return KURL_NULL;
	return ku->err;
}

/*****************
 *** HMAC-SHA1 ***
 *****************/

/* This code is public-domain - it is based on libcrypt placed in the public domain by Wei Dai and other contributors. */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

typedef struct sha1nfo {
	union { uint8_t b[BLOCK_LENGTH]; uint32_t w[BLOCK_LENGTH/4]; } buf;
	uint8_t bufOffset;
	union { uint8_t b[HASH_LENGTH]; uint32_t w[HASH_LENGTH/4]; } state;
	uint32_t byteCount;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

void sha1_init(sha1nfo *s)
{
	const uint8_t table[] = { 0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef, 0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10, 0xf0,0xe1,0xd2,0xc3 };
	memcpy(s->state.b, table, HASH_LENGTH);
	s->byteCount = 0;
	s->bufOffset = 0;
}

#define rol32(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_hashBlock(sha1nfo *s)
{
	uint32_t i, t, a = s->state.w[0], b = s->state.w[1], c = s->state.w[2], d = s->state.w[3], e = s->state.w[4];
	for (i = 0; i < 80; i++) {
		if (i >= 16) {
			t = s->buf.w[(i+13)&15] ^ s->buf.w[(i+8)&15] ^ s->buf.w[(i+2)&15] ^ s->buf.w[i&15];
			s->buf.w[i&15] = rol32(t, 1);
		}
		if (i < 20)      t = 0x5a827999 + (d ^ (b & (c ^ d)));
		else if (i < 40) t = 0x6ed9eba1 + (b ^ c ^ d);
		else if (i < 60) t = 0x8f1bbcdc + ((b & c) | (d & (b | c)));
		else             t = 0xca62c1d6 + (b ^ c ^ d);
		t += rol32(a, 5) + e + s->buf.w[i&15];
		e = d; d = c; c = rol32(b, 30); b = a; a = t;
	}
	s->state.w[0] += a; s->state.w[1] += b; s->state.w[2] += c; s->state.w[3] += d; s->state.w[4] += e;
}

static inline void sha1_add(sha1nfo *s, uint8_t data)
{
	s->buf.b[s->bufOffset ^ 3] = data;
	if (++s->bufOffset == BLOCK_LENGTH) {
		sha1_hashBlock(s);
		s->bufOffset = 0;
	}
}

void sha1_write1(sha1nfo *s, uint8_t data)
{
	++s->byteCount;
	sha1_add(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len)
{
	while (len--) sha1_write1(s, (uint8_t)*data++);
}

const uint8_t *sha1_final(sha1nfo *s)
{
	int i;
	sha1_add(s, 0x80);
	while (s->bufOffset != 56) sha1_add(s, 0);
	sha1_add(s, 0);
	sha1_add(s, 0);
	sha1_add(s, 0);
	sha1_add(s, s->byteCount >> 29);
	sha1_add(s, s->byteCount >> 21);
	sha1_add(s, s->byteCount >> 13);
	sha1_add(s, s->byteCount >> 5);
	sha1_add(s, s->byteCount << 3);
	for (i = 0; i < 5; ++i) {
		uint32_t a = s->state.w[i];
		s->state.w[i] = a<<24 | (a<<8&0x00ff0000) | (a>>8&0x0000ff00) | a>>24;
	}
	return s->state.b;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_init_hmac(sha1nfo *s, const uint8_t* key, int l_key)
{
	uint8_t i;
	memset(s->keyBuffer, 0, BLOCK_LENGTH);
	if (l_key > BLOCK_LENGTH) {
		sha1_init(s);
		while (l_key--) sha1_write1(s, *key++);
		memcpy(s->keyBuffer, sha1_final(s), HASH_LENGTH);
	} else memcpy(s->keyBuffer, key, l_key);
	sha1_init(s);
	for (i = 0; i < BLOCK_LENGTH; ++i)
		sha1_write1(s, s->keyBuffer[i] ^ HMAC_IPAD);
}

const uint8_t *sha1_final_hmac(sha1nfo *s)
{
	uint8_t i;
	memcpy(s->innerHash, sha1_final(s), HASH_LENGTH);
	sha1_init(s);
	for (i = 0; i < BLOCK_LENGTH; ++i) sha1_write1(s, s->keyBuffer[i] ^ HMAC_OPAD);
	for (i = 0; i < HASH_LENGTH; ++i) sha1_write1(s, s->innerHash[i]);
	return sha1_final(s);
}

/*******************
 *** S3 protocol ***
 *******************/

#include <time.h>
#include <ctype.h>

static void s3_sign(const char *key, const char *data, char out[29])
{
	const char *b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *digest;
	int i, j, rest;
	sha1nfo s;
	sha1_init_hmac(&s, (uint8_t*)key, strlen(key));
	sha1_write(&s, data, strlen(data));
	digest = sha1_final_hmac(&s);
	for (j = i = 0, rest = 8; i < 20; ++j) { // base64 encoding
		if (rest <= 6) {
			int next = i < 19? digest[i+1] : 0;
			out[j] = b64tab[(int)(digest[i] << (6-rest) & 0x3f) | next >> (rest+2)], ++i, rest += 2;
		} else out[j] = b64tab[(int)digest[i] >> (rest-6) & 0x3f], rest -= 6;
	}
	out[j++] = '='; out[j] = 0; // SHA1 digest always has 160 bits, or 20 bytes. We need one '=' at the end.
}

static char *s3_read_awssecret(const char *fn)
{
	char *p, *secret, buf[128], *path;
	FILE *fp;
	int l;
	if (fn == 0) {
		char *home;
		home = getenv("HOME");
		if (home == 0) return 0;
		l = strlen(home) + 12;
		path = (char*)malloc(strlen(home) + 12);
		strcat(strcpy(path, home), "/.awssecret");
	} else path = (char*)fn;
	fp = fopen(path, "r");
	if (path != fn) free(path);
	if (fp == 0) return 0;
	l = fread(buf, 1, 127, fp);
	fclose(fp);
	buf[l] = 0;
	for (p = buf; *p != 0 && *p != '\n'; ++p);
	if (*p == 0) return 0;
	*p = 0; secret = p + 1;
	for (++p; *p != 0 && *p != '\n'; ++p);
	*p = 0;
	l = p - buf + 1;
	p = (char*)malloc(l);
	memcpy(p, buf, l);
	return p;
}

typedef struct { int l, m; char *s; } kstring_t;

static inline int kputsn(const char *p, int l, kstring_t *s)
{
	if (s->l + l + 1 >= s->m) {
		s->m = s->l + l + 2;
		kroundup32(s->m);
		s->s = (char*)realloc(s->s, s->m);
	}
	memcpy(s->s + s->l, p, l);
	s->l += l;
	s->s[s->l] = 0;
	return l;
}

s3aux_t s3_parse(const char *url, const char *_id, const char *_secret, const char *fn_secret)
{
	const char *id, *secret, *bucket, *obj;
	char *id_secret = 0, date[64], sig[29];
	time_t t;
	struct tm tmt;
	s3aux_t a = {0,0};
	kstring_t str = {0,0,0};
	// parse URL
	if (strstr(url, "s3://") != url) return a;
	bucket = url + 5;
	for (obj = bucket; *obj && *obj != '/'; ++obj);
	if (*obj == 0) return a; // no object
	// acquire AWS credential and time
	if (_id == 0 || _secret == 0) {
		id_secret = s3_read_awssecret(fn_secret);
		if (id_secret == 0) return a; // fail to read the AWS credential
		id = id_secret;
		secret = id_secret + strlen(id) + 1;
	} else id = _id, secret = _secret;
	// compose URL for curl
	kputsn("https://", 8, &str);
	kputsn(bucket, obj - bucket, &str);
	kputsn(".s3.amazonaws.com", 17, &str);
	kputsn(obj, strlen(obj), &str);
	a.url = str.s;
	// compose the Date line
	str.l = str.m = 0; str.s = 0;
	t = time(0);
	strftime(date, 64, "%a, %d %b %Y %H:%M:%S +0000", gmtime_r(&t, &tmt));
	kputsn("Date: ", 6, &str);
	kputsn(date, strlen(date), &str);
	a.date = str.s;
	// compose the string to sign and sign it
	str.l = str.m = 0; str.s = 0;
	kputsn("GET\n\n\n", 6, &str);
	kputsn(date, strlen(date), &str);
	kputsn("\n", 1, &str);
	kputsn(bucket-1, strlen(bucket-1), &str);
	s3_sign(secret, str.s, sig);
	// compose the Authorization line
	str.l = 0;
	kputsn("Authorization: AWS ", 19, &str);
	kputsn(id, strlen(id), &str);
	kputsn(":", 1, &str);
	kputsn(sig, strlen(sig), &str);
	a.auth = str.s;
//	printf("curl -H '%s' -H '%s' %s\n", a.date, a.auth, a.url);
	return a;
}

/*********************
 *** Main function ***
 *********************/

#ifdef KURL_MAIN
int main(int argc, char *argv[])
{
	kurl_t *f;
	int c, l, l_buf = 0x10000;
	off_t start = 0, rest = -1;
	uint8_t *buf;
	char *p;
	kurl_opt_t opt;

	memset(&opt, 0, sizeof(kurl_opt_t));
	while ((c = getopt(argc, argv, "c:l:a:")) >= 0) {
		if (c == 'c') start = strtol(optarg, &p, 0);
		else if (c == 'l') rest = strtol(optarg, &p, 0);
		else if (c == 'a') opt.s3key_fn = optarg;
	}
	if (optind == argc) {
		fprintf(stderr, "Usage: kurl [-c start] [-l length] <url>\n");
		return 1;
	}
	kurl_init();
	f = kurl_open(argv[optind], &opt);
	if (f == 0) {
		fprintf(stderr, "ERROR: fail to open URL\n");
		return 2;
	}
	if (start > 0) {
		if (kurl_seek(f, start, SEEK_SET) < 0) {
			kurl_close(f);
			fprintf(stderr, "ERROR: fail to seek\n");
			return 3;
		}
	}
	buf = (uint8_t*)calloc(l_buf, 1);
	while (rest != 0) {
		int to_read = rest > 0 && rest < l_buf? rest : l_buf;
		l = kurl_read(f, buf, to_read);
		if (l == 0) break;
		fwrite(buf, 1, l, stdout);
		rest -= l;
	}
	free(buf);
	kurl_close(f);
	kurl_destroy();
	return 0;
}
#endif
