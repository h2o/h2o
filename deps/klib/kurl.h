#ifndef KURL_H
#define KURL_H

#include <sys/types.h>

#define KURL_NULL       1
#define KURL_INV_WHENCE 2
#define KURL_SEEK_OUT   3
#define KURL_NO_AUTH    4

struct kurl_t;
typedef struct kurl_t kurl_t;

typedef struct {
	const char *s3keyid;
	const char *s3secretkey;
	const char *s3key_fn;
} kurl_opt_t;

#ifdef __cplusplus
extern "C" {
#endif

int kurl_init(void);
void kurl_destroy(void);

kurl_t *kurl_open(const char *url, kurl_opt_t *opt);
kurl_t *kurl_dopen(int fd);
int kurl_close(kurl_t *ku);
ssize_t kurl_read(kurl_t *ku, void *buf, size_t nbytes);
off_t kurl_seek(kurl_t *ku, off_t offset, int whence);
int kurl_buflen(kurl_t *ku, int len);

off_t kurl_tell(const kurl_t *ku);
int kurl_eof(const kurl_t *ku);
int kurl_fileno(const kurl_t *ku);
int kurl_error(const kurl_t *ku);

#ifdef __cplusplus
}
#endif

#ifndef KNETFILE_H
#define KNETFILE_H
typedef kurl_t knetFile;
#define knet_open(fn, mode) kurl_open(fn, 0)
#define knet_dopen(fd, mode) kurl_dopen(fd)
#define knet_close(fp) kurl_close(fp)
#define knet_read(fp, buf, len) kurl_read(fp, buf, len)
#define knet_seek(fp, off, whence) kurl_seek(fp, off, whence)
#define knet_tell(fp) kurl_tell(fp)
#define knet_fileno(fp) kurl_fileno(fp)
#define knet_win32_init() kurl_init()
#define knet_win32_destroy() kurl_destroy()
#endif

#endif
