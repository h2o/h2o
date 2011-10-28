/* The MIT License

   Copyright (c) 2008 Broad Institute / Massachusetts Institute of Technology
                 2011 Attractive Chaos <attractor@live.co.uk>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include "bgzf.h"

#ifdef _USE_KNETFILE
#include "knetfile.h"
typedef knetFile *_bgzf_file_t;
#define _bgzf_open(fn, mode) knet_open(fn, mode)
#define _bgzf_dopen(fp, mode) knet_dopen(fp, mode)
#define _bgzf_close(fp) knet_close(fp)
#define _bgzf_fileno(fp) ((fp)->fd)
#define _bgzf_tell(fp) knet_tell(fp)
#define _bgzf_seek(fp, offset, whence) knet_seek(fp, offset, whence)
#define _bgzf_read(fp, buf, len) knet_read(fp, buf, len)
#define _bgzf_write(fp, buf, len) knet_write(fp, buf, len)
#else // ~defined(_USE_KNETFILE)
#if defined(_WIN32) || defined(_MSC_VER)
#define ftello(fp) ftell(fp)
#define fseeko(fp, offset, whence) fseek(fp, offset, whence)
#else // ~defined(_WIN32)
extern off_t ftello(FILE *stream);
extern int fseeko(FILE *stream, off_t offset, int whence);
#endif // ~defined(_WIN32)
typedef FILE *_bgzf_file_t;
#define _bgzf_open(fn, mode) fopen(fn, mode)
#define _bgzf_dopen(fp, mode) fdopen(fp, mode)
#define _bgzf_close(fp) fclose(fp)
#define _bgzf_fileno(fp) fileno(fp)
#define _bgzf_tell(fp) ftello(fp)
#define _bgzf_seek(fp, offset, whence) fseeko(fp, offset, whence)
#define _bgzf_read(fp, buf, len) fread(buf, 1, len, fp)
#define _bgzf_write(fp, buf, len) fwrite(buf, 1, len, fp)
#endif // ~define(_USE_KNETFILE)

#define BLOCK_HEADER_LENGTH 18
#define BLOCK_FOOTER_LENGTH 8

/* BGZF/GZIP header (speciallized from RFC 1952; little endian):
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 | 31|139|  8|  4|              0|  0|255|      6| 66| 67|      2|BLK_LEN|
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/
static const uint8_t g_magic[19] = "\037\213\010\4\0\0\0\0\0\377\6\0\102\103\2\0\0\0";

#ifdef BGZF_CACHE
typedef struct {
	int size;
	uint8_t *block;
	int64_t end_offset;
} cache_t;
#include "khash.h"
KHASH_MAP_INIT_INT64(cache, cache_t)
#endif

static inline void packInt16(uint8_t *buffer, uint16_t value)
{
	buffer[0] = value;
	buffer[1] = value >> 8;
}

static inline int unpackInt16(const uint8_t *buffer)
{
	return buffer[0] | buffer[1] << 8;
}

static inline void packInt32(uint8_t *buffer, uint32_t value)
{
	buffer[0] = value;
	buffer[1] = value >> 8;
	buffer[2] = value >> 16;
	buffer[3] = value >> 24;
}

static BGZF *bgzf_read_init()
{
	BGZF *fp;
	fp = calloc(1, sizeof(BGZF));
	fp->open_mode = 'r';
	fp->uncompressed_block = malloc(BGZF_BLOCK_SIZE);
	fp->compressed_block = malloc(BGZF_BLOCK_SIZE);
#ifdef BGZF_CACHE
	fp->cache = kh_init(cache);
#endif
	return fp;
}

static BGZF *bgzf_write_init(int compress_level) // compress_level==-1 for the default level
{
	BGZF *fp;
	fp = calloc(1, sizeof(BGZF));
	fp->open_mode = 'w';
	fp->uncompressed_block = malloc(BGZF_BLOCK_SIZE);
	fp->compressed_block = malloc(BGZF_BLOCK_SIZE);
	fp->compress_level = compress_level < 0? Z_DEFAULT_COMPRESSION : compress_level; // Z_DEFAULT_COMPRESSION==-1
	if (fp->compress_level > 9) fp->compress_level = Z_DEFAULT_COMPRESSION;
	return fp;
}
// get the compress level from the mode string
static int mode2level(const char *__restrict mode)
{
	int i, compress_level = -1;
	for (i = 0; mode[i]; ++i)
		if (mode[i] >= '0' && mode[i] <= '9') break;
	if (mode[i]) compress_level = (int)mode[i] - '0';
	if (strchr(mode, 'u')) compress_level = 0;
	return compress_level;
}

BGZF *bgzf_open(const char *path, const char *mode)
{
	BGZF *fp = 0;
	if (strchr(mode, 'r') || strchr(mode, 'R')) {
		_bgzf_file_t fpr;
		if ((fpr = _bgzf_open(path, "r")) == 0) return 0;
		fp = bgzf_read_init();
		fp->fp = fpr;
	} else if (strchr(mode, 'w') || strchr(mode, 'W')) {
		FILE *fpw;
		if ((fpw = fopen(path, "w")) == 0) return 0;
		fp = bgzf_write_init(mode2level(mode));
		fp->fp = fpw;
	}
	return fp;
}

BGZF *bgzf_dopen(int fd, const char *mode)
{
	BGZF *fp = 0;
	if (strchr(mode, 'r') || strchr(mode, 'R')) {
		_bgzf_file_t fpr;
		if ((fpr = _bgzf_dopen(fd, "r")) == 0) return 0;
		fp = bgzf_read_init();
		fp->fp = fpr;
	} else if (strchr(mode, 'w') || strchr(mode, 'W')) {
		FILE *fpw;
		if ((fpw = fdopen(fd, "w")) == 0) return 0;
		fp = bgzf_write_init(mode2level(mode));
		fp->fp = fpw;
	}
	return fp;
}

// Deflate the block in fp->uncompressed_block into fp->compressed_block. Also adds an extra field that stores the compressed block length.
static int deflate_block(BGZF *fp, int block_length)
{
	uint8_t *buffer = fp->compressed_block;
	int buffer_size = BGZF_BLOCK_SIZE;
	int input_length = block_length;
	int compressed_length = 0;
	int remaining;
	uint32_t crc;

	assert(block_length <= BGZF_BLOCK_SIZE); // guaranteed by the caller
	memcpy(buffer, g_magic, BLOCK_HEADER_LENGTH); // the last two bytes are a place holder for the length of the block
	while (1) { // loop to retry for blocks that do not compress enough
		int status;
		z_stream zs;
		zs.zalloc = NULL;
		zs.zfree = NULL;
		zs.next_in = fp->uncompressed_block;
		zs.avail_in = input_length;
		zs.next_out = (void*)&buffer[BLOCK_HEADER_LENGTH];
		zs.avail_out = buffer_size - BLOCK_HEADER_LENGTH - BLOCK_FOOTER_LENGTH;
		status = deflateInit2(&zs, fp->compress_level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY); // -15 to disable zlib header/footer
		if (status != Z_OK) {
			fp->errcode |= BGZF_ERR_ZLIB;
			return -1;
		}
		status = deflate(&zs, Z_FINISH);
		if (status != Z_STREAM_END) { // not compressed enough
			deflateEnd(&zs); // reset the stream
			if (status == Z_OK) { // reduce the size and recompress
				input_length -= 1024;
				assert(input_length > 0); // logically, this should not happen
				continue;
			}
			fp->errcode |= BGZF_ERR_ZLIB;
			return -1;
		}
		if (deflateEnd(&zs) != Z_OK) {
			fp->errcode |= BGZF_ERR_ZLIB;
			return -1;
		}
		compressed_length = zs.total_out;
		compressed_length += BLOCK_HEADER_LENGTH + BLOCK_FOOTER_LENGTH;
		assert(compressed_length <= BGZF_BLOCK_SIZE);
		break;
	}

	assert(compressed_length > 0);
	packInt16((uint8_t*)&buffer[16], compressed_length - 1); // write the compressed_length; -1 to fit 2 bytes
	crc = crc32(0L, NULL, 0L);
	crc = crc32(crc, fp->uncompressed_block, input_length);
	packInt32((uint8_t*)&buffer[compressed_length-8], crc);
	packInt32((uint8_t*)&buffer[compressed_length-4], input_length);

	remaining = block_length - input_length;
	if (remaining > 0) {
		assert(remaining <= input_length);
		memcpy(fp->uncompressed_block, fp->uncompressed_block + input_length, remaining);
	}
	fp->block_offset = remaining;
	return compressed_length;
}

// Inflate the block in fp->compressed_block into fp->uncompressed_block
static int inflate_block(BGZF* fp, int block_length)
{
	z_stream zs;
	zs.zalloc = NULL;
	zs.zfree = NULL;
	zs.next_in = fp->compressed_block + 18;
	zs.avail_in = block_length - 16;
	zs.next_out = fp->uncompressed_block;
	zs.avail_out = BGZF_BLOCK_SIZE;

	if (inflateInit2(&zs, -15) != Z_OK) {
		fp->errcode |= BGZF_ERR_ZLIB;
		return -1;
	}
	if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
		inflateEnd(&zs);
		fp->errcode |= BGZF_ERR_ZLIB;
		return -1;
	}
	if (inflateEnd(&zs) != Z_OK) {
		fp->errcode |= BGZF_ERR_ZLIB;
		return -1;
	}
	return zs.total_out;
}

static int check_header(const uint8_t *header)
{
	return (header[0] == 31 && header[1] == 139 && header[2] == 8 && (header[3] & 4) != 0
			&& unpackInt16((uint8_t*)&header[10]) == 6
			&& header[12] == 'B' && header[13] == 'C'
			&& unpackInt16((uint8_t*)&header[14]) == 2);
}

#ifdef BGZF_CACHE
static void free_cache(BGZF *fp)
{
	khint_t k;
	khash_t(cache) *h = (khash_t(cache)*)fp->cache;
	if (fp->open_mode != 'r') return;
	for (k = kh_begin(h); k < kh_end(h); ++k)
		if (kh_exist(h, k)) free(kh_val(h, k).block);
	kh_destroy(cache, h);
}

static int load_block_from_cache(BGZF *fp, int64_t block_address)
{
	khint_t k;
	cache_t *p;
	khash_t(cache) *h = (khash_t(cache)*)fp->cache;
	k = kh_get(cache, h, block_address);
	if (k == kh_end(h)) return 0;
	p = &kh_val(h, k);
	if (fp->block_length != 0) fp->block_offset = 0;
	fp->block_address = block_address;
	fp->block_length = p->size;
	memcpy(fp->uncompressed_block, p->block, BGZF_BLOCK_SIZE);
	_bgzf_seek((_bgzf_file_t)fp->fp, p->end_offset, SEEK_SET);
	return p->size;
}

static void cache_block(BGZF *fp, int size)
{
	int ret;
	khint_t k;
	cache_t *p;
	khash_t(cache) *h = (khash_t(cache)*)fp->cache;
	if (BGZF_BLOCK_SIZE >= fp->cache_size) return;
	if ((kh_size(h) + 1) * BGZF_BLOCK_SIZE > fp->cache_size) {
		/* A better way would be to remove the oldest block in the
		 * cache, but here we remove a random one for simplicity. This
		 * should not have a big impact on performance. */
		for (k = kh_begin(h); k < kh_end(h); ++k)
			if (kh_exist(h, k)) break;
		if (k < kh_end(h)) {
			free(kh_val(h, k).block);
			kh_del(cache, h, k);
		}
	}
	k = kh_put(cache, h, fp->block_address, &ret);
	if (ret == 0) return; // if this happens, a bug!
	p = &kh_val(h, k);
	p->size = fp->block_length;
	p->end_offset = fp->block_address + size;
	p->block = malloc(BGZF_BLOCK_SIZE);
	memcpy(kh_val(h, k).block, fp->uncompressed_block, BGZF_BLOCK_SIZE);
}
#else
static void free_cache(BGZF *fp) {}
static int load_block_from_cache(BGZF *fp, int64_t block_address) {return 0;}
static void cache_block(BGZF *fp, int size) {}
#endif

int bgzf_read_block(BGZF *fp)
{
	uint8_t header[BLOCK_HEADER_LENGTH], *compressed_block;
	int count, size = 0, block_length, remaining;
	int64_t block_address;
	block_address = _bgzf_tell((_bgzf_file_t)fp->fp);
	if (load_block_from_cache(fp, block_address)) return 0;
	count = _bgzf_read(fp->fp, header, sizeof(header));
	if (count == 0) { // no data read
		fp->block_length = 0;
		return 0;
	}
	if (count != sizeof(header) || !check_header(header)) {
		fp->errcode |= BGZF_ERR_HEADER;
		return -1;
	}
	size = count;
	block_length = unpackInt16((uint8_t*)&header[16]) + 1; // +1 because when writing this number, we used "-1"
	compressed_block = (uint8_t*)fp->compressed_block;
	memcpy(compressed_block, header, BLOCK_HEADER_LENGTH);
	remaining = block_length - BLOCK_HEADER_LENGTH;
	count = _bgzf_read(fp->fp, &compressed_block[BLOCK_HEADER_LENGTH], remaining);
	if (count != remaining) {
		fp->errcode |= BGZF_ERR_IO;
		return -1;
	}
	size += count;
	if (inflate_block(fp, block_length) < 0) return -1;
	if (fp->block_length != 0) fp->block_offset = 0; // Do not reset offset if this read follows a seek.
	fp->block_address = block_address;
	fp->block_length = count;
	cache_block(fp, size);
	return 0;
}

ssize_t bgzf_read(BGZF *fp, void *data, ssize_t length)
{
	ssize_t bytes_read = 0;
	uint8_t *output = data;
	if (length <= 0) return 0;
	assert(fp->open_mode == 'r');
	while (bytes_read < length) {
		int copy_length, available = fp->block_length - fp->block_offset;
		uint8_t *buffer;
		if (available <= 0) {
			if (bgzf_read_block(fp) != 0) return -1;
			available = fp->block_length - fp->block_offset;
			if (available <= 0) break;
		}
		copy_length = length - bytes_read < available? length - bytes_read : available;
		buffer = fp->uncompressed_block;
		memcpy(output, buffer + fp->block_offset, copy_length);
		fp->block_offset += copy_length;
		output += copy_length;
		bytes_read += copy_length;
	}
	if (fp->block_offset == fp->block_length) {
		fp->block_address = _bgzf_tell((_bgzf_file_t)fp->fp);
		fp->block_offset = fp->block_length = 0;
	}
	return bytes_read;
}

int bgzf_flush(BGZF *fp)
{
	assert(fp->open_mode == 'w');
	while (fp->block_offset > 0) {
		int block_length;
		block_length = deflate_block(fp, fp->block_offset);
		if (block_length < 0) return -1;
		if (fwrite(fp->compressed_block, 1, block_length, fp->fp) != block_length) {
			fp->errcode |= BGZF_ERR_IO; // possibly truncated file
			return -1;
		}
		fp->block_address += block_length;
	}
	return 0;
}

int bgzf_flush_try(BGZF *fp, ssize_t size)
{
	if (fp->block_offset + size > BGZF_BLOCK_SIZE)
		return bgzf_flush(fp);
	return -1;
}

ssize_t bgzf_write(BGZF *fp, const void *data, ssize_t length)
{
	const uint8_t *input = data;
	int block_length = BGZF_BLOCK_SIZE, bytes_written;
	assert(fp->open_mode == 'w');
	input = data;
	bytes_written = 0;
	while (bytes_written < length) {
		uint8_t* buffer = fp->uncompressed_block;
		int copy_length = block_length - fp->block_offset < length - bytes_written? block_length - fp->block_offset : length - bytes_written;
		memcpy(buffer + fp->block_offset, input, copy_length);
		fp->block_offset += copy_length;
		input += copy_length;
		bytes_written += copy_length;
		if (fp->block_offset == block_length && bgzf_flush(fp)) break;
	}
	return bytes_written;
}

int bgzf_close(BGZF* fp)
{
	int ret, count, block_length;
	if (fp == 0) return -1;
	if (fp->open_mode == 'w') {
		if (bgzf_flush(fp) != 0) return -1;
		block_length = deflate_block(fp, 0); // write an empty block
		count = fwrite(fp->compressed_block, 1, block_length, fp->fp);
		if (fflush(fp->fp) != 0) {
			fp->errcode |= BGZF_ERR_IO;
			return -1;
		}
	}
	ret = fp->open_mode == 'w'? fclose(fp->fp) : _bgzf_close(fp->fp);
	if (ret != 0) return -1;
	free(fp->uncompressed_block);
	free(fp->compressed_block);
	free_cache(fp);
	free(fp);
	return 0;
}

void bgzf_set_cache_size(BGZF *fp, int cache_size)
{
	if (fp) fp->cache_size = cache_size;
}

int bgzf_check_EOF(BGZF *fp)
{
	static uint8_t magic[28] = "\037\213\010\4\0\0\0\0\0\377\6\0\102\103\2\0\033\0\3\0\0\0\0\0\0\0\0\0";
	uint8_t buf[28];
	off_t offset;
	offset = _bgzf_tell((_bgzf_file_t)fp->fp);
	if (_bgzf_seek(fp->fp, -28, SEEK_END) < 0) return 0;
	_bgzf_read(fp->fp, buf, 28);
	_bgzf_seek(fp->fp, offset, SEEK_SET);
	return (memcmp(magic, buf, 28) == 0)? 1 : 0;
}

int64_t bgzf_seek(BGZF* fp, int64_t pos, int where)
{
	int block_offset;
	int64_t block_address;

	if (fp->open_mode != 'r' || where != SEEK_SET) {
		fp->errcode |= BGZF_ERR_MISUSE;
		return -1;
	}
	block_offset = pos & 0xFFFF;
	block_address = pos >> 16;
	if (_bgzf_seek(fp->fp, block_address, SEEK_SET) < 0) {
		fp->errcode |= BGZF_ERR_IO;
		return -1;
	}
	fp->block_length = 0;  // indicates current block has not been loaded
	fp->block_address = block_address;
	fp->block_offset = block_offset;
	return 0;
}

int bgzf_is_bgzf(const char *fn)
{
	uint8_t buf[16];
	int n;
	_bgzf_file_t fp;
	if ((fp = _bgzf_open(fn, "r")) == 0) return 0;
	n = _bgzf_read(fp, buf, 16);
	_bgzf_close(fp);
	if (n != 16) return 0;
	return memcmp(g_magic, buf, 16) == 0? 1 : 0;
}

int bgzf_getc(BGZF *fp)
{
	int c;
	if (fp->block_offset >= fp->block_length) {
		if (bgzf_read_block(fp) != 0) return -2; /* error */
		if (fp->block_length == 0) return -1; /* end-of-file */
	}
	c = ((unsigned char*)fp->uncompressed_block)[fp->block_offset++];
    if (fp->block_offset == fp->block_length) {
        fp->block_address = _bgzf_tell((_bgzf_file_t)fp->fp);
        fp->block_offset = 0;
        fp->block_length = 0;
    }
	return c;
}

#ifndef kroundup32
#define kroundup32(x) (--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
#endif

int bgzf_getline(BGZF *fp, int delim, kstring_t *str)
{
	int l, state = 0;
	unsigned char *buf = (unsigned char*)fp->uncompressed_block;
	str->l = 0;
	do {
		if (fp->block_offset >= fp->block_length) {
			if (bgzf_read_block(fp) != 0) { state = -2; break; }
			if (fp->block_length == 0) { state = -1; break; }
		}
		for (l = fp->block_offset; l < fp->block_length && buf[l] != delim; ++l);
		if (l < fp->block_length) state = 1;
		l -= fp->block_offset;
		if (str->l + l + 1 >= str->m) {
			str->m = str->l + l + 2;
			kroundup32(str->m);
			str->s = (char*)realloc(str->s, str->m);
		}
		memcpy(str->s + str->l, buf + fp->block_offset, l);
		str->l += l;
		fp->block_offset += l + 1;
		if (fp->block_offset >= fp->block_length) {
			fp->block_address = _bgzf_tell((_bgzf_file_t)fp->fp);
			fp->block_offset = 0;
			fp->block_length = 0;
		} 
	} while (state == 0);
	if (str->l == 0 && state < 0) return state;
	str->s[str->l] = 0;
	return str->l;
}
