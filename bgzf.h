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

/* The BGZF library was originally written by Bob Handsaker from the Broad
 * Institute. It was later improved by the SAMtools developers. */

#ifndef __BGZF_H
#define __BGZF_H

#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#define BGZF_BLOCK_SIZE 0x10000 // 64k

#define BGZF_ERR_ZLIB   1
#define BGZF_ERR_HEADER 2
#define BGZF_ERR_IO     4
#define BGZF_ERR_MISUSE 8

typedef struct {
    int open_mode:8, compress_level:8, errcode:16;
	int cache_size;
    int block_length, block_offset;
    int64_t block_address;
    void *uncompressed_block, *compressed_block;
	void *cache; // a pointer to a hash table
	void *fp; // actual file handler; FILE* on writing; FILE* or knetFile* on reading
} BGZF;

#ifndef KSTRING_T
#define KSTRING_T kstring_t
typedef struct __kstring_t {
	size_t l, m;
	char *s;
} kstring_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

	/******************
	 * Basic routines *
	 ******************/

	/**
	 * Open an existing file descriptor for reading or writing.
	 *
	 * @param fd    file descriptor
	 * @param mode  mode matching /[rwu0-9]+/: 'r' for reading, 'w' for writing and a digit specifies
	 *              the zlib compression level; if both 'r' and 'w' are present, 'w' is ignored.
     * @return      BGZF file handler; 0 on error
	 */
	BGZF* bgzf_dopen(int fd, const char *mode);

	/**
	 * Open the specified file for reading or writing.
	 */
	BGZF* bgzf_open(const char* path, const char *mode);

	/**
	 * Close the BGZF and free all associated resources.
	 *
	 * @param fp    BGZF file handler
	 * @return      0 on success and -1 on error
	 */
	int bgzf_close(BGZF *fp);

	/**
	 * Read up to _length_ bytes from the file storing into _data_.
	 *
	 * @param fp     BGZF file handler
	 * @param data   data array to read into
	 * @param length size of data to read
	 * @return       number of bytes actually read; 0 on end-of-file and -1 on error
	 */
	ssize_t bgzf_read(BGZF *fp, void *data, ssize_t length);

	/**
	 * Write _length_ bytes from _data_ to the file.
	 *
	 * @param fp     BGZF file handler
	 * @param data   data array to write
	 * @param length size of data to write
	 * @return       number of bytes actually written; -1 on error
	 */
	ssize_t bgzf_write(BGZF *fp, const void *data, ssize_t length);

	/**
	 * Write the data in the buffer to the file.
	 */
	int bgzf_flush(BGZF *fp);

	/**
	 * Return a virtual file pointer to the current location in the file.
	 * No interpetation of the value should be made, other than a subsequent
	 * call to bgzf_seek can be used to position the file at the same point.
	 * Return value is non-negative on success.
	 */
	#define bgzf_tell(fp) ((fp->block_address << 16) | (fp->block_offset & 0xFFFF))

	/**
	 * Set the file to read from the location specified by _pos_.
	 *
	 * @param fp     BGZF file handler
	 * @param pos    virtual file offset returned by bgzf_tell()
	 * @param whence must be SEEK_SET
	 * @return       0 on success and -1 on error
	 */
	int64_t bgzf_seek(BGZF *fp, int64_t pos, int whence);

	/**
	 * Check if the BGZF end-of-file (EOF) marker is present
	 *
	 * @param fp    BGZF file handler opened for reading
	 * @return      1 if EOF is present; 0 if not or on I/O error
	 */
	int bgzf_check_EOF(BGZF *fp);

	/**
	 * Check if a file is in the BGZF format
	 *
	 * @param fn    file name
	 * @return      1 if _fn_ is BGZF; 0 if not or on I/O error
	 */
	 int bgzf_is_bgzf(const char *fn);

	/*********************
	 * Advanced routines *
	 *********************/

	/**
	 * Set the cache size. Only effective when compiled with -DBGZF_CACHE.
	 *
	 * @param fp    BGZF file handler
	 * @param size  size of cache in bytes; 0 to disable caching (default)
	 */
	void bgzf_set_cache_size(BGZF *fp, int size);

	/**
	 * Flush the file if the remaining buffer size is smaller than _size_ 
	 */
	int bgzf_flush_try(BGZF *fp, ssize_t size);

	/**
	 * Read one byte from a BGZF file. It is faster than bgzf_read()
	 * @param fp     BGZF file handler
	 * @return       byte read; -1 on end-of-file or error
	 */
	int bgzf_getc(BGZF *fp);

	/**
	 * Read one line from a BGZF file. It is faster than bgzf_getc()
	 *
	 * @param fp     BGZF file handler
	 * @param delim  delimitor
	 * @param str    string to write to; must be initialized
	 * @return       length of the string; 0 on end-of-file; negative on error
	 */
	int bgzf_getline(BGZF *fp, int delim, kstring_t *str);

	/**
	 * Read the next BGZF block.
	 */
	int bgzf_read_block(BGZF *fp);

#ifdef __cplusplus
}
#endif

#endif
