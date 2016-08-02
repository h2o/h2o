/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "h2o/file.h"

h2o_iovec_t h2o_file_read(const char *fn)
{
    int fd;
    struct stat st;
    h2o_iovec_t ret = {NULL};

    /* open */
    if ((fd = open(fn, O_RDONLY | O_CLOEXEC)) == -1)
        goto Error;
    fstat(fd, &st);
    /* allocate memory */
    if (st.st_size > SIZE_MAX) {
        errno = ENOMEM;
        goto Error;
    }
    if ((ret.base = malloc((size_t)st.st_size)) == NULL)
        goto Error;
    /* read */
    while (ret.len != (size_t)st.st_size) {
        ssize_t r;
        while ((r = read(fd, ret.base + ret.len, (size_t)st.st_size - ret.len)) == -1 && errno == EINTR)
            ;
        if (r <= 0)
            goto Error;
        ret.len += r;
    }
    /* close */
    close(fd);
    return ret;

Error:
    if (fd != -1)
        close(fd);
    free(ret.base);
    return (h2o_iovec_t){NULL};
}
