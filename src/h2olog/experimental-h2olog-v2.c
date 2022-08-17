/*
 * Copyright (c) 2022 Fastly, Inc., Goro Fuji.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#ifndef H2OLOG_DEFAULT_SOCKET_PATH
#define H2OLOG_DEFAULT_SOCKET_PATH "/tmp/h2olog.sock"
#endif

static void usage(const char *prog_name, FILE *fp)
{
    fprintf(fp, "Usage: %s -u socket_file\n", prog_name);
}

static const char *guess_socket_file(void)
{
    const char *socket_file = getenv("H2OLOG_SOCKET");
    if (socket_file) {
        return socket_file;
    }
    return H2OLOG_DEFAULT_SOCKET_PATH;
}

int main(int argc, char *argv[])
{
    int c;
    const char *socket_file = NULL;
    while ((c = getopt(argc, argv, "hu:")) != -1) {
        switch (c) {
        case 'u':
            socket_file = optarg;
            break;
        case 'h':
            usage(argv[0], stdout);
            return 0;
        default:
            assert(0);
            return EXIT_FAILURE;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "too many arguments.\n");
        usage(argv[0], stderr);
        return EXIT_FAILURE;
    }

    if (!socket_file) {
        socket_file = guess_socket_file();
    }

    struct sockaddr_un sa = {
        .sun_family = AF_UNIX,
    };
    if (strlen(socket_file) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "'%s' is too long as the name of a unix domain socket.\n", socket_file);
    }
    strcpy(sa.sun_path, socket_file);

    int fd;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("failed to create a socket");
        return EXIT_FAILURE;
    }
    if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("failed to connect to the socket");
        return EXIT_FAILURE;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    while (select(fd + 1, &fds, NULL, NULL, NULL) > 0) {
        char buf[4096];
        ssize_t ret = read(fd, buf, sizeof(buf));
        if (ret == -1) {
            if (ret != EINTR)
                break;
        } else if (ret > 0) {
            fwrite(buf, 1, ret, stdout);
        } else {
            // disconnected
            break;
        }
    }
    close(fd);

    return 0;
}
