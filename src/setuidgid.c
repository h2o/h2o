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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* taken from sysexits.h */
#ifndef EX_OSERR
#define EX_OSERR 71
#endif
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

int main(int argc, char **argv)
{
    struct passwd *user;

    if (argc < 3) {
        fprintf(stderr, "no command (usage: setuidgid user cmd args...)\n");
        return EX_CONFIG;
    }
    --argc;
    ++argv;

    errno = 0;
    if ((user = getpwnam(*argv)) == NULL) {
        if (errno == 0) {
            fprintf(stderr, "unknown user:%s\n", *argv);
            return EX_CONFIG;
        } else {
            perror("getpwnam");
            return EX_OSERR;
        }
    }
    --argc;
    ++argv;

    if (setgid(user->pw_gid) != 0) {
        perror("setgid failed");
        return EX_OSERR;
    }
    if (initgroups(user->pw_name, user->pw_gid) != 0) {
        perror("initgroups failed");
        return EX_OSERR;
    }
    if (setuid(user->pw_uid) != 0) {
        perror("setuid failed");
        return EX_OSERR;
    }

    execvp(*argv, argv);
    fprintf(stderr, "execvp failed to launch file:%s:%s\n", *argv, strerror(errno));
    return EX_OSERR;
}
