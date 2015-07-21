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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* taken from sysexits.h */
#ifndef EX_OSERR
#define EX_OSERR 71
#endif
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

#define NOTIFY_FD 5

int main(int argc, char **argv)
{
    int opt_ch;
    const char *rmpath = NULL;
    struct passwd *user = NULL;

    /* parse args */
    while ((opt_ch = getopt(argc, argv, "r:u:h")) != -1) {
        switch (opt_ch) {
        case 'r':
            rmpath = optarg;
            break;
        case 'u':
            if ((user = getpwnam(optarg)) == NULL) {
                fprintf(stderr, "unknown user:%s\n", optarg);
                return EX_CONFIG;
            }
            break;
        default:
            printf("%s [-u user] [r remove-path] -- cmd args\n", argv[0]);
            return 0;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc == 0) {
        fprintf(stderr, "no command\n");
        return EX_CONFIG;
    }

    /* setuid */
    if (user != NULL) {
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
    }

    /* fork and exec */
    pid_t pid = fork();
    switch (pid) {
    case -1:
        perror("fork failed");
        return EX_OSERR;
    case 0:
        close(NOTIFY_FD);
        execvp(argv[0], argv);
        fprintf(stderr, "failed to exec %s:%s\n", argv[0], strerror(errno));
        return EX_CONFIG;
    default:
        break;
    }

    /* wait until the caller stops running */
    while (1) {
        char buf[32];
        ssize_t r = read(NOTIFY_FD, buf, sizeof(buf));
        if (r == 0 || (r == -1 && errno != EINTR))
            break;
    }

    /* kill the child process */
    kill(pid, SIGTERM);
    while (waitpid(pid, NULL, 0) != pid)
        ;

    /* cleanup */
    if (rmpath != NULL) {
        execl("/bin/rm", "/bin/rm", "-rf", rmpath, NULL);
        perror("failed to exec /bin/rm");
        return EX_OSERR;
    }

    return 0;
}
