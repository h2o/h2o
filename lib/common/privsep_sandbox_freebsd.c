/*
 * Copyright (c) 2020 Christian S.J. Peron
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/capsicum.h>

#include <stdio.h>
#include <err.h>

static char *nullfs_mounts[] = {
    "bin",
    "libexec",
    "etc/ssl",
    "lib",
    "sbin",
    "usr/lib",
    "usr/libexec",
    "usr/bin",
    "usr/sbin",
    "usr/share",
    "usr/local",
    "var/",
    NULL
};

void sandbox_emit_freebsd_hints(char *root)
{
    char *path, **copy;

    copy = nullfs_mounts;
    /*
     * NB: copy /etc/passwd/group
     */
    /*
     * On Linux, we get away with --bind mounts to create the outer sandbox
     */
    while ((path = *copy++)) {
        printf("mount -t nullfs -o ro /%s %s/%s;\n", path, root, path);
    }
    /*
     * This assumes a typical FreeBSD devfs setup. rc creates default rulesets
     * for various levels of jails. We aren't going to need PTYs so we can stop
     * at level 3.
     */
    printf("mount -t devfs devfs %s/dev;\n", root);
    printf("devfs -m %s/dev ruleset 1\n", root);
    printf("devfs -m %s/dev rule applyset;\n", root);
    printf("devfs -m %s/dev ruleset 2\n", root);
    printf("devfs -m %s/dev rule applyset;\n", root);
}

void
sandbox_bind_freebsd(int policy)
{

	if (cap_enter() == -1) {
		err(1, "cap_enter failed");
	}
    printf("[PRIVSEP] sandbox type: CAPSICUM bound to process\n");
}

#endif	/* __FreeBSD__ */
