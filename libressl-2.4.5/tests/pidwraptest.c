/*
 * Checks if LibreSSL's PRNG is fork-safe.
 * From https://www.agwa.name/blog/post/libressls_prng_is_unsafe_on_linux
 * This code is in the public domain.
 *
 * Original source: https://gist.github.com/AGWA/eb84e55ca25a7da1deb0
 */

#undef LIBRESSL_INTERNAL
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static void random_bytes (unsigned char* p, size_t len)
{
	if (RAND_bytes(p, len) != 1) {
		fprintf(stderr, "RAND_bytes failed\n");
		abort();
	}
}

static void random_stir (void)
{
	if (RAND_poll() != 1) {
		fprintf(stderr, "RAND_poll failed\n");
		abort();
	}
}

static void print_buffer (unsigned char* p, size_t len)
{
	while (len--) {
		printf("%02x", (unsigned int)*p++);
	}
}

int main ()
{
	char c = 0;
	int	pipefd[2];
	pipe(pipefd);
	setbuf(stdout, NULL);

	if (fork() == 0) {
		unsigned char buffer[32];
		pid_t grandparent_pid = getpid();

		random_bytes(buffer, sizeof(buffer));

		if (fork() == 0) {
			random_stir();
			setsid();
			while (1) {
				pid_t	grandchild_pid = fork();
				if (grandchild_pid == 0) {
					random_stir();
					if (getpid() == grandparent_pid) {
						random_bytes(buffer, sizeof(buffer));
						print_buffer(buffer, sizeof(buffer));
						printf("\n");
					}
					_exit(0);
				}
				wait(NULL);
				if (grandchild_pid == grandparent_pid) {
					break;
				}
			}
			write(pipefd[1], &c, 1);
			_exit(0);
		}

		random_bytes(buffer, sizeof(buffer));
		print_buffer(buffer, sizeof(buffer));
		printf(" ");
		_exit(0);
	}
	wait(NULL);
	close(pipefd[1]);
	read(pipefd[0], &c, 1);
	return 0;
}

