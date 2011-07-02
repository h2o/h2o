#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include "kseq.h"
KSTREAM_INIT(int, read, 4096)

#define BUF_SIZE 65536

int main(int argc, char *argv[])
{
	clock_t t;
	if (argc == 1) {
		fprintf(stderr, "Usage: %s <in.txt>\n", argv[0]);
		return 1;
	}
	{
		FILE *fp;
		char *s;
		t = clock();
		s = malloc(BUF_SIZE);
		fp = fopen(argv[1], "r");
		while (fgets(s, BUF_SIZE, fp));
		fclose(fp);
		fprintf(stderr, "[fgets] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
	}
	{
		int fd, dret;
		kstream_t *ks;
		kstring_t s;
		t = clock();
		s.l = s.m = 0; s.s = 0;
		fd = open(argv[1], O_RDONLY);
		ks = ks_init(fd);
		while (ks_getuntil(ks, '\n', &s, &dret) >= 0);
		free(s.s);
		ks_destroy(ks);
		close(fd);
		fprintf(stderr, "[kstream] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
	}
	return 0;
}
