#include <zlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include "kseq.h"

#define BUF_SIZE 4096
KSTREAM_INIT(gzFile, gzread, BUF_SIZE)

int main(int argc, char *argv[])
{
	gzFile fp;
	clock_t t;
	if (argc == 1) {
		fprintf(stderr, "Usage: kseq_bench <in.gz>\n");
		return 1;
	}
	{
		uint8_t *buf = malloc(BUF_SIZE);
		fp = gzopen(argv[1], "r");
		t = clock();
		while (gzread(fp, buf, BUF_SIZE) > 0);
		fprintf(stderr, "[gzread] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
		gzclose(fp);
		free(buf);
	}
	{
		kstream_t *ks;
		fp = gzopen(argv[1], "r");
		ks = ks_init(fp);
		t = clock();
		while (ks_getc(ks) >= 0);
		fprintf(stderr, "[ks_getc] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
		ks_destroy(ks);
		gzclose(fp);
	}
	{
		kstream_t *ks;
		kstring_t *s;
		int dret;
		s = calloc(1, sizeof(kstring_t));
		fp = gzopen(argv[1], "r");
		ks = ks_init(fp);
		t = clock();
		while (ks_getuntil(ks, '\n', s, &dret) >= 0);
		fprintf(stderr, "[ks_getuntil] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
		ks_destroy(ks);
		gzclose(fp);
		free(s->s); free(s);
	}
	if (argc == 2) {
		fp = gzopen(argv[1], "r");
		t = clock();
		while (gzgetc(fp) >= 0);
		fprintf(stderr, "[gzgetc] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
		gzclose(fp);
	}
	if (argc == 2) {
		char *buf = malloc(BUF_SIZE);
		fp = gzopen(argv[1], "r");
		t = clock();
		while (gzgets(fp, buf, BUF_SIZE) > 0);
		fprintf(stderr, "[gzgets] %.2f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
		gzclose(fp);
		free(buf);
	}
	return 0;
}
