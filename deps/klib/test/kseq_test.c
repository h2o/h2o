#include <zlib.h>
#include <stdio.h>
#include "kseq.h"
KSEQ_INIT(gzFile, gzread)

int main(int argc, char *argv[])
{
	gzFile fp;
	kseq_t *seq;
	int l;
	if (argc == 1) {
		fprintf(stderr, "Usage: %s <in.fasta>\n", argv[0]);
		return 1;
	}
	fp = gzopen(argv[1], "r");
	seq = kseq_init(fp);
	while ((l = kseq_read(seq)) >= 0) {
		printf("name: %s\n", seq->name.s);
		if (seq->comment.l) printf("comment: %s\n", seq->comment.s);
		printf("seq: %s\n", seq->seq.s);
		if (seq->qual.l) printf("qual: %s\n", seq->qual.s);
	}
	printf("return value: %d\n", l);
	kseq_destroy(seq);
	gzclose(fp);
	return 0;
}
