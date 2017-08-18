/*
 * Copyright (c) 2014, 2015 Joel Sing <jsing@openbsd.org>
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

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "apps.h"

static struct {
	int dryrun;
	int verbose;
} certhash_config;

struct option certhash_options[] = {
	{
		.name = "n",
		.desc = "Perform a dry-run - do not make any changes",
		.type = OPTION_FLAG,
		.opt.flag = &certhash_config.dryrun,
	},
	{
		.name = "v",
		.desc = "Verbose",
		.type = OPTION_FLAG,
		.opt.flag = &certhash_config.verbose,
	},
	{ NULL },
};

struct hashinfo {
	char *filename;
	char *target;
	unsigned long hash;
	unsigned int index;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	int is_crl;
	int is_dup;
	int exists;
	int changed;
	struct hashinfo *reference;
	struct hashinfo *next;
};

static struct hashinfo *
hashinfo(const char *filename, unsigned long hash, unsigned char *fingerprint)
{
	struct hashinfo *hi;

	if ((hi = calloc(1, sizeof(*hi))) == NULL)
		return (NULL);
	if (filename != NULL) {
		if ((hi->filename = strdup(filename)) == NULL) {
			free(hi);
			return (NULL);
		}
	}
	hi->hash = hash;
	if (fingerprint != NULL)
		memcpy(hi->fingerprint, fingerprint, sizeof(hi->fingerprint));

	return (hi);
}

static void
hashinfo_free(struct hashinfo *hi)
{
	if (hi == NULL)
		return;

	free(hi->filename);
	free(hi->target);
	free(hi);
}

#ifdef DEBUG
static void
hashinfo_print(struct hashinfo *hi)
{
	int i;

	printf("hashinfo %s %08lx %u %i\n", hi->filename, hi->hash,
	    hi->index, hi->is_crl);
	for (i = 0; i < (int)EVP_MAX_MD_SIZE; i++) {
		printf("%02X%c", hi->fingerprint[i],
		    (i + 1 == (int)EVP_MAX_MD_SIZE) ? '\n' : ':');
	}
}
#endif

static int
hashinfo_compare(const void *a, const void *b)
{
	struct hashinfo *hia = *(struct hashinfo **)a;
	struct hashinfo *hib = *(struct hashinfo **)b;
	int rv;

	rv = hia->hash < hib->hash ? -1 : hia->hash > hib->hash;
	if (rv != 0)
		return (rv);
	rv = memcmp(hia->fingerprint, hib->fingerprint,
	    sizeof(hia->fingerprint));
	if (rv != 0)
		return (rv);
	return strcmp(hia->filename, hib->filename);
}

static struct hashinfo *
hashinfo_chain(struct hashinfo *head, struct hashinfo *entry)
{
	struct hashinfo *hi = head;

	if (hi == NULL)
		return (entry);
	while (hi->next != NULL)
		hi = hi->next;
	hi->next = entry;

	return (head);
}

static void
hashinfo_chain_free(struct hashinfo *hi)
{
	struct hashinfo *next;

	while (hi != NULL) {
		next = hi->next;
		hashinfo_free(hi);
		hi = next;
	}
}

static size_t
hashinfo_chain_length(struct hashinfo *hi)
{
	int len = 0;

	while (hi != NULL) {
		len++;
		hi = hi->next;
	}
	return (len);
}

static int
hashinfo_chain_sort(struct hashinfo **head)
{
	struct hashinfo **list, *entry;
	size_t len;
	int i;

	if (*head == NULL)
		return (0);

	len = hashinfo_chain_length(*head);
	if ((list = reallocarray(NULL, len, sizeof(struct hashinfo *))) == NULL)
		return (-1);

	for (entry = *head, i = 0; entry != NULL; entry = entry->next, i++)
		list[i] = entry;
	qsort(list, len, sizeof(struct hashinfo *), hashinfo_compare);

	*head = entry = list[0];
	for (i = 1; i < len; i++) {
		entry->next = list[i];
		entry = list[i];
	}
	entry->next = NULL;

	free(list);
	return (0);
}

static char *
hashinfo_linkname(struct hashinfo *hi)
{
	char *filename;

	if (asprintf(&filename, "%08lx.%s%u", hi->hash,
	    (hi->is_crl ? "r" : ""), hi->index) == -1)
		return (NULL);

	return (filename);
}

static int
filename_is_hash(const char *filename)
{
	const char *p = filename;

	while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))
		p++;
	if (*p++ != '.')
		return (0);
	if (*p == 'r')		/* CRL format. */
		p++;
	while (*p >= '0' && *p <= '9')
		p++;
	if (*p != '\0')
		return (0);

	return (1);
}

static int
filename_is_pem(const char *filename)
{
	const char *q, *p = filename;

	if ((q = strchr(p, '\0')) == NULL)
		return (0);
	if ((q - p) < 4)
		return (0);
	if (strncmp((q - 4), ".pem", 4) != 0)
		return (0);

	return (1);
}

static struct hashinfo *
hashinfo_from_linkname(const char *linkname, const char *target)
{
	struct hashinfo *hi = NULL;
	const char *errstr;
	char *l, *p, *ep;
	long long val;

	if ((l = strdup(linkname)) == NULL)
		goto err;
	if ((p = strchr(l, '.')) == NULL)
		goto err;
	*p++ = '\0';

	if ((hi = hashinfo(linkname, 0, NULL)) == NULL)
		goto err;
	if ((hi->target = strdup(target)) == NULL)
		goto err;

	errno = 0;
	val = strtoll(l, &ep, 16);
	if (l[0] == '\0' || *ep != '\0')
		goto err;
	if (errno == ERANGE && (val == LLONG_MAX || val == LLONG_MIN))
		goto err;
	if (val < 0 || val > ULONG_MAX)
		goto err;
	hi->hash = (unsigned long)val;

	if (*p == 'r') {
		hi->is_crl = 1;
		p++;
	}

	val = strtonum(p, 0, 0xffffffff, &errstr);
	if (errstr != NULL)
		goto err;

	hi->index = (unsigned int)val;

	goto done;

err:
	hashinfo_free(hi);
	hi = NULL;

done:
	free(l);

	return (hi);
}

static struct hashinfo *
certhash_cert(BIO *bio, const char *filename)
{
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	struct hashinfo *hi = NULL;
	const EVP_MD *digest;
	X509 *cert = NULL;
	unsigned long hash;
	unsigned int len;

	if ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL)
		goto err;

	hash = X509_subject_name_hash(cert);

	digest = EVP_sha256();
	if (X509_digest(cert, digest, fingerprint, &len) != 1) {
		fprintf(stderr, "out of memory\n");
		goto err;
	}

	hi = hashinfo(filename, hash, fingerprint);

err:
	X509_free(cert);

	return (hi);
}

static struct hashinfo *
certhash_crl(BIO *bio, const char *filename)
{
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	struct hashinfo *hi = NULL;
	const EVP_MD *digest;
	X509_CRL *crl = NULL;
	unsigned long hash;
	unsigned int len;

	if ((crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL)) == NULL)
		return (NULL);

	hash = X509_NAME_hash(X509_CRL_get_issuer(crl));

	digest = EVP_sha256();
	if (X509_CRL_digest(crl, digest, fingerprint, &len) != 1) {
		fprintf(stderr, "out of memory\n");
		goto err;
	}

	hi = hashinfo(filename, hash, fingerprint);

err:
	X509_CRL_free(crl);

	return (hi);
}

static int
certhash_addlink(struct hashinfo **links, struct hashinfo *hi)
{
	struct hashinfo *link = NULL;

	if ((link = hashinfo(NULL, hi->hash, hi->fingerprint)) == NULL)
		goto err;

	if ((link->filename = hashinfo_linkname(hi)) == NULL)
		goto err;

	link->reference = hi;
	link->changed = 1;
	*links = hashinfo_chain(*links, link);
	hi->reference = link;

	return (0);

err:
	hashinfo_free(link);
	return (-1);
}

static void
certhash_findlink(struct hashinfo *links, struct hashinfo *hi)
{
	struct hashinfo *link;

	for (link = links; link != NULL; link = link->next) {
		if (link->is_crl == hi->is_crl &&
		    link->hash == hi->hash &&
		    link->index == hi->index &&
		    link->reference == NULL) {
			link->reference = hi;
			if (link->target == NULL ||
			    strcmp(link->target, hi->filename) != 0)
				link->changed = 1;
			hi->reference = link;
			break;
		}
	}
}

static void
certhash_index(struct hashinfo *head, const char *name)
{
	struct hashinfo *last, *entry;
	int index = 0;

	last = NULL;
	for (entry = head; entry != NULL; entry = entry->next) {
		if (last != NULL) {
			if (entry->hash == last->hash) {
				if (memcmp(entry->fingerprint,
				    last->fingerprint,
				    sizeof(entry->fingerprint)) == 0) {
					fprintf(stderr, "WARNING: duplicate %s "
					    "in %s (using %s), ignoring...\n",
					    name, entry->filename,
					    last->filename);
					entry->is_dup = 1;
					continue;
				}
				index++;
			} else {
				index = 0;
			}
		}
		entry->index = index;
		last = entry;
	}
}

static int
certhash_merge(struct hashinfo **links, struct hashinfo **certs,
    struct hashinfo **crls)
{
	struct hashinfo *cert, *crl;

	/* Pass 1 - sort and index entries. */
	if (hashinfo_chain_sort(certs) == -1)
		return (-1);
	if (hashinfo_chain_sort(crls) == -1)
		return (-1);
	certhash_index(*certs, "certificate");
	certhash_index(*crls, "CRL");

	/* Pass 2 - map to existing links. */
	for (cert = *certs; cert != NULL; cert = cert->next) {
		if (cert->is_dup == 1)
			continue;
		certhash_findlink(*links, cert);
	}
	for (crl = *crls; crl != NULL; crl = crl->next) {
		if (crl->is_dup == 1)
			continue;
		certhash_findlink(*links, crl);
	}

	/* Pass 3 - determine missing links. */
	for (cert = *certs; cert != NULL; cert = cert->next) {
		if (cert->is_dup == 1 || cert->reference != NULL)
			continue;
		if (certhash_addlink(links, cert) == -1)
			return (-1);
	}
	for (crl = *crls; crl != NULL; crl = crl->next) {
		if (crl->is_dup == 1 || crl->reference != NULL)
			continue;
		if (certhash_addlink(links, crl) == -1)
			return (-1);
	}

	return (0);
}

static int
certhash_link(struct dirent *dep, struct hashinfo **links)
{
	struct hashinfo *hi = NULL;
	char target[PATH_MAX];
	struct stat sb;
	int n;

	if (lstat(dep->d_name, &sb) == -1) {
		fprintf(stderr, "failed to stat %s\n", dep->d_name);
		return (-1);
	}
	if (!S_ISLNK(sb.st_mode))
		return (0);

	n = readlink(dep->d_name, target, sizeof(target) - 1);
	if (n == -1) {
		fprintf(stderr, "failed to readlink %s\n", dep->d_name);
		return (-1);
	}
	target[n] = '\0';

	hi = hashinfo_from_linkname(dep->d_name, target);
	if (hi == NULL) {
		fprintf(stderr, "failed to get hash info %s\n", dep->d_name);
		return (-1);
	}
	hi->exists = 1;
	*links = hashinfo_chain(*links, hi);

	return (0);
}

static int
certhash_file(struct dirent *dep, struct hashinfo **certs,
    struct hashinfo **crls)
{
	struct hashinfo *hi = NULL;
	int has_cert, has_crl;
	int ret = -1;
	BIO *bio = NULL;
	FILE *f;

	has_cert = has_crl = 0;

	if ((f = fopen(dep->d_name, "r")) == NULL) {
		fprintf(stderr, "failed to fopen %s\n", dep->d_name);
		goto err;
	}
	if ((bio = BIO_new_fp(f, BIO_CLOSE)) == NULL) {
		fprintf(stderr, "failed to create bio\n");
		fclose(f);
		goto err;
	}

	if ((hi = certhash_cert(bio, dep->d_name)) != NULL) {
		has_cert = 1;
		*certs = hashinfo_chain(*certs, hi);
	}

	if (BIO_reset(bio) != 0) {
		fprintf(stderr, "BIO_reset failed\n");
		goto err;
	}

	if ((hi = certhash_crl(bio, dep->d_name)) != NULL) {
		has_crl = hi->is_crl = 1;
		*crls = hashinfo_chain(*crls, hi);
	}

	if (!has_cert && !has_crl)
		fprintf(stderr, "PEM file %s does not contain a certificate "
		    "or CRL, ignoring...\n", dep->d_name);

	ret = 0;

err:
	BIO_free(bio);

	return (ret);
}

static int
certhash_directory(const char *path)
{
	struct hashinfo *links = NULL, *certs = NULL, *crls = NULL, *link;
	int ret = 0;
	struct dirent *dep;
	DIR *dip = NULL;

	if ((dip = opendir(".")) == NULL) {
		fprintf(stderr, "failed to open directory %s\n", path);
		goto err;
	}

	if (certhash_config.verbose)
		fprintf(stdout, "scanning directory %s\n", path);

	/* Create lists of existing hash links, certs and CRLs. */
	while ((dep = readdir(dip)) != NULL) {
		if (filename_is_hash(dep->d_name)) {
			if (certhash_link(dep, &links) == -1)
				goto err;
		}
		if (filename_is_pem(dep->d_name)) {
			if (certhash_file(dep, &certs, &crls) == -1)
				goto err;
		}
	}

	if (certhash_merge(&links, &certs, &crls) == -1) {
		fprintf(stderr, "certhash merge failed\n");
		goto err;
	}

	/* Remove spurious links. */
	for (link = links; link != NULL; link = link->next) {
		if (link->exists == 0 ||
		    (link->reference != NULL && link->changed == 0))
			continue;
		if (certhash_config.verbose)
			fprintf(stdout, "%s link %s -> %s\n",
			    (certhash_config.dryrun ? "would remove" :
				"removing"), link->filename, link->target);
		if (certhash_config.dryrun)
			continue;
		if (unlink(link->filename) == -1) {
			fprintf(stderr, "failed to remove link %s\n",
			    link->filename);
			goto err;
		}
	}

	/* Create missing links. */
	for (link = links; link != NULL; link = link->next) {
		if (link->exists == 1 && link->changed == 0)
			continue;
		if (certhash_config.verbose)
			fprintf(stdout, "%s link %s -> %s\n",
			    (certhash_config.dryrun ? "would create" :
				"creating"), link->filename,
			    link->reference->filename);
		if (certhash_config.dryrun)
			continue;
		if (symlink(link->reference->filename, link->filename) == -1) {
			fprintf(stderr, "failed to create link %s -> %s\n",
			    link->filename, link->reference->filename);
			goto err;
		}
	}

	goto done;

err:
	ret = 1;

done:
	hashinfo_chain_free(certs);
	hashinfo_chain_free(crls);
	hashinfo_chain_free(links);

	if (dip != NULL)
		closedir(dip);
	return (ret);
}

static void
certhash_usage(void)
{
	fprintf(stderr, "usage: certhash [-nv] dir ...\n");
	options_usage(certhash_options);
}

int
certhash_main(int argc, char **argv)
{
	int argsused;
	int i, cwdfd, ret = 0;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&certhash_config, 0, sizeof(certhash_config));

	if (options_parse(argc, argv, certhash_options, NULL, &argsused) != 0) {
                certhash_usage();
                return (1);
        }

	if ((cwdfd = open(".", O_RDONLY)) == -1) {
		perror("failed to open current directory");
		return (1);
	}

	for (i = argsused; i < argc; i++) {
		if (chdir(argv[i]) == -1) {
			fprintf(stderr,
			    "failed to change to directory %s: %s\n",
			    argv[i], strerror(errno));
			ret = 1;
			continue;
		}
		ret |= certhash_directory(argv[i]);
		if (fchdir(cwdfd) == -1) {
			perror("failed to restore current directory");
			ret = 1;
			break;		/* can't continue safely */
		}
	}
	close(cwdfd);

	return (ret);
}
