/*
 * Public domain
 * certhash dummy implementation for platforms without symlinks
 */

#include "apps.h"

int
certhash_main(int argc, char **argv)
{
	fprintf(stderr, "certhash is not enabled on this platform\n");
	return (1);
}
