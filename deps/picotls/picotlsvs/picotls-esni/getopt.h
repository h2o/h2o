#ifndef GETOPT_H
#ifndef __APPLE__

#define GETOPT_H

#ifndef _GETOPT_H
#define _GETOPT_H
#endif

extern int opterr; /* if error message should be printed */
extern int optind; /* index into parent argv vector */
extern int optopt; /* character checked for validity */
extern int optreset; /* reset getopt  */
extern const char* optarg; /* argument associated with option */

int getopt(int nargc, char* const nargv[], const char* ostr);

#endif
#endif
