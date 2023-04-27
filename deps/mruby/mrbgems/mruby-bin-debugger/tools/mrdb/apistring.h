/*
 * apistring.h
 */

#ifndef APISTRING_H_
#define APISTRING_H_

#include "mruby.h"

/* both functions return a null pointer on failure */
char *mrdb_strndup(mrb_state *mrb, const char *s, size_t size);
char *mrdb_strdup(mrb_state *mrb, const char *s);

#endif /* APISTRING_H_ */
