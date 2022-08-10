/*
** apistring.c
**
*/

#include <string.h>
#include "apistring.h"

static size_t
mrb_debug_strnlen(const char *s, size_t maxlen)
{
  const char *p = (const char*)memchr(s, '\0', maxlen);
  return p != NULL ? (size_t)(p - s) : maxlen;
}

char*
mrdb_strndup(mrb_state *mrb, const char *s, size_t size)
{
  size_t l = mrb_debug_strnlen(s, size);
  char *d = (char*)mrb_malloc_simple(mrb, l + 1);
  if (d != NULL) {
    memcpy(d, s, l);
    d[l] = '\0';
  }
  return d;
}

char*
mrdb_strdup(mrb_state *mrb, const char *s)
{
  size_t z = strlen(s) + 1;
  char *d = (char*)mrb_malloc_simple(mrb, z);
  return d != NULL ? (char*)memcpy(d, s, z) : NULL;
}
