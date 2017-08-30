/*
 * apilist.h
 */

#ifndef APILIST_H_
#define APILIST_H_

#include <mruby.h>
#include "mrdb.h"

int32_t mrb_debug_list(mrb_state *, mrb_debug_context *, char *, uint16_t, uint16_t);
char* mrb_debug_get_source(mrb_state *, mrdb_state *, const char *, const char *);

#endif /* APILIST_H_ */
