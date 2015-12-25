/*
 * apiprint.h
 */

#ifndef APIPRINT_H_
#define APIPRINT_H_

#include <mruby.h>
#include "mrdb.h"

mrb_value mrb_debug_eval(mrb_state*, mrb_debug_context*, const char*, size_t, mrb_bool*);

#endif /* APIPRINT_H_ */
