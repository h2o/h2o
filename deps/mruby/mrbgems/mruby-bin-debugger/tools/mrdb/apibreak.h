/*
** apibreak.h
**
*/

#ifndef APIBREAK_H_
#define APIBREAK_H_

#include <mruby.h>
#include "mrdb.h"

int32_t mrb_debug_set_break_line(mrb_state *, mrb_debug_context *, const char *, uint16_t);
int32_t mrb_debug_set_break_method(mrb_state *, mrb_debug_context *, const char *, const char *);
int32_t mrb_debug_get_breaknum(mrb_state *, mrb_debug_context *);
int32_t mrb_debug_get_break_all(mrb_state *, mrb_debug_context *, uint32_t, mrb_debug_breakpoint bp[]);
int32_t mrb_debug_get_break(mrb_state *, mrb_debug_context *, uint32_t, mrb_debug_breakpoint *);
int32_t mrb_debug_delete_break(mrb_state *, mrb_debug_context *, uint32_t);
int32_t mrb_debug_delete_break_all(mrb_state *, mrb_debug_context *);
int32_t mrb_debug_enable_break(mrb_state *, mrb_debug_context *, uint32_t);
int32_t mrb_debug_enable_break_all(mrb_state *, mrb_debug_context *);
int32_t mrb_debug_disable_break(mrb_state *, mrb_debug_context *, uint32_t);
int32_t mrb_debug_disable_break_all(mrb_state *, mrb_debug_context *);
int32_t mrb_debug_check_breakpoint_line(mrb_state *, mrb_debug_context *, const char *, uint16_t);
int32_t mrb_debug_check_breakpoint_method(mrb_state *, mrb_debug_context *, struct RClass *, mrb_sym, mrb_bool*);

#endif /* APIBREAK_H_ */
