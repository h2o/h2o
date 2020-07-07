/*
** mrdb.h - mruby debugger
**
*/

#ifndef MRDB_H
#define MRDB_H

#include <mruby.h>

#include "mrdbconf.h"

#ifdef _MSC_VER
# define __func__ __FUNCTION__
#endif

#define MAX_COMMAND_WORD (16)

typedef enum debug_command_id {
  DBGCMD_RUN,
  DBGCMD_CONTINUE,
  DBGCMD_NEXT,
  DBGCMD_STEP,
  DBGCMD_BREAK,
  DBGCMD_INFO_BREAK,
  DBGCMD_INFO_LOCAL,
  DBGCMD_WATCH,
  DBGCMD_INFO_WATCH,
  DBGCMD_ENABLE,
  DBGCMD_DISABLE,
  DBGCMD_DELETE,
  DBGCMD_PRINT,
  DBGCMD_DISPLAY,
  DBGCMD_INFO_DISPLAY,
  DBGCMD_DELETE_DISPLAY,
  DBGCMD_EVAL,
  DBGCMD_BACKTRACE,
  DBGCMD_LIST,
  DBGCMD_HELP,
  DBGCMD_QUIT,
  DBGCMD_UNKNOWN
} debug_command_id;

typedef enum dbgcmd_state {
  DBGST_CONTINUE,
  DBGST_PROMPT,
  DBGST_COMMAND_ERROR,
  DBGST_MAX,
  DBGST_RESTART
} dbgcmd_state;

typedef enum mrdb_exemode {
  DBG_INIT,
  DBG_RUN,
  DBG_STEP,
  DBG_NEXT,
  DBG_QUIT,
} mrdb_exemode;

typedef enum mrdb_exephase {
  DBG_PHASE_BEFORE_RUN,
  DBG_PHASE_RUNNING,
  DBG_PHASE_AFTER_RUN,
  DBG_PHASE_RESTART,
} mrdb_exephase;

typedef enum mrdb_brkmode {
  BRK_INIT,
  BRK_BREAK,
  BRK_STEP,
  BRK_NEXT,
  BRK_QUIT,
} mrdb_brkmode;

typedef enum {
  MRB_DEBUG_BPTYPE_NONE,
  MRB_DEBUG_BPTYPE_LINE,
  MRB_DEBUG_BPTYPE_METHOD,
} mrb_debug_bptype;

struct mrb_irep;
struct mrbc_context;
struct mrb_debug_context;

typedef struct mrb_debug_linepoint {
  const char *file;
  uint16_t lineno;
} mrb_debug_linepoint;

typedef struct mrb_debug_methodpoint {
  const char *class_name;
  const char *method_name;
} mrb_debug_methodpoint;

typedef struct mrb_debug_breakpoint {
  uint32_t bpno;
  uint8_t enable;
  mrb_debug_bptype type;
  union point {
    mrb_debug_linepoint linepoint;
    mrb_debug_methodpoint methodpoint;
  } point;
} mrb_debug_breakpoint;

typedef struct mrb_debug_context {
  struct mrb_irep *root_irep;
  struct mrb_irep *irep;
  const mrb_code *pc;
  mrb_value *regs;

  const char *prvfile;
  int32_t prvline;
  mrb_callinfo *prvci;

  mrdb_exemode xm;
  mrdb_exephase xphase;
  mrdb_brkmode bm;
  int16_t bmi;

  uint16_t ccnt;
  uint16_t scnt;

  mrb_debug_breakpoint bp[MAX_BREAKPOINT];
  uint32_t bpnum;
  int32_t next_bpno;
  int32_t method_bpno;
  int32_t stopped_bpno;
  mrb_bool isCfunc;

  mrdb_exemode (*break_hook)(mrb_state *mrb, struct mrb_debug_context *dbg);

} mrb_debug_context;

typedef struct mrdb_state {
  char *command;
  uint8_t wcnt;
  uint8_t pi;
  char *words[MAX_COMMAND_WORD];
  const char *srcpath;
  uint32_t print_no;

  mrb_debug_context *dbg;
} mrdb_state;

typedef dbgcmd_state (*debug_command_func)(mrb_state*, mrdb_state*);

/* cmdrun.c */
dbgcmd_state dbgcmd_run(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_continue(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_step(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_next(mrb_state*, mrdb_state*);
/* cmdbreak.c */
dbgcmd_state dbgcmd_break(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_info_break(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_info_local(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_delete(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_enable(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_disable(mrb_state*, mrdb_state*);
/* cmdprint.c */
dbgcmd_state dbgcmd_print(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_eval(mrb_state*, mrdb_state*);
/* cmdmisc.c */
dbgcmd_state dbgcmd_list(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_help(mrb_state*, mrdb_state*);
dbgcmd_state dbgcmd_quit(mrb_state*, mrdb_state*);

#endif
