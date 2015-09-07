/*
** cmdrun.c - mruby debugger run command functions
**
*/

#include "mruby/opcode.h"
#include "mrdb.h"

dbgcmd_state
dbgcmd_run(mrb_state *mrb, mrdb_state *mrdb)
{
  mrb_debug_context *dbg = mrdb->dbg;

  if( dbg->xm == DBG_INIT ){
    dbg->xm = DBG_RUN;
  } else {
    dbg->xm = DBG_QUIT;
    if( dbg->xphase == DBG_PHASE_RUNNING ){
      struct RClass *exc;
      puts("Start it from the beginning.");
      exc = mrb_define_class(mrb, "DebuggerRestart", mrb_class_get(mrb, "Exception"));
      mrb_raise(mrb, exc, "Restart mrdb.");
    }
  }
  
  return DBGST_RESTART;
}

dbgcmd_state
dbgcmd_continue(mrb_state *mrb, mrdb_state *mrdb)
{
  mrb_debug_context *dbg = mrdb->dbg;
  int ccnt = 1;

  if( mrdb->wcnt > 1 ){
    sscanf(mrdb->words[1], "%d", &ccnt);
  }
  dbg->ccnt = (uint16_t)(ccnt > 0 ? ccnt : 1);  /* count of continue */

  if( dbg->xphase == DBG_PHASE_AFTER_RUN ){
    puts("The program is not running.");
    dbg->xm = DBG_QUIT;
  } else {
    dbg->xm = DBG_RUN;
  }
  return DBGST_CONTINUE;
}

dbgcmd_state
dbgcmd_step(mrb_state *mrb, mrdb_state *mrdb)
{
  mrdb->dbg->xm = DBG_STEP;
  return DBGST_CONTINUE;
}
