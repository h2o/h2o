/*
** apibreak.c
**
*/

#include <string.h>
#include <mruby.h>
#include <mruby/irep.h>
#include "mrdb.h"
#include <mruby/debug.h>
#include <mruby/opcode.h>
#include <mruby/class.h>
#include <mruby/proc.h>
#include <mruby/variable.h>
#include "mrdberror.h"
#include "apibreak.h"

#define MAX_BREAKPOINTNO (MAX_BREAKPOINT * 1024)
#define MRB_DEBUG_BP_FILE_OK   (0x0001)
#define MRB_DEBUG_BP_LINENO_OK (0x0002)

static uint16_t
check_lineno(mrb_irep_debug_info_file *info_file, uint16_t lineno)
{
  uint32_t count = info_file->line_entry_count;
  uint16_t l_idx;

  if (info_file->line_type == mrb_debug_line_ary) {
    for (l_idx = 0; l_idx < count; ++l_idx) {
      if (lineno == info_file->lines.ary[l_idx]) {
        return lineno;
      }
    }
  }
  else {
    for (l_idx = 0; l_idx < count; ++l_idx) {
      if (lineno == info_file->lines.flat_map[l_idx].line) {
        return lineno;
      }
    }
  }

  return 0;
}

static int32_t
get_break_index(mrb_debug_context *dbg, uint32_t bpno)
{
  uint32_t i;
  int32_t index;
  char hit = FALSE;

  for(i = 0 ; i < dbg->bpnum; i++) {
    if (dbg->bp[i].bpno == bpno) {
      hit = TRUE;
      index = i;
      break;
    }
  }

  if (hit == FALSE) {
    return MRB_DEBUG_BREAK_INVALID_NO;
  }

  return index;
}

static void
free_breakpoint(mrb_state *mrb, mrb_debug_breakpoint *bp)
{
  switch(bp->type) {
    case MRB_DEBUG_BPTYPE_LINE:
      mrb_free(mrb, (void*)bp->point.linepoint.file);
      break;
    case MRB_DEBUG_BPTYPE_METHOD:
      mrb_free(mrb, (void*)bp->point.methodpoint.method_name);
      if (bp->point.methodpoint.class_name != NULL) {
        mrb_free(mrb, (void*)bp->point.methodpoint.class_name);
      }
      break;
    default:
      break;
  }
}

static uint16_t
check_file_lineno(struct mrb_irep *irep, const char *file, uint16_t lineno)
{
  mrb_irep_debug_info_file *info_file;
  uint16_t result = 0;
  uint16_t f_idx;
  uint16_t fix_lineno;
  uint16_t i;

  for (f_idx = 0; f_idx < irep->debug_info->flen; ++f_idx) {
    info_file = irep->debug_info->files[f_idx];
    if (!strcmp(info_file->filename, file)) {
      result = MRB_DEBUG_BP_FILE_OK;

      fix_lineno = check_lineno(info_file, lineno);
      if (fix_lineno != 0) {
        return result | MRB_DEBUG_BP_LINENO_OK;
      }
    }
    for (i=0; i < irep->rlen; ++i) {
      result  |= check_file_lineno(irep->reps[i], file, lineno);
      if (result == (MRB_DEBUG_BP_FILE_OK | MRB_DEBUG_BP_LINENO_OK)) {
        return result;
      }
    }
  }
  return result;
}

static int32_t
compare_break_method(mrb_state *mrb, mrb_debug_breakpoint *bp, struct RClass *class_obj, mrb_sym method_sym, mrb_bool* isCfunc)
{
  const char* class_name;
  const char* method_name;
  mrb_method_t m;
  struct RClass* sc;
  const char* sn;
  mrb_sym ssym;
  mrb_debug_methodpoint *method_p;
  mrb_bool is_defined;

  method_name = mrb_sym2name(mrb, method_sym);

  method_p = &bp->point.methodpoint;
  if (strcmp(method_p->method_name, method_name) == 0) {
    class_name = mrb_class_name(mrb, class_obj);
    if (class_name == NULL) {
      if (method_p->class_name == NULL) {
        return bp->bpno;
      }
    }
    else if (method_p->class_name != NULL) {
      m = mrb_method_search_vm(mrb, &class_obj, method_sym);
      if (MRB_METHOD_UNDEF_P(m)) {
        return MRB_DEBUG_OK;
      }
      if (MRB_METHOD_CFUNC_P(m)) {
        *isCfunc = TRUE;
      }

      is_defined = mrb_class_defined(mrb, method_p->class_name);
      if (is_defined == FALSE) {
        return MRB_DEBUG_OK;
      }

      sc = mrb_class_get(mrb, method_p->class_name);
      ssym = mrb_symbol(mrb_check_intern_cstr(mrb, method_p->method_name));
      m = mrb_method_search_vm(mrb, &sc, ssym);
      if (MRB_METHOD_UNDEF_P(m)) {
        return MRB_DEBUG_OK;
      }

      class_name = mrb_class_name(mrb, class_obj);
      sn = mrb_class_name(mrb, sc);
      if (strcmp(sn, class_name) == 0) {
        return bp->bpno;
      }
    }
  }
  return MRB_DEBUG_OK;
}

int32_t
mrb_debug_set_break_line(mrb_state *mrb, mrb_debug_context *dbg, const char *file, uint16_t lineno)
{
  int32_t index;
  char* set_file;
  uint16_t result;

  if ((mrb == NULL)||(dbg == NULL)||(file == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  if (dbg->bpnum >= MAX_BREAKPOINT) {
    return MRB_DEBUG_BREAK_NUM_OVER;
  }

  if (dbg->next_bpno > MAX_BREAKPOINTNO) {
    return MRB_DEBUG_BREAK_NO_OVER;
  }

  /* file and lineno check (line type mrb_debug_line_ary only.) */
  result = check_file_lineno(dbg->root_irep, file, lineno);
  if (result == 0) {
    return MRB_DEBUG_BREAK_INVALID_FILE;
  }
  else if (result == MRB_DEBUG_BP_FILE_OK) {
    return MRB_DEBUG_BREAK_INVALID_LINENO;
  }

  set_file = (char*)mrb_malloc(mrb, strlen(file) + 1);

  index = dbg->bpnum;
  dbg->bp[index].bpno = dbg->next_bpno;
  dbg->next_bpno++;
  dbg->bp[index].enable = TRUE;
  dbg->bp[index].type = MRB_DEBUG_BPTYPE_LINE;
  dbg->bp[index].point.linepoint.lineno = lineno;
  dbg->bpnum++;

  strncpy(set_file, file, strlen(file) + 1);

  dbg->bp[index].point.linepoint.file = set_file;

  return dbg->bp[index].bpno;
}

int32_t
mrb_debug_set_break_method(mrb_state *mrb, mrb_debug_context *dbg, const char *class_name, const char *method_name)
{
  int32_t index;
  char* set_class;
  char* set_method;

  if ((mrb == NULL) || (dbg == NULL) || (method_name == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  if (dbg->bpnum >= MAX_BREAKPOINT) {
    return MRB_DEBUG_BREAK_NUM_OVER;
  }

  if (dbg->next_bpno > MAX_BREAKPOINTNO) {
    return MRB_DEBUG_BREAK_NO_OVER;
  }

  if (class_name != NULL) {
    set_class = (char*)mrb_malloc(mrb, strlen(class_name) + 1);
    strncpy(set_class, class_name, strlen(class_name) + 1);
  }
  else {
    set_class = NULL;
  }

  set_method = (char*)mrb_malloc(mrb, strlen(method_name) + 1);

  strncpy(set_method, method_name, strlen(method_name) + 1);

  index = dbg->bpnum;
  dbg->bp[index].bpno = dbg->next_bpno;
  dbg->next_bpno++;
  dbg->bp[index].enable = TRUE;
  dbg->bp[index].type = MRB_DEBUG_BPTYPE_METHOD;
  dbg->bp[index].point.methodpoint.method_name = set_method;
  dbg->bp[index].point.methodpoint.class_name = set_class;
  dbg->bpnum++;

  return dbg->bp[index].bpno;
}

int32_t
mrb_debug_get_breaknum(mrb_state *mrb, mrb_debug_context *dbg)
{
  if ((mrb == NULL) || (dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  return dbg->bpnum;
}

int32_t
mrb_debug_get_break_all(mrb_state *mrb, mrb_debug_context *dbg, uint32_t size, mrb_debug_breakpoint *bp)
{
  uint32_t get_size = 0;

  if ((mrb == NULL) || (dbg == NULL) || (bp == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  if (dbg->bpnum >= size) {
    get_size = size;
  }
  else {
    get_size = dbg->bpnum;
  }

  memcpy(bp, dbg->bp, sizeof(mrb_debug_breakpoint) * get_size);

  return get_size;
}

int32_t
mrb_debug_get_break(mrb_state *mrb, mrb_debug_context *dbg, uint32_t bpno, mrb_debug_breakpoint *bp)
{
  int32_t index;

  if ((mrb == NULL) || (dbg == NULL) || (bp == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  index = get_break_index(dbg, bpno);
  if (index == MRB_DEBUG_BREAK_INVALID_NO) {
    return MRB_DEBUG_BREAK_INVALID_NO;
  }

  bp->bpno = dbg->bp[index].bpno;
  bp->enable = dbg->bp[index].enable;
  bp->point = dbg->bp[index].point;
  bp->type = dbg->bp[index].type;

  return 0;
}

int32_t
mrb_debug_delete_break(mrb_state *mrb, mrb_debug_context *dbg, uint32_t bpno)
{
  uint32_t i;
  int32_t index;

  if ((mrb == NULL) ||(dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  index = get_break_index(dbg, bpno);
  if (index == MRB_DEBUG_BREAK_INVALID_NO) {
    return MRB_DEBUG_BREAK_INVALID_NO;
  }

  free_breakpoint(mrb, &dbg->bp[index]);

  for(i = index ; i < dbg->bpnum; i++) {
    if ((i + 1) == dbg->bpnum) {
      memset(&dbg->bp[i], 0, sizeof(mrb_debug_breakpoint));
    }
    else {
      memcpy(&dbg->bp[i], &dbg->bp[i + 1], sizeof(mrb_debug_breakpoint));
    }
  }

  dbg->bpnum--;

  return MRB_DEBUG_OK;
}

int32_t
mrb_debug_delete_break_all(mrb_state *mrb, mrb_debug_context *dbg)
{
  uint32_t i;

  if ((mrb == NULL) || (dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  for(i = 0 ; i < dbg->bpnum ; i++) {
    free_breakpoint(mrb, &dbg->bp[i]);
  }

  dbg->bpnum = 0;

  return MRB_DEBUG_OK;
}

int32_t
mrb_debug_enable_break(mrb_state *mrb, mrb_debug_context *dbg, uint32_t bpno)
{
  int32_t index = 0;

  if ((mrb == NULL) || (dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  index = get_break_index(dbg, bpno);
  if (index == MRB_DEBUG_BREAK_INVALID_NO) {
    return MRB_DEBUG_BREAK_INVALID_NO;
  }

  dbg->bp[index].enable = TRUE;

  return MRB_DEBUG_OK;
}

int32_t
mrb_debug_enable_break_all(mrb_state *mrb, mrb_debug_context *dbg)
{
  uint32_t i;

  if ((mrb == NULL) || (dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  for(i = 0 ; i < dbg->bpnum; i++) {
    dbg->bp[i].enable = TRUE;
  }

  return MRB_DEBUG_OK;
}

int32_t
mrb_debug_disable_break(mrb_state *mrb, mrb_debug_context *dbg, uint32_t bpno)
{
  int32_t index = 0;

  if ((mrb == NULL) || (dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  index = get_break_index(dbg, bpno);
  if (index == MRB_DEBUG_BREAK_INVALID_NO) {
    return MRB_DEBUG_BREAK_INVALID_NO;
  }

  dbg->bp[index].enable = FALSE;

  return MRB_DEBUG_OK;
}

int32_t
mrb_debug_disable_break_all(mrb_state *mrb, mrb_debug_context *dbg)
{
  uint32_t i;

  if ((mrb == NULL) || (dbg == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  for(i = 0 ; i < dbg->bpnum; i++) {
    dbg->bp[i].enable = FALSE;
  }

  return MRB_DEBUG_OK;
}

static mrb_bool
check_start_pc_for_line(mrb_irep *irep, mrb_code *pc, uint16_t line)
{
  if (pc > irep->iseq) {
    if (line == mrb_debug_get_line(irep, pc - irep->iseq - 1)) {
      return FALSE;
    }
  }
  return TRUE;
}

int32_t
mrb_debug_check_breakpoint_line(mrb_state *mrb, mrb_debug_context *dbg, const char *file, uint16_t line)
{
  mrb_debug_breakpoint *bp;
  mrb_debug_linepoint *line_p;
  uint32_t i;

  if ((mrb == NULL) || (dbg == NULL) || (file == NULL) || (line <= 0)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  if (!check_start_pc_for_line(dbg->irep, dbg->pc, line)) {
    return MRB_DEBUG_OK;
  }

  bp = dbg->bp;
  for(i=0; i<dbg->bpnum; i++) {
    switch (bp->type) {
      case MRB_DEBUG_BPTYPE_LINE:
        if (bp->enable == TRUE) {
          line_p = &bp->point.linepoint;
          if ((strcmp(line_p->file, file) == 0) && (line_p->lineno == line)) {
            return bp->bpno;
          }
        }
        break;
      case MRB_DEBUG_BPTYPE_METHOD:
        break;
      case MRB_DEBUG_BPTYPE_NONE:
      default:
        return MRB_DEBUG_OK;
    }
    bp++;
  }
  return MRB_DEBUG_OK;
}


int32_t
mrb_debug_check_breakpoint_method(mrb_state *mrb, mrb_debug_context *dbg, struct RClass *class_obj, mrb_sym method_sym, mrb_bool* isCfunc)
{
  mrb_debug_breakpoint *bp;
  int32_t bpno;
  uint32_t i;

  if ((mrb == NULL) || (dbg == NULL) || (class_obj == NULL)) {
    return MRB_DEBUG_INVALID_ARGUMENT;
  }

  bp = dbg->bp;
  for(i=0; i<dbg->bpnum; i++) {
    if (bp->type == MRB_DEBUG_BPTYPE_METHOD) {
      if (bp->enable == TRUE) {
        bpno = compare_break_method(mrb, bp, class_obj, method_sym, isCfunc);
        if (bpno > 0) {
          return bpno;
        }
      }
    }
    else if (bp->type == MRB_DEBUG_BPTYPE_NONE) {
      break;
    }
    bp++;
  }

  return 0;
}
