/**
** @file mruby/debug.h - mruby debug info
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_DEBUG_H
#define MRUBY_DEBUG_H

#include "common.h"

/**
 * MRuby Debugging.
 */
MRB_BEGIN_DECL

typedef enum mrb_debug_line_type {
  mrb_debug_line_ary = 0,
  mrb_debug_line_flat_map,
  mrb_debug_line_packed_map
} mrb_debug_line_type;

typedef struct mrb_irep_debug_info_line {
  uint32_t start_pos;
  uint16_t line;
} mrb_irep_debug_info_line;

typedef struct mrb_irep_debug_info_file {
  uint32_t start_pos;
  mrb_sym filename_sym;
  uint32_t line_entry_count;
  mrb_debug_line_type line_type;
  union {
    const char *s;
    void *ptr;
    const uint16_t *ary;
    const mrb_irep_debug_info_line *flat_map;
    const uint8_t *packed_map;
  } lines;
} mrb_irep_debug_info_file;

typedef struct mrb_irep_debug_info {
  uint32_t pc_count;
  uint16_t flen;
  mrb_irep_debug_info_file **files;
} mrb_irep_debug_info;

/*
 * get line from irep's debug info and program counter
 * @return returns NULL if not found
 */
MRB_API const char *mrb_debug_get_filename(mrb_state *mrb, const mrb_irep *irep, uint32_t pc);

/*
 * get line from irep's debug info and program counter
 * @return returns -1 if not found
 */
MRB_API int32_t mrb_debug_get_line(mrb_state *mrb, const mrb_irep *irep, uint32_t pc);

MRB_API mrb_irep_debug_info *mrb_debug_info_alloc(mrb_state *mrb, mrb_irep *irep);
MRB_API mrb_irep_debug_info_file *mrb_debug_info_append_file(
    mrb_state *mrb, mrb_irep_debug_info *info,
    const char *filename, uint16_t *lines,
    uint32_t start_pos, uint32_t end_pos);
MRB_API void mrb_debug_info_free(mrb_state *mrb, mrb_irep_debug_info *d);

MRB_END_DECL

#endif /* MRUBY_DEBUG_H */
