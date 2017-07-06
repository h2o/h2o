#include <string.h>
#include "mruby.h"
#include "mruby/irep.h"
#include "mruby/debug.h"

static mrb_irep_debug_info_file *
get_file(mrb_irep_debug_info *info, uint32_t pc)
{
  mrb_irep_debug_info_file **ret;
  int32_t count;

  if (pc >= info->pc_count) { return NULL; }
  /* get upper bound */
  ret = info->files;
  count =  info->flen;
  while (count > 0) {
    int32_t step = count / 2;
    mrb_irep_debug_info_file **it = ret + step;
    if (!(pc < (*it)->start_pos)) {
      ret = it + 1;
      count -= step + 1;
    } else { count = step; }
  }

  --ret;

  /* check returning file exists inside debug info */
  mrb_assert(info->files <= ret && ret < (info->files + info->flen));
  /* check pc is within the range of returning file */
  mrb_assert((*ret)->start_pos <= pc &&
             pc < (((ret + 1 - info->files) < info->flen)
                   ? (*(ret+1))->start_pos : info->pc_count));

  return *ret;
}

static mrb_debug_line_type
select_line_type(const uint16_t *lines, size_t lines_len)
{
  size_t line_count = 0;
  int prev_line = -1;
  size_t i;
  for (i = 0; i < lines_len; ++i) {
    if (lines[i] != prev_line) {
      ++line_count;
    }
  }
  return (sizeof(uint16_t) * lines_len) <= (sizeof(mrb_irep_debug_info_line) * line_count)
      ? mrb_debug_line_ary : mrb_debug_line_flat_map;
}

MRB_API char const*
mrb_debug_get_filename(mrb_irep *irep, uint32_t pc)
{
  if (irep && pc < irep->ilen) {
    mrb_irep_debug_info_file* f = NULL;
    if (!irep->debug_info) { return irep->filename; }
    else if ((f = get_file(irep->debug_info, pc))) {
      return f->filename;
    }
  }
  return NULL;
}

MRB_API int32_t
mrb_debug_get_line(mrb_irep *irep, uint32_t pc)
{
  if (irep && pc < irep->ilen) {
    mrb_irep_debug_info_file* f = NULL;
    if (!irep->debug_info) {
      return irep->lines? irep->lines[pc] : -1;
    }
    else if ((f = get_file(irep->debug_info, pc))) {
      switch (f->line_type) {
        case mrb_debug_line_ary:
          mrb_assert(f->start_pos <= pc && pc < (f->start_pos + f->line_entry_count));
          return f->lines.ary[pc - f->start_pos];

        case mrb_debug_line_flat_map: {
          /* get upper bound */
          mrb_irep_debug_info_line *ret = f->lines.flat_map;
          uint32_t count = f->line_entry_count;
          while (count > 0) {
            int32_t step = count / 2;
            mrb_irep_debug_info_line *it = ret + step;
            if (!(pc < it->start_pos)) {
              ret = it + 1;
              count -= step + 1;
            } else { count = step; }
          }

          --ret;

          /* check line entry pointer range */
          mrb_assert(f->lines.flat_map <= ret && ret < (f->lines.flat_map + f->line_entry_count));
          /* check pc range */
          mrb_assert(ret->start_pos <= pc &&
                     pc < (((uint32_t)(ret + 1 - f->lines.flat_map) < f->line_entry_count)
                           ? (ret+1)->start_pos : irep->debug_info->pc_count));

          return ret->line;
        }
      }
    }
  }
  return -1;
}

MRB_API mrb_irep_debug_info *
mrb_debug_info_alloc(mrb_state *mrb, mrb_irep *irep)
{
  static const mrb_irep_debug_info initial = { 0, 0, NULL };
  mrb_irep_debug_info *ret;

  mrb_assert(!irep->debug_info);
  ret = (mrb_irep_debug_info *)mrb_malloc(mrb, sizeof(*ret));
  *ret = initial;
  irep->debug_info = ret;
  return ret;
}

MRB_API mrb_irep_debug_info_file *
mrb_debug_info_append_file(mrb_state *mrb, mrb_irep *irep,
                           uint32_t start_pos, uint32_t end_pos)
{
  mrb_irep_debug_info *info;
  mrb_irep_debug_info_file *ret;
  uint32_t file_pc_count;
  size_t fn_len;
  mrb_int len;
  uint32_t i;

  if (!irep->debug_info) { return NULL; }

  mrb_assert(irep->filename);
  mrb_assert(irep->lines);

  info = irep->debug_info;

  if (info->flen > 0 && strcmp(irep->filename, info->files[info->flen - 1]->filename) == 0) {
    return NULL;
  }

  ret = (mrb_irep_debug_info_file *)mrb_malloc(mrb, sizeof(*ret));
  info->files =
      (mrb_irep_debug_info_file**)(
          info->files
          ? mrb_realloc(mrb, info->files, sizeof(mrb_irep_debug_info_file*) * (info->flen + 1))
          : mrb_malloc(mrb, sizeof(mrb_irep_debug_info_file*)));
  info->files[info->flen++] = ret;

  file_pc_count = end_pos - start_pos;

  ret->start_pos = start_pos;
  info->pc_count = end_pos;

  fn_len = strlen(irep->filename);
  ret->filename_sym = mrb_intern(mrb, irep->filename, fn_len);
  len = 0;
  ret->filename = mrb_sym2name_len(mrb, ret->filename_sym, &len);

  ret->line_type = select_line_type(irep->lines + start_pos, end_pos - start_pos);
  ret->lines.ptr = NULL;

  switch (ret->line_type) {
    case mrb_debug_line_ary:
      ret->line_entry_count = file_pc_count;
      ret->lines.ary = (uint16_t*)mrb_malloc(mrb, sizeof(uint16_t) * file_pc_count);
      for (i = 0; i < file_pc_count; ++i) {
        ret->lines.ary[i] = irep->lines[start_pos + i];
      }
      break;

    case mrb_debug_line_flat_map: {
      uint16_t prev_line = 0;
      mrb_irep_debug_info_line m;
      ret->lines.flat_map = (mrb_irep_debug_info_line*)mrb_malloc(mrb, sizeof(mrb_irep_debug_info_line) * 1);
      ret->line_entry_count = 0;
      for (i = 0; i < file_pc_count; ++i) {
        if (irep->lines[start_pos + i] == prev_line) { continue; }

        ret->lines.flat_map = (mrb_irep_debug_info_line*)mrb_realloc(
            mrb, ret->lines.flat_map,
            sizeof(mrb_irep_debug_info_line) * (ret->line_entry_count + 1));
        m.start_pos = start_pos + i;
        m.line = irep->lines[start_pos + i];
        ret->lines.flat_map[ret->line_entry_count] = m;

        /* update */
        ++ret->line_entry_count;
        prev_line = irep->lines[start_pos + i];
      }
    } break;

    default: mrb_assert(0); break;
  }

  return ret;
}

MRB_API void
mrb_debug_info_free(mrb_state *mrb, mrb_irep_debug_info *d)
{
  uint32_t i;

  if (!d) { return; }

  for (i = 0; i < d->flen; ++i) {
    mrb_assert(d->files[i]);
    mrb_free(mrb, d->files[i]->lines.ptr);
    mrb_free(mrb, d->files[i]);
  }
  mrb_free(mrb, d->files);
  mrb_free(mrb, d);
}
