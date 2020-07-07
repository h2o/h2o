#include <string.h>
#include <mruby.h>
#include <mruby/irep.h>
#include <mruby/debug.h>

static mrb_irep_debug_info_file*
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
    }
    else { count = step; }
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
mrb_debug_get_filename(mrb_state *mrb, mrb_irep *irep, ptrdiff_t pc)
{
  if (irep && pc >= 0 && pc < irep->ilen) {
    mrb_irep_debug_info_file* f = NULL;
    if (!irep->debug_info) return NULL;
    else if ((f = get_file(irep->debug_info, (uint32_t)pc))) {
      return mrb_sym_name_len(mrb, f->filename_sym, NULL);
    }
  }
  return NULL;
}

MRB_API int32_t
mrb_debug_get_line(mrb_state *mrb, mrb_irep *irep, ptrdiff_t pc)
{
  if (irep && pc >= 0 && pc < irep->ilen) {
    mrb_irep_debug_info_file* f = NULL;
    if (!irep->debug_info) {
      return -1;
    }
    else if ((f = get_file(irep->debug_info, (uint32_t)pc))) {
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
            }
            else { count = step; }
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

MRB_API mrb_irep_debug_info*
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

MRB_API mrb_irep_debug_info_file*
mrb_debug_info_append_file(mrb_state *mrb, mrb_irep_debug_info *d,
                           const char *filename, uint16_t *lines,
                           uint32_t start_pos, uint32_t end_pos)
{
  mrb_irep_debug_info_file *f;
  uint32_t file_pc_count;
  size_t fn_len;
  uint32_t i;

  if (!d) return NULL;
  if (start_pos == end_pos) return NULL;

  mrb_assert(filename);
  mrb_assert(lines);

  if (d->flen > 0) {
    const char *fn = mrb_sym_name_len(mrb, d->files[d->flen - 1]->filename_sym, NULL);
    if (strcmp(filename, fn) == 0)
      return NULL;
  }

  f = (mrb_irep_debug_info_file*)mrb_malloc(mrb, sizeof(*f));
  d->files = (mrb_irep_debug_info_file**)(
          d->files
          ? mrb_realloc(mrb, d->files, sizeof(mrb_irep_debug_info_file*) * (d->flen + 1))
          : mrb_malloc(mrb, sizeof(mrb_irep_debug_info_file*)));
  d->files[d->flen++] = f;

  file_pc_count = end_pos - start_pos;

  f->start_pos = start_pos;
  d->pc_count = end_pos;

  fn_len = strlen(filename);
  f->filename_sym = mrb_intern(mrb, filename, fn_len);

  f->line_type = select_line_type(lines + start_pos, end_pos - start_pos);
  f->lines.ptr = NULL;

  switch (f->line_type) {
    case mrb_debug_line_ary:
      f->line_entry_count = file_pc_count;
      f->lines.ary = (uint16_t*)mrb_malloc(mrb, sizeof(uint16_t) * file_pc_count);
      for (i = 0; i < file_pc_count; ++i) {
        f->lines.ary[i] = lines[start_pos + i];
      }
      break;

    case mrb_debug_line_flat_map: {
      uint16_t prev_line = 0;
      mrb_irep_debug_info_line m;
      f->lines.flat_map = (mrb_irep_debug_info_line*)mrb_malloc(mrb, sizeof(mrb_irep_debug_info_line) * 1);
      f->line_entry_count = 0;
      for (i = 0; i < file_pc_count; ++i) {
        if (lines[start_pos + i] == prev_line) { continue; }

        f->lines.flat_map = (mrb_irep_debug_info_line*)mrb_realloc(
            mrb, f->lines.flat_map,
            sizeof(mrb_irep_debug_info_line) * (f->line_entry_count + 1));
        m.start_pos = start_pos + i;
        m.line = lines[start_pos + i];
        f->lines.flat_map[f->line_entry_count] = m;

        /* update */
        ++f->line_entry_count;
        prev_line = lines[start_pos + i];
      }
    } break;

    default: mrb_assert(0); break;
  }

  return f;
}

MRB_API void
mrb_debug_info_free(mrb_state *mrb, mrb_irep_debug_info *d)
{
  uint32_t i;

  if (!d) { return; }

  if (d->files) {
    for (i = 0; i < d->flen; ++i) {
      if (d->files[i]) {
        mrb_free(mrb, d->files[i]->lines.ptr);
        mrb_free(mrb, d->files[i]);
      }
    }
    mrb_free(mrb, d->files);
  }
  mrb_free(mrb, d);
}
