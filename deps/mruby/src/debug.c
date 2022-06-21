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

size_t
mrb_packed_int_len(uint32_t num)
{
  size_t llen = 0;

  do {
    llen++;
  } while (num >>= 7);
  return llen;
}

size_t
mrb_packed_int_encode(uint32_t num, uint8_t *p, uint8_t *pend)
{
  size_t llen = 0;

  do {
    uint8_t byte = num & 0x7f;
    num >>= 7;
    if (num != 0) byte |= 0x80;
    if (p < pend) *p++ = byte;
    llen++;
  } while (num != 0);

  return llen;
}

uint32_t
mrb_packed_int_decode(uint8_t *p, uint8_t **newpos)
{
  size_t i = 0, shift = 0;
  uint32_t n = 0;

  do {
    n |= ((uint32_t)(p[i] & 0x7f)) << shift;
    i++;
    shift += 7;
  } while (shift < sizeof(uint32_t) * 8 && (p[i - 1] & 0x80));
  if (newpos) *newpos = p + i;
  return n;
}

MRB_API char const*
mrb_debug_get_filename(mrb_state *mrb, const mrb_irep *irep, uint32_t pc)
{
  if (irep && pc < irep->ilen) {
    mrb_irep_debug_info_file* f = NULL;
    if (!irep->debug_info) return NULL;
    else if ((f = get_file(irep->debug_info, pc))) {
      return mrb_sym_name_len(mrb, f->filename_sym, NULL);
    }
  }
  return NULL;
}

MRB_API int32_t
mrb_debug_get_line(mrb_state *mrb, const mrb_irep *irep, uint32_t pc)
{
  if (irep && pc < irep->ilen) {
    mrb_irep_debug_info_file* f = NULL;
    if (!irep->debug_info) {
      return -1;
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

        case mrb_debug_line_packed_map: {
          uint8_t *p = f->lines.packed_map;
          uint8_t *pend = p + f->line_entry_count;
          uint32_t pos = 0, line = 0, line_diff;
          while (p < pend) {
            pos += mrb_packed_int_decode(p, &p);
            line_diff = mrb_packed_int_decode(p, &p);
            if (pc < pos) break;
            line += line_diff;
          }
          return line;
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
  d->files = (mrb_irep_debug_info_file**)mrb_realloc(mrb, d->files, sizeof(mrb_irep_debug_info_file*) * (d->flen + 1));
  d->files[d->flen++] = f;

  file_pc_count = end_pos - start_pos;

  f->start_pos = start_pos;
  d->pc_count = end_pos;

  fn_len = strlen(filename);
  f->filename_sym = mrb_intern(mrb, filename, fn_len);
  f->line_type = mrb_debug_line_packed_map;
  f->lines.ptr = NULL;

  uint16_t prev_line = 0;
  uint32_t prev_pc = 0;
  size_t packed_size = 0;
  uint8_t *p, *pend;

  for (i = 0; i < file_pc_count; ++i) {
    if (lines[start_pos + i] == prev_line) continue;
    packed_size += mrb_packed_int_len(start_pos+i-prev_pc);
    prev_pc = start_pos+i;
    packed_size += mrb_packed_int_len(lines[start_pos+i]-prev_line);
    prev_line = lines[start_pos + i];
  }
  p = f->lines.packed_map = (uint8_t*)mrb_malloc(mrb, packed_size);
  pend = p + packed_size;
  prev_line = 0; prev_pc = 0;
  for (i = 0; i < file_pc_count; ++i) {
    if (lines[start_pos + i] == prev_line) continue;
    p += mrb_packed_int_encode(start_pos+i-prev_pc, p, pend);
    prev_pc = start_pos + i;
    p += mrb_packed_int_encode(lines[start_pos + i]-prev_line, p, pend);
    prev_line = lines[start_pos + i];
  }
  f->line_entry_count = (uint32_t)packed_size;

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
