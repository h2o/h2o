/*
** load.c - mruby binary loader
**
** See Copyright Notice in mruby.h
*/

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <mruby/dump.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/debug.h>
#include <mruby/error.h>
#include <mruby/data.h>

#if SIZE_MAX < UINT32_MAX
# error size_t must be at least 32 bits wide
#endif

#define FLAG_SRC_MALLOC 1
#define FLAG_SRC_STATIC 0

#define SIZE_ERROR_MUL(nmemb, size) ((size_t)(nmemb) > SIZE_MAX / (size))

static size_t
skip_padding(const uint8_t *buf)
{
  const size_t align = MRB_DUMP_ALIGNMENT;
  return -(intptr_t)buf & (align-1);
}

static size_t
offset_crc_body(void)
{
  struct rite_binary_header header;
  return ((uint8_t *)header.binary_crc - (uint8_t *)&header) + sizeof(header.binary_crc);
}

#ifndef MRB_WITHOUT_FLOAT
double mrb_str_len_to_dbl(mrb_state *mrb, const char *s, size_t len, mrb_bool badcheck);

static double
str_to_double(mrb_state *mrb, const char *p, size_t len)
{
  /* `i`, `inf`, `infinity` */
  if (len > 0 && p[0] == 'i') return INFINITY;

  /* `I`, `-inf`, `-infinity` */
  if (p[0] == 'I' || (len > 1 && p[0] == '-' && p[1] == 'i')) return -INFINITY;
  return mrb_str_len_to_dbl(mrb, p, len, TRUE);
}
#endif

mrb_value mrb_str_len_to_inum(mrb_state *mrb, const char *str, mrb_int len, mrb_int base, int badcheck);

static void
tempirep_free(mrb_state *mrb, void *p)
{
  if (p) mrb_irep_decref(mrb, (mrb_irep *)p);
}

static const mrb_data_type tempirep_type = { "temporary irep", tempirep_free };

static mrb_irep*
read_irep_record_1(mrb_state *mrb, const uint8_t *bin, size_t *len, uint8_t flags)
{
  int i;
  const uint8_t *src = bin;
  ptrdiff_t diff;
  uint16_t tt, pool_data_len, snl;
  int plen;
  struct RData *irep_obj = mrb_data_object_alloc(mrb, mrb->object_class, NULL, &tempirep_type);
  mrb_irep *irep = mrb_add_irep(mrb);
  int ai = mrb_gc_arena_save(mrb);

  irep_obj->data = irep;

  /* skip record size */
  src += sizeof(uint32_t);

  /* number of local variable */
  irep->nlocals = bin_to_uint16(src);
  src += sizeof(uint16_t);

  /* number of register variable */
  irep->nregs = bin_to_uint16(src);
  src += sizeof(uint16_t);

  /* number of child irep */
  irep->rlen = (size_t)bin_to_uint16(src);
  src += sizeof(uint16_t);

  /* Binary Data Section */
  /* ISEQ BLOCK */
  irep->ilen = (uint16_t)bin_to_uint32(src);
  src += sizeof(uint32_t);
  src += skip_padding(src);

  if (irep->ilen > 0) {
    if (SIZE_ERROR_MUL(irep->ilen, sizeof(mrb_code))) {
      return NULL;
    }
    if ((flags & FLAG_SRC_MALLOC) == 0) {
      irep->iseq = (mrb_code*)src;
      src += sizeof(mrb_code) * irep->ilen;
      irep->flags |= MRB_ISEQ_NO_FREE;
    }
    else {
      size_t data_len = sizeof(mrb_code) * irep->ilen;
      void *buf = mrb_malloc(mrb, data_len);
      irep->iseq = (mrb_code *)buf;
      memcpy(buf, src, data_len);
      src += data_len;
    }
  }

  /* POOL BLOCK */
  plen = bin_to_uint32(src); /* number of pool */
  src += sizeof(uint32_t);
  if (plen > 0) {
    if (SIZE_ERROR_MUL(plen, sizeof(mrb_value))) {
      return NULL;
    }
    irep->pool = (mrb_value*)mrb_malloc(mrb, sizeof(mrb_value) * plen);

    for (i = 0; i < plen; i++) {
      const char *s;
      mrb_bool st = (flags & FLAG_SRC_MALLOC)==0;

      tt = *src++; /* pool TT */
      pool_data_len = bin_to_uint16(src); /* pool data length */
      src += sizeof(uint16_t);
      s = (const char*)src;
      src += pool_data_len;
      switch (tt) { /* pool data */
      case IREP_TT_FIXNUM: {
        mrb_value num = mrb_str_len_to_inum(mrb, s, pool_data_len, 10, FALSE);
#ifdef MRB_WITHOUT_FLOAT
        irep->pool[i] = num;
#else
        irep->pool[i] = mrb_float_p(num)? mrb_float_pool(mrb, mrb_float(num)) : num;
#endif
        }
        break;

#ifndef MRB_WITHOUT_FLOAT
      case IREP_TT_FLOAT:
        irep->pool[i] = mrb_float_pool(mrb, str_to_double(mrb, s, pool_data_len));
        break;
#endif

      case IREP_TT_STRING:
        irep->pool[i] = mrb_str_pool(mrb, s, pool_data_len, st);
        break;

      default:
        /* should not happen */
        irep->pool[i] = mrb_nil_value();
        break;
      }
      irep->plen++;
      mrb_gc_arena_restore(mrb, ai);
    }
  }

  /* SYMS BLOCK */
  irep->slen = (uint16_t)bin_to_uint32(src);  /* syms length */
  src += sizeof(uint32_t);
  if (irep->slen > 0) {
    if (SIZE_ERROR_MUL(irep->slen, sizeof(mrb_sym))) {
      return NULL;
    }
    irep->syms = (mrb_sym *)mrb_malloc(mrb, sizeof(mrb_sym) * irep->slen);

    for (i = 0; i < irep->slen; i++) {
      snl = bin_to_uint16(src);               /* symbol name length */
      src += sizeof(uint16_t);

      if (snl == MRB_DUMP_NULL_SYM_LEN) {
        irep->syms[i] = 0;
        continue;
      }

      if (flags & FLAG_SRC_MALLOC) {
        irep->syms[i] = mrb_intern(mrb, (char *)src, snl);
      }
      else {
        irep->syms[i] = mrb_intern_static(mrb, (char *)src, snl);
      }
      src += snl + 1;

      mrb_gc_arena_restore(mrb, ai);
    }
  }

  irep->reps = (mrb_irep**)mrb_calloc(mrb, irep->rlen, sizeof(mrb_irep*));

  diff = src - bin;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  *len = (size_t)diff;

  irep_obj->data = NULL;

  return irep;
}

static mrb_irep*
read_irep_record(mrb_state *mrb, const uint8_t *bin, size_t *len, uint8_t flags)
{
  struct RData *irep_obj = mrb_data_object_alloc(mrb, mrb->object_class, NULL, &tempirep_type);
  int ai = mrb_gc_arena_save(mrb);
  mrb_irep *irep = read_irep_record_1(mrb, bin, len, flags);
  int i;

  mrb_gc_arena_restore(mrb, ai);
  if (irep == NULL) {
    return NULL;
  }

  irep_obj->data = irep;

  bin += *len;
  for (i=0; i<irep->rlen; i++) {
    size_t rlen;

    irep->reps[i] = read_irep_record(mrb, bin, &rlen, flags);
    mrb_gc_arena_restore(mrb, ai);
    if (irep->reps[i] == NULL) {
      return NULL;
    }
    bin += rlen;
    *len += rlen;
  }

  irep_obj->data = NULL;

  return irep;
}

static mrb_irep*
read_section_irep(mrb_state *mrb, const uint8_t *bin, uint8_t flags)
{
  size_t len;

  bin += sizeof(struct rite_section_irep_header);
  return read_irep_record(mrb, bin, &len, flags);
}

static int
read_debug_record(mrb_state *mrb, const uint8_t *start, mrb_irep* irep, size_t *record_len, const mrb_sym *filenames, size_t filenames_len)
{
  const uint8_t *bin = start;
  ptrdiff_t diff;
  size_t record_size;
  uint16_t f_idx;
  int i;

  if (irep->debug_info) { return MRB_DUMP_INVALID_IREP; }

  irep->debug_info = (mrb_irep_debug_info*)mrb_calloc(mrb, 1, sizeof(mrb_irep_debug_info));
  irep->debug_info->pc_count = (uint32_t)irep->ilen;

  record_size = (size_t)bin_to_uint32(bin);
  bin += sizeof(uint32_t);

  irep->debug_info->flen = bin_to_uint16(bin);
  irep->debug_info->files = (mrb_irep_debug_info_file**)mrb_calloc(mrb, irep->debug_info->flen, sizeof(mrb_irep_debug_info*));
  bin += sizeof(uint16_t);

  for (f_idx = 0; f_idx < irep->debug_info->flen; ++f_idx) {
    mrb_irep_debug_info_file *file;
    uint16_t filename_idx;

    file = (mrb_irep_debug_info_file *)mrb_calloc(mrb, 1, sizeof(*file));
    irep->debug_info->files[f_idx] = file;

    file->start_pos = bin_to_uint32(bin);
    bin += sizeof(uint32_t);

    /* filename */
    filename_idx = bin_to_uint16(bin);
    bin += sizeof(uint16_t);
    mrb_assert(filename_idx < filenames_len);
    file->filename_sym = filenames[filename_idx];

    file->line_entry_count = bin_to_uint32(bin);
    bin += sizeof(uint32_t);
    file->line_type = (mrb_debug_line_type)bin_to_uint8(bin);
    bin += sizeof(uint8_t);
    switch (file->line_type) {
      case mrb_debug_line_ary: {
        uint32_t l;

        file->lines.ary = (uint16_t *)mrb_malloc(mrb, sizeof(uint16_t) * (size_t)(file->line_entry_count));
        for (l = 0; l < file->line_entry_count; ++l) {
          file->lines.ary[l] = bin_to_uint16(bin);
          bin += sizeof(uint16_t);
        }
      } break;

      case mrb_debug_line_flat_map: {
        uint32_t l;

        file->lines.flat_map = (mrb_irep_debug_info_line*)mrb_calloc(
            mrb, (size_t)(file->line_entry_count), sizeof(mrb_irep_debug_info_line));
        for (l = 0; l < file->line_entry_count; ++l) {
          file->lines.flat_map[l].start_pos = bin_to_uint32(bin);
          bin += sizeof(uint32_t);
          file->lines.flat_map[l].line = bin_to_uint16(bin);
          bin += sizeof(uint16_t);
        }
      } break;

      default: return MRB_DUMP_GENERAL_FAILURE;
    }
  }

  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);

  if (record_size != (size_t)diff) {
    return MRB_DUMP_GENERAL_FAILURE;
  }

  for (i = 0; i < irep->rlen; i++) {
    size_t len;
    int ret;

    ret = read_debug_record(mrb, bin, irep->reps[i], &len, filenames, filenames_len);
    if (ret != MRB_DUMP_OK) return ret;
    bin += len;
  }

  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  *record_len = (size_t)diff;

  return MRB_DUMP_OK;
}

static int
read_section_debug(mrb_state *mrb, const uint8_t *start, mrb_irep *irep, uint8_t flags)
{
  const uint8_t *bin;
  ptrdiff_t diff;
  struct rite_section_debug_header *header;
  uint16_t i;
  size_t len = 0;
  int result;
  uint16_t filenames_len;
  mrb_sym *filenames;
  mrb_value filenames_obj;

  bin = start;
  header = (struct rite_section_debug_header *)bin;
  bin += sizeof(struct rite_section_debug_header);

  filenames_len = bin_to_uint16(bin);
  bin += sizeof(uint16_t);
  filenames_obj = mrb_str_new(mrb, NULL, sizeof(mrb_sym) * (size_t)filenames_len);
  filenames = (mrb_sym*)RSTRING_PTR(filenames_obj);
  for (i = 0; i < filenames_len; ++i) {
    uint16_t f_len = bin_to_uint16(bin);
    bin += sizeof(uint16_t);
    if (flags & FLAG_SRC_MALLOC) {
      filenames[i] = mrb_intern(mrb, (const char *)bin, (size_t)f_len);
    }
    else {
      filenames[i] = mrb_intern_static(mrb, (const char *)bin, (size_t)f_len);
    }
    bin += f_len;
  }

  result = read_debug_record(mrb, bin, irep, &len, filenames, filenames_len);
  if (result != MRB_DUMP_OK) goto debug_exit;

  bin += len;
  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  if ((uint32_t)diff != bin_to_uint32(header->section_size)) {
    result = MRB_DUMP_GENERAL_FAILURE;
  }

debug_exit:
  mrb_str_resize(mrb, filenames_obj, 0);
  return result;
}

static int
read_lv_record(mrb_state *mrb, const uint8_t *start, mrb_irep *irep, size_t *record_len, mrb_sym const *syms, uint32_t syms_len)
{
  const uint8_t *bin = start;
  ptrdiff_t diff;
  int i;

  irep->lv = (struct mrb_locals*)mrb_malloc(mrb, sizeof(struct mrb_locals) * (irep->nlocals - 1));

  for (i = 0; i + 1< irep->nlocals; ++i) {
    uint16_t const sym_idx = bin_to_uint16(bin);
    bin += sizeof(uint16_t);
    if (sym_idx == RITE_LV_NULL_MARK) {
      irep->lv[i].name = 0;
      irep->lv[i].r = 0;
    }
    else {
      if (sym_idx >= syms_len) {
        return MRB_DUMP_GENERAL_FAILURE;
      }
      irep->lv[i].name = syms[sym_idx];

      irep->lv[i].r = bin_to_uint16(bin);
    }
    bin += sizeof(uint16_t);
  }

  for (i = 0; i < irep->rlen; ++i) {
    size_t len;
    int ret;

    ret = read_lv_record(mrb, bin, irep->reps[i], &len, syms, syms_len);
    if (ret != MRB_DUMP_OK) return ret;
    bin += len;
  }

  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  *record_len = (size_t)diff;

  return MRB_DUMP_OK;
}

static int
read_section_lv(mrb_state *mrb, const uint8_t *start, mrb_irep *irep, uint8_t flags)
{
  const uint8_t *bin;
  ptrdiff_t diff;
  struct rite_section_lv_header const *header;
  uint32_t i;
  size_t len = 0;
  int result;
  uint32_t syms_len;
  mrb_sym *syms;
  mrb_value syms_obj;
  mrb_sym (*intern_func)(mrb_state*, const char*, size_t) =
    (flags & FLAG_SRC_MALLOC)? mrb_intern : mrb_intern_static;

  bin = start;
  header = (struct rite_section_lv_header const*)bin;
  bin += sizeof(struct rite_section_lv_header);

  syms_len = bin_to_uint32(bin);
  bin += sizeof(uint32_t);
  syms_obj = mrb_str_new(mrb, NULL, sizeof(mrb_sym) * (size_t)syms_len);
  syms = (mrb_sym*)RSTRING_PTR(syms_obj);
  for (i = 0; i < syms_len; ++i) {
    uint16_t const str_len = bin_to_uint16(bin);
    bin += sizeof(uint16_t);

    syms[i] = intern_func(mrb, (const char*)bin, str_len);
    bin += str_len;
  }

  result = read_lv_record(mrb, bin, irep, &len, syms, syms_len);
  if (result != MRB_DUMP_OK) goto lv_exit;

  bin += len;
  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  if ((uint32_t)diff != bin_to_uint32(header->section_size)) {
    result = MRB_DUMP_GENERAL_FAILURE;
  }

lv_exit:
  mrb_str_resize(mrb, syms_obj, 0);
  return result;
}

static int
read_binary_header(const uint8_t *bin, size_t bufsize, size_t *bin_size, uint16_t *crc, uint8_t *flags)
{
  const struct rite_binary_header *header = (const struct rite_binary_header *)bin;

  if (bufsize < sizeof(struct rite_binary_header)) {
    return MRB_DUMP_READ_FAULT;
  }

  if (memcmp(header->binary_ident, RITE_BINARY_IDENT, sizeof(header->binary_ident)) != 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }

  if (memcmp(header->binary_version, RITE_BINARY_FORMAT_VER, sizeof(header->binary_version)) != 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }

  if (crc) {
    *crc = bin_to_uint16(header->binary_crc);
  }
  *bin_size = (size_t)bin_to_uint32(header->binary_size);

  if (bufsize < *bin_size) {
    return MRB_DUMP_READ_FAULT;
  }

  return MRB_DUMP_OK;
}

static mrb_irep*
read_irep(mrb_state *mrb, const uint8_t *bin, size_t bufsize, uint8_t flags)
{
  int result;
  struct RData *irep_obj = NULL;
  mrb_irep *irep = NULL;
  const struct rite_section_header *section_header;
  uint16_t crc;
  size_t bin_size = 0;
  size_t n;

  if ((mrb == NULL) || (bin == NULL)) {
    return NULL;
  }

  result = read_binary_header(bin, bufsize, &bin_size, &crc, &flags);
  if (result != MRB_DUMP_OK) {
    return NULL;
  }

  n = offset_crc_body();
  if (crc != calc_crc_16_ccitt(bin + n, bin_size - n, 0)) {
    return NULL;
  }

  irep_obj = mrb_data_object_alloc(mrb, mrb->object_class, NULL, &tempirep_type);

  bin += sizeof(struct rite_binary_header);
  do {
    section_header = (const struct rite_section_header *)bin;
    if (memcmp(section_header->section_ident, RITE_SECTION_IREP_IDENT, sizeof(section_header->section_ident)) == 0) {
      irep = read_section_irep(mrb, bin, flags);
      if (!irep) return NULL;
      irep_obj->data = irep;
    }
    else if (memcmp(section_header->section_ident, RITE_SECTION_DEBUG_IDENT, sizeof(section_header->section_ident)) == 0) {
      if (!irep) return NULL;   /* corrupted data */
      result = read_section_debug(mrb, bin, irep, flags);
      if (result < MRB_DUMP_OK) {
        return NULL;
      }
    }
    else if (memcmp(section_header->section_ident, RITE_SECTION_LV_IDENT, sizeof(section_header->section_ident)) == 0) {
      if (!irep) return NULL;
      result = read_section_lv(mrb, bin, irep, flags);
      if (result < MRB_DUMP_OK) {
        return NULL;
      }
    }
    bin += bin_to_uint32(section_header->section_size);
  } while (memcmp(section_header->section_ident, RITE_BINARY_EOF, sizeof(section_header->section_ident)) != 0);

  irep_obj->data = NULL;

  return irep;
}

mrb_irep*
mrb_read_irep(mrb_state *mrb, const uint8_t *bin)
{
#if defined(MRB_USE_LINK_TIME_RO_DATA_P) || defined(MRB_USE_CUSTOM_RO_DATA_P)
  uint8_t flags = mrb_ro_data_p((char*)bin) ? FLAG_SRC_STATIC : FLAG_SRC_MALLOC;
#else
  uint8_t flags = FLAG_SRC_STATIC;
#endif

  return read_irep(mrb, bin, (size_t)-1, flags);
}

MRB_API mrb_irep*
mrb_read_irep_buf(mrb_state *mrb, const void *buf, size_t bufsize)
{
  return read_irep(mrb, (const uint8_t *)buf, bufsize, FLAG_SRC_MALLOC);
}

void mrb_exc_set(mrb_state *mrb, mrb_value exc);

static void
irep_error(mrb_state *mrb)
{
  mrb_exc_set(mrb, mrb_exc_new_str_lit(mrb, E_SCRIPT_ERROR, "irep load error"));
}

void mrb_codedump_all(mrb_state*, struct RProc*);

static mrb_value
load_irep(mrb_state *mrb, mrb_irep *irep, mrbc_context *c)
{
  struct RProc *proc;

  if (!irep) {
    irep_error(mrb);
    return mrb_nil_value();
  }
  proc = mrb_proc_new(mrb, irep);
  proc->c = NULL;
  mrb_irep_decref(mrb, irep);
  if (c && c->dump_result) mrb_codedump_all(mrb, proc);
  if (c && c->no_exec) return mrb_obj_value(proc);
  return mrb_top_run(mrb, proc, mrb_top_self(mrb), 0);
}

MRB_API mrb_value
mrb_load_irep_cxt(mrb_state *mrb, const uint8_t *bin, mrbc_context *c)
{
  struct RData *irep_obj = mrb_data_object_alloc(mrb, mrb->object_class, NULL, &tempirep_type);
  mrb_irep *irep = mrb_read_irep(mrb, bin);
  mrb_value ret;

  irep_obj->data = irep;
  mrb_irep_incref(mrb, irep);
  ret = load_irep(mrb, irep, c);
  irep_obj->data = NULL;
  mrb_irep_decref(mrb, irep);
  return ret;
}

MRB_API mrb_value
mrb_load_irep_buf_cxt(mrb_state *mrb, const void *buf, size_t bufsize, mrbc_context *c)
{
  return load_irep(mrb, mrb_read_irep_buf(mrb, buf, bufsize), c);
}

MRB_API mrb_value
mrb_load_irep(mrb_state *mrb, const uint8_t *bin)
{
  return mrb_load_irep_cxt(mrb, bin, NULL);
}

MRB_API mrb_value
mrb_load_irep_buf(mrb_state *mrb, const void *buf, size_t bufsize)
{
  return mrb_load_irep_buf_cxt(mrb, buf, bufsize, NULL);
}

#ifndef MRB_DISABLE_STDIO

mrb_irep*
mrb_read_irep_file(mrb_state *mrb, FILE* fp)
{
  mrb_irep *irep = NULL;
  uint8_t *buf;
  const size_t header_size = sizeof(struct rite_binary_header);
  size_t buf_size = 0;
  uint8_t flags = 0;
  int result;

  if ((mrb == NULL) || (fp == NULL)) {
    return NULL;
  }

  buf = (uint8_t*)mrb_malloc(mrb, header_size);
  if (fread(buf, header_size, 1, fp) == 0) {
    goto irep_exit;
  }
  result = read_binary_header(buf, (size_t)-1, &buf_size, NULL, &flags);
  if (result != MRB_DUMP_OK || buf_size <= header_size) {
    goto irep_exit;
  }

  buf = (uint8_t*)mrb_realloc(mrb, buf, buf_size);
  if (fread(buf+header_size, buf_size-header_size, 1, fp) == 0) {
    goto irep_exit;
  }
  irep = read_irep(mrb, buf, (size_t)-1, FLAG_SRC_MALLOC);

irep_exit:
  mrb_free(mrb, buf);
  return irep;
}

MRB_API mrb_value
mrb_load_irep_file_cxt(mrb_state *mrb, FILE* fp, mrbc_context *c)
{
  return load_irep(mrb, mrb_read_irep_file(mrb, fp), c);
}

MRB_API mrb_value
mrb_load_irep_file(mrb_state *mrb, FILE* fp)
{
  return mrb_load_irep_file_cxt(mrb, fp, NULL);
}
#endif /* MRB_DISABLE_STDIO */
