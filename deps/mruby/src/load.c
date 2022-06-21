/*
** load.c - mruby binary loader
**
** See Copyright Notice in mruby.h
*/

#include <mruby.h>
#include <mruby/dump.h>
#include <mruby/irep.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/debug.h>
#include <mruby/error.h>
#include <mruby/data.h>
#include <mruby/endian.h>
#include <string.h>

#if SIZE_MAX < UINT32_MAX
# error size_t must be at least 32 bits wide
#endif

#define FLAG_SRC_MALLOC 1
#define FLAG_SRC_STATIC 0

#define SIZE_ERROR_MUL(nmemb, size) ((size_t)(nmemb) > SIZE_MAX / (size))

#define DEFINE_READ_IREP_FUNC(funcdecl, basecall) \
  funcdecl \
  { \
    int ai = mrb_gc_arena_save(mrb); \
    struct RProc *proc = basecall; \
    struct mrb_irep *irep = (mrb_irep*)(proc ? proc->body.irep : NULL); \
    if (irep) proc->body.irep = NULL; \
    mrb_gc_arena_restore(mrb, ai); \
    return irep; \
  }

#ifndef MRB_NO_FLOAT
static double
str_to_double(mrb_state *mrb, const char *p)
{
  /* dump IEEE754 little endian binary */
  union {
    char s[sizeof(double)];
    double f;
  } u;

  if (littleendian) {
    memcpy(u.s, p, sizeof(double));
  }
  else {
    size_t i;
    for (i=0; i<sizeof(double); i++) {
      u.s[i] = p[sizeof(double)-i-1];
    }
  }
  return u.f;
}
#endif

static mrb_bool
read_irep_record_1(mrb_state *mrb, const uint8_t *bin, const uint8_t *end, size_t *len, uint8_t flags, mrb_irep **irepp)
{
  int i;
  const uint8_t *src = bin;
  ptrdiff_t diff;
  uint16_t tt, pool_data_len, snl;
  int plen;
  mrb_pool_value *pool;
  mrb_sym *syms;
  int ai = mrb_gc_arena_save(mrb);
  mrb_irep *irep = mrb_add_irep(mrb);

  *irepp = irep;

  /* skip record size */
  src += sizeof(uint32_t);

  /* number of local variable */
  irep->nlocals = bin_to_uint16(src);
  src += sizeof(uint16_t);

  /* number of register variable */
  irep->nregs = bin_to_uint16(src);
  src += sizeof(uint16_t);

  /* number of child irep */
  irep->rlen = bin_to_uint16(src);
  src += sizeof(uint16_t);

  /* Binary Data Section */
  /* ISEQ BLOCK (and CATCH HANDLER TABLE BLOCK) */
  irep->clen = bin_to_uint16(src);  /* number of catch handler */
  src += sizeof(uint16_t);
  irep->ilen = bin_to_uint32(src);
  src += sizeof(uint32_t);

  if (irep->ilen > 0) {
    size_t data_len = sizeof(mrb_code) * irep->ilen +
                      sizeof(struct mrb_irep_catch_handler) * irep->clen;
    mrb_static_assert(sizeof(struct mrb_irep_catch_handler) == 13);
    if (SIZE_ERROR_MUL(irep->ilen, sizeof(mrb_code))) {
      return FALSE;
    }
    if (src + data_len > end) return FALSE;
    if ((flags & FLAG_SRC_MALLOC) == 0) {
      irep->iseq = (mrb_code*)src;
      irep->flags |= MRB_ISEQ_NO_FREE;
    }
    else {
      void *buf = mrb_malloc(mrb, data_len);
      irep->iseq = (mrb_code *)buf;
      memcpy(buf, src, data_len);
    }
    src += data_len;
  }

  /* POOL BLOCK */
  plen = bin_to_uint16(src); /* number of pool */
  src += sizeof(uint16_t);
  if (src > end) return FALSE;
  if (plen > 0) {
    if (SIZE_ERROR_MUL(plen, sizeof(mrb_value))) {
      return FALSE;
    }
    irep->pool = pool = (mrb_pool_value*)mrb_calloc(mrb, sizeof(mrb_pool_value), plen);

    for (i = 0; i < plen; i++) {
      mrb_bool st = (flags & FLAG_SRC_MALLOC)==0;

      tt = *src++; /* pool TT */
      switch (tt) { /* pool data */
      case IREP_TT_INT32:
        {
          if (src + sizeof(uint32_t) > end) return FALSE;
          mrb_int v = (int32_t)bin_to_uint32(src);
          src += sizeof(uint32_t);
#ifdef MRB_64BIT
          pool[i].tt = IREP_TT_INT64;
          pool[i].u.i64 = (int64_t)v;
#else
          pool[i].tt = IREP_TT_INT32;
          pool[i].u.i32 = v;
#endif
        }
        break;
      case IREP_TT_INT64:
#ifdef MRB_INT64
        {
          if (src + sizeof(uint32_t)*2 > end) return FALSE;
          uint64_t i64 = bin_to_uint32(src);
          src += sizeof(uint32_t);
          i64 <<= 32;
          i64 |= bin_to_uint32(src);
          src += sizeof(uint32_t);
          pool[i].tt = tt;
          pool[i].u.i64 = (int64_t)i64;
        }
        break;
#else
        return FALSE;
#endif

      case IREP_TT_BIGINT:
        pool_data_len = bin_to_uint8(src); /* pool data length */
        src += sizeof(uint8_t);
        if (src + pool_data_len > end) return FALSE;
        {
          char *p;
          pool[i].tt = IREP_TT_BIGINT;
          p = (char*)mrb_malloc(mrb, pool_data_len+2);
          memcpy(p, src, pool_data_len+2);
          pool[i].u.str = (const char*)p;
        }
        src += pool_data_len + 2;
        break;

      case IREP_TT_FLOAT:
#ifndef MRB_NO_FLOAT
        if (src + sizeof(double) > end) return FALSE;
        pool[i].tt = tt;
        pool[i].u.f = str_to_double(mrb, (const char*)src);
        src += sizeof(double);
        break;
#else
        return FALSE;           /* MRB_NO_FLOAT */
#endif

      case IREP_TT_STR:
        pool_data_len = bin_to_uint16(src); /* pool data length */
        src += sizeof(uint16_t);
        if (src + pool_data_len > end) return FALSE;
        if (st) {
          pool[i].tt = (pool_data_len<<2) | IREP_TT_SSTR;
          pool[i].u.str = (const char*)src;
        }
        else {
          char *p;
          pool[i].tt = (pool_data_len<<2) | IREP_TT_STR;
          p = (char*)mrb_malloc(mrb, pool_data_len+1);
          memcpy(p, src, pool_data_len+1);
          pool[i].u.str = (const char*)p;
        }
        src += pool_data_len + 1;
        break;

      default:
        /* should not happen */
        return FALSE;
      }
      irep->plen = i+1;
    }
  }

  /* SYMS BLOCK */
  irep->slen = bin_to_uint16(src);  /* syms length */
  src += sizeof(uint16_t);
  if (src > end) return FALSE;
  if (irep->slen > 0) {
    if (SIZE_ERROR_MUL(irep->slen, sizeof(mrb_sym))) {
      return FALSE;
    }
    irep->syms = syms = (mrb_sym *)mrb_malloc(mrb, sizeof(mrb_sym) * irep->slen);

    for (i = 0; i < irep->slen; i++) {
      snl = bin_to_uint16(src);               /* symbol name length */
      src += sizeof(uint16_t);

      if (snl == MRB_DUMP_NULL_SYM_LEN) {
        syms[i] = 0;
        continue;
      }

      if (src + snl > end) return FALSE;
      if (flags & FLAG_SRC_MALLOC) {
        syms[i] = mrb_intern(mrb, (char *)src, snl);
      }
      else {
        syms[i] = mrb_intern_static(mrb, (char *)src, snl);
      }
      src += snl + 1;
      mrb_gc_arena_restore(mrb, ai);
    }
  }

  diff = src - bin;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  *len = (size_t)diff;

  return TRUE;
}

static mrb_bool
read_irep_record(mrb_state *mrb, const uint8_t *bin, const uint8_t *end, size_t *len, uint8_t flags, mrb_irep **irepp)
{
  int ai = mrb_gc_arena_save(mrb);
  mrb_bool readsuccess = read_irep_record_1(mrb, bin, end, len, flags, irepp);
  mrb_irep **reps;
  int i;

  mrb_gc_arena_restore(mrb, ai);
  if (!readsuccess) {
    return FALSE;
  }

  reps = (mrb_irep**)mrb_calloc(mrb, (*irepp)->rlen, sizeof(mrb_irep*));
  (*irepp)->reps = (const mrb_irep**)reps;

  bin += *len;
  for (i=0; i<(*irepp)->rlen; i++) {
    size_t rlen;

    readsuccess = read_irep_record(mrb, bin, end, &rlen, flags, &reps[i]);
    mrb_gc_arena_restore(mrb, ai);
    if (!readsuccess) {
      return FALSE;
    }
    bin += rlen;
    *len += rlen;
  }

  return TRUE;
}

static mrb_irep*
read_section_irep(mrb_state *mrb, const uint8_t *bin, size_t size, uint8_t flags, struct RProc **proc)
{
  if (size < sizeof(struct rite_section_irep_header)) return NULL;
  /*
   * This proc object keeps all the data in progress to avoid memory leaks
   * if something goes wrong while reading irep.
   */
  *proc = mrb_proc_new(mrb, NULL);

  mrb_irep **irepp = (mrb_irep**)&(*proc)->body.irep;
  size_t len;
  bin += sizeof(struct rite_section_irep_header);
  if (read_irep_record(mrb, bin, bin+size, &len, flags, irepp)) {
    return *irepp;
  }
  else {
    return NULL;
  }
}

static int
read_debug_record(mrb_state *mrb, const uint8_t *start, const uint8_t *end, mrb_irep* irep, size_t *record_len, const mrb_sym *filenames, size_t filenames_len)
{
  const uint8_t *bin = start;
  ptrdiff_t diff;
  size_t record_size;
  uint16_t f_idx;
  int i;
  mrb_irep_debug_info *debug;

  if (irep->debug_info) { return MRB_DUMP_INVALID_IREP; }

  irep->debug_info = debug = (mrb_irep_debug_info*)mrb_calloc(mrb, 1, sizeof(mrb_irep_debug_info));
  debug->pc_count = (uint32_t)irep->ilen;

  record_size = (size_t)bin_to_uint32(bin);
  bin += sizeof(uint32_t);

  debug->flen = bin_to_uint16(bin);
  bin += sizeof(uint16_t);
  if (bin > end) return MRB_DUMP_GENERAL_FAILURE;
  debug->files = (mrb_irep_debug_info_file**)mrb_calloc(mrb, irep->debug_info->flen, sizeof(mrb_irep_debug_info*));

  for (f_idx = 0; f_idx < debug->flen; ++f_idx) {
    mrb_irep_debug_info_file *file;
    uint16_t filename_idx;

    if (bin > end) return MRB_DUMP_GENERAL_FAILURE;
    file = (mrb_irep_debug_info_file *)mrb_calloc(mrb, 1, sizeof(*file));
    debug->files[f_idx] = file;

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
        size_t l = sizeof(uint16_t) * (size_t)file->line_entry_count;

        if (bin + l > end) return MRB_DUMP_GENERAL_FAILURE;
        file->lines.ary = (uint16_t *)mrb_malloc(mrb, l);
        for (l = 0; l < file->line_entry_count; ++l) {
          file->lines.ary[l] = bin_to_uint16(bin);
          bin += sizeof(uint16_t);
        }
      } break;

      case mrb_debug_line_flat_map: {
        size_t c = (size_t)file->line_entry_count;
        size_t n = sizeof(mrb_irep_debug_info_line);

        if (bin + c*n > end) return MRB_DUMP_GENERAL_FAILURE;
        file->lines.flat_map = (mrb_irep_debug_info_line*)mrb_calloc(mrb, c, n);
        for (size_t l = 0; l < file->line_entry_count; ++l) {
          file->lines.flat_map[l].start_pos = bin_to_uint32(bin);
          bin += sizeof(uint32_t);
          file->lines.flat_map[l].line = bin_to_uint16(bin);
          bin += sizeof(uint16_t);
        }
      } break;

      case mrb_debug_line_packed_map: {
        size_t l = (size_t)file->line_entry_count;

        if (bin + l > end) return MRB_DUMP_GENERAL_FAILURE;
        file->lines.packed_map = (uint8_t*)mrb_calloc(mrb, 1, l);
        memcpy(file->lines.packed_map, bin, file->line_entry_count);
        bin += file->line_entry_count;
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

    ret = read_debug_record(mrb, bin, end, (mrb_irep*)irep->reps[i], &len, filenames, filenames_len);
    if (ret != MRB_DUMP_OK) return ret;
    bin += len;
  }

  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  *record_len = (size_t)diff;

  return MRB_DUMP_OK;
}

static int
read_section_debug(mrb_state *mrb, const uint8_t *start, size_t size, mrb_irep *irep, uint8_t flags)
{
  const uint8_t *bin;
  const uint8_t *end = start + size;
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
  if (bin > end) return MRB_DUMP_GENERAL_FAILURE;
  filenames_obj = mrb_str_new(mrb, NULL, sizeof(mrb_sym) * (size_t)filenames_len);
  filenames = (mrb_sym*)RSTRING_PTR(filenames_obj);
  for (i = 0; i < filenames_len; ++i) {
    uint16_t f_len = bin_to_uint16(bin);
    bin += sizeof(uint16_t);
    if (bin + f_len > end) {
      result = MRB_DUMP_GENERAL_FAILURE;
      goto debug_exit;
    }
    if (flags & FLAG_SRC_MALLOC) {
      filenames[i] = mrb_intern(mrb, (const char *)bin, (size_t)f_len);
    }
    else {
      filenames[i] = mrb_intern_static(mrb, (const char *)bin, (size_t)f_len);
    }
    bin += f_len;
  }

  result = read_debug_record(mrb, bin, end, irep, &len, filenames, filenames_len);
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
  mrb_sym *lv;
  ptrdiff_t diff;
  int i;

  if (irep->nlocals == 0) return MRB_DUMP_GENERAL_FAILURE;
  irep->lv = lv = (mrb_sym*)mrb_malloc(mrb, sizeof(mrb_sym) * (irep->nlocals - 1));

  for (i = 0; i + 1 < irep->nlocals; ++i) {
    uint16_t const sym_idx = bin_to_uint16(bin);
    bin += sizeof(uint16_t);
    if (sym_idx == RITE_LV_NULL_MARK) {
      lv[i] = 0;
    }
    else {
      if (sym_idx >= syms_len) {
        return MRB_DUMP_GENERAL_FAILURE;
      }
      lv[i] = syms[sym_idx];
    }
  }

  for (i = 0; i < irep->rlen; ++i) {
    size_t len;
    int ret;

    ret = read_lv_record(mrb, bin, (mrb_irep*)irep->reps[i], &len, syms, syms_len);
    if (ret != MRB_DUMP_OK) return ret;
    bin += len;
  }

  diff = bin - start;
  mrb_assert_int_fit(ptrdiff_t, diff, size_t, SIZE_MAX);
  *record_len = (size_t)diff;

  return MRB_DUMP_OK;
}

static int
read_section_lv(mrb_state *mrb, const uint8_t *start, size_t size, mrb_irep *irep, uint8_t flags)
{
  const uint8_t *bin;
  const uint8_t *end = start + size;
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
  if (bin > end) return MRB_DUMP_READ_FAULT;
  syms_obj = mrb_str_new(mrb, NULL, sizeof(mrb_sym) * (size_t)syms_len);
  syms = (mrb_sym*)RSTRING_PTR(syms_obj);
  for (i = 0; i < syms_len; ++i) {
    uint16_t const str_len = bin_to_uint16(bin);
    bin += sizeof(uint16_t);
    if (bin > end) return MRB_DUMP_READ_FAULT;
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
read_binary_header(const uint8_t *bin, size_t bufsize, size_t *bin_size, uint8_t *flags)
{
  const struct rite_binary_header *header = (const struct rite_binary_header *)bin;

  if (bufsize < sizeof(struct rite_binary_header)) {
    return MRB_DUMP_READ_FAULT;
  }

  if (memcmp(header->binary_ident, RITE_BINARY_IDENT, sizeof(header->binary_ident)) != 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }

  /* if major version is different, they are incompatible */
  if (memcmp(header->major_version, RITE_BINARY_MAJOR_VER, sizeof(header->major_version)) != 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }
  /* if minor version is different, we can accept the older version */
  if (memcmp(header->minor_version, RITE_BINARY_MINOR_VER, sizeof(header->minor_version)) > 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }

  *bin_size = (size_t)bin_to_uint32(header->binary_size);

  if (bufsize < *bin_size) {
    return MRB_DUMP_READ_FAULT;
  }

  return MRB_DUMP_OK;
}

static struct RProc*
read_irep(mrb_state *mrb, const uint8_t *bin, size_t bufsize, uint8_t flags)
{
  int result;
  struct RProc *proc = NULL;
  mrb_irep *irep = NULL;
  const struct rite_section_header *section_header;
  size_t bin_size = 0;

  if ((mrb == NULL) || (bin == NULL)) {
    return NULL;
  }

  result = read_binary_header(bin, bufsize, &bin_size, &flags);
  if (result != MRB_DUMP_OK) {
    return NULL;
  }

  bin += sizeof(struct rite_binary_header);
  bin_size -= sizeof(struct rite_binary_header);
  while (bin_size > sizeof(struct rite_section_header)) {
    section_header = (const struct rite_section_header *)bin;
    uint32_t section_size = bin_to_uint32(section_header->section_size);
    if (bin_size < section_size) return NULL;
    if (memcmp(section_header->section_ident, RITE_SECTION_IREP_IDENT, sizeof(section_header->section_ident)) == 0) {
      irep = read_section_irep(mrb, bin, bin_size, flags, &proc);
      if (!irep) return NULL;
    }
    else if (memcmp(section_header->section_ident, RITE_SECTION_DEBUG_IDENT, sizeof(section_header->section_ident)) == 0) {
      if (!irep) return NULL;   /* corrupted data */
      result = read_section_debug(mrb, bin, bin_size, irep, flags);
      if (result < MRB_DUMP_OK) {
        return NULL;
      }
    }
    else if (memcmp(section_header->section_ident, RITE_SECTION_LV_IDENT, sizeof(section_header->section_ident)) == 0) {
      if (!irep) return NULL;
      result = read_section_lv(mrb, bin, bin_size, irep, flags);
      if (result < MRB_DUMP_OK) {
        return NULL;
      }
    }
    else if (memcmp(section_header->section_ident, RITE_BINARY_EOF, sizeof(section_header->section_ident)) != 0) {
      break;
    }

    bin += section_size;
    bin_size -= section_size;
  }

  return proc;
}

static struct RProc*
mrb_proc_read_irep(mrb_state *mrb, const uint8_t *bin)
{
  uint8_t flags = mrb_ro_data_p((char*)bin) ? FLAG_SRC_STATIC : FLAG_SRC_MALLOC;

  return read_irep(mrb, bin, (size_t)UINT32_MAX, flags);
}

DEFINE_READ_IREP_FUNC(
  mrb_irep *mrb_read_irep(mrb_state *mrb, const uint8_t *bin),
  mrb_proc_read_irep(mrb, bin))

static struct RProc*
mrb_proc_read_irep_buf(mrb_state *mrb, const void *buf, size_t bufsize)
{
  return read_irep(mrb, (const uint8_t *)buf, bufsize, FLAG_SRC_MALLOC);
}

DEFINE_READ_IREP_FUNC(
  MRB_API mrb_irep *mrb_read_irep_buf(mrb_state *mrb, const void *buf, size_t bufsize),
  mrb_proc_read_irep_buf(mrb, buf, bufsize))

void mrb_exc_set(mrb_state *mrb, mrb_value exc);

static void
irep_error(mrb_state *mrb)
{
  mrb_exc_set(mrb, mrb_exc_new_lit(mrb, E_SCRIPT_ERROR, "irep load error"));
}

void mrb_codedump_all(mrb_state*, struct RProc*);

static mrb_value
load_irep(mrb_state *mrb, struct RProc *proc, mrbc_context *c)
{
  if (!proc || !proc->body.irep) {
    irep_error(mrb);
    return mrb_nil_value();
  }
  proc->c = NULL;
  if (c && c->dump_result) mrb_codedump_all(mrb, proc);
  if (c && c->no_exec) return mrb_obj_value(proc);
  return mrb_top_run(mrb, proc, mrb_top_self(mrb), 0);
}

MRB_API mrb_value
mrb_load_irep_cxt(mrb_state *mrb, const uint8_t *bin, mrbc_context *c)
{
  struct RProc *proc = mrb_proc_read_irep(mrb, bin);
  if (!proc) return mrb_undef_value();
  return load_irep(mrb, proc, c);
}

MRB_API mrb_value
mrb_load_irep_buf_cxt(mrb_state *mrb, const void *buf, size_t bufsize, mrbc_context *c)
{
  return load_irep(mrb, mrb_proc_read_irep_buf(mrb, buf, bufsize), c);
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

MRB_API mrb_value
mrb_load_proc(mrb_state *mrb, const struct RProc *proc)
{
  return mrb_top_run(mrb, proc, mrb_top_self(mrb), 0);
}

#ifndef MRB_NO_STDIO

static struct RProc*
mrb_proc_read_irep_file(mrb_state *mrb, FILE *fp)
{
  struct RProc *proc = NULL;
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
  result = read_binary_header(buf, (size_t)-1, &buf_size, &flags);
  if (result != MRB_DUMP_OK || buf_size <= header_size) {
    goto irep_exit;
  }

  buf = (uint8_t*)mrb_realloc(mrb, buf, buf_size);
  if (fread(buf+header_size, buf_size-header_size, 1, fp) == 0) {
    goto irep_exit;
  }
  proc = read_irep(mrb, buf, (size_t)-1, FLAG_SRC_MALLOC);

irep_exit:
  mrb_free(mrb, buf);
  return proc;
}

DEFINE_READ_IREP_FUNC(
  mrb_irep *mrb_read_irep_file(mrb_state *mrb, FILE *fp),
  mrb_proc_read_irep_file(mrb, fp))

MRB_API mrb_value
mrb_load_irep_file_cxt(mrb_state *mrb, FILE* fp, mrbc_context *c)
{
  return load_irep(mrb, mrb_proc_read_irep_file(mrb, fp), c);
}

MRB_API mrb_value
mrb_load_irep_file(mrb_state *mrb, FILE* fp)
{
  return mrb_load_irep_file_cxt(mrb, fp, NULL);
}
#endif /* MRB_NO_STDIO */
