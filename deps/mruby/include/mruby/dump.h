/*
** mruby/dump.h - mruby binary dumper (mrbc binary format)
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_DUMP_H
#define MRUBY_DUMP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "mruby.h"
#include "mruby/irep.h"

#define DUMP_DEBUG_INFO 1
#define DUMP_ENDIAN_BIG 2
#define DUMP_ENDIAN_LIL 4
#define DUMP_ENDIAN_NAT 6 
#define DUMP_ENDIAN_MASK 6 

int mrb_dump_irep(mrb_state *mrb, mrb_irep *irep, uint8_t flags, uint8_t **bin, size_t *bin_size);
#ifdef ENABLE_STDIO
int mrb_dump_irep_binary(mrb_state*, mrb_irep*, uint8_t, FILE*);
int mrb_dump_irep_cfunc(mrb_state *mrb, mrb_irep*, uint8_t flags, FILE *f, const char *initname);
mrb_irep *mrb_read_irep_file(mrb_state*, FILE*);
MRB_API mrb_value mrb_load_irep_file(mrb_state*,FILE*);
MRB_API mrb_value mrb_load_irep_file_cxt(mrb_state*, FILE*, mrbc_context*);
#endif
MRB_API mrb_irep *mrb_read_irep(mrb_state*, const uint8_t*);

/* dump/load error code
 *
 * NOTE: MRB_DUMP_GENERAL_FAILURE is caused by
 * unspecified issues like malloc failed.
 */
#define MRB_DUMP_OK                     0
#define MRB_DUMP_GENERAL_FAILURE      (-1)
#define MRB_DUMP_WRITE_FAULT          (-2)
#define MRB_DUMP_READ_FAULT           (-3)
#define MRB_DUMP_CRC_ERROR            (-4)
#define MRB_DUMP_INVALID_FILE_HEADER  (-5)
#define MRB_DUMP_INVALID_IREP         (-6)
#define MRB_DUMP_INVALID_ARGUMENT     (-7)

/* null symbol length */
#define MRB_DUMP_NULL_SYM_LEN         0xFFFF

/* Rite Binary File header */
#define RITE_BINARY_IDENT              "RITE"
#define RITE_BINARY_IDENT_LIL          "ETIR"
#define RITE_BINARY_FORMAT_VER         "0003"
#define RITE_COMPILER_NAME             "MATZ"
#define RITE_COMPILER_VERSION          "0000"

#define RITE_VM_VER                    "0000"

#define RITE_BINARY_EOF                "END\0"
#define RITE_SECTION_IREP_IDENT        "IREP"
#define RITE_SECTION_LINENO_IDENT      "LINE"
#define RITE_SECTION_DEBUG_IDENT       "DBG\0"
#define RITE_SECTION_LV_IDENT          "LVAR"

#define MRB_DUMP_DEFAULT_STR_LEN      128
#define MRB_DUMP_ALIGNMENT            sizeof(uint32_t)

/* binary header */
struct rite_binary_header {
  uint8_t binary_ident[4];    /* Binary Identifier */
  uint8_t binary_version[4];  /* Binary Format Version */
  uint8_t binary_crc[2];      /* Binary CRC */
  uint8_t binary_size[4];     /* Binary Size */
  uint8_t compiler_name[4];   /* Compiler name */
  uint8_t compiler_version[4];
};

/* section header */
#define RITE_SECTION_HEADER \
  uint8_t section_ident[4]; \
  uint8_t section_size[4]

struct rite_section_header {
  RITE_SECTION_HEADER;
};

struct rite_section_irep_header {
  RITE_SECTION_HEADER;

  uint8_t rite_version[4];    /* Rite Instruction Specification Version */
};

struct rite_section_lineno_header {
  RITE_SECTION_HEADER;
};

struct rite_section_debug_header {
  RITE_SECTION_HEADER;
};

struct rite_section_lv_header {
  RITE_SECTION_HEADER;
};

#define RITE_LV_NULL_MARK              UINT16_MAX

struct rite_binary_footer {
  RITE_SECTION_HEADER;
};

static inline int
bigendian_p()
{
  int i;
  char *p;

  i = 1;
  p = (char*)&i;
  return p[0]?0:1;
}

static inline size_t
uint8_to_bin(uint8_t s, uint8_t *bin)
{
  *bin = s;
  return sizeof(uint8_t);
}

static inline size_t
uint16_to_bin(uint16_t s, uint8_t *bin)
{
  *bin++ = (s >> 8) & 0xff;
  *bin   = s & 0xff;
  return sizeof(uint16_t);
}

static inline size_t
uint32_to_bin(uint32_t l, uint8_t *bin)
{
  *bin++ = (l >> 24) & 0xff;
  *bin++ = (l >> 16) & 0xff;
  *bin++ = (l >> 8) & 0xff;
  *bin   = l & 0xff;
  return sizeof(uint32_t);
}

static inline size_t
uint32l_to_bin(uint32_t l, uint8_t *bin)
{
  bin[3] = (l >> 24) & 0xff;
  bin[2] = (l >> 16) & 0xff;
  bin[1] = (l >> 8) & 0xff;
  bin[0] = l & 0xff;
  return sizeof(uint32_t);
}

static inline uint32_t
bin_to_uint32(const uint8_t *bin)
{
  return (uint32_t)bin[0] << 24 |
         (uint32_t)bin[1] << 16 |
         (uint32_t)bin[2] << 8  |
         (uint32_t)bin[3];
}

static inline uint32_t
bin_to_uint32l(const uint8_t *bin)
{
  return (uint32_t)bin[3] << 24 |
         (uint32_t)bin[2] << 16 |
         (uint32_t)bin[1] << 8  |
         (uint32_t)bin[0];
}

static inline uint16_t
bin_to_uint16(const uint8_t *bin)
{
  return (uint16_t)bin[0] << 8 |
         (uint16_t)bin[1];
}

static inline uint8_t
bin_to_uint8(const uint8_t *bin)
{
  return (uint8_t)bin[0];
}

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

/* crc.c */
uint16_t
calc_crc_16_ccitt(const uint8_t *src, size_t nbytes, uint16_t crc);

#endif  /* MRUBY_DUMP_H */
