/*
** mruby/irep.h - mrb_irep structure
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_IREP_H
#define MRUBY_IREP_H

#include "common.h"
#include <mruby/compile.h>

/**
 * Compiled mruby scripts.
 */
MRB_BEGIN_DECL

enum irep_pool_type {
  IREP_TT_STRING,
  IREP_TT_FIXNUM,
  IREP_TT_FLOAT,
};

struct mrb_locals {
  mrb_sym name;
  uint16_t r;
};

/* Program data array struct */
typedef struct mrb_irep {
  uint16_t nlocals;        /* Number of local variables */
  uint16_t nregs;          /* Number of register variables */
  uint8_t flags;

  mrb_code *iseq;
  mrb_value *pool;
  mrb_sym *syms;
  struct mrb_irep **reps;

  struct mrb_locals *lv;
  /* debug info */
  const char *filename;
  uint16_t *lines;
  struct mrb_irep_debug_info* debug_info;

  size_t ilen, plen, slen, rlen, refcnt;
} mrb_irep;

#define MRB_ISEQ_NO_FREE 1

MRB_API mrb_irep *mrb_add_irep(mrb_state *mrb);
MRB_API mrb_value mrb_load_irep(mrb_state*, const uint8_t*);
MRB_API mrb_value mrb_load_irep_cxt(mrb_state*, const uint8_t*, mrbc_context*);
void mrb_irep_free(mrb_state*, struct mrb_irep*);
void mrb_irep_incref(mrb_state*, struct mrb_irep*);
void mrb_irep_decref(mrb_state*, struct mrb_irep*);

MRB_END_DECL

#endif  /* MRUBY_IREP_H */
