/**
** @file mruby/istruct.h - Inline structures
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_ISTRUCT_H
#define MRUBY_ISTRUCT_H

#include "common.h"
#include <string.h>

/**
 * Inline structures that fit in RVALUE
 *
 * They cannot have finalizer, and cannot have instance variables.
 */
MRB_BEGIN_DECL

#define ISTRUCT_DATA_SIZE (sizeof(void*) * 3)

struct RIStruct {
  MRB_OBJECT_HEADER;
  union {
    intptr_t inline_alignment[3];
    char inline_data[ISTRUCT_DATA_SIZE];
  };
};

#define RISTRUCT(obj)         ((struct RIStruct*)(mrb_ptr(obj)))
#define ISTRUCT_PTR(obj)      (RISTRUCT(obj)->inline_data)

MRB_INLINE mrb_int mrb_istruct_size()
{
  return ISTRUCT_DATA_SIZE;
}

MRB_INLINE void* mrb_istruct_ptr(mrb_value object)
{
  return ISTRUCT_PTR(object);
}

MRB_INLINE void mrb_istruct_copy(mrb_value dest, mrb_value src)
{
  memcpy(ISTRUCT_PTR(dest), ISTRUCT_PTR(src), ISTRUCT_DATA_SIZE);
}

MRB_END_DECL

#endif /* MRUBY_ISTRUCT_H */
