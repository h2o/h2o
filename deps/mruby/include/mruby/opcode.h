/**
** @file mruby/opcode.h - RiteVM operation codes
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_OPCODE_H
#define MRUBY_OPCODE_H

enum mrb_insn {
#define OPCODE(x,_) OP_ ## x,
#include "mruby/ops.h"
#undef OPCODE
};

#define OP_L_STRICT  1
#define OP_L_CAPTURE 2
#define OP_L_METHOD  OP_L_STRICT
#define OP_L_LAMBDA  (OP_L_STRICT|OP_L_CAPTURE)
#define OP_L_BLOCK   OP_L_CAPTURE

#define OP_R_NORMAL 0
#define OP_R_BREAK  1
#define OP_R_RETURN 2

#define PEEK_B(pc) (*(pc))
#define PEEK_S(pc) ((pc)[0]<<8|(pc)[1])
#define PEEK_W(pc) ((pc)[0]<<16|(pc)[1]<<8|(pc)[2])

#define READ_B() PEEK_B(pc++)
#define READ_S() (pc+=2, PEEK_S(pc-2))
#define READ_W() (pc+=3, PEEK_W(pc-3))

#define FETCH_Z() /* nothing */
#define FETCH_B() do {a=READ_B();} while (0)
#define FETCH_BB() do {a=READ_B(); b=READ_B();} while (0)
#define FETCH_BBB() do {a=READ_B(); b=READ_B(); c=READ_B();} while (0)
#define FETCH_BS() do {a=READ_B(); b=READ_S();} while (0)
#define FETCH_BSS() do {a=READ_B(); b=READ_S(); c=READ_S();} while (0)
#define FETCH_S() do {a=READ_S();} while (0)
#define FETCH_W() do {a=READ_W();} while (0)

#endif  /* MRUBY_OPCODE_H */
