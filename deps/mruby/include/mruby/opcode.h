/*
** mruby/opcode.h - RiteVM operation codes
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
#define FETCH_S() do {a=READ_S();} while (0)
#define FETCH_W() do {a=READ_W();} while (0)

/* with OP_EXT1 (1st 16bit) */
#define FETCH_Z_1() FETCH_Z()
#define FETCH_B_1() FETCH_S()
#define FETCH_BB_1() do {a=READ_S(); b=READ_B();} while (0)
#define FETCH_BBB_1() do {a=READ_S(); b=READ_B(); c=READ_B();} while (0)
#define FETCH_BS_1() do {a=READ_S(); b=READ_S();} while (0)
#define FETCH_S_1() FETCH_S()
#define FETCH_W_1() FETCH_W()

/* with OP_EXT2 (2nd 16bit) */
#define FETCH_Z_2() FETCH_Z()
#define FETCH_B_2() FETCH_B()
#define FETCH_BB_2() do {a=READ_B(); b=READ_S();} while (0)
#define FETCH_BBB_2() do {a=READ_B(); b=READ_S(); c=READ_B();} while (0)
#define FETCH_BS_2() FETCH_BS()
#define FETCH_S_2() FETCH_S()
#define FETCH_W_2() FETCH_W()

/* with OP_EXT3 (1st & 2nd 16bit) */
#define FETCH_Z_3() FETCH_Z()
#define FETCH_B_3() FETCH_B()
#define FETCH_BB_3() do {a=READ_S(); b=READ_S();} while (0)
#define FETCH_BBB_3() do {a=READ_S(); b=READ_S(); c=READ_B();} while (0)
#define FETCH_BS_3() do {a=READ_S(); b=READ_S();} while (0)
#define FETCH_S_3() FETCH_S()
#define FETCH_W_3() FETCH_W()

#endif  /* MRUBY_OPCODE_H */
