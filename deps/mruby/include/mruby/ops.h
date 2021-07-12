/* operand types:
   + Z: no operand (Z,Z,Z,Z)
   + B: 8bit (B,S,B,B)
   + BB: 8+8bit (BB,SB,BS,SS)
   + BBB: 8+8+8bit (BBB,SBB,BSB,SSB)
   + BS: 8+16bit (BS,SS,BS,BS)
   + S: 16bit (S,S,S,S)
   + W: 24bit (W,W,W,W)
*/

/*-----------------------------------------------------------------------
operation code    operands      semantics
------------------------------------------------------------------------*/
OPCODE(NOP,        Z)        /* no operation */
OPCODE(MOVE,       BB)       /* R(a) = R(b) */
OPCODE(LOADL,      BB)       /* R(a) = Pool(b) */
OPCODE(LOADI,      BB)       /* R(a) = mrb_int(b) */
OPCODE(LOADINEG,   BB)       /* R(a) = mrb_int(-b) */
OPCODE(LOADI__1,   B)        /* R(a) = mrb_int(-1) */
OPCODE(LOADI_0,    B)        /* R(a) = mrb_int(0) */
OPCODE(LOADI_1,    B)        /* R(a) = mrb_int(1) */
OPCODE(LOADI_2,    B)        /* R(a) = mrb_int(2) */
OPCODE(LOADI_3,    B)        /* R(a) = mrb_int(3) */
OPCODE(LOADI_4,    B)        /* R(a) = mrb_int(4) */
OPCODE(LOADI_5,    B)        /* R(a) = mrb_int(5) */
OPCODE(LOADI_6,    B)        /* R(a) = mrb_int(6) */
OPCODE(LOADI_7,    B)        /* R(a) = mrb_int(7) */
OPCODE(LOADSYM,    BB)       /* R(a) = Syms(b) */
OPCODE(LOADNIL,    B)        /* R(a) = nil */
OPCODE(LOADSELF,   B)        /* R(a) = self */
OPCODE(LOADT,      B)        /* R(a) = true */
OPCODE(LOADF,      B)        /* R(a) = false */
OPCODE(GETGV,      BB)       /* R(a) = getglobal(Syms(b)) */
OPCODE(SETGV,      BB)       /* setglobal(Syms(b), R(a)) */
OPCODE(GETSV,      BB)       /* R(a) = Special[Syms(b)] */
OPCODE(SETSV,      BB)       /* Special[Syms(b)] = R(a) */
OPCODE(GETIV,      BB)       /* R(a) = ivget(Syms(b)) */
OPCODE(SETIV,      BB)       /* ivset(Syms(b),R(a)) */
OPCODE(GETCV,      BB)       /* R(a) = cvget(Syms(b)) */
OPCODE(SETCV,      BB)       /* cvset(Syms(b),R(a)) */
OPCODE(GETCONST,   BB)       /* R(a) = constget(Syms(b)) */
OPCODE(SETCONST,   BB)       /* constset(Syms(b),R(a)) */
OPCODE(GETMCNST,   BB)       /* R(a) = R(a)::Syms(b) */
OPCODE(SETMCNST,   BB)       /* R(a+1)::Syms(b) = R(a) */
OPCODE(GETUPVAR,   BBB)      /* R(a) = uvget(b,c) */
OPCODE(SETUPVAR,   BBB)      /* uvset(b,c,R(a)) */
OPCODE(JMP,        S)        /* pc=a */
OPCODE(JMPIF,      BS)       /* if R(a) pc=b */
OPCODE(JMPNOT,     BS)       /* if !R(a) pc=b */
OPCODE(JMPNIL,     BS)       /* if R(a)==nil pc=b */
OPCODE(ONERR,      S)        /* rescue_push(a) */
OPCODE(EXCEPT,     B)        /* R(a) = exc */
OPCODE(RESCUE,     BB)       /* R(b) = R(a).isa?(R(b)) */
OPCODE(POPERR,     B)        /* a.times{rescue_pop()} */
OPCODE(RAISE,      B)        /* raise(R(a)) */
OPCODE(EPUSH,      B)        /* ensure_push(SEQ[a]) */
OPCODE(EPOP,       B)        /* A.times{ensure_pop().call} */
OPCODE(SENDV,      BB)       /* R(a) = call(R(a),Syms(b),*R(a+1)) */
OPCODE(SENDVB,     BB)       /* R(a) = call(R(a),Syms(b),*R(a+1),&R(a+2)) */
OPCODE(SEND,       BBB)      /* R(a) = call(R(a),Syms(b),R(a+1),...,R(a+c)) */
OPCODE(SENDB,      BBB)      /* R(a) = call(R(a),Syms(b),R(a+1),...,R(a+c),&R(a+c+1)) */
OPCODE(CALL,       Z)        /* R(0) = self.call(frame.argc, frame.argv) */
OPCODE(SUPER,      BB)       /* R(a) = super(R(a+1),... ,R(a+b+1)) */
OPCODE(ARGARY,     BS)       /* R(a) = argument array (16=m5:r1:m5:d1:lv4) */
OPCODE(ENTER,      W)        /* arg setup according to flags (23=m5:o5:r1:m5:k5:d1:b1) */
OPCODE(KEY_P,      BB)       /* R(a) = kdict.key?(Syms(b))                      # todo */
OPCODE(KEYEND,     Z)        /* raise unless kdict.empty?                       # todo */
OPCODE(KARG,       BB)       /* R(a) = kdict[Syms(b)]; kdict.delete(Syms(b))    # todo */
OPCODE(RETURN,     B)        /* return R(a) (normal) */
OPCODE(RETURN_BLK, B)        /* return R(a) (in-block return) */
OPCODE(BREAK,      B)        /* break R(a) */
OPCODE(BLKPUSH,    BS)       /* R(a) = block (16=m5:r1:m5:d1:lv4) */
OPCODE(ADD,        B)        /* R(a) = R(a)+R(a+1) */
OPCODE(ADDI,       BB)       /* R(a) = R(a)+mrb_int(b) */
OPCODE(SUB,        B)        /* R(a) = R(a)-R(a+1) */
OPCODE(SUBI,       BB)       /* R(a) = R(a)-mrb_int(b) */
OPCODE(MUL,        B)        /* R(a) = R(a)*R(a+1) */
OPCODE(DIV,        B)        /* R(a) = R(a)/R(a+1) */
OPCODE(EQ,         B)        /* R(a) = R(a)==R(a+1) */
OPCODE(LT,         B)        /* R(a) = R(a)<R(a+1) */
OPCODE(LE,         B)        /* R(a) = R(a)<=R(a+1) */
OPCODE(GT,         B)        /* R(a) = R(a)>R(a+1) */
OPCODE(GE,         B)        /* R(a) = R(a)>=R(a+1) */
OPCODE(ARRAY,      BB)       /* R(a) = ary_new(R(a),R(a+1)..R(a+b)) */
OPCODE(ARRAY2,     BBB)      /* R(a) = ary_new(R(b),R(b+1)..R(b+c)) */
OPCODE(ARYCAT,     B)        /* ary_cat(R(a),R(a+1)) */
OPCODE(ARYPUSH,    B)        /* ary_push(R(a),R(a+1)) */
OPCODE(ARYDUP,     B)        /* R(a) = ary_dup(R(a)) */
OPCODE(AREF,       BBB)      /* R(a) = R(b)[c] */
OPCODE(ASET,       BBB)      /* R(a)[c] = R(b) */
OPCODE(APOST,      BBB)      /* *R(a),R(a+1)..R(a+c) = R(a)[b..] */
OPCODE(INTERN,     B)        /* R(a) = intern(R(a)) */
OPCODE(STRING,     BB)       /* R(a) = str_dup(Lit(b)) */
OPCODE(STRCAT,     B)        /* str_cat(R(a),R(a+1)) */
OPCODE(HASH,       BB)       /* R(a) = hash_new(R(a),R(a+1)..R(a+b*2-1)) */
OPCODE(HASHADD,    BB)       /* R(a) = hash_push(R(a),R(a+1)..R(a+b*2)) */
OPCODE(HASHCAT,    B)        /* R(a) = hash_cat(R(a),R(a+1)) */
OPCODE(LAMBDA,     BB)       /* R(a) = lambda(SEQ[b],L_LAMBDA) */
OPCODE(BLOCK,      BB)       /* R(a) = lambda(SEQ[b],L_BLOCK) */
OPCODE(METHOD,     BB)       /* R(a) = lambda(SEQ[b],L_METHOD) */
OPCODE(RANGE_INC,  B)        /* R(a) = range_new(R(a),R(a+1),FALSE) */
OPCODE(RANGE_EXC,  B)        /* R(a) = range_new(R(a),R(a+1),TRUE) */
OPCODE(OCLASS,     B)        /* R(a) = ::Object */
OPCODE(CLASS,      BB)       /* R(a) = newclass(R(a),Syms(b),R(a+1)) */
OPCODE(MODULE,     BB)       /* R(a) = newmodule(R(a),Syms(b)) */
OPCODE(EXEC,       BB)       /* R(a) = blockexec(R(a),SEQ[b]) */
OPCODE(DEF,        BB)       /* R(a).newmethod(Syms(b),R(a+1)) */
OPCODE(ALIAS,      BB)       /* alias_method(target_class,Syms(a),Syms(b)) */
OPCODE(UNDEF,      B)        /* undef_method(target_class,Syms(a)) */
OPCODE(SCLASS,     B)        /* R(a) = R(a).singleton_class */
OPCODE(TCLASS,     B)        /* R(a) = target_class */
OPCODE(DEBUG,      BBB)      /* print a,b,c */
OPCODE(ERR,        B)        /* raise(LocalJumpError, Lit(a)) */
OPCODE(EXT1,       Z)        /* make 1st operand 16bit */
OPCODE(EXT2,       Z)        /* make 2nd operand 16bit */
OPCODE(EXT3,       Z)        /* make 1st and 2nd operands 16bit */
OPCODE(STOP,       Z)        /* stop VM */
OPCODE(LOADI16,    BS)       /* R(a) = mrb_int(b) */
