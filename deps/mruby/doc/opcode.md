# The new bytecode

We will reimplement VM to use 8bit instruction code. By
bytecode, we mean real byte code. The whole purpose is
reducing the memory consumption of mruby VM.

# Instructions

Instructions are bytes. There can be 256 instructions. Currently we
have 94 instructions. Instructions can take 0 to 3 operands.

## operands

The size of operands can be either 8bits, 16bits or 24bits.
In the table.1 below, the second field describes the size (and
sign) of operands.

* B: 8bit
* sB: signed 8bit
* S: 16bit
* sS: signed 16bit
* W: 24bit

First two byte operands may be extended to 16bit. When those byte
operands are bigger than 256, the instruction will be prefixed by
`OP_EXT1` (means 1st operand is 16bit) or `OP_EXT2` (means 2nd operand
is 16bit) or `OP_EXT3` (means 1st and 2nd operands are 16bit).

For instructions marked by `'`, `OP_EXT1` can be prefixed. For those
with `"`, either `OP_EXT1` or `OP_EXT2` or `OP_EXT2` can be prefixed.

## table.1 Instruction Table

|Instruction Name |Operand type |Semantics        
|-----------------|-------------|-----------------
|OP_NOP           | -           |                 
|OP_MOVE"         |BB           |R(a) = R(b)      
|OP_LOADL"        |BB           |R(a) = Pool(b)   
|OP_LOADI"        |BsB          |R(a) = mrb_int(b)
|OP_LOADI_0'      |B            |R(a) = 0
|OP_LOADI_1'      |B            |R(a) = 1
|OP_LOADI_2'      |B            |R(a) = 2
|OP_LOADI_3'      |B            |R(a) = 3
|OP_LOADSYM"      |BB           |R(a) = Syms(b)
|OP_LOADNIL'      |B            |R(a) = nil
|OP_LOADSELF'     |B            |R(a) = self
|OP_LOADT'        |B            |R(a) = true
|OP_LOADF'        |B            |R(a) = false
|OP_GETGV"        |BB           |R(a) = getglobal(Syms(b))
|OP_SETGV"        |BB           |setglobal(Syms(b), R(a))
|OP_GETSV"        |BB           |R(a) = Special[b]
|OP_SETSV"        |BB           |Special[b] = R(a)
|OP_GETIV"        |BB           |R(a) = ivget(Syms(b))
|OP_SETIV"        |BB           |ivset(Syms(b),R(a))
|OP_GETCV"        |BB           |R(a) = cvget(Syms(b))
|OP_SETCV"        |BB           |cvset(Syms(b),R(a))
|OP_GETCONST"     |BB           |R(a) = constget(Syms(b))
|OP_SETCONST"     |BB           |constset(Syms(b),R(a))
|OP_GETMCNST"     |BB           |R(a) = R(a)::Syms(b)
|OP_SETMCNST"     |BB           |R(a+1)::Syms(b) = R(a)
|OP_GETUPVAR'     |BBB          |R(a) = uvget(b,c)
|OP_SETUPVAR'     |BBB          |uvset(b,c,R(a))
|OP_JMP           |S            |pc+=a
|OP_JMPIF'        |SB           |if R(b) pc+=a
|OP_JMPNOT'       |SB           |if !R(b) pc+=a
|OP_ONERR         |sS           |rescue_push(pc+a)
|OP_EXCEPT'       |B            |R(a) = exc
|OP_RESCUE"       |BB           |R(b) = R(a).isa?(R(b))
|OP_POPERR        |B            |a.times{rescue_pop()}
|OP_RAISE'        |B            |raise(R(a))
|OP_EPUSH'        |B            |ensure_push(SEQ[a])
|OP_EPOP          |B            |A.times{ensure_pop().call}
|OP_SENDV"        |BB           |R(a) = call(R(a),Syms(b),*R(a+1))
|OP_SENDVB"       |BB           |R(a) = call(R(a),Syms(b),*R(a+1),&R(a+2))
|OP_SEND"         |BBB          |R(a) = call(R(a),Syms(b),R(a+1),...,R(a+c))
|OP_SENDB"        |BBB          |R(a) = call(R(a),Syms(Bx),R(a+1),...,R(a+c),&R(a+c+1))
|OP_CALL'         |B            |R(a) = self.call(frame.argc, frame.argv)
|OP_SUPER'        |BB           |R(a) = super(R(a+1),... ,R(a+b+1))
|OP_ARGARY'       |BS           |R(a) = argument array (16=5:1:5:1:4)
|OP_ENTER         |W            |arg setup according to flags (23=5:5:1:5:5:1:1)
|OP_KARG"         |BB           |R(a) = kdict[Syms(Bx)]                          # todo
|OP_KARG2"        |BB           |R(a) = kdict[Syms(Bx)]; kdict.rm(Syms(b))       # todo
|OP_RETURN'       |B            |return R(a) (normal)
|OP_RETURN_BLK'   |B            |return R(a) (in-block return)
|OP_BREAK'        |B            |break R(a)
|OP_BLKPUSH'      |BS           |R(a) = block (16=5:1:5:1:4)
|OP_ADD"          |BB           |R(a) = R(a)+R(a+1)
|OP_ADDI"         |BBB          |R(a) = R(a)+mrb_int(c)
|OP_SUB"          |BB           |R(a) = R(a)-R(a+1)
|OP_SUBI"         |BB           |R(a) = R(a)-C
|OP_MUL"          |BB           |R(a) = R(a)*R(a+1)
|OP_DIV"          |BB           |R(a) = R(a)/R(a+1)
|OP_EQ"           |BB           |R(a) = R(a)==R(a+1)
|OP_LT"           |BB           |R(a) = R(a)<R(a+1)
|OP_LE"           |BB           |R(a) = R(a)<=R(a+1)
|OP_GT"           |BB           |R(a) = R(a)>R(a+1)
|OP_GE"           |BB           |R(a) = R(a)>=R(a+1)
|OP_ARRAY'        |BB           |R(a) = ary_new(R(a),R(a+1)..R(a+b))
|OP_ARRAY2"       |BB           |R(a) = ary_new(R(b),R(b+1)..R(b+c))
|OP_ARYCAT'       |B            |ary_cat(R(a),R(a+1))
|OP_ARYPUSH'      |B            |ary_push(R(a),R(a+1))
|OP_AREF'         |BB           |R(a) = R(a)[b]
|OP_ASET'         |BB           |R(a)[b] = R(a+1)
|OP_APOST'        |BB           |*R(a),R(A+1)..R(A+C) = R(a)[B..]
|OP_STRING"       |BB           |R(a) = str_dup(Lit(b))
|OP_STRCAT'       |B            |str_cat(R(a),R(a+1))
|OP_HASH'         |BB           |R(a) = hash_new(R(a),R(a+1)..R(a+b))
|OP_HASHADD'      |BB           |R(a) = hash_push(R(a),R(a+1)..R(a+b))
|OP_LAMBDA"       |BB           |R(a) = lambda(SEQ[b],OP_L_LAMBDA)
|OP_BLOCK"        |BB           |R(a) = lambda(SEQ[b],OP_L_BLOCK)
|OP_METHOD"       |BB           |R(a) = lambda(SEQ[b],OP_L_METHOD)
|OP_RANGE_INC'    |B            |R(a) = range_new(R(a),R(a+1),FALSE)
|OP_RANGE_EXC'    |B            |R(a) = range_new(R(a),R(a+1),TRUE)
|OP_OCLASS'       |B            |R(a) = ::Object
|OP_CLASS"        |BB           |R(a) = newclass(R(a),Syms(b),R(a+1))
|OP_MODULE"       |BB           |R(a) = newmodule(R(a),Syms(b))
|OP_EXEC"         |BB           |R(a) = blockexec(R(a),SEQ[b])
|OP_DEF"          |BB           |R(a).newmethod(Syms(b),R(a+1))
|OP_ALIAS'        |B            |alias_method(R(a),R(a+1),R(a+2))
|OP_UNDEF"        |BB           |undef_method(R(a),Syms(b))
|OP_SCLASS'       |B            |R(a) = R(a).singleton_class
|OP_TCLASS'       |B            |R(a) = target_class
|OP_ERR'          |B            |raise(RuntimeError, Lit(Bx))
|OP_EXT1          |-            |make 1st operand 16bit
|OP_EXT2          |-            |make 2nd operand 16bit
|OP_EXT3          |-            |make 1st and 2nd operands 16bit
|OP_STOP          |-            |stop VM
