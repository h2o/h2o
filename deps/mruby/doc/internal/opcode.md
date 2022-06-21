# The new bytecode

We will reimplement the VM to use 8bit instruction code. By
bytecode, we mean real byte code. The whole purpose is
reducing the memory consumption of mruby VM.

# Instructions

Instructions are bytes. There can be 256 instructions. Currently, we
have 94 instructions. Instructions can take 0 to 3 operands.

## operands

The size of operands can be either 8bits, 16bits or 24bits.
In the table.1 below, the second field describes the size (and
sign) of operands.

* B: 8bit
* S: 16bit
* sS: signed 16bit
* W: 24bit

## table.1 Instruction Table

| Instruction Name | Operand type | Semantics                                                |
|------------------|--------------|----------------------------------------------------------|
| `OP_NOP`         | `-`          | `no operation`                                           |
| `OP_MOVE`        | `BB`         | `R(a) = R(b)`                                            |
| `OP_LOADL`       | `BB`         | `R(a) = Pool(b)`                                         |
| `OP_LOADI`       | `BB`         | `R(a) = mrb_int(b)`                                      |
| `OP_LOADINEG`    | `BB`         | `R(a) = mrb_int(-b)`                                     |
| `OP_LOADI__1`    | `B`          | `R(a) = mrb_int(-1)`                                     |
| `OP_LOADI_0`     | `B`          | `R(a) = mrb_int(0)`                                      |
| `OP_LOADI_1`     | `B`          | `R(a) = mrb_int(1)`                                      |
| `OP_LOADI_2`     | `B`          | `R(a) = mrb_int(2)`                                      |
| `OP_LOADI_3`     | `B`          | `R(a) = mrb_int(3)`                                      |
| `OP_LOADI_4`     | `B`          | `R(a) = mrb_int(4)`                                      |
| `OP_LOADI_5`     | `B`          | `R(a) = mrb_int(5)`                                      |
| `OP_LOADI_6`     | `B`          | `R(a) = mrb_int(6)`                                      |
| `OP_LOADI_7`     | `B`          | `R(a) = mrb_int(7)`                                      |
| `OP_LOADI16`     | `BS`         | `R(a) = mrb_int(b)`                                      |
| `OP_LOADI32`     | `BSS`        | `R(a) = mrb_int((b<<16)+c)`                              |
| `OP_LOADSYM`     | `BB`         | `R(a) = Syms(b)`                                         |
| `OP_LOADNIL`     | `B`          | `R(a) = nil`                                             |
| `OP_LOADSELF`    | `B`          | `R(a) = self`                                            |
| `OP_LOADT`       | `B`          | `R(a) = true`                                            |
| `OP_LOADF`       | `B`          | `R(a) = false`                                           |
| `OP_GETGV`       | `BB`         | `R(a) = getglobal(Syms(b))`                              |
| `OP_SETGV`       | `BB`         | `setglobal(Syms(b), R(a))`                               |
| `OP_GETSV`       | `BB`         | `R(a) = Special[Syms(b)]`                                |
| `OP_SETSV`       | `BB`         | `Special[Syms(b)] = R(a)`                                |
| `OP_GETIV`       | `BB`         | `R(a) = ivget(Syms(b))`                                  |
| `OP_SETIV`       | `BB`         | `ivset(Syms(b),R(a))`                                    |
| `OP_GETCV`       | `BB`         | `R(a) = cvget(Syms(b))`                                  |
| `OP_SETCV`       | `BB`         | `cvset(Syms(b),R(a))`                                    |
| `OP_GETCONST`    | `BB`         | `R(a) = constget(Syms(b))`                               |
| `OP_SETCONST`    | `BB`         | `constset(Syms(b),R(a))`                                 |
| `OP_GETMCNST`    | `BB`         | `R(a) = R(a)::Syms(b)`                                   |
| `OP_SETMCNST`    | `BB`         | `R(a+1)::Syms(b) = R(a)`                                 |
| `OP_GETUPVAR`    | `BBB`        | `R(a) = uvget(b,c)`                                      |
| `OP_SETUPVAR`    | `BBB`        | `uvset(b,c,R(a))`                                        |
| `OP_JMP`         | `S`          | `pc+=a`                                                  |
| `OP_JMPIF`       | `BS`         | `if R(a) pc+=b`                                          |
| `OP_JMPNOT`      | `BS`         | `if !R(a) pc+=b`                                         |
| `OP_JMPNIL`      | `BS`         | `if R(a)==nil pc+=b`                                     |
| `OP_JMPUW`       | `S`          | `unwind_and_jump_to(a)`                                  |
| `OP_EXCEPT`      | `B`          | `R(a) = exc`                                             |
| `OP_RESCUE`      | `BB`         | `R(b) = R(a).isa?(R(b))`                                 |
| `OP_RAISEIF`     | `B`          | `raise(R(a)) if R(a)`                                    |
| `OP_SEND`        | `BBB`        | `R(a) = call(R(a),Syms(b),R(a+1),...,R(a+c))`            |
| `OP_SENDB`       | `BBB`        | `R(a) = call(R(a),Syms(b),R(a+1),...,R(a+c),&R(a+c+1))`  |
| `OP_CALL`        | `-`          | `R(0) = self.call(frame.argc, frame.argv)`               |
| `OP_SUPER`       | `BB`         | `R(a) = super(R(a+1),... ,R(a+b+1))`                     |
| `OP_ARGARY`      | `BS`         | `R(a) = argument array (16=m5:r1:m5:d1:lv4)`             |
| `OP_ENTER`       | `W`          | `arg setup according to flags (23=m5:o5:r1:m5:k5:d1:b1)` |
| `OP_KEY_P`       | `BB`         | `R(a) = kdict.key?(Syms(b))`                             |
| `OP_KEYEND`      | `-`          | `raise unless kdict.empty?`                              |
| `OP_KARG`        | `BB`         | `R(a) = kdict[Syms(b)]; kdict.delete(Syms(b))`           |
| `OP_RETURN`      | `B`          | `return R(a) (normal)`                                   |
| `OP_RETURN_BLK`  | `B`          | `return R(a) (in-block return)`                          |
| `OP_BREAK`       | `B`          | `break R(a)`                                             |
| `OP_BLKPUSH`     | `BS`         | `R(a) = block (16=m5:r1:m5:d1:lv4)`                      |
| `OP_ADD`         | `B`          | `R(a) = R(a)+R(a+1)`                                     |
| `OP_ADDI`        | `BB`         | `R(a) = R(a)+mrb_int(b)`                                 |
| `OP_SUB`         | `B`          | `R(a) = R(a)-R(a+1)`                                     |
| `OP_SUBI`        | `BB`         | `R(a) = R(a)-mrb_int(b)`                                 |
| `OP_MUL`         | `B`          | `R(a) = R(a)*R(a+1)`                                     |
| `OP_DIV`         | `B`          | `R(a) = R(a)/R(a+1)`                                     |
| `OP_EQ`          | `B`          | `R(a) = R(a)==R(a+1)`                                    |
| `OP_LT`          | `B`          | `R(a) = R(a)<R(a+1)`                                     |
| `OP_LE`          | `B`          | `R(a) = R(a)<=R(a+1)`                                    |
| `OP_GT`          | `B`          | `R(a) = R(a)>R(a+1)`                                     |
| `OP_GE`          | `B`          | `R(a) = R(a)>=R(a+1)`                                    |
| `OP_ARRAY`       | `BB`         | `R(a) = ary_new(R(a),R(a+1)..R(a+b))`                    |
| `OP_ARRAY2`      | `BBB`        | `R(a) = ary_new(R(b),R(b+1)..R(b+c))`                    |
| `OP_ARYCAT`      | `B`          | `ary_cat(R(a),R(a+1))`                                   |
| `OP_ARYPUSH`     | `BB`         | `ary_push(R(a),R(a+1)..R(a+b))`                          |
| `OP_ARYDUP`      | `B`          | `R(a) = ary_dup(R(a))`                                   |
| `OP_AREF`        | `BBB`        | `R(a) = R(b)[c]`                                         |
| `OP_ASET`        | `BBB`        | `R(b)[c] = R(a)`                                         |
| `OP_APOST`       | `BBB`        | `*R(a),R(a+1)..R(a+c) = R(a)[b..]`                       |
| `OP_INTERN`      | `B`          | `R(a) = intern(R(a))`                                    |
| `OP_STRING`      | `BB`         | `R(a) = str_dup(Pool(b))`                                |
| `OP_STRCAT`      | `B`          | `str_cat(R(a),R(a+1))`                                   |
| `OP_HASH`        | `BB`         | `R(a) = hash_new(R(a),R(a+1)..R(a+b*2-1))`               |
| `OP_HASHADD`     | `BB`         | `hash_push(R(a),R(a+1)..R(a+b*2))`                       |
| `OP_HASHCAT`     | `B`          | `R(a) = hash_cat(R(a),R(a+1))`                           |
| `OP_LAMBDA`      | `BB`         | `R(a) = lambda(Irep(b),OP_L_LAMBDA)`                     |
| `OP_BLOCK`       | `BB`         | `R(a) = lambda(Irep(b),OP_L_BLOCK)`                      |
| `OP_METHOD`      | `BB`         | `R(a) = lambda(Irep(b),OP_L_METHOD)`                     |
| `OP_RANGE_INC`   | `B`          | `R(a) = range_new(R(a),R(a+1),FALSE)`                    |
| `OP_RANGE_EXC`   | `B`          | `R(a) = range_new(R(a),R(a+1),TRUE)`                     |
| `OP_OCLASS`      | `B`          | `R(a) = ::Object`                                        |
| `OP_CLASS`       | `BB`         | `R(a) = newclass(R(a),Syms(b),R(a+1))`                   |
| `OP_MODULE`      | `BB`         | `R(a) = newmodule(R(a),Syms(b))`                         |
| `OP_EXEC`        | `BB`         | `R(a) = blockexec(R(a),Irep[b])`                         |
| `OP_DEF`         | `BB`         | `R(a).newmethod(Syms(b),R(a+1)); R(a) = Syms(b)`         |
| `OP_ALIAS`       | `BB`         | `alias_method(target_class,Syms(a),Syms(b))`             |
| `OP_UNDEF`       | `B`          | `undef_method(target_class,Syms(a))`                     |
| `OP_SCLASS`      | `B`          | `R(a) = R(a).singleton_class`                            |
| `OP_TCLASS`      | `B`          | `R(a) = target_class`                                    |
| `OP_DEBUG`       | `BBB`        | `print a,b,c`                                            |
| `OP_ERR`         | `B`          | `raise(LocalJumpError, Pool(a))`                         |
| `OP_EXT1`        | `-`          | `make 1st operand 16bit`                                 |
| `OP_EXT2`        | `-`          | `make 2nd operand 16bit`                                 |
| `OP_EXT3`        | `-`          | `make 1st and 2nd operands 16bit`                        |
| `OP_STOP`        | `-`          | `stop VM`                                                |
|------------------|--------------|----------------------------------------------------------|
