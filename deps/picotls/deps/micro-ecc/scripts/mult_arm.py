#!/usr/bin/env python

import sys

if len(sys.argv) < 2:
    print "Provide the integer size in 32-bit words"
    sys.exit(1)

size = int(sys.argv[1])

full_rows = size // 3
init_size = size % 3

if init_size == 0:
    full_rows = full_rows - 1
    init_size = 3

def emit(line, *args):
    s = '"' + line + r' \n\t"'
    print s % args

rx = [3, 4, 5]
ry = [6, 7, 8]

#### set up registers
emit("add r0, %s", (size - init_size) * 4) # move z
emit("add r2, %s", (size - init_size) * 4) # move y

emit("ldmia r1!, {%s}", ", ".join(["r%s" % (rx[i]) for i in xrange(init_size)]))
emit("ldmia r2!, {%s}", ", ".join(["r%s" % (ry[i]) for i in xrange(init_size)]))

print ""
if init_size == 1:
    emit("umull r9, r10, r3, r6")
    emit("stmia r0!, {r9, r10}")
else:
    #### first two multiplications of initial block
    emit("umull r11, r12, r3, r6")
    emit("stmia r0!, {r11}")
    print ""
    emit("mov r10, #0")
    emit("umull r11, r9, r3, r7")
    emit("adds r12, r12, r11")
    emit("adc r9, r9, #0")
    emit("umull r11, r14, r4, r6")
    emit("adds r12, r12, r11")
    emit("adcs r9, r9, r14")
    emit("adc r10, r10, #0")
    emit("stmia r0!, {r12}")
    print ""

    #### rest of initial block, with moving accumulator registers
    acc = [9, 10, 11, 12, 14]
    if init_size == 3:
        emit("mov r%s, #0", acc[2])
        for i in xrange(0, 3):
            emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], rx[i], ry[2 - i])
            emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
            emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[4])
            emit("adc r%s, r%s, #0", acc[2], acc[2])
        emit("stmia r0!, {r%s}", acc[0])
        print ""
        acc = acc[1:] + acc[:1]

        emit("mov r%s, #0", acc[2])
        for i in xrange(0, 2):
            emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], rx[i + 1], ry[2 - i])
            emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
            emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[4])
            emit("adc r%s, r%s, #0", acc[2], acc[2])
        emit("stmia r0!, {r%s}", acc[0])
        print ""
        acc = acc[1:] + acc[:1]
    
    emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], rx[init_size-1], ry[init_size-1])
    emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
    emit("adc r%s, r%s, r%s", acc[1], acc[1], acc[4])
    emit("stmia r0!, {r%s}", acc[0])
    emit("stmia r0!, {r%s}", acc[1])
print ""

#### reset y and z pointers
emit("sub r0, %s", (2 * init_size + 3) * 4)
emit("sub r2, %s", (init_size + 3) * 4)

#### load y registers
emit("ldmia r2!, {%s}", ", ".join(["r%s" % (ry[i]) for i in xrange(3)]))

#### load additional x registers
if init_size != 3:
    emit("ldmia r1!, {%s}", ", ".join(["r%s" % (rx[i]) for i in xrange(init_size, 3)]))
print ""

prev_size = init_size
for row in xrange(full_rows):
    emit("umull r11, r12, r3, r6")
    emit("stmia r0!, {r11}")
    print ""
    emit("mov r10, #0")
    emit("umull r11, r9, r3, r7")
    emit("adds r12, r12, r11")
    emit("adc r9, r9, #0")
    emit("umull r11, r14, r4, r6")
    emit("adds r12, r12, r11")
    emit("adcs r9, r9, r14")
    emit("adc r10, r10, #0")
    emit("stmia r0!, {r12}")
    print ""

    acc = [9, 10, 11, 12, 14]
    emit("mov r%s, #0", acc[2])
    for i in xrange(0, 3):
        emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], rx[i], ry[2 - i])
        emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
        emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[4])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
    emit("stmia r0!, {r%s}", acc[0])
    print ""
    acc = acc[1:] + acc[:1]

    #### now we need to start shifting x and loading from z
    x_regs = [3, 4, 5]
    for r in xrange(0, prev_size):
        x_regs = x_regs[1:] + x_regs[:1]
        emit("ldmia r1!, {r%s}", x_regs[2])
        emit("mov r%s, #0", acc[2])
        for i in xrange(0, 3):
            emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], x_regs[i], ry[2 - i])
            emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
            emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[4])
            emit("adc r%s, r%s, #0", acc[2], acc[2])
        emit("ldr r%s, [r0]", acc[3]) # load stored value from initial block, and add to accumulator
        emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
        emit("adcs r%s, r%s, #0", acc[1], acc[1])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
        emit("stmia r0!, {r%s}", acc[0])
        print ""
        acc = acc[1:] + acc[:1]

    # done shifting x, start shifting y
    y_regs = [6, 7, 8]
    for r in xrange(0, prev_size):
        y_regs = y_regs[1:] + y_regs[:1]
        emit("ldmia r2!, {r%s}", y_regs[2])
        emit("mov r%s, #0", acc[2])
        for i in xrange(0, 3):
            emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], x_regs[i], y_regs[2 - i])
            emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
            emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[4])
            emit("adc r%s, r%s, #0", acc[2], acc[2])
        emit("ldr r%s, [r0]", acc[3]) # load stored value from initial block, and add to accumulator
        emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
        emit("adcs r%s, r%s, #0", acc[1], acc[1])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
        emit("stmia r0!, {r%s}", acc[0])
        print ""
        acc = acc[1:] + acc[:1]

    # done both shifts, do remaining corner
    emit("mov r%s, #0", acc[2])
    for i in xrange(0, 2):
        emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], x_regs[i + 1], y_regs[2 - i])
        emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
        emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[4])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
    emit("stmia r0!, {r%s}", acc[0])
    print ""
    acc = acc[1:] + acc[:1]
    
    emit("umull r%s, r%s, r%s, r%s", acc[3], acc[4], x_regs[2], y_regs[2])
    emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[3])
    emit("adc r%s, r%s, r%s", acc[1], acc[1], acc[4])
    emit("stmia r0!, {r%s}", acc[0])
    emit("stmia r0!, {r%s}", acc[1])
    print ""
    
    prev_size = prev_size + 3
    if row < full_rows - 1:
        #### reset x, y and z pointers
        emit("sub r0, %s", (2 * prev_size + 3) * 4)
        emit("sub r1, %s", prev_size * 4)
        emit("sub r2, %s", (prev_size + 3) * 4)

        #### load x and y registers
        emit("ldmia r1!, {%s}", ",".join(["r%s" % (rx[i]) for i in xrange(3)]))
        emit("ldmia r2!, {%s}", ",".join(["r%s" % (ry[i]) for i in xrange(3)]))
        
        print ""
