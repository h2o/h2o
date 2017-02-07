#!/usr/bin/env python

import sys

if len(sys.argv) < 2:
    print "Provide the integer size in 32-bit words"
    sys.exit(1)

size = int(sys.argv[1])

if size > 8:
    print "This script doesn't work with integer size %s due to laziness" % (size)
    sys.exit(1)

init_size = 0
if size > 6:
    init_size = size - 6

def emit(line, *args):
    s = '"' + line + r' \n\t"'
    print s % args

def mulacc(acc, r1, r2):
    if size <= 6:
        emit("umull r1, r14, r%s, r%s", r1, r2)
        emit("adds r%s, r%s, r1", acc[0], acc[0])
        emit("adcs r%s, r%s, r14", acc[1], acc[1])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
    else:
        emit("mov r14, r%s", acc[1])
        emit("umlal r%s, r%s, r%s, r%s", acc[0], acc[1], r1, r2)
        emit("cmp r14, r%s", acc[1])
        emit("it hi")
        emit("adchi r%s, r%s, #0", acc[2], acc[2])

r = [2, 3, 4, 5, 6, 7]

s = size - init_size

if init_size == 1:
    emit("ldmia r1!, {r2}")
    emit("add r1, %s", (size - init_size * 2) * 4)
    emit("ldmia r1!, {r5}")
    
    emit("add r0, %s", (size - init_size) * 4)
    emit("umull r8, r9, r2, r5")
    emit("stmia r0!, {r8, r9}")
    
    emit("sub r0, %s", (size + init_size) * 4)
    emit("sub r1, %s", (size) * 4)
    print ""
elif init_size == 2:
    emit("ldmia r1!, {r2, r3}")
    emit("add r1, %s", (size - init_size * 2) * 4)
    emit("ldmia r1!, {r5, r6}")
    
    emit("add r0, %s", (size - init_size) * 4)
    print ""

    emit("umull r8, r9, r2, r5")
    emit("stmia r0!, {r8}")
    print ""
    
    emit("umull r12, r10, r2, r6")
    emit("adds r9, r9, r12")
    emit("adc r10, r10, #0")
    emit("stmia r0!, {r9}")
    print ""
    
    emit("umull r8, r9, r3, r6")
    emit("adds r10, r10, r8")
    emit("adc r11, r9, #0")
    emit("stmia r0!, {r10, r11}")
    print ""
    
    emit("sub r0, %s", (size + init_size) * 4)
    emit("sub r1, %s", (size) * 4)

# load input words
emit("ldmia r1!, {%s}", ", ".join(["r%s" % (r[i]) for i in xrange(s)]))
print ""

emit("umull r11, r12, r2, r2")
emit("stmia r0!, {r11}")
print ""
emit("mov r9, #0")
emit("umull r10, r11, r2, r3")
emit("adds r12, r12, r10")
emit("adcs r8, r11, #0")
emit("adc r9, r9, #0")
emit("adds r12, r12, r10")
emit("adcs r8, r8, r11")
emit("adc r9, r9, #0")
emit("stmia r0!, {r12}")
print ""
emit("mov r10, #0")
emit("umull r11, r12, r2, r4")
emit("adds r11, r11, r11")
emit("adcs r12, r12, r12")
emit("adc r10, r10, #0")
emit("adds r8, r8, r11")
emit("adcs r9, r9, r12")
emit("adc r10, r10, #0")
emit("umull r11, r12, r3, r3")
emit("adds r8, r8, r11")
emit("adcs r9, r9, r12")
emit("adc r10, r10, #0")
emit("stmia r0!, {r8}")
print ""

acc = [8, 9, 10]
old_acc = [11, 12]
for i in xrange(3, s):
    emit("mov r%s, #0", old_acc[1])
    tmp = [acc[1], acc[2]]
    acc = [acc[0], old_acc[0], old_acc[1]]
    old_acc = tmp
    
    # gather non-equal words
    emit("umull r%s, r%s, r%s, r%s", acc[0], acc[1], r[0], r[i])
    for j in xrange(1, (i+1)//2):
        mulacc(acc, r[j], r[i-j])
    # multiply by 2
    emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[0])
    emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[1])
    emit("adc r%s, r%s, r%s", acc[2], acc[2], acc[2])
    
    # add equal word (if any)
    if ((i+1) % 2) != 0:
        mulacc(acc, r[i//2], r[i//2])
    
    # add old accumulator
    emit("adds r%s, r%s, r%s", acc[0], acc[0], old_acc[0])
    emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
    emit("adc r%s, r%s, #0", acc[2], acc[2])
    
    # store
    emit("stmia r0!, {r%s}", acc[0])
    print ""

regs = list(r)
for i in xrange(init_size):
    regs = regs[1:] + regs[:1]
    emit("ldmia r1!, {r%s}", regs[5])
    
    for limit in [4, 5]:
        emit("mov r%s, #0", old_acc[1])
        tmp = [acc[1], acc[2]]
        acc = [acc[0], old_acc[0], old_acc[1]]
        old_acc = tmp
    
        # gather non-equal words
        emit("umull r%s, r%s, r%s, r%s", acc[0], acc[1], regs[0], regs[limit])
        for j in xrange(1, (limit+1)//2):
            mulacc(acc, regs[j], regs[limit-j])
    
        emit("ldr r14, [r0]") # load stored value from initial block, and add to accumulator
        emit("adds r%s, r%s, r14", acc[0], acc[0])
        emit("adcs r%s, r%s, #0", acc[1], acc[1])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
    
        # multiply by 2
        emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[0])
        emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[1])
        emit("adc r%s, r%s, r%s", acc[2], acc[2], acc[2])
    
        # add equal word
        if limit == 4:
            mulacc(acc, regs[2], regs[2])
    
        # add old accumulator
        emit("adds r%s, r%s, r%s", acc[0], acc[0], old_acc[0])
        emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
        emit("adc r%s, r%s, #0", acc[2], acc[2])
    
        # store
        emit("stmia r0!, {r%s}", acc[0])
        print ""

for i in xrange(1, s-3):
    emit("mov r%s, #0", old_acc[1])
    tmp = [acc[1], acc[2]]
    acc = [acc[0], old_acc[0], old_acc[1]]
    old_acc = tmp

    # gather non-equal words
    emit("umull r%s, r%s, r%s, r%s", acc[0], acc[1], regs[i], regs[s - 1])
    for j in xrange(1, (s-i)//2):
        mulacc(acc, regs[i+j], regs[s - 1 - j])

    # multiply by 2
    emit("adds r%s, r%s, r%s", acc[0], acc[0], acc[0])
    emit("adcs r%s, r%s, r%s", acc[1], acc[1], acc[1])
    emit("adc r%s, r%s, r%s", acc[2], acc[2], acc[2])

    # add equal word (if any)
    if ((s-i) % 2) != 0:
        mulacc(acc, regs[i + (s-i)//2], regs[i + (s-i)//2])

    # add old accumulator
    emit("adds r%s, r%s, r%s", acc[0], acc[0], old_acc[0])
    emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
    emit("adc r%s, r%s, #0", acc[2], acc[2])

    # store
    emit("stmia r0!, {r%s}", acc[0])
    print ""

acc = acc[1:] + acc[:1]
emit("mov r%s, #0", acc[2])
emit("umull r1, r%s, r%s, r%s", old_acc[1], regs[s - 3], regs[s - 1])
emit("adds r1, r1, r1")
emit("adcs r%s, r%s, r%s", old_acc[1], old_acc[1], old_acc[1])
emit("adc r%s, r%s, #0", acc[2], acc[2])
emit("adds r%s, r%s, r1", acc[0], acc[0])
emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
emit("adc r%s, r%s, #0", acc[2], acc[2])
emit("umull r1, r%s, r%s, r%s", old_acc[1], regs[s - 2], regs[s - 2])
emit("adds r%s, r%s, r1", acc[0], acc[0])
emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
emit("adc r%s, r%s, #0", acc[2], acc[2])
emit("stmia r0!, {r%s}", acc[0])
print ""

acc = acc[1:] + acc[:1]
emit("mov r%s, #0", acc[2])
emit("umull r1, r%s, r%s, r%s", old_acc[1], regs[s - 2], regs[s - 1])
emit("adds r1, r1, r1")
emit("adcs r%s, r%s, r%s", old_acc[1], old_acc[1], old_acc[1])
emit("adc r%s, r%s, #0", acc[2], acc[2])
emit("adds r%s, r%s, r1", acc[0], acc[0])
emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
emit("adc r%s, r%s, #0", acc[2], acc[2])
emit("stmia r0!, {r%s}", acc[0])
print ""

acc = acc[1:] + acc[:1]
emit("umull r1, r%s, r%s, r%s", old_acc[1], regs[s - 1], regs[s - 1])
emit("adds r%s, r%s, r1", acc[0], acc[0])
emit("adcs r%s, r%s, r%s", acc[1], acc[1], old_acc[1])
emit("stmia r0!, {r%s}", acc[0])
emit("stmia r0!, {r%s}", acc[1])
