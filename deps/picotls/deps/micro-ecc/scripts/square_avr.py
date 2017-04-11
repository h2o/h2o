#!/usr/bin/env python

import sys

if len(sys.argv) < 2:
    print "Provide the integer size in bytes"
    sys.exit(1)

size = int(sys.argv[1])

if size > 40:
    print "This script doesn't work with integer size %s due to laziness" % (size)
    sys.exit(1)

init_size = size - 20
if size < 20:
    init_size = 0

def rg(i):
    return i + 2

def lo(i):
    return i + 2

def hi(i):
    return i + 12

def emit(line, *args):
    s = '"' + line + r' \n\t"'
    print s % args

#### set up registers
zero = "r25"
emit("ldi %s, 0", zero) # zero register

if init_size > 0:
    emit("movw r28, r26") # y = x
    h = (init_size + 1)//2
    
    for i in xrange(h):
        emit("ld r%s, x+", lo(i))
    emit("adiw r28, %s", size - init_size) # move y to other end
    for i in xrange(h):
        emit("ld r%s, y+", hi(i))

    emit("adiw r30, %s", size - init_size) # move z

    if init_size == 1:
        emit("mul %s, %s", lo(0), hi(0))
        emit("st z+, r0")
        emit("st z+, r1")
    else:
        #### first one
        print ""
        emit("ldi r23, 0")
        emit("mul %s, %s", lo(0), hi(0))
        emit("st z+, r0")
        emit("mov r22, r1")
        print ""

        #### rest of initial block, with moving accumulator registers
        acc = [22, 23, 24]
        for r in xrange(1, h):
            emit("ldi r%s, 0", acc[2])
            for i in xrange(0, (r+2)//2):
                emit("mul r%s, r%s", lo(i), hi(r - i))
                emit("add r%s, r0", acc[0])
                emit("adc r%s, r1", acc[1])
                emit("adc r%s, %s", acc[2], zero)
            emit("st z+, r%s", acc[0])
            print ""
            acc = acc[1:] + acc[:1]
        
        lo_r = range(2, 2 + h)
        hi_r = range(12, 12 + h)
        
        # now we need to start loading more from the high end
        for r in xrange(h, init_size):
            hi_r = hi_r[1:] + hi_r[:1]
            emit("ld r%s, y+", hi_r[h-1])
            
            emit("ldi r%s, 0", acc[2])
            for i in xrange(0, (r+2)//2):
                emit("mul r%s, r%s", lo(i), hi_r[h - 1 - i])
                emit("add r%s, r0", acc[0])
                emit("adc r%s, r1", acc[1])
                emit("adc r%s, %s", acc[2], zero)
            emit("st z+, r%s", acc[0])
            print ""
            acc = acc[1:] + acc[:1]
            
        # loaded all of the high end bytes; now need to start loading the rest of the low end
        for r in xrange(1, init_size-h):
            lo_r = lo_r[1:] + lo_r[:1]
            emit("ld r%s, x+", lo_r[h-1])
            
            emit("ldi r%s, 0", acc[2])
            for i in xrange(0, (init_size+1 - r)//2):
                emit("mul r%s, r%s", lo_r[i], hi_r[h - 1 - i])
                emit("add r%s, r0", acc[0])
                emit("adc r%s, r1", acc[1])
                emit("adc r%s, %s", acc[2], zero)
            emit("st z+, r%s", acc[0])
            print ""
            acc = acc[1:] + acc[:1]
        
        lo_r = lo_r[1:] + lo_r[:1]
        emit("ld r%s, x+", lo_r[h-1])
        
        # now we have loaded everything, and we just need to finish the last corner
        for r in xrange(init_size-h, init_size-1):
            emit("ldi r%s, 0", acc[2])
            for i in xrange(0, (init_size+1 - r)//2):
                emit("mul r%s, r%s", lo_r[i], hi_r[h - 1 - i])
                emit("add r%s, r0", acc[0])
                emit("adc r%s, r1", acc[1])
                emit("adc r%s, %s", acc[2], zero)
            emit("st z+, r%s", acc[0])
            print ""
            acc = acc[1:] + acc[:1]
            lo_r = lo_r[1:] + lo_r[:1] # make the indexing easy
        
        emit("mul r%s, r%s", lo_r[0], hi_r[h - 1])
        emit("add r%s, r0", acc[0])
        emit("adc r%s, r1", acc[1])
        emit("st z+, r%s", acc[0])
        emit("st z+, r%s", acc[1])
    print ""
    emit("sbiw r26, %s", init_size) # reset x
    emit("sbiw r30, %s", size + init_size) # reset z

# TODO you could do more rows of size 20 here if your integers are larger than 40 bytes

s = size - init_size

for i in xrange(s):
    emit("ld r%s, x+", rg(i))

#### first few columns
# NOTE: this is only valid if size >= 3
print ""
emit("ldi r23, 0")
emit("mul r%s, r%s", rg(0), rg(0))
emit("st z+, r0")
emit("mov r22, r1")
print ""
emit("ldi r24, 0")
emit("mul r%s, r%s", rg(0), rg(1))
emit("add r22, r0")
emit("adc r23, r1")
emit("adc r24, %s", zero)
emit("add r22, r0")
emit("adc r23, r1")
emit("adc r24, %s", zero)
emit("st z+, r22")
print ""
emit("ldi r22, 0")
emit("mul r%s, r%s", rg(0), rg(2))
emit("add r23, r0")
emit("adc r24, r1")
emit("adc r22, %s", zero)
emit("add r23, r0")
emit("adc r24, r1")
emit("adc r22, %s", zero)
emit("mul r%s, r%s", rg(1), rg(1))
emit("add r23, r0")
emit("adc r24, r1")
emit("adc r22, %s", zero)
emit("st z+, r23")
print ""

acc = [23, 24, 22]
old_acc = [28, 29]
for i in xrange(3, s):
    emit("ldi r%s, 0", old_acc[1])
    tmp = [acc[1], acc[2]]
    acc = [acc[0], old_acc[0], old_acc[1]]
    old_acc = tmp
    
    # gather non-equal words
    emit("mul r%s, r%s", rg(0), rg(i))
    emit("mov r%s, r0", acc[0])
    emit("mov r%s, r1", acc[1])
    for j in xrange(1, (i+1)//2):
        emit("mul r%s, r%s", rg(j), rg(i-j))
        emit("add r%s, r0", acc[0])
        emit("adc r%s, r1", acc[1])
        emit("adc r%s, %s", acc[2], zero)
    # multiply by 2
    emit("lsl r%s", acc[0])
    emit("rol r%s", acc[1])
    emit("rol r%s", acc[2])
    
    # add equal word (if any)
    if ((i+1) % 2) != 0:
        emit("mul r%s, r%s", rg(i//2), rg(i//2))
        emit("add r%s, r0", acc[0])
        emit("adc r%s, r1", acc[1])
        emit("adc r%s, %s", acc[2], zero)
    
    # add old accumulator
    emit("add r%s, r%s", acc[0], old_acc[0])
    emit("adc r%s, r%s", acc[1], old_acc[1])
    emit("adc r%s, %s", acc[2], zero)
    
    # store
    emit("st z+, r%s", acc[0])
    print ""

regs = range(2, 22)
for i in xrange(init_size):
    regs = regs[1:] + regs[:1]
    emit("ld r%s, x+", regs[19])
    
    for limit in [18, 19]:
        emit("ldi r%s, 0", old_acc[1])
        tmp = [acc[1], acc[2]]
        acc = [acc[0], old_acc[0], old_acc[1]]
        old_acc = tmp
    
        # gather non-equal words
        emit("mul r%s, r%s", regs[0], regs[limit])
        emit("mov r%s, r0", acc[0])
        emit("mov r%s, r1", acc[1])
        for j in xrange(1, (limit+1)//2):
            emit("mul r%s, r%s", regs[j], regs[limit-j])
            emit("add r%s, r0", acc[0])
            emit("adc r%s, r1", acc[1])
            emit("adc r%s, %s", acc[2], zero)
    
        emit("ld r0, z") # load stored value from initial block, and add to accumulator (note z does not increment)
        emit("add r%s, r0", acc[0])
        emit("adc r%s, r25", acc[1])
        emit("adc r%s, r25", acc[2])
    
        # multiply by 2
        emit("lsl r%s", acc[0])
        emit("rol r%s", acc[1])
        emit("rol r%s", acc[2])
    
        # add equal word
        if limit == 18:
            emit("mul r%s, r%s", regs[9], regs[9])
            emit("add r%s, r0", acc[0])
            emit("adc r%s, r1", acc[1])
            emit("adc r%s, %s", acc[2], zero)
    
        # add old accumulator
        emit("add r%s, r%s", acc[0], old_acc[0])
        emit("adc r%s, r%s", acc[1], old_acc[1])
        emit("adc r%s, %s", acc[2], zero)
    
        # store
        emit("st z+, r%s", acc[0])
        print ""

for i in xrange(1, s-3):
    emit("ldi r%s, 0", old_acc[1])
    tmp = [acc[1], acc[2]]
    acc = [acc[0], old_acc[0], old_acc[1]]
    old_acc = tmp

    # gather non-equal words
    emit("mul r%s, r%s", regs[i], regs[s - 1])
    emit("mov r%s, r0", acc[0])
    emit("mov r%s, r1", acc[1])
    for j in xrange(1, (s-i)//2):
        emit("mul r%s, r%s", regs[i+j], regs[s - 1 - j])
        emit("add r%s, r0", acc[0])
        emit("adc r%s, r1", acc[1])
        emit("adc r%s, %s", acc[2], zero)
    # multiply by 2
    emit("lsl r%s", acc[0])
    emit("rol r%s", acc[1])
    emit("rol r%s", acc[2])

    # add equal word (if any)
    if ((s-i) % 2) != 0:
        emit("mul r%s, r%s", regs[i + (s-i)//2], regs[i + (s-i)//2])
        emit("add r%s, r0", acc[0])
        emit("adc r%s, r1", acc[1])
        emit("adc r%s, %s", acc[2], zero)

    # add old accumulator
    emit("add r%s, r%s", acc[0], old_acc[0])
    emit("adc r%s, r%s", acc[1], old_acc[1])
    emit("adc r%s, %s", acc[2], zero)

    # store
    emit("st z+, r%s", acc[0])
    print ""

acc = acc[1:] + acc[:1]
emit("ldi r%s, 0", acc[2])
emit("mul r%s, r%s", regs[17], regs[19])
emit("add r%s, r0", acc[0])
emit("adc r%s, r1", acc[1])
emit("adc r%s, %s", acc[2], zero)
emit("add r%s, r0", acc[0])
emit("adc r%s, r1", acc[1])
emit("adc r%s, %s", acc[2], zero)
emit("mul r%s, r%s", regs[18], regs[18])
emit("add r%s, r0", acc[0])
emit("adc r%s, r1", acc[1])
emit("adc r%s, %s", acc[2], zero)
emit("st z+, r%s", acc[0])
print ""

acc = acc[1:] + acc[:1]
emit("ldi r%s, 0", acc[2])
emit("mul r%s, r%s", regs[18], regs[19])
emit("add r%s, r0", acc[0])
emit("adc r%s, r1", acc[1])
emit("adc r%s, %s", acc[2], zero)
emit("add r%s, r0", acc[0])
emit("adc r%s, r1", acc[1])
emit("adc r%s, %s", acc[2], zero)
emit("st z+, r%s", acc[0])
print ""

emit("mul r%s, r%s", regs[19], regs[19])
emit("add r%s, r0", acc[1])
emit("adc r%s, r1", acc[2])
emit("st z+, r%s", acc[1])

emit("st z+, r%s", acc[2])
emit("eor r1, r1")
