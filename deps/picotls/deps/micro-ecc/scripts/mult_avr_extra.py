#!/usr/bin/env python

import sys

if len(sys.argv) < 2:
    print "Provide the integer size in bytes"
    sys.exit(1)

size = int(sys.argv[1])

def lhi(i):
    return i + 2

def rhi(i):
    return i + 6

left_lo = [10, 11, 12, 13]
right_lo = [14, 15, 16, 17]

def llo(i):
    return left_lo[i]

def rlo(i):
    return right_lo[i]

def emit(line, *args):
    s = '"' + line + r' \n\t"'
    print s % args

def update_low():
    global left_lo
    global right_lo
    left_lo = left_lo[1:] + left_lo[:1]
    right_lo = right_lo[1:] + right_lo[:1]
    emit("ld r%s, x+", left_lo[3])
    emit("ld r%s, y+", right_lo[3])

accum = [19, 20, 21]

def acc(i):
    return accum[i]

def rotate_acc():
    global accum
    accum = accum[1:] + accum[:1]

# Load high values
for i in xrange(4):
    emit("ld r%s, x+", lhi(i))
    emit("ld r%s, y+", rhi(i))

emit("sbiw r26, %s", size + 4)
emit("sbiw r28, %s", size + 4)
emit("sbiw r30, %s", size)

# Load low values
for i in xrange(4):
    emit("ld r%s, x+", llo(i))
    emit("ld r%s, y+", rlo(i))
print ""

# Compute initial triangles
emit("mul r%s, r%s", lhi(0), rlo(0))
emit("mov r%s, r0", acc(0))
emit("mov r%s, r1", acc(1))
emit("ldi r%s, 0", acc(2))
emit("ld r0, z")
emit("add r%s, r0", acc(0))
emit("adc r%s, r25", acc(1))
emit("mul r%s, r%s", rhi(0), llo(0))
emit("add r%s, r0", acc(0))
emit("adc r%s, r1", acc(1))
emit("adc r%s, r25", acc(2))
emit("st z+, r%s", acc(0))
print ""
rotate_acc()

for i in xrange(1, 4):
    emit("ldi r%s, 0", acc(2))
    emit("ld r0, z")
    emit("add r%s, r0", acc(0))
    emit("adc r%s, r25", acc(1))
    for j in xrange(i + 1):
        emit("mul r%s, r%s", lhi(j), rlo(i-j))
        emit("add r%s, r0", acc(0))
        emit("adc r%s, r1", acc(1))
        emit("adc r%s, r25", acc(2))
        emit("mul r%s, r%s", rhi(j), llo(i-j))
        emit("add r%s, r0", acc(0))
        emit("adc r%s, r1", acc(1))
        emit("adc r%s, r25", acc(2))
    emit("st z+, r%s", acc(0))
    print ""
    rotate_acc()

# Compute rows overlapping old block
for i in xrange(4, size):
    emit("ldi r%s, 0", acc(2))
    emit("ld r0, z")
    emit("add r%s, r0", acc(0))
    emit("adc r%s, r25", acc(1))
    update_low()
    for j in xrange(4):
        emit("mul r%s, r%s", lhi(j), rlo(3-j))
        emit("add r%s, r0", acc(0))
        emit("adc r%s, r1", acc(1))
        emit("adc r%s, r25", acc(2))
        emit("mul r%s, r%s", rhi(j), llo(3-j))
        emit("add r%s, r0", acc(0))
        emit("adc r%s, r1", acc(1))
        emit("adc r%s, r25", acc(2))
    emit("st z+, r%s", acc(0))
    print ""
    rotate_acc()

# Compute new triangle
left_combined = [llo(1), llo(2), llo(3), lhi(0), lhi(1), lhi(2), lhi(3)]
right_combined = [rlo(1), rlo(2), rlo(3), rhi(0), rhi(1), rhi(2), rhi(3)]

def left(i):
    return left_combined[i]

def right(i):
    return right_combined[i]

for i in xrange(6):
    emit("ldi r%s, 0", acc(2))
    for j in xrange(7 - i):
        emit("mul r%s, r%s", left(i+j), right(6-j))
        emit("add r%s, r0", acc(0))
        emit("adc r%s, r1", acc(1))
        emit("adc r%s, r25", acc(2))
    emit("st z+, r%s", acc(0))
    print ""
    rotate_acc()

emit("mul r%s, r%s", left(6), right(6))
emit("add r%s, r0", acc(0))
emit("adc r%s, r1", acc(1))
emit("st z+, r%s", acc(0))
emit("st z+, r%s", acc(1))
emit("adiw r26, 4")
emit("adiw r28, 4")
