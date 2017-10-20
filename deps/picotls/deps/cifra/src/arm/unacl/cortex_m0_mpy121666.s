// Implementation of multiplication of an fe25519 bit value with the curve constant 121666.
//
// B. Haase, Endress + Hauser Conducta GmbH & Ko. KG
// public domain.
//
// gnu assembler format.
//
// Generated and tested with C++ functions in the test subdirectory.
//
// ATTENTION:
// Not yet tested on target hardware.


	.cpu cortex-m0
	.fpu softvfp
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 1
	.eabi_attribute 30, 2
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
	.code	16
	
	.file	"cortex_m0_reduce25519.s"
	
	.text
	.align	2

	.global	fe25519_mpyWith121666_asm
	.code	16
	.thumb_func
	.type	fe25519_mpyWith121666_asm, %function

fe25519_mpyWith121666_asm:	
    push {r4,r5,r6,r7,r14}
    ldr r7,__label_for_immediate_56130
    ldr r2,[r1,#28]
    lsl r5,r2,#16
    lsr r6,r2,#16
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r5,r2
    mov r2,#0
    adc r6,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r5,r2
    adc r6,r3
    lsl r2,r5,#1
    lsr r2,r2,#1
    str r2,[r0,#28]
    lsr r5,r5,#31
    lsl r6,r6,#1
    orr r5,r6
    mov r6,#19
    mul r5,r6
    mov r6,#0
    ldr r2,[r1,#0]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r5,r3
    adc r6,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r5,r2
    mov r2,#0
    adc r6,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r5,r2
    adc r6,r3
    str r5,[r0,#0]
    mov r5,#0
    ldr r2,[r1,#4]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r6,r3
    adc r5,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r6,r2
    mov r2,#0
    adc r5,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r6,r2
    adc r5,r3
    str r6,[r0,#4]
    mov r6,#0
    ldr r2,[r1,#8]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r5,r3
    adc r6,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r5,r2
    mov r2,#0
    adc r6,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r5,r2
    adc r6,r3
    str r5,[r0,#8]
    mov r5,#0
    ldr r2,[r1,#12]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r6,r3
    adc r5,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r6,r2
    mov r2,#0
    adc r5,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r6,r2
    adc r5,r3
    str r6,[r0,#12]
    mov r6,#0
    ldr r2,[r1,#16]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r5,r3
    adc r6,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r5,r2
    mov r2,#0
    adc r6,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r5,r2
    adc r6,r3
    str r5,[r0,#16]
    mov r5,#0
    ldr r2,[r1,#20]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r6,r3
    adc r5,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r6,r2
    mov r2,#0
    adc r5,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r6,r2
    adc r5,r3
    str r6,[r0,#20]
    mov r6,#0
    ldr r2,[r1,#24]
    lsl r3,r2,#16
    lsr r4,r2,#16
    add r5,r3
    adc r6,r4
    lsr r3,r2,#16
    uxth r2,r2
    mul r2,r7
    mul r3,r7
    add r5,r2
    mov r2,#0
    adc r6,r2
    lsl r2,r3,#16
    lsr r3,r3,#16
    add r5,r2
    adc r6,r3
    str r5,[r0,#24]
    mov r5,#0
    ldr r2,[r0,#28]
    add r6,r2
    str r6,[r0,#28]
    pop {r4,r5,r6,r7,r15}

	.align	2
__label_for_immediate_56130:
	.word 56130
	    			
	.size	fe25519_mpyWith121666_asm, .-fe25519_mpyWith121666_asm
		    	
