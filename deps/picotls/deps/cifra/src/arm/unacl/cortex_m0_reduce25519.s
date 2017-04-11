// Implementation of a partial reduction modulo 2^255 - 38.
//
// B. Haase, Endress + Hauser Conducta GmbH & Ko. KG
// public domain.
//
// gnu assembler format.
//
// Generated and tested with C++ functions in the test subdirectory and on the target.
//

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

	.global	fe25519_reduceTo256Bits_asm
	.code	16
	.thumb_func
	.type	fe25519_reduceTo256Bits_asm, %function

fe25519_reduceTo256Bits_asm:	
    push {r4,r5,r6,r7,r14}
    ldr r2,[r1,#60]
    lsr r3,r2,#16
    uxth r2,r2
    mov r7,#38
    mul r2,r7
    mul r3,r7
    ldr r4,[r1,#28]
    lsr r5,r3,#16
    lsl r3,r3,#16
    mov r6,#0
    add r4,r2
    adc r5,r6
    add r4,r3
    adc r5,r6
    lsl r2,r4,#1
    lsr r2,r2,#1
    str r2,[r0,#28]
    lsr r4,r4,#31
    lsl r5,r5,#1
    orr r4,r5
    mov r2,#19
    mul r2,r4
    ldr r4,[r1,#0]
    add r2,r4
    mov r3,#0
    adc r3,r6
    ldr r4,[r1,#32]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r2,r4
    adc r3,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r2,r4
    adc r3,r5
    str r2,[r0,#0]
    ldr r4,[r1,#4]
    add r3,r4
    mov r2,#0
    adc r2,r6
    ldr r4,[r1,#36]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r3,r4
    adc r2,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r3,r4
    adc r2,r5
    str r3,[r0,#4]
    ldr r4,[r1,#8]
    add r2,r4
    mov r3,#0
    adc r3,r6
    ldr r4,[r1,#40]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r2,r4
    adc r3,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r2,r4
    adc r3,r5
    str r2,[r0,#8]
    ldr r4,[r1,#12]
    add r3,r4
    mov r2,#0
    adc r2,r6
    ldr r4,[r1,#44]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r3,r4
    adc r2,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r3,r4
    adc r2,r5
    str r3,[r0,#12]
    ldr r4,[r1,#16]
    add r2,r4
    mov r3,#0
    adc r3,r6
    ldr r4,[r1,#48]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r2,r4
    adc r3,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r2,r4
    adc r3,r5
    str r2,[r0,#16]
    ldr r4,[r1,#20]
    add r3,r4
    mov r2,#0
    adc r2,r6
    ldr r4,[r1,#52]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r3,r4
    adc r2,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r3,r4
    adc r2,r5
    str r3,[r0,#20]
    ldr r4,[r1,#24]
    add r2,r4
    mov r3,#0
    adc r3,r6
    ldr r4,[r1,#56]
    lsr r5,r4,#16
    uxth r4,r4
    mul r5,r7
    mul r4,r7
    add r2,r4
    adc r3,r6
    lsl r4,r5,#16
    lsr r5,r5,#16
    add r2,r4
    adc r3,r5
    str r2,[r0,#24]
    ldr r4,[r0,#28]
    add r4,r3
    str r4,[r0,#28]
    pop {r4,r5,r6,r7,r15}
			
	.size	fe25519_reduceTo256Bits_asm, .-fe25519_reduceTo256Bits_asm
		    	
