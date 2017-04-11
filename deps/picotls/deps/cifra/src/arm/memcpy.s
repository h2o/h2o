	.text
	.syntax unified
	.global memcpy
	.func memcpy
	.thumb_func

memcpy:
	/* on entry
	 *   r0 = targ
	 *   r1 = src
	 *   r2 = len (bytes)
	 * on exit
	 *   r0 = targ (unchanged)
	 */
	push	{r0, r4, lr}
	
	/* If targ or src are unaligned, drop to byte
	 * processing. */
	mov	r3, r0
	movs	r4, #3
	orrs	r3, r1
	ands	r3, r4
	bne 	L_bytewise
	
	/* Process words */
L_wordwise:
	cmp	r2, #4
	blo	L_bytewise
	ldr 	r4, [r1]
	adds	r1, #4
	str	r4, [r0]
	adds	r0, #4
	subs	r2, #4
	b	L_wordwise

	/* Process bytes */	
L_bytewise:
	cmp	r2, #0
	beq	L_fin
	ldrb	r4, [r1]
	adds	r1, #1
	strb	r4, [r0]
	adds	r0, #1
	subs	r2, #1
	b	L_bytewise
	
L_fin:
	pop {r0, r4, pc}
	.endfunc
