	.text
	.syntax unified
	.global memset
	.func memset
	.thumb_func

memset:
	/* on entry
	 *   r0 = targ
	 *   r1 = value
	 *   r2 = len (bytes)
	 * on exit
	 *   r0 = targ (unchanged)
	 */
	push	{r0, r4, lr}
	
	/* If targ is unaligned, drop to byte
	 * processing. */
	movs	r3, #3
	ands	r3, r0
	bne 	L_bytewise
	
	/* Process words */
	/* Build r4 by repeating r1. */
	uxtb	r4, r1
	lsls	r3, r4, #8
	orrs	r4, r3
	lsls	r3, r4, #16
	orrs	r4, r3

L_wordwise:
	cmp	r2, #4
	blo	L_bytewise
	str	r4, [r0]
	adds	r0, #4
	subs	r2, #4
	b	L_wordwise

	/* Process bytes */	
L_bytewise:
	cmp	r2, #0
	beq	L_fin
	strb	r1, [r0]
	adds	r0, #1
	subs	r2, #1
	b	L_bytewise
	
L_fin:
	pop {r0, r4, pc}
	.endfunc
