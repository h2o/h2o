	.text
	.syntax unified
	.global semihost
	.func semihost
	.thumb_func

semihost:
	/* on entry
	 *	r0 = op
	 *	r1 = arg */
	push {r7, lr}
	bkpt 0xab
	pop {r7, pc}

	.endfunc
