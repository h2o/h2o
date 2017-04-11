 .align	2
	.global	square256_asm
	.type	square256_asm, %function
square256_asm:
	push {r4-r7,lr}
	mov r2, r8
	mov r3, r9
	mov r4, r10
	mov r5, r11
	push {r0-r5}

	mov r12, r0
	mov r4, r1
	ldm r4!, {r0-r3}
	push {r4}
	/////////BEGIN LOW PART //////////////////////
		///SQR 128, in r0-r3
		mov r8, r2
		mov r9, r3
		eor r4, r4
		sub r2, r0
		sbc r3, r1
		sbc r4, r4
		eor r2, r4
		eor r3, r4
		sub r2, r4
		sbc r3, r4
		mov r10, r2
		mov r11, r3
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r7, r7
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r7, r7
			add r1, r0
			adc r2, r3
			adc r7, r3
	mov r3, r12
	stm r3!, {r0-r1}
	push {r3}

		mov r12, r0
		mov r0, r8
		mov r8, r1
		mov r1, r9
		mov r9, r2
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r4, r4
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r4, r4
			add r1, r0
			adc r2, r3
			adc r3, r4
		eor r4, r4
		mov r6, r9
		add r0, r6
		adc r7, r1
		adc r2, r4
		adc r3, r4
		mov r1, r11
		mov r11, r0
		mov r0, r10
		mov r9, r2
		mov r10,r3 
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r4, r4
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r4, r4
			add r1, r0
			adc r2, r3
			adc r3, r4
		mov r6, r11
		mov r4, r11
		mov r5, r7
		sub r6, r0
		sbc r7, r1
		sbc r4, r2
		sbc r5, r3
		eor r1, r1
		sbc r1, r1
		mov r2, r12
		mov r3, r8
		add r2, r6
		adc r3, r7
		mov r6, r9
		mov r7, r10
		adc r4, r6
		adc r5, r7
		adc r6, r1
		adc r7, r1 
		//results r12, r8, r2-r7
	/////////END LOW PART ////////////////////////
	pop {r0,r1}
	stm r0!, {r2, r3}
	push {r0, r4-r7}
	ldm r1, {r0-r3}
	/////////BEGIN HIGH PART //////////////////////
		///SQR 128, in r0-r3
		mov r8, r2
		mov r9, r3
		eor r4, r4
		sub r2, r0
		sbc r3, r1
		sbc r4, r4
		eor r2, r4
		eor r3, r4
		sub r2, r4
		sbc r3, r4
		mov r10, r2
		mov r11, r3
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r7, r7
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r7, r7
			add r1, r0
			adc r2, r3
			adc r7, r3
		mov r12, r0
		mov r0, r8
		mov r8, r1
		mov r1, r9
		mov r9, r2
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r4, r4
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r4, r4
			add r1, r0
			adc r2, r3
			adc r3, r4
		eor r4, r4
		mov r6, r9
		add r0, r6
		adc r7, r1
		adc r2, r4
		adc r3, r4
		mov r1, r11
		mov r11, r0
		mov r0, r10
		mov r9, r2
		mov r10,r3 
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r4, r4
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r4, r4
			add r1, r0
			adc r2, r3
			adc r3, r4
		mov r6, r11
		mov r4, r11
		mov r5, r7
		sub r6, r0
		sbc r7, r1
		sbc r4, r2
		sbc r5, r3
		eor r1, r1
		sbc r1, r1
		mov r2, r12
		mov r3, r8
		add r2, r6
		adc r3, r7
		mov r6, r9
		mov r7, r10
		adc r4, r6
		adc r5, r7
		adc r6, r1
		adc r7, r1 
		//results r12, r8, r2-r7
	/////////END HIGH PART ////////////////////////
	mov r0, r12	
	mov r1, r8
	mov r8, r4
	mov r9, r5
	mov r10, r6
	mov r11, r7
	pop {r4}
	mov r12, r4//str
	pop {r4-r7}
	add r0, r4
	adc r1, r5
	adc r2, r6
	adc r3, r7
	mov r4, r12
	stm r4!, {r0-r3}//low part
	mov r4, r8
	mov r5, r9
	mov r6, r10
	mov r7, r11
	eor r0, r0
	adc r4, r0
	adc r5, r0
	adc r6, r0
	adc r7, r0
	pop {r0, r1} //r0->out, r1, in
	push {r0,r4-r7}
	ldm r1, {r0-r7}
	sub r0, r4
	sbc r1, r5
	sbc r2, r6
	sbc r3, r7
	sbc r4, r4
	eor r0, r4
	eor r1, r4
	eor r2, r4
	eor r3, r4
	sub r0, r4
	sbc r1, r4
	sbc r2, r4
	sbc r3, r4
	//////////BEGIN MIDDLE PART////////////////
		///SQR 128, in r0-r3
		mov r8, r2
		mov r9, r3
		eor r4, r4
		sub r2, r0
		sbc r3, r1
		sbc r4, r4
		eor r2, r4
		eor r3, r4
		sub r2, r4
		sbc r3, r4
		mov r10, r2
		mov r11, r3
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r7, r7
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r7, r7
			add r1, r0
			adc r2, r3
			adc r7, r3
		mov r12, r0
		mov r0, r8
		mov r8, r1
		mov r1, r9
		mov r9, r2
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r4, r4
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r4, r4
			add r1, r0
			adc r2, r3
			adc r3, r4
		eor r4, r4
		mov r6, r9
		add r0, r6
		adc r7, r1
		adc r2, r4
		adc r3, r4
		mov r1, r11
		mov r11, r0
		mov r0, r10
		mov r9, r2
		mov r10,r3 
			//SQR64, in: r0, r1, out: r0-r3, used: r0-r6
			mov r2, r0 
			eor r3, r3
			sub r2, r1
			sbc r3, r3
			eor r2, r3
			sub r2, r3
			lsr r3, r0, #16
			uxth r0, r0
			mov r4, r0
			mul r4, r3
			mul r0, r0
			mul r3, r3
			lsr r5, r4, #16
			lsl r4, #16
			add r0, r4
			adc r3, r5
			add r0, r4
			adc r3, r5
			lsr r4, r1, #16
			uxth r1, r1
			mov r5, r1
			mul r5, r4
			mul r1, r1
			mul r4, r4
			eor r6, r6
			add r1, r3
			adc r4, r6
			lsr r3, r5, #16
			lsl r5, r5, #16
			add r1, r5
			adc r4, r3
			add r1, r5
			adc r3, r4
			lsr r4, r2, #16
			uxth r2, r2
			mov r5, r2
			mul r5, r4
			mul r2, r2
			mul r4, r4
			lsr r6, r5, #16
			lsl r5, #16
			add r2, r5
			adc r4, r6
			add r5, r2
			adc r6, r4
			eor r4, r4
			mov r2, r1
			sub r1, r5
			sbc r2, r6
			sbc r4, r4
			add r1, r0
			adc r2, r3
			adc r3, r4
		mov r6, r11
		mov r4, r11
		mov r5, r7
		sub r6, r0
		sbc r7, r1
		sbc r4, r2
		sbc r5, r3
		eor r1, r1
		sbc r1, r1
		mov r2, r12
		mov r3, r8
		add r2, r6
		adc r3, r7
		mov r6, r9
		mov r7, r10
		adc r4, r6
		adc r5, r7
		adc r6, r1
		adc r7, r1 
		//results r12, r8, r2-r7
	//////////END MIDDLE PART//////////////////
	mvn r2, r2
	mvn r3, r3
	mvn r4, r4
	mvn r5, r5
	mvn r6, r6
	mvn r7, r7
	pop {r1}
	push {r4-r7}
	mov r4, #1
	asr r4, #1
	ldm r1!, {r4-r7}
	mov r0, r12
	mov r12, r1 ////////ref	
	mov r1, r8
	mvn r0, r0
	mvn r1, r1
	adc r0, r4
	adc r1, r5
	adc r2, r6
	adc r3, r7
	eor r4, r4
	adc r4, r4 
	mov r8, r4 //carry A --ini
	mov r4, r12
	ldm r4, {r4-r7}
	add r0, r4
	adc r1, r5
	adc r2, r6
	adc r3, r7
	mov r9, r4
	mov r4, r12
	stm r4!, {r0-r3}
	mov r12, r4
	mov r4, r9
	pop {r0-r3}	
	adc r4, r0
	adc r5, r1
	adc r6, r2
	adc r7, r3
	eor r0, r0
	adc r0, r0
	mov r9, r0 //carry B --ini
	mov r0, r8 
	asr r0, #1 //carry A --end
	pop {r0-r3}
	adc r4, r0
	adc r5, r1
	adc r6, r2
	adc r7, r3
	mov r8, r0
	mov r0, r12
	stm r0!, {r4-r7}
	mov r11, r0
	mov r0, r8
	eor r4, r4
	mov r5, r9
	adc r5, r4 //carry B --end
	mvn r6, r4
	add r5, r6
	adc r6, r4
	add r0, r5
	adc r1, r6
	adc r2, r6
	adc r3, r6
	mov r7, r11
	stm r7!, {r0-r3}

	pop {r3-r6}
	mov r8, r3
	mov r9, r4
	mov r10, r5
	mov r11, r6
	pop {r4-r7,pc}
	bx	lr
	.size	square256_asm, .-square256_asm
