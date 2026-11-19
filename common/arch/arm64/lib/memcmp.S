/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2013-2021, Arm Limited.
 *
 * Adapted from the original at:
 * https://github.com/ARM-software/optimized-routines/blob/e823e3abf5f89ecb/string/aarch64/memcmp.S
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

/* Assumptions:
 *
 * ARMv8-a, AArch64, unaligned accesses.
 */

/* Performance uses the scalar portion of ARM optimized-routines.
 * Kernel generic memcmp must not touch FPSIMD registers. */
#ifdef CONFIG_ONYX_PERFORMANCE
#define L(label) .L ## label

#define src1	x0
#define src2	x1
#define limit	x2
#define result	w0

#define data1	x3
#define data1w	w3
#define data2	x4
#define data2w	w4
#define data3	x5
#define data3w	w5
#define data4	x6
#define data4w	w6
#define tmp	x6
#define src1end	x7
#define src2end	x8

SYM_FUNC_START(__pi_memcmp)

	cmp	limit, 16
	b.lo	L(less16)
	ldp	data1, data3, [src1]
	ldp	data2, data4, [src2]
	ccmp	data1, data2, 0, ne
	ccmp	data3, data4, 0, eq
	b.ne	L(return2)

	add	src1end, src1, limit
	add	src2end, src2, limit
	cmp	limit, 32
	b.ls	L(last_bytes)
	sub	limit, limit, 32

	.p2align 4
L(loop32):
	ldp	data1, data3, [src1, 16]
	ldp	data2, data4, [src2, 16]
	cmp	data1, data2
	ccmp	data3, data4, 0, eq
	b.ne	L(return2)
	cmp	limit, 16
	b.ls	L(last_bytes)

	ldp	data1, data3, [src1, 32]
	ldp	data2, data4, [src2, 32]
	cmp	data1, data2
	ccmp	data3, data4, 0, eq
	b.ne	L(return2)
	add	src1, src1, 32
	add	src2, src2, 32
L(last64):
	subs	limit, limit, 32
	b.hi	L(loop32)

	/* Compare last 1-16 bytes using unaligned access.  */
L(last_bytes):
	ldp	data1, data3, [src1end, -16]
	ldp	data2, data4, [src2end, -16]
L(return2):
	cmp	data1, data2
	csel	data1, data1, data3, ne
	csel	data2, data2, data4, ne

	/* Compare data bytes and set return value to 0, -1 or 1.  */
L(return):
#ifndef __AARCH64EB__
	rev	data1, data1
	rev	data2, data2
#endif
	cmp	data1, data2
	cset	result, ne
	cneg	result, result, lo
	ret

	.p2align 4
L(less16):
	add	src1end, src1, limit
	add	src2end, src2, limit
	tbz	limit, 3, L(less8)
	ldr	data1, [src1]
	ldr	data2, [src2]
	ldr	data3, [src1end, -8]
	ldr	data4, [src2end, -8]
	b	L(return2)

	.p2align 4
L(less8):
	tbz	limit, 2, L(less4)
	ldr	data1w, [src1]
	ldr	data2w, [src2]
	ldr	data3w, [src1end, -4]
	ldr	data4w, [src2end, -4]
	b	L(return2)

L(less4):
	tbz	limit, 1, L(less2)
	ldrh	data1w, [src1]
	ldrh	data2w, [src2]
	cmp	data1w, data2w
	b.ne	L(return)
L(less2):
	mov	result, 0
	tbz	limit, 0, L(return_zero)
	ldrb	data1w, [src1end, -1]
	ldrb	data2w, [src2end, -1]
	sub	result, data1w, data2w
L(return_zero):
	ret

SYM_FUNC_END(__pi_memcmp)
SYM_FUNC_ALIAS_WEAK(memcmp, __pi_memcmp)
EXPORT_SYMBOL_NOKASAN(memcmp)
#else
#define L(label) .L ## label

/* Parameters and result.  */
#define src1		x0
#define src2		x1
#define limit		x2
#define result		w0

/* Internal variables.  */
#define data1		x3
#define data1w		w3
#define data1h		x4
#define data2		x5
#define data2w		w5
#define data2h		x6
#define tmp1		x7
#define tmp2		x8

SYM_FUNC_START(__pi_memcmp)
	subs	limit, limit, 8
	b.lo	L(less8)

	ldr	data1, [src1], 8
	ldr	data2, [src2], 8
	cmp	data1, data2
	b.ne	L(return)

	subs	limit, limit, 8
	b.gt	L(more16)

	ldr	data1, [src1, limit]
	ldr	data2, [src2, limit]
	b	L(return)

L(more16):
	ldr	data1, [src1], 8
	ldr	data2, [src2], 8
	cmp	data1, data2
	bne	L(return)

	/* Jump directly to comparing the last 16 bytes for 32 byte (or less)
	   strings.  */
	subs	limit, limit, 16
	b.ls	L(last_bytes)

	/* We overlap loads between 0-32 bytes at either side of SRC1 when we
	   try to align, so limit it only to strings larger than 128 bytes.  */
	cmp	limit, 96
	b.ls	L(loop16)

	/* Align src1 and adjust src2 with bytes not yet done.  */
	and	tmp1, src1, 15
	add	limit, limit, tmp1
	sub	src1, src1, tmp1
	sub	src2, src2, tmp1

	/* Loop performing 16 bytes per iteration using aligned src1.
	   Limit is pre-decremented by 16 and must be larger than zero.
	   Exit if <= 16 bytes left to do or if the data is not equal.  */
	.p2align 4
L(loop16):
	ldp	data1, data1h, [src1], 16
	ldp	data2, data2h, [src2], 16
	subs	limit, limit, 16
	ccmp	data1, data2, 0, hi
	ccmp	data1h, data2h, 0, eq
	b.eq	L(loop16)

	cmp	data1, data2
	bne	L(return)
	mov	data1, data1h
	mov	data2, data2h
	cmp	data1, data2
	bne	L(return)

	/* Compare last 1-16 bytes using unaligned access.  */
L(last_bytes):
	add	src1, src1, limit
	add	src2, src2, limit
	ldp	data1, data1h, [src1]
	ldp	data2, data2h, [src2]
	cmp	data1, data2
	bne	L(return)
	mov	data1, data1h
	mov	data2, data2h
	cmp	data1, data2

	/* Compare data bytes and set return value to 0, -1 or 1.  */
L(return):
#ifndef __AARCH64EB__
	rev	data1, data1
	rev	data2, data2
#endif
	cmp	data1, data2
L(ret_eq):
	cset	result, ne
	cneg	result, result, lo
	ret

	.p2align 4
	/* Compare up to 8 bytes.  Limit is [-8..-1].  */
L(less8):
	adds	limit, limit, 4
	b.lo	L(less4)
	ldr	data1w, [src1], 4
	ldr	data2w, [src2], 4
	cmp	data1w, data2w
	b.ne	L(return)
	sub	limit, limit, 4
L(less4):
	adds	limit, limit, 4
	beq	L(ret_eq)
L(byte_loop):
	ldrb	data1w, [src1], 1
	ldrb	data2w, [src2], 1
	subs	limit, limit, 1
	ccmp	data1w, data2w, 0, ne	/* NZCV = 0b0000.  */
	b.eq	L(byte_loop)
	sub	result, data1w, data2w
	ret
SYM_FUNC_END(__pi_memcmp)
SYM_FUNC_ALIAS_WEAK(memcmp, __pi_memcmp)
EXPORT_SYMBOL_NOKASAN(memcmp)
#endif
