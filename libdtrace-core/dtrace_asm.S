/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Portions Copyright 2008 John Birrell <jb@freebsd.org>
 *
 * $FreeBSD: head/sys/cddl/dev/dtrace/amd64/dtrace_asm.S 298171 2016-04-17 23:08:47Z markj $
 *
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define _ASM

#include <machine/asmacros.h>
#include "dtrace.h"

/*
uintptr_t
dtrace_caller(int aframes)
*/
	ENTRY(dtrace_caller)
	movq	$-1, %rax
	ret
	END(dtrace_caller)

/*
void
dtrace_copy(uintptr_t src, uintptr_t dest, size_t size)
*/
	ENTRY(dtrace_copy)
	pushq	%rbp
	movq	%rsp, %rbp

	xchgq	%rdi, %rsi		/* make %rsi source, %rdi dest */
	movq	%rdx, %rcx		/* load count */
	repz				/* repeat for count ... */
	smovb				/*   move from %ds:rsi to %ed:rdi */
	leave
	ret
	END(dtrace_copy)

/*
uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
*/
	ENTRY(dtrace_cas32)
	movl	%esi, %eax
	lock
	cmpxchgl %edx, (%rdi)
	ret
	END(dtrace_cas32)

/*
void *
dtrace_casptr(void *target, void *cmp, void *new)
*/
	ENTRY(dtrace_casptr)
	movq	%rsi, %rax
	lock
	cmpxchgq %rdx, (%rdi)
	ret
	END(dtrace_casptr)

/*
uintptr_t
dtrace_fulword(void *addr)
*/
	ENTRY(dtrace_fulword)
	movq	(%rdi), %rax
	ret
	END(dtrace_fulword)

/*
void
dtrace_membar_producer(void)
*/
	ENTRY(dtrace_membar_producer)
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	END(dtrace_membar_producer)

/*
void
dtrace_membar_consumer(void)
*/
	ENTRY(dtrace_membar_consumer)
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	END(dtrace_membar_consumer)
