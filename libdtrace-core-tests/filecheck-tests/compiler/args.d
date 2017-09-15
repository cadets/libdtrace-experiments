/*-
* Copyright (c) 2017 Domagoj Stolfa
* All rights reserved.
*
* This software was developed by BAE Systems, the University of Cambridge
* Computer Laboratory, and Memorial University under DARPA/AFRL contract
* FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
* (TC) research program.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

BEGIN
{
/*
 * CHECK: ldgs %r1, 262 ! DT_VAR(262) = "arg0"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 263 ! DT_VAR(263) = "arg1"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 264 ! DT_VAR(264) = "arg2"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 265 ! DT_VAR(265) = "arg3"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 266 ! DT_VAR(266) = "arg4"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 267 ! DT_VAR(267) = "arg5"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 268 ! DT_VAR(268) = "arg6"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 269 ! DT_VAR(269) = "arg7"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 270 ! DT_VAR(270) = "arg8"
 * CHECK-NEXT: ret %r1
 *
 * CHECK: ldgs %r1, 271 ! DT_VAR(271) = "arg9"
 * CHECK-NEXT: ret %r1
 */


	trace(arg0);
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
	trace(arg6);
	trace(arg7);
	trace(arg8);
	trace(arg9);
}
