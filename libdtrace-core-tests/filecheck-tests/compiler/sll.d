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
 * CHECK: setx %r1, 0 ! 0x2
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1

 * CHECK: setx %r1, 0 ! 0x1
 * CHECK-NEXT: stgs 1281, %r1 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: ret %r1

 * CHECK: ldgs %r1, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ldgs %r2, 1281 ! DT_VAR(1281) = "y"
 * CHECK-NEXT: sll %r1, %r1, %r2
 * CHECK-NEXT: stgs 1282, %r1 ! DT_VAR(1282) = "z"
 * CHECK-NEXT: ret %r1
 */
	x = 2;
	y = 1;
	z = x << y;
}
