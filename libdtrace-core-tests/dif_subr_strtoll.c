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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

int
main(void)
{
	/*
	 * Test the strtoll() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	int64_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_strtoll(dtapi_conf, "4123", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != 4123, ("rd (%ld) != 4123\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "abc", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "-1234", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != -1234, ("rd (%ld) != -1234\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "-1234a", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != -1234, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "1234a", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != 1234, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "s1234", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "12a34", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != 12, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "    12a34", &err);
	DTCHECK(err, ("STRTOLL failed: %s\n", strerror(err)));
	DTCHECK(rd != 12, ("rd (%ld) != 0\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

