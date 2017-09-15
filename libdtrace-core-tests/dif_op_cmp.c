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
	 * Test the CMP operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	dtapi_op_cmp(dtapi_conf, 20, 5, &err);
	DTCHECK(err, ("CMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != 15,
	    ("cc_r (%ld) != 15\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != 0,
	    ("cc_n (%ld) != 0\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != 0,
	    ("cc_z (%hhu) != 0\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 0,
	    ("cc_c (%hhu) != 0\n", dtapi_state->cc_c));

	dtapi_op_cmp(dtapi_conf, 20, 20, &err);
	DTCHECK(err, ("CMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != 0,
	    ("cc_r (%ld) != 0\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != 0,
	    ("cc_n (%ld) != 0\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != 1,
	    ("cc_z (%hhu) != 1\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 0,
	    ("cc_c (%hhu) != 0\n", dtapi_state->cc_c));

	dtapi_op_cmp(dtapi_conf, 10, 20, &err);
	DTCHECK(err, ("CMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != -10,
	    ("cc_r (%ld) != -10\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != 1,
	    ("cc_n (%ld) != 1\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != 0,
	    ("cc_z (%hhu) != 0\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 1,
	    ("cc_c (%hhu) != 1\n", dtapi_state->cc_c));

	dtapi_deinit(dtapi_conf);
	return (0);
}

