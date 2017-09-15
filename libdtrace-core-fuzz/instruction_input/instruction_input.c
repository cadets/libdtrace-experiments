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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../../libdtrace-core/dtrace.h"
#include "../../libdtrace-core/dtrace_impl.h"

#ifndef _DTRACE_TESTS
#error Compilation of this file only works if _DTRACE_TESTS is enabled.
#endif

static void dtrace_nullop() {}

static dtrace_pops_t pops = {
(void (*)(void *, dtrace_probedesc_t *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *, dtrace_argdesc_t *))dtrace_nullop,
NULL,
(int (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop
};

static dtrace_pattr_t pap = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

int
main(void)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	cred_t *cr;
	int err;
	void *arg;
	uint32_t priv;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	priv = 0x01;
	arg = NULL;
	cr = NULL;

	err = dtrace_init();
	if (err) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_register("test", &pap, priv, cr, &pops, arg, &id);
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	probeid = dtrace_probe_create(id, "test", "test", "test", 0, NULL);

	mstate->dtms_probe = dtrace_getprobe(probeid);
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	scanf("%d", &instr);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
	if (err) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_unregister(id);
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_deinit();
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	free(mstate);
	free(vstate);
	free(state);
	free(estate);

	return (err);
}
