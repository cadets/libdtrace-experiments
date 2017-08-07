#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "../../libdtrace-core/dtrace.h"
#include "../../libdtrace-core/dtrace_impl.h"

#ifndef _DTRACE_TESTS
#error Compilation of this file only works if _DTRACE_TESTS is enabled.
#endif

static dtrace_difo_t *
alloc_difo(dif_instr_t *buf, uint64_t *inttab, char *strtab,
    dtrace_difv_t *vartab, uint_t buflen, uint_t intlen, uint_t strlen,
    uint_t varlen, dtrace_diftype_t rtype, uint_t refcnt, uint_t destructive)
{
	dtrace_difo_t *dp;

	dp = malloc(sizeof(dtrace_difo_t));

	dp->dtdo_buf = buf;
	dp->dtdo_inttab = inttab;
	dp->dtdo_strtab = strtab;
	dp->dtdo_vartab = vartab;
	dp->dtdo_len = buflen;
	dp->dtdo_intlen = intlen;
	dp->dtdo_strlen = strlen;
	dp->dtdo_varlen = varlen;
	dp->dtdo_rtype = rtype;
	dp->dtdo_refcnt = refcnt;
	dp->dtdo_destructive = destructive;

	return (dp);
}

static void
scanf_var(dtrace_difv_t *var)
{
	scanf("%" SCNu32, &var->dtdv_name);
	scanf("%" SCNu32, &var->dtdv_id);
	scanf("%" SCNu8, &var->dtdv_kind);
	scanf("%" SCNu8, &var->dtdv_scope);
	scanf("%" SCNu16, &var->dtdv_flags);
	scanf("%" SCNu8, &var->dtdv_type.dtdt_kind);
	scanf("%" SCNu8, &var->dtdv_type.dtdt_ckind);
	scanf("%" SCNu8, &var->dtdv_type.dtdt_flags);
	scanf("%" SCNu32, &var->dtdv_type.dtdt_size);
}

static void
scanf_statvar(dtrace_statvar_t *var)
{
	scanf("%" SCNu64, &var->dtsv_data);
	scanf("%zu", &var->dtsv_size);
	scanf("%d", &var->dtsv_refcnt);
	scanf("%" SCNu64, &var->dtsv_data);
	scanf_var(&var->dtsv_var);
}

int
main(void)
{
	dtrace_difo_t *dp;
	cred_t *cr;
	dtrace_vstate_t *vstate;
	dtrace_statvar_t *vstate_globals;
	dtrace_statvar_t *vstate_locals;
	dtrace_difv_t *vstate_tlocals;
	dif_instr_t *instr_buf;
	uint64_t *inttab;
	uint64_t intentry;
	char *strtab;
	dtrace_difv_t *vartab;
	uint_t buflen;
	uint_t intlen;
	uint_t strlen;
	uint_t varlen;
	uint_t i;
	uint_t nregs;
	uint32_t dt_size;
	dif_instr_t instr;
	int err;
	int nglobals;
	int nlocals;
	int ntlocals;
	char c;
	uint8_t dt_type;
	uint8_t dt_ckind;
	uint8_t dt_flags;

	dp = NULL;
	cr = NULL;
	instr_buf = NULL;
	inttab = NULL;
	intentry = 0;
	strtab = NULL;
	vartab = NULL;
	buflen = 0;
	intlen = 0;
	strlen = 0;
	varlen = 0;
	i = 0;
	nregs = 0;
	dt_size = 0;
	instr = 0;
	err = 0;
	dt_type = 0;
	dt_ckind = 0;
	dt_flags = 0;
	vstate = calloc(1, sizeof (dtrace_vstate_t));

	err = dtrace_init();
	if (err) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	/*
	 * The lengths of the buffers
	 */
	scanf("%u", &buflen);
	scanf("%u", &intlen);
	scanf("%u", &strlen);
	scanf("%u", &varlen);

	instr_buf = malloc(sizeof(dif_instr_t) * buflen);
	inttab = malloc(sizeof(uint64_t) * intlen);
	strtab = malloc(strlen);
	vartab = malloc(sizeof(dtrace_difv_t) * varlen);

	/*
	 * Fill in the instructions
	 */
	for (i = 0; i < buflen; i++) {
		scanf("%u", &instr);
		instr_buf[i] = instr;
	}

	/*
	 * Fill in the integer table
	 */
	for (i = 0; i < intlen; i++) {
		scanf("%" SCNu64, &intentry);
		inttab[i] = intentry;
	}

	/*
	 * Fill in the string table
	 */
	for (i = 0; i < strlen; i++) {
		scanf("%c", &c);
		strtab[i] = c;
	}

	/*
	 * Fill in the variable table
	 */
	for (i = 0; i < varlen; i++) {
		scanf_var(&vartab[i]);
	}

	/*
	 * TODO: Check that the state is well defined.
	 *
	 * XXX: We are currently fuzzing everything in the interface, assuming
	 * we have some form of access to everything. This is not necessarily
	 * true for vstate, and should be done a bit better.
	 */

	/*
	 * Read the amount of variables.
	 *
	 * XXX: This will overflow, and is not necessarily controlled by the
	 * user?
	 */
	scanf("%d", &nglobals);
	scanf("%d", &ntlocals);
	scanf("%d", &nlocals);

	vstate->dtvs_nglobals = nglobals;
	vstate->dtvs_ntlocals = ntlocals;
	vstate->dtvs_nlocals = nlocals;

	/*
	 * Allocate all of the necessary buffers
	 */
	vstate->dtvs_state = calloc(1, sizeof(dtrace_state_t));
	vstate_globals = malloc(sizeof(dtrace_statvar_t *) * nglobals);
	vstate_tlocals = malloc(sizeof(dtrace_difv_t) * ntlocals);
	vstate_locals = malloc(sizeof(dtrace_statvar_t *) * nlocals);
	memset(&vstate->dtvs_dynvars, 0, sizeof(dtrace_dstate_t));

	/*
	 * XXX:
	 * Fill in the global variables arbitrarily. This may or may not be the
	 * case with DTrace.
	 */
	for (i = 0; i < nglobals; i++) {
		scanf_statvar(&vstate_globals[i]);
	}

	for (i = 0; i < ntlocals; i++) {
		scanf_var(&vstate_tlocals[i]);
	}

	for (i = 0; i < nlocals; i++) {
		scanf_statvar(&vstate_locals[i]);
	}

	vstate->dtvs_globals = &vstate_globals;
	vstate->dtvs_tlocals = vstate_tlocals;
	vstate->dtvs_locals = &vstate_locals;

	scanf("%u", &nregs);

	err = dtrace_difo_validate(dp, vstate, nregs, cr);
	if (err)
		return (1);

	err = dtrace_deinit();
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	free(instr_buf);
	free(inttab);
	free(strtab);
	free(vartab);
	free(vstate);
	free(dp);

	return (0);
}
