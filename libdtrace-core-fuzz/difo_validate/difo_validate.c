#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "../../libdtrace-core/dtrace.h"
#include "../../libdtrace-core/dtrace_impl.h"

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

int
main(void)
{
	dtrace_difo_t *dp;
	dtrace_vstate_t *vstate;
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
	uint32_t dt_size;
	dif_instr_t instr;
	int err;
	char c;
	uint8_t dt_type;
	uint8_t dt_ckind;
	uint8_t dt_flags;

	dp = NULL;
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
		scanf("%u", &intentry);
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
		scanf("%" SCNu32, &vartab[i].dtdv_name);
		scanf("%" SCNu32, &vartab[i].dtdv_id);
		scanf("%" SCNu8, &vartab[i].dtdv_kind);
		scanf("%" SCNu8, &vartab[i].dtdv_scope);
		scanf("%" SCNu16, &vartab[i].dtdv_flags);
		scanf("%" SCNu8, &vartab[i].dtdv_type.dtdt_kind);
		scanf("%" SCNu8, &vartab[i].dtdv_type.dtdt_ckind);
		scanf("%" SCNu8, &vartab[i].dtdv_type.dtdt_flags);
		scanf("%" SCNu32, &vartab[i].dtdv_type.dtdt_size);
	}

	err = dtrace_deinit();
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	free(vstate);

	return (err);
}
