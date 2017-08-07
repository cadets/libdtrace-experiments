#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
	uint_t buflen;
	uint_t intlen;
	uint_t strlen;
	uint_t varlen;
	uint8_t dt_type;
	uint8_t dt_ckind;
	uint8_t dt_flags;
	uint32_t dt_size;
	dif_instr_t instr;
	int err;

	vstate = calloc(1, sizeof (dtrace_vstate_t));

	err = dtrace_init();
	if (err) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_deinit();
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	free(vstate);

	return (err);
}
