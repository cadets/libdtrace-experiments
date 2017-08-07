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
