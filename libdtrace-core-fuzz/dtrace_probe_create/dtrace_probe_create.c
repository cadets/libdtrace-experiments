#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../../libdtrace-core/dtrace.h"
#include "../../libdtrace-core/dtrace_impl.h"

#define	MAX_PROBES 20000

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
	char provname[DTRACE_PROVNAMELEN];
	char modname[DTRACE_MODNAMELEN];
	char funcname[DTRACE_FUNCNAMELEN];
	char name[DTRACE_NAMELEN];
	int aframes;
	uint32_t priv;
	int err;
	void *arg;
	int i;
	char c;
	dtrace_provider_id_t id;
	dtrace_id_t probeid;
	cred_t *cr;

	fgets(provname, DTRACE_PROVNAMELEN, stdin);
	provname[strcspn(provname, "\n")] = 0;
	scanf("%u", &priv);

	err = dtrace_init();
	if (err) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	cr = NULL;
	arg = NULL;

	err = dtrace_register(provname, &pap, priv, cr, &pops, arg, &id);
	if (err != 0) {
		printf("error: %s\n", strerror(err));
		return (1);
	}

	for (i = 0; i < MAX_PROBES; i++) {
		scanf("%c", &c);
		fgets(modname, DTRACE_MODNAMELEN, stdin);
		modname[strcspn(modname, "\n")] = 0;
		fgets(funcname, DTRACE_FUNCNAMELEN, stdin);
		funcname[strcspn(funcname, "\n")] = 0;
		fgets(name, DTRACE_NAMELEN, stdin);
		name[strcspn(name, "\n")] = 0;
		scanf("%u", &aframes);

		probeid = dtrace_probe_create(id, modname, funcname, name, aframes, NULL);
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

	return (0);
}


