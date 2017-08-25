#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

static void
dtrace_nullop(void)
{}

static dtrace_pops_t test_provider_ops = {
(void (*)(void *, dtrace_probedesc_t *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *, dtrace_argdesc_t *))dtrace_nullop,
/*(uint64_t (*)(void *, dtrace_id_t, void *, int, int))dtrace_nullop,*/
NULL,
(int (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop
};

static dtrace_pattr_t test_provider_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

int
main(void)
{
	/*
	 * Test probe creation
	 */
	dtrace_provider_id_t id;
	dtrace_id_t probeid, lookupid;
	int err;
	size_t sz;
	char (*provs)[DTRACE_PROVNAMELEN];

	err = dtrace_init();
	if (err) {
		printf("DTrace not properly initialized: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	if (err) {
		printf("Failed to register a provider: %s\n", strerror(err));
		return (1);
	}

	provs = (char (*)[DTRACE_PROVNAMELEN]) dtrace_providers(&sz);
	if (sz != 2) {
		printf("Too many providers: %zu\n", sz);
		return (1);
	}

	if (strcmp("dtrace", provs[0]) != 0) {
		printf("The first provider is not dtrace: %s\n", provs[0]);
		return (1);
	}

	if (strcmp("test_provider", provs[1]) != 0) {
		printf("The second provider is not test_provider: %s\n",
		    provs[1]);
		return (1);
	}

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	if (probeid != 4) {
		printf("Wrong probe ID: %d\n", probeid);
		return (1);
	}

	lookupid = dtrace_probe_lookup(id, "test", "probe", "foo");
	if (lookupid != probeid) {
		printf("Looked up probe ID does not match the correct one: %d\n",
		    lookupid);
		return (1);
	}

	/*
	 * TODO: We are not really testing this at all. We should be checking
	 * the diff of the state and the internal buffers.
	 */
	dtrace_probe(probeid, 0, 0, 0, 0, 0);

	err = dtrace_unregister(id);
	if (err) {
		printf("Failed to unregister a provider: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_deinit();
	if (err) {
		printf("DTrace not properly deinitialized: %s\n", strerror(err));
		return (1);
	}

	return (0);
}

