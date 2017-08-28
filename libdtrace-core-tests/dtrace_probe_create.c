#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

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
	DTCHECK(err, ("DTrace not properly initialized: %s\n", strerror(err)));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	DTCHECK(err, ("Failed to register a provider: %s\n", strerror(err)));

	provs = (char (*)[DTRACE_PROVNAMELEN]) dtrace_providers(&sz);

	DTCHECK(sz != 2, ("Too many providers: %zu\n", sz));
	DTCHECKSTR("dtrace", provs[0],
	    ("The first provider is not dtrace: %s\n", provs[0]));
	DTCHECKSTR("test_provider", provs[1],
	    ("The second provider is not test_provider: %s\n", provs[1]));

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	DTCHECK(probeid != 4, ("Wrong probe ID (expected 4): %d\n", probeid));

	lookupid = dtrace_probe_lookup(id, "test", "probe", "foo");

	DTCHECK(lookupid != probeid,
	    ("Looked up probe ID does not match the correct one (4): %d\n",
	     lookupid));

	err = dtrace_unregister(id);
	DTCHECK(err, ("Failed to unregister a provider: %s\n", strerror(err)));

	err = dtrace_deinit();
	DTCHECK(err, ("DTrace not properly deinitialized: %s\n", strerror(err)));
	return (0);
}

