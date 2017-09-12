#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

static uint64_t
test_getargval(void *arg __unused, dtrace_id_t id __unused, void *parg,
    int argno __unused, int aframes __unused)
{

	return (*((uint64_t *) parg));
}

static void
dtrace_nullop(void)
{}

static dtrace_pops_t test_provider_ops = {
.dtps_provide = (void (*)(void *, dtrace_probedesc_t *))dtrace_nullop,
.dtps_enable = (void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
.dtps_disable = (void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
.dtps_suspend = (void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
.dtps_resume = (void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
.dtps_getargdesc = (void (*)(void *, dtrace_id_t, void *, dtrace_argdesc_t *))dtrace_nullop,
.dtps_getargval = (uint64_t (*)(void *, dtrace_id_t, void *, int, int))test_getargval,
.dtps_usermode = (int (*)(void *, dtrace_id_t, void *))dtrace_nullop,
.dtps_destroy = (void (*)(void *, dtrace_id_t, void *))dtrace_nullop
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
	 * Test the args[] variable.
	 */
	dtapi_conf_t *dtapi_conf;
	dtrace_id_t probeid;
	dtrace_probe_t *probe;
	dtrace_provider_id_t id;
	uint64_t rd;
	const char *buf = "hello world";
	int err;
	uint64_t testval = 1234;
	uint64_t arg[5] = { 0, 99, 3241, 5123, 0 };

	err = dtrace_init();
	DTCHECK(err, ("DTrace not properly initialized: %s\n", strerror(err)));

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = 0;

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	DTCHECK(err, ("Provider creation failed: %s\n", strerror(err)));

	probeid = dtrace_probe_create(id, "test", "probe", "foo", 0, NULL);
	probe = dtrace_getprobe(probeid);
	probe->dtpr_arg = &testval;

	rd = dtapi_var_args(dtapi_conf, arg, 0, probeid, &err);
	DTCHECK(err, ("ARGS failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%lu) != 0\n", rd));

	rd = dtapi_var_args(dtapi_conf, arg, 1, probeid, &err);
	DTCHECK(err, ("ARGS failed: %s\n", strerror(err)));
	DTCHECK(rd != 99, ("rd (%lu) != 99\n", rd));

	rd = dtapi_var_args(dtapi_conf, arg, 2, probeid, &err);
	DTCHECK(err, ("ARGS failed: %s\n", strerror(err)));
	DTCHECK(rd != 3241, ("rd (%lu) != 3241\n", rd));

	rd = dtapi_var_args(dtapi_conf, arg, 3, probeid, &err);
	DTCHECK(err, ("ARGS failed: %s\n", strerror(err)));
	DTCHECK(rd != 5123, ("rd (%lu) != 5123\n", rd));

	rd = dtapi_var_args(dtapi_conf, arg, 4, probeid, &err);
	DTCHECK(err, ("ARGS failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%lu) != 0\n", rd));

	rd = dtapi_var_args(dtapi_conf, arg, 5, probeid, &err);
	DTCHECK(err, ("ARGS failed: %s\n", strerror(err)));
	DTCHECK(rd != testval, ("rd (%lu) != 1234\n", rd));

	dtapi_deinit(dtapi_conf);
	err = dtrace_unregister(id);
	DTCHECK(err, ("Could not unregister provider: %s\n", strerror(err)));
	err = dtrace_deinit();
	DTCHECK(err, ("DTrace not properly deinitialized: %s\n", strerror(err)));
	return (0);
}

