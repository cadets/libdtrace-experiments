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
	 * Test the probeid variable.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	dtrace_id_t probeid;
	int err;

	err = dtrace_init();
	DTCHECK(err, ("DTrace not properly initialized: %s", strerror(err)));

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	probeid = 3;
	dtapi_set_probe(dtapi_conf, probeid);

	rd = dtapi_var_id(dtapi_conf, &err);
	DTCHECK(err, ("ID failed: %s\n", strerror(err)));
	DTCHECK(rd != 3, ("rd (%lu) != 3\n", rd));

	dtapi_deinit(dtapi_conf);
	err = dtrace_deinit();
	DTCHECK(err, ("DTrace not properly deinitialized: %s", strerror(err)));
	return (0);
}

