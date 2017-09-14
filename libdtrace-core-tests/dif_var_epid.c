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
	 * Test the epid variable.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	dtapi_var_set_epid(dtapi_conf, 123);

	rd = dtapi_var_epid(dtapi_conf, &err);
	DTCHECK(err, ("EPID failed: %s\n", strerror(err)));
	DTCHECK(rd != 123, ("rd (%lu) != 123\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

