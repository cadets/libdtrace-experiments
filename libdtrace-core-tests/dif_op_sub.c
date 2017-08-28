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
	 * Test the SUB operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_sub(dtapi_conf, 100, 50, &err);

	DTCHECK(err, ("SUB failed: %s\n", strerror(err)));
	DTCHECK(rd != 50, ("rd (%lu) != 50\n", rd));

	rd = dtapi_op_sub(dtapi_conf, 0, 1, &err);

	DTCHECK(err, ("SUB failed: %s\n", strerror(err)));
	DTCHECK(rd != 0xFFFFFFFFFFFFFFFF,
	    ("rd (%lu) != 0xFFFFFFFFFFFFFFFF\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

