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
	 * Test the ADD operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_add(dtapi_conf, 100, 50, &err);

	DTCHECK(err, ("ADD failed: %s\n", strerror(err)));
	DTCHECK(rd != 150, ("rd (%lu) != 150\n", rd));

	rd = dtapi_op_add(dtapi_conf, 0xFFFFFFFFFFFFFFFF, 1, &err);

	DTCHECK(err, ("ADD failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%lu) != 0\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

