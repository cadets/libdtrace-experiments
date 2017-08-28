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
	 * Test the MOV operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_mov(dtapi_conf, 1234, &err);

	DTCHECK(err, ("MOV failed: %s\n", strerror(err)));
	DTCHECK(rd != 1234, ("rd (%ld) != 1234\n", rd));

	rd = dtapi_op_mov(dtapi_conf, -1, &err);

	DTCHECK(err, ("MOV failed: %s\n", strerror(err)));
	DTCHECK(rd != -1, ("rd (%ld) != -1\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

