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
	 * Test the SDIV operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_sdiv(dtapi_conf, 1024, -2, &err);

	DTCHECK(err, ("SDIV failed: %s\n", strerror(err)));
	DTCHECK(rd != -512, ("rd (%ld) != -512\n", rd));

	rd = dtapi_op_sdiv(dtapi_conf, -1024, 2, &err);

	DTCHECK(err, ("SDIV failed: %s\n", strerror(err)));
	DTCHECK(rd != -512, ("rd (%ld) != -512\n", rd));

	rd = dtapi_op_sdiv(dtapi_conf, 1024, 2, &err);

	DTCHECK(err, ("SDIV failed: %s\n", strerror(err)));
	DTCHECK(rd != 512, ("rd (%ld) != 512\n", rd));

	rd = dtapi_op_sdiv(dtapi_conf, -1024, -2, &err);

	DTCHECK(err, ("SDIV failed: %s\n", strerror(err)));
	DTCHECK(rd != 512, ("rd (%ld) != 512\n", rd));

	rd = dtapi_op_sdiv(dtapi_conf, 1024, 0, &err);

	DTCHECK(err != EINVAL,
	    ("SDIV failed (expected EINVAL): %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%ld) != 0\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

