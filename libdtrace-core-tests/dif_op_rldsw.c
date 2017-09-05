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
	 * Test the RLDSW operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	int32_t var;
	uint64_t rd;

	var = -1;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_rldsw(dtapi_conf, var, &err);

	DTCHECK(err, ("RLDSW failed: %s\n", strerror(err)));
	DTCHECK(rd != 0xFFFFFFFFFFFFFFFF,
	    ("rd (%#lx) != 0xFFFFFFFFFFFFFFFF\n", rd));

	var = 7357116;
	rd = dtapi_op_rldsw(dtapi_conf, var, &err);

	DTCHECK(err, ("RLDSW failed: %s\n", strerror(err)));
	DTCHECK(rd != 7357116,
	    ("rd (%lu) != 7357116\n", rd));

	return (0);
}

