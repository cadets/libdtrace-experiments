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
	 * Test the LDUB operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	uint16_t var;
	uint64_t rd;

	var = 73;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_ldub(dtapi_conf, (uint8_t) var, &err);

	DTCHECK(err, ("LDUB failed: %s\n", strerror(err)));
	DTCHECK(rd != 73,
	    ("rd (%lu) != 73\n", rd));

	var = 256;
	rd = dtapi_op_ldub(dtapi_conf, (uint8_t) var, &err);

	DTCHECK(err, ("LDUB failed: %s\n", strerror(err)));
	DTCHECK(rd != 0,
	    ("rd (%lu) != 0\n", rd));

	dtapi_deinit(dtapi_conf);

	return (0);
}

