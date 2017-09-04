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
	 * Test the LDUH operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	uint32_t var;
	uint64_t rd;

	var = 73;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_lduh(dtapi_conf, (uint16_t) var, &err);

	DTCHECK(err, ("LDUH failed: %s\n", strerror(err)));
	DTCHECK(rd != 73,
	    ("rd (%lu) != 73\n", rd));

	var = 256;
	rd = dtapi_op_lduh(dtapi_conf, (uint16_t) var, &err);

	DTCHECK(err, ("LDUH failed: %s\n", strerror(err)));
	DTCHECK(rd != 256,
	    ("rd (%lu) != 256\n", rd));

	var = 1 << 16;
	rd = dtapi_op_lduh(dtapi_conf, (uint16_t) var, &err);

	DTCHECK(err, ("LDUH failed: %s\n", strerror(err)));
	DTCHECK(rd != 0,
	    ("rd (%lu) != 0\n", rd));

	dtapi_deinit(dtapi_conf);

	return (0);
}

