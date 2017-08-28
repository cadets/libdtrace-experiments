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
	 * Test the UREM operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_urem(dtapi_conf, 1024, 513, &err);

	DTCHECK(err, ("UREM failed: %s\n", strerror(err)));
	DTCHECK(rd != 511, ("rd (%lu) != 511\n", rd));

	rd = dtapi_op_urem(dtapi_conf, 1024, -513, &err);

	DTCHECK(err, ("UREM failed: %s\n", strerror(err)));
	DTCHECK(rd != 0x400, ("rd (%#lx) != 0x400\n", rd));

	rd = dtapi_op_urem(dtapi_conf, -1024, 513, &err);

	DTCHECK(err, ("UREM failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%lu) != 0\n", rd));

	rd = dtapi_op_urem(dtapi_conf, -1024, -513, &err);

	DTCHECK(err, ("UREM failed: %s\n", strerror(err)));
	DTCHECK(rd != 0xFFFFFFFFFFFFFC00, ("rd (%#lx) != 0xFFFFFFFFFFFFFC00\n", rd));

	rd = dtapi_op_urem(dtapi_conf, 1024, 0, &err);

	DTCHECK(err != EINVAL,
	    ("UREM failed (expected EINVAL): %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%lu) != 0\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

