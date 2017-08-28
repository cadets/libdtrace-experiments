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
	 * Test the SRL operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t r1, r2, rd;
	int err;

	r1 = 0xD0600000;
	r2 = 20;
	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_srl(dtapi_conf, r1, r2, &err);

	DTCHECK(err, ("SRL failed: %s\n", strerror(err)));
	DTCHECK(rd != 0xD06, ("rd (%#lx) != 0xD06\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

