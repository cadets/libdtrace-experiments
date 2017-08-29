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
	 * Test the BA operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	pc = dtapi_op_ba(dtapi_conf, 1234, &err);
	DTCHECK(err, ("BA failed: %s\n", strerror(err)));
	DTCHECK(pc != 1234, ("pc (%u) != 1234\n", pc));

	dtapi_deinit(dtapi_conf);
	return (0);
}

