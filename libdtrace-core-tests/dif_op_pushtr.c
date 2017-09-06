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
	 * Test the PUSHTR operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;

	dtapi_conf = dtapi_init(100, 32, DTRACE_ACCESS_KERNEL);

	dtapi_op_pushtr(dtapi_conf, 0, 4, 0xFF, &err);
	DTCHECK(err, ("PUSHTR failed: %s\n", strerror(err)));
	dtapi_deinit(dtapi_conf);

	return (0);
}
