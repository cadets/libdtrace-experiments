#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

int
main(void)
{
	/*
	 * Test the NOP operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_nop(dtapi_conf, &err);
	if (err) {
		printf("NOP failed: %s\n", strerror(err));
		return (1);
	}

	dtapi_deinit(dtapi_conf);

	return (0);
}
