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
	 * Test the RET operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_set_textlen(dtapi_conf, 1000);
	pc = dtapi_op_ret(dtapi_conf, &err);
	if (err) {
		printf("RET failed: %s\n", strerror(err));
		return (1);
	}

	if (pc != 1000) {
		printf("pc (%u) != 1000\n", pc);
		return (1);
	}

	dtapi_deinit(dtapi_conf);
	return (0);
}
